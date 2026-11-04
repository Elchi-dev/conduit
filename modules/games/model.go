package games

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers "sqlite", for itch.io, Lutris and GOG Galaxy
)

// Game is one game in the unified library, whichever launcher it comes from.
type Game struct {
	// ID is "<launcher>:<native id>", e.g. "steam:570" or "epic:Fortnite".
	ID       string `json:"id"`
	Title    string `json:"title"`
	Launcher string `json:"launcher"`
	NativeID string `json:"nativeId"`
	// AppID is the Steam app id (Steam games only), kept for older callers.
	AppID       int      `json:"appId,omitempty"`
	Installed   bool     `json:"installed"`
	InstallPath string   `json:"installPath,omitempty"`
	SizeBytes   int64    `json:"sizeBytes,omitempty"`
	Size        string   `json:"size,omitempty"`
	Executables []string `json:"executables,omitempty"`
	// ProcessNames are the executable names the game runs as.
	ProcessNames []string `json:"processNames,omitempty"`
	// Cover is a portrait (2:3) cover image URL, when one is known.
	Cover string `json:"cover,omitempty"`
	// HasCover says /api/v1/games/covers/{id} can serve a cover (remote or
	// from the launcher's local cache).
	HasCover   bool   `json:"hasCover"`
	LastPlayed string `json:"lastPlayed,omitempty"`
	// PlaySeconds is the play time Conduit recorded.
	PlaySeconds int64 `json:"playSeconds"`
	// LauncherPlaySeconds is the play time the launcher itself recorded,
	// when its local files say (Steam, GOG Galaxy, itch.io, Lutris).
	LauncherPlaySeconds int64 `json:"launcherPlaySeconds,omitempty"`
	// TotalPlaySeconds is the larger of the two.
	TotalPlaySeconds int64  `json:"totalPlaySeconds"`
	Updated          string `json:"updated,omitempty"`
	Running          bool   `json:"running"`
	Custom           bool   `json:"custom,omitempty"`
	// Folder is the Steam library folder (Steam games only).
	Folder string `json:"folder,omitempty"`

	launch       launchSpec
	coverFile    string    // a cover image in the launcher's local cache
	launcherLast time.Time // last played, according to the launcher
}

// launchSpec says how to start a game: a URI handed to the system, or a
// program with arguments.
type launchSpec struct {
	URI  string
	Exe  string
	Args []string
	Dir  string
}

func (l launchSpec) describe() string {
	if l.URI != "" {
		return l.URI
	}
	if l.Exe == "" {
		return ""
	}
	return commandLine(l.Exe, l.Args)
}

// launcherInfo describes a launcher the module knows.
type launcherInfo struct {
	ID   string
	Name string
	// OS lists where the launcher (or a stand-in such as Heroic) exists.
	OS []string
	// Note explains a limitation, shown by refresh.
	Note string
	scan func(e *env) (found bool, games []Game, err error)
}

// LauncherStatus is one launcher's detection result.
type LauncherStatus struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Supported bool   `json:"supported"`
	Detected  bool   `json:"detected"`
	Games     int    `json:"games"`
	Note      string `json:"note,omitempty"`
	Error     string `json:"error,omitempty"`
}

func launchers() []launcherInfo {
	all := []string{"windows", "darwin", "linux"}
	return []launcherInfo{
		{ID: "steam", Name: "Steam", OS: all, scan: scanSteam},
		{ID: "epic", Name: "Epic Games", OS: all, scan: scanEpic,
			Note: "On Linux through Heroic or Legendary."},
		{ID: "gog", Name: "GOG", OS: all, scan: scanGOG,
			Note: "On Linux through Heroic."},
		{ID: "riot", Name: "Riot Games", OS: []string{"windows", "darwin"}, scan: scanRiot},
		{ID: "battlenet", Name: "Battle.net", OS: []string{"windows", "darwin"}, scan: scanBattleNet},
		{ID: "ea", Name: "EA app", OS: []string{"windows"}, scan: scanEA},
		{ID: "ubisoft", Name: "Ubisoft Connect", OS: []string{"windows"}, scan: scanUbisoft},
		{ID: "xbox", Name: "Xbox", OS: []string{"windows"}, scan: scanXbox,
			Note: "Games installed by the Xbox app into XboxGames folders. Other Microsoft Store apps aren't listed."},
		{ID: "itch", Name: "itch.io", OS: all, scan: scanItch},
		{ID: "lutris", Name: "Lutris", OS: []string{"linux"}, scan: scanLutris},
		{ID: "windows", Name: "Other installed games", OS: []string{"windows"}, scan: scanUninstall,
			Note: "Programs from known game publishers in the Windows list of installed programs."},
	}
}

// launcherName returns a launcher's display name.
func launcherName(id string) string {
	if id == "custom" {
		return "Custom"
	}
	for _, l := range launchers() {
		if l.ID == id {
			return l.Name
		}
	}
	return id
}

// regKey is one registry key with its string and number values.
type regKey struct {
	Name   string
	Values map[string]string
}

// env is where the scanners look. Tests point it at fixture folders and a
// fake registry.
type env struct {
	GOOS         string
	Home         string
	ProgramData  string // C:\ProgramData
	AppData      string // %APPDATA% (Roaming)
	LocalAppData string // %LOCALAPPDATA%
	ConfigHome   string // $XDG_CONFIG_HOME or ~/.config
	DataHome     string // $XDG_DATA_HOME or ~/.local/share
	SteamPath    string // configured Steam folder
	// Reg lists the subkeys of a registry key ("HKLM", `SOFTWARE\...`).
	Reg func(root, path string) []regKey
	// RegValues reads one key's values.
	RegValues func(root, path string) map[string]string
	// Drives lists drive roots to look for XboxGames folders on.
	Drives []string
}

func defaultEnv(steamPath string) *env {
	home, _ := os.UserHomeDir()
	e := &env{GOOS: runtime.GOOS, Home: home, SteamPath: steamPath, Reg: regSubkeys, RegValues: regValues}
	e.ProgramData = os.Getenv("ProgramData")
	if e.ProgramData == "" && e.GOOS == "windows" {
		e.ProgramData = `C:\ProgramData`
	}
	e.AppData = os.Getenv("APPDATA")
	e.LocalAppData = os.Getenv("LOCALAPPDATA")
	e.ConfigHome = os.Getenv("XDG_CONFIG_HOME")
	if e.ConfigHome == "" {
		e.ConfigHome = filepath.Join(home, ".config")
	}
	e.DataHome = os.Getenv("XDG_DATA_HOME")
	if e.DataHome == "" {
		e.DataHome = filepath.Join(home, ".local", "share")
	}
	if e.GOOS == "windows" {
		for c := 'C'; c <= 'Z'; c++ {
			d := string(c) + `:\`
			if _, err := os.Stat(d); err == nil {
				e.Drives = append(e.Drives, d)
			}
		}
	}
	return e
}

func (e *env) reg(root, path string) []regKey {
	if e.Reg == nil {
		return nil
	}
	return e.Reg(root, path)
}

func (e *env) regValues(root, path string) map[string]string {
	if e.RegValues == nil {
		return nil
	}
	return e.RegValues(root, path)
}

// supported reports whether a launcher exists on this OS.
func (l launcherInfo) supported(goos string) bool {
	for _, o := range l.OS {
		if o == goos {
			return true
		}
	}
	return false
}

func exists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func humanSize(b int64) string {
	if b <= 0 {
		return ""
	}
	return fmt.Sprintf("%.1f GB", float64(b)/1e9)
}

// openSQLite opens a launcher's SQLite database read-only from a private
// copy, so the launcher's own locks and write-ahead log never get in the way.
func openSQLite(path string) (*sql.DB, func(), error) {
	dir, err := os.MkdirTemp("", "conduit-games-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	dst := filepath.Join(dir, "db.sqlite")
	if err := copyFile(path, dst); err != nil {
		cleanup()
		return nil, nil, err
	}
	for _, suf := range []string{"-wal", "-shm"} {
		if exists(path + suf) {
			_ = copyFile(path+suf, dst+suf)
		}
	}
	db, err := sql.Open("sqlite", "file:"+dst+"?_pragma=busy_timeout(2000)")
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return db, func() { db.Close(); cleanup() }, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// slug turns a title into an id-safe lowercase string.
func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

func baseNames(paths []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		n := filepath.Base(strings.ReplaceAll(p, `\`, "/"))
		if n == "." || n == "/" || n == "" || seen[strings.ToLower(n)] {
			continue
		}
		seen[strings.ToLower(n)] = true
		out = append(out, n)
	}
	return out
}

// joinNative joins a launcher-supplied relative executable onto an install
// path, accepting either slash style.
func joinNative(dir, rel string) string {
	if rel == "" {
		return ""
	}
	rel = strings.ReplaceAll(rel, `\`, string(filepath.Separator))
	rel = strings.ReplaceAll(rel, "/", string(filepath.Separator))
	if filepath.IsAbs(rel) || (len(rel) > 2 && rel[1] == ':') {
		return rel
	}
	return filepath.Join(dir, rel)
}
