package games

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// steamCDN is where Steam serves portrait library covers.
const steamCDN = "https://cdn.cloudflare.steamstatic.com/steam/apps/%d/library_600x900.jpg"

// steamDirs lists the folders Steam may live in on this OS, the configured
// one first.
func steamDirs(e *env) []string {
	if e.SteamPath != "" {
		return []string{e.SteamPath}
	}
	h := e.Home
	switch e.GOOS {
	case "windows":
		var out []string
		if v := e.regValues("HKCU", `Software\Valve\Steam`); v["SteamPath"] != "" {
			out = append(out, filepath.FromSlash(v["SteamPath"]))
		}
		return append(out, `C:\Program Files (x86)\Steam`, `C:\Program Files\Steam`)
	case "darwin":
		return []string{filepath.Join(h, "Library", "Application Support", "Steam")}
	default:
		return []string{
			filepath.Join(h, ".steam", "steam"),
			filepath.Join(h, ".local", "share", "Steam"),
			filepath.Join(h, ".var", "app", "com.valvesoftware.Steam", ".local", "share", "Steam"), // Flatpak
			filepath.Join(h, "snap", "steam", "common", ".local", "share", "Steam"),
		}
	}
}

// findSteam returns the first folder that holds a Steam install.
func findSteam(e *env) (string, error) {
	for _, c := range steamDirs(e) {
		if c != "" && exists(filepath.Join(c, "steamapps")) {
			return c, nil
		}
	}
	return "", errors.New("Steam isn't installed here, or set its folder in the settings")
}

func scanSteam(e *env) (bool, []Game, error) {
	dir, err := findSteam(e)
	if err != nil {
		return false, nil, nil
	}
	gs, err := steamLibrary(dir)
	return true, gs, err
}

// parseVDF reads Valve's KeyValues text format into nested maps. Keys are
// lowercased.
func parseVDF(r io.Reader) (map[string]any, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	var toks []string
	for sc.Scan() {
		line := sc.Text()
		for i := 0; i < len(line); i++ {
			switch c := line[i]; {
			case c == '"':
				j := i + 1
				var b strings.Builder
				for ; j < len(line) && line[j] != '"'; j++ {
					if line[j] == '\\' && j+1 < len(line) {
						j++
					}
					b.WriteByte(line[j])
				}
				toks = append(toks, "\x00"+b.String())
				i = j
			case c == '{' || c == '}':
				toks = append(toks, string(c))
			case c == '/' && i+1 < len(line) && line[i+1] == '/':
				i = len(line)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	pos := 0
	var obj func() (map[string]any, error)
	obj = func() (map[string]any, error) {
		out := map[string]any{}
		for pos < len(toks) {
			t := toks[pos]
			if t == "}" {
				pos++
				return out, nil
			}
			if !strings.HasPrefix(t, "\x00") {
				return nil, errors.New("malformed VDF")
			}
			key := strings.ToLower(t[1:])
			pos++
			if pos >= len(toks) {
				return nil, errors.New("malformed VDF")
			}
			if toks[pos] == "{" {
				pos++
				v, err := obj()
				if err != nil {
					return nil, err
				}
				out[key] = v
			} else {
				out[key] = toks[pos][1:]
				pos++
			}
		}
		return out, nil
	}
	return obj()
}

func readVDF(path string) (map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseVDF(f)
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func sub(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		n, _ := m[k].(map[string]any)
		if n == nil {
			return nil
		}
		m = n
	}
	return m
}

// steamTool reports Steam entries that aren't games (runtimes, Proton).
func steamTool(name string) bool {
	for _, p := range []string{"Steamworks Common", "Proton", "Steam Linux Runtime", "Steamworks Shared"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// steamPlayTimes reads per-app play time and last-played time from every
// Steam user's localconfig.vdf on this computer.
func steamPlayTimes(steam string) map[int]struct {
	minutes int64
	last    time.Time
} {
	out := map[int]struct {
		minutes int64
		last    time.Time
	}{}
	files, _ := filepath.Glob(filepath.Join(steam, "userdata", "*", "config", "localconfig.vdf"))
	for _, f := range files {
		v, err := readVDF(f)
		if err != nil {
			continue
		}
		apps := sub(v, "userlocalconfigstore", "software", "valve", "steam", "apps")
		for k, raw := range apps {
			a, _ := raw.(map[string]any)
			id, _ := strconv.Atoi(k)
			if a == nil || id == 0 {
				continue
			}
			cur := out[id]
			if m, _ := strconv.ParseInt(str(a, "playtime"), 10, 64); m > cur.minutes {
				cur.minutes = m
			}
			if ts, _ := strconv.ParseInt(str(a, "lastplayed"), 10, 64); ts > 0 && time.Unix(ts, 0).After(cur.last) {
				cur.last = time.Unix(ts, 0)
			}
			out[id] = cur
		}
	}
	return out
}

// steamLibrary lists installed games across all Steam library folders.
func steamLibrary(steam string) ([]Game, error) {
	dirs := []string{steam}
	if v, err := readVDF(filepath.Join(steam, "steamapps", "libraryfolders.vdf")); err == nil {
		if lf, ok := v["libraryfolders"].(map[string]any); ok {
			for _, e := range lf {
				if f, ok := e.(map[string]any); ok && str(f, "path") != "" && filepath.Clean(str(f, "path")) != filepath.Clean(steam) {
					dirs = append(dirs, str(f, "path"))
				}
			}
		}
	}
	times := steamPlayTimes(steam)
	out := []Game{}
	seen := map[int]bool{}
	for _, d := range dirs {
		mans, _ := filepath.Glob(filepath.Join(d, "steamapps", "appmanifest_*.acf"))
		for _, mf := range mans {
			v, err := readVDF(mf)
			if err != nil {
				continue
			}
			st, _ := v["appstate"].(map[string]any)
			if st == nil {
				continue
			}
			id, _ := strconv.Atoi(str(st, "appid"))
			name := str(st, "name")
			if id == 0 || name == "" || steamTool(name) || seen[id] {
				continue
			}
			seen[id] = true
			size, _ := strconv.ParseInt(str(st, "sizeondisk"), 10, 64)
			g := Game{
				ID: fmt.Sprintf("steam:%d", id), Title: name, Launcher: "steam", NativeID: strconv.Itoa(id), AppID: id,
				Installed: true, SizeBytes: size, Size: humanSize(size), Folder: d,
				InstallPath: filepath.Join(d, "steamapps", "common", str(st, "installdir")),
				Cover:       fmt.Sprintf(steamCDN, id), HasCover: true,
				launch: launchSpec{URI: fmt.Sprintf("steam://rungameid/%d", id)},
			}
			if g.Size == "" {
				g.Size = "0.0 GB"
			}
			if ts, _ := strconv.ParseInt(str(st, "lastupdated"), 10, 64); ts > 0 {
				g.Updated = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
			for _, c := range []string{
				filepath.Join(steam, "appcache", "librarycache", fmt.Sprintf("%d_library_600x900.jpg", id)),
				filepath.Join(steam, "appcache", "librarycache", strconv.Itoa(id), "library_600x900.jpg"),
			} {
				if exists(c) {
					g.coverFile = c
					break
				}
			}
			if t, ok := times[id]; ok {
				g.LauncherPlaySeconds = t.minutes * 60
				g.launcherLast = t.last
			}
			out = append(out, g)
		}
	}
	return out, nil
}
