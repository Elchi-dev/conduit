package games

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// gogGalaxyDB is GOG Galaxy 2's database.
func gogGalaxyDB(e *env) string {
	switch e.GOOS {
	case "windows":
		if e.ProgramData == "" {
			return ""
		}
		return filepath.Join(e.ProgramData, "GOG.com", "Galaxy", "storage", "galaxy-2.0.db")
	case "darwin":
		return filepath.Join("/Users", "Shared", "GOG.com", "Galaxy", "Storage", "galaxy-2.0.db")
	}
	return ""
}

type galaxyInfo struct {
	installs map[string]string // product id -> install path
	titles   map[string]string
	covers   map[string]string
	minutes  map[string]int64
	last     map[string]time.Time
}

// readGalaxy reads what GOG Galaxy knows about installed games, titles,
// covers and play time. Every query is optional: Galaxy's schema shifts
// between versions, so a missing table just leaves that part empty.
func readGalaxy(path string) *galaxyInfo {
	if !exists(path) {
		return nil
	}
	db, done, err := openSQLite(path)
	if err != nil {
		return nil
	}
	defer done()
	gi := &galaxyInfo{installs: map[string]string{}, titles: map[string]string{}, covers: map[string]string{}, minutes: map[string]int64{}, last: map[string]time.Time{}}
	if rows, err := db.Query(`SELECT productId, installationPath FROM InstalledBaseProducts`); err == nil {
		for rows.Next() {
			var id int64
			var p string
			if rows.Scan(&id, &p) == nil {
				gi.installs[strconv.FormatInt(id, 10)] = p
			}
		}
		rows.Close()
	}
	if rows, err := db.Query(`SELECT productId, title FROM LimitedDetails`); err == nil {
		for rows.Next() {
			var id int64
			var t string
			if rows.Scan(&id, &t) == nil && t != "" {
				gi.titles[strconv.FormatInt(id, 10)] = t
			}
		}
		rows.Close()
	}
	if rows, err := db.Query(`SELECT gp.releaseKey, gpt.type, gp.value FROM GamePieces gp JOIN GamePieceTypes gpt ON gp.gamePieceTypeId = gpt.id
		WHERE gp.releaseKey LIKE 'gog_%' AND gpt.type IN ('originalImages','originalTitle')`); err == nil {
		for rows.Next() {
			var key, typ, val string
			if rows.Scan(&key, &typ, &val) != nil {
				continue
			}
			id := strings.TrimPrefix(key, "gog_")
			var v struct {
				Title         string `json:"title"`
				VerticalCover string `json:"verticalCover"`
			}
			if json.Unmarshal([]byte(val), &v) != nil {
				continue
			}
			if typ == "originalTitle" && v.Title != "" {
				gi.titles[id] = v.Title
			}
			if typ == "originalImages" && strings.HasPrefix(v.VerticalCover, "https://") {
				gi.covers[id] = v.VerticalCover
			}
		}
		rows.Close()
	}
	if rows, err := db.Query(`SELECT releaseKey, minutesInGame FROM GameTimes WHERE releaseKey LIKE 'gog_%'`); err == nil {
		for rows.Next() {
			var key string
			var m int64
			if rows.Scan(&key, &m) == nil {
				gi.minutes[strings.TrimPrefix(key, "gog_")] = m
			}
		}
		rows.Close()
	}
	if rows, err := db.Query(`SELECT gameReleaseKey, lastPlayedDate FROM LastPlayedDates WHERE gameReleaseKey LIKE 'gog_%'`); err == nil {
		for rows.Next() {
			var key, d string
			if rows.Scan(&key, &d) == nil {
				for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339} {
					if t, err := time.Parse(layout, d); err == nil {
						gi.last[strings.TrimPrefix(key, "gog_")] = t
						break
					}
				}
			}
		}
		rows.Close()
	}
	return gi
}

func scanGOG(e *env) (bool, []Game, error) {
	found := false
	var out []Game
	seen := map[string]bool{}
	gi := readGalaxy(gogGalaxyDB(e))
	if gi != nil {
		found = true
	}
	enrich := func(g *Game) {
		if gi == nil {
			return
		}
		if t := gi.titles[g.NativeID]; t != "" && g.Title == "" {
			g.Title = t
		}
		if g.Cover == "" {
			g.Cover = gi.covers[g.NativeID]
		}
		g.LauncherPlaySeconds = gi.minutes[g.NativeID] * 60
		g.launcherLast = gi.last[g.NativeID]
	}
	// Windows: every GOG installer (Galaxy or offline) registers here.
	galaxyClient := ""
	if v := e.regValues("HKLM", `SOFTWARE\WOW6432Node\GOG.com\GalaxyClient\paths`); v["client"] != "" {
		galaxyClient = filepath.Join(v["client"], "GalaxyClient.exe")
	}
	for _, k := range e.reg("HKLM", `SOFTWARE\WOW6432Node\GOG.com\Games`) {
		found = true
		v := k.Values
		id := v["gameID"]
		if id == "" {
			id = k.Name
		}
		if seen[id] || v["dependsOn"] != "" && v["dependsOn"] != id {
			continue
		}
		seen[id] = true
		g := Game{ID: "gog:" + id, Title: v["gameName"], Launcher: "gog", NativeID: id, Installed: true, InstallPath: v["path"]}
		enrich(&g)
		exe := v["exe"]
		if exe != "" {
			g.Executables = []string{exe}
			g.ProcessNames = baseNames(g.Executables)
		}
		switch {
		case exe != "":
			// GOG games run without the client, so start the game itself.
			g.launch = launchSpec{Exe: exe, Args: splitArgs(v["launchParam"]), Dir: firstNonEmpty(v["workingDir"], v["path"])}
		case galaxyClient != "":
			g.launch = launchSpec{Exe: galaxyClient, Args: []string{"/command=runGame", "/gameId=" + id, "/path=" + v["path"]}}
		default:
			g.launch = launchSpec{URI: "goggalaxy://openGameView/" + id}
		}
		out = append(out, g)
	}
	// macOS (and Windows installs missing from the registry): Galaxy's list.
	if gi != nil {
		for id, p := range gi.installs {
			if seen[id] {
				continue
			}
			seen[id] = true
			g := Game{ID: "gog:" + id, Launcher: "gog", NativeID: id, Installed: true, InstallPath: p,
				launch: launchSpec{URI: "goggalaxy://openGameView/" + id}}
			enrich(&g)
			out = append(out, g)
		}
	}
	// Heroic (mostly Linux).
	for _, h := range heroicDirs(e) {
		b, err := os.ReadFile(filepath.Join(h, "gog_store", "installed.json"))
		if err != nil {
			continue
		}
		found = true
		lib := heroicLibrary(filepath.Join(h, "store_cache", "gog_library.json"))
		for k, v := range heroicLibrary(filepath.Join(h, "gog_store", "library.json")) {
			if _, ok := lib[k]; !ok {
				lib[k] = v
			}
		}
		var inst struct {
			Installed []struct {
				AppName     string `json:"appName"`
				InstallPath string `json:"install_path"`
				Executable  string `json:"executable"`
				IsDLC       bool   `json:"is_dlc"`
				Platform    string `json:"platform"`
			} `json:"installed"`
		}
		if json.Unmarshal(b, &inst) != nil {
			continue
		}
		for _, it := range inst.Installed {
			if it.IsDLC || it.AppName == "" || seen[it.AppName] {
				continue
			}
			seen[it.AppName] = true
			g := Game{ID: "gog:" + it.AppName, Title: lib[it.AppName].title, Launcher: "gog", NativeID: it.AppName,
				Installed: true, InstallPath: it.InstallPath, Cover: lib[it.AppName].cover,
				launch: launchSpec{URI: "heroic://launch?appName=" + url.QueryEscape(it.AppName) + "&runner=gog"}}
			if it.Executable != "" {
				g.Executables = []string{joinNative(it.InstallPath, it.Executable)}
				g.ProcessNames = baseNames(g.Executables)
			}
			enrich(&g)
			out = append(out, g)
		}
	}
	for i := range out {
		if out[i].Title == "" {
			out[i].Title = filepath.Base(strings.ReplaceAll(out[i].InstallPath, `\`, "/"))
		}
		out[i].HasCover = out[i].Cover != ""
	}
	return found, out, nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// splitArgs splits a command line on spaces, keeping quoted parts together.
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	quote := rune(0)
	has := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
			has = true
		case r == ' ' || r == '\t':
			if cur.Len() > 0 || has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 || has {
		out = append(out, cur.String())
	}
	return out
}
