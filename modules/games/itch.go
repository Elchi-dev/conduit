package games

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func itchDB(e *env) string {
	switch e.GOOS {
	case "windows":
		if e.AppData == "" {
			return ""
		}
		return filepath.Join(e.AppData, "itch", "db", "butler.db")
	case "darwin":
		return filepath.Join(e.Home, "Library", "Application Support", "itch", "db", "butler.db")
	}
	return filepath.Join(e.ConfigHome, "itch", "db", "butler.db")
}

// parseTime reads the timestamps SQLite stores as text.
func parseTime(s string) time.Time {
	for _, l := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func scanItch(e *env) (bool, []Game, error) {
	path := itchDB(e)
	if !exists(path) {
		return false, nil, nil
	}
	db, done, err := openSQLite(path)
	if err != nil {
		return true, nil, fmt.Errorf("couldn't open the itch.io database: %w", err)
	}
	defer done()
	rows, err := db.Query(`SELECT c.id, c.game_id, COALESCE(g.title, ''), COALESCE(g.cover_url, ''), COALESCE(g.still_cover_url, ''),
		COALESCE(c.installed_size, 0), COALESCE(c.seconds_run, 0), COALESCE(CAST(c.last_touched_at AS TEXT), ''),
		COALESCE(c.verdict, ''), COALESCE(c.install_folder_name, ''), COALESCE(l.path, '')
		FROM caves c LEFT JOIN games g ON g.id = c.game_id LEFT JOIN install_locations l ON l.id = c.install_location_id`)
	if err != nil {
		return true, nil, fmt.Errorf("couldn't read the itch.io database: %w", err)
	}
	defer rows.Close()
	var out []Game
	seen := map[int64]bool{}
	for rows.Next() {
		var cave, title, cover, still, last, verdict, folder, loc string
		var gameID, size, secs int64
		if err := scanRow(rows, &cave, &gameID, &title, &cover, &still, &size, &secs, &last, &verdict, &folder, &loc); err != nil || seen[gameID] {
			continue
		}
		seen[gameID] = true
		var v struct {
			BasePath   string `json:"basePath"`
			Candidates []struct {
				Path string `json:"path"`
			} `json:"candidates"`
		}
		_ = json.Unmarshal([]byte(verdict), &v)
		inst := v.BasePath
		if inst == "" && loc != "" && folder != "" {
			inst = filepath.Join(loc, folder)
		}
		if still != "" {
			cover = still // animated covers have a still version
		}
		if !strings.HasPrefix(cover, "https://") {
			cover = ""
		}
		g := Game{
			ID: "itch:" + strconv.FormatInt(gameID, 10), Title: title, Launcher: "itch", NativeID: strconv.FormatInt(gameID, 10),
			Installed: true, InstallPath: inst, SizeBytes: size, Size: humanSize(size), Cover: cover, HasCover: cover != "",
			LauncherPlaySeconds: secs, launcherLast: parseTime(last),
			launch: launchSpec{URI: "itch://caves/" + cave + "/launch"},
		}
		for _, c := range v.Candidates {
			g.Executables = append(g.Executables, joinNative(inst, c.Path))
		}
		g.ProcessNames = baseNames(g.Executables)
		if g.Title == "" {
			g.Title = folder
		}
		out = append(out, g)
	}
	return true, out, nil
}

// scanRow scans a row, accepting text or integer ids.
func scanRow(rows *sql.Rows, cave *string, rest ...any) error {
	var c any
	if err := rows.Scan(append([]any{&c}, rest...)...); err != nil {
		return err
	}
	switch x := c.(type) {
	case []byte:
		*cave = string(x)
	default:
		*cave = fmt.Sprint(x)
	}
	return nil
}

func lutrisDBs(e *env) []string {
	return []string{
		filepath.Join(e.DataHome, "lutris", "pga.db"),
		filepath.Join(e.Home, ".var", "app", "net.lutris.Lutris", "data", "lutris", "pga.db"), // Flatpak
	}
}

func scanLutris(e *env) (bool, []Game, error) {
	if e.GOOS != "linux" {
		return false, nil, nil
	}
	found := false
	var out []Game
	seen := map[string]bool{}
	for _, path := range lutrisDBs(e) {
		if !exists(path) {
			continue
		}
		found = true
		db, done, err := openSQLite(path)
		if err != nil {
			continue
		}
		rows, err := db.Query(`SELECT id, COALESCE(name,''), COALESCE(slug,''), COALESCE(runner,''), COALESCE(directory,''),
			COALESCE(executable,''), COALESCE(lastplayed,0), COALESCE(playtime,0), COALESCE(service,'')
			FROM games WHERE installed = 1`)
		if err != nil {
			done()
			continue
		}
		cover := filepath.Join(filepath.Dir(path), "coverart")
		if !exists(cover) {
			cover = filepath.Join(e.Home, ".cache", "lutris", "coverart")
		}
		for rows.Next() {
			var id, last int64
			var hours float64
			var name, sl, runner, dir, exe, service string
			if rows.Scan(&id, &name, &sl, &runner, &dir, &exe, &last, &hours, &service) != nil || sl == "" || seen[sl] {
				continue
			}
			// Games Lutris imported from Steam are already listed by Steam.
			if runner == "steam" || service == "steam" {
				continue
			}
			seen[sl] = true
			g := Game{ID: "lutris:" + sl, Title: name, Launcher: "lutris", NativeID: strconv.FormatInt(id, 10),
				Installed: true, InstallPath: dir, LauncherPlaySeconds: int64(hours * 3600),
				launch: launchSpec{URI: "lutris:rungameid/" + strconv.FormatInt(id, 10)}}
			if last > 0 {
				g.launcherLast = time.Unix(last, 0)
			}
			if exe != "" {
				g.Executables = []string{joinNative(dir, exe)}
				g.ProcessNames = baseNames(g.Executables)
			}
			if c := filepath.Join(cover, sl+".jpg"); exists(c) {
				g.coverFile = c
			}
			out = append(out, g)
		}
		rows.Close()
		done()
	}
	return found, out, nil
}
