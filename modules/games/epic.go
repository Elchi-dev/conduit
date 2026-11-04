package games

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// epicDataDir is the Epic Games Launcher's data folder.
func epicDataDir(e *env) string {
	switch e.GOOS {
	case "windows":
		if e.ProgramData == "" {
			return ""
		}
		return filepath.Join(e.ProgramData, "Epic", "EpicGamesLauncher", "Data")
	case "darwin":
		return filepath.Join(e.Home, "Library", "Application Support", "Epic", "EpicGamesLauncher", "Data")
	}
	return ""
}

// heroicDirs lists Heroic Games Launcher configuration folders.
func heroicDirs(e *env) []string {
	switch e.GOOS {
	case "windows":
		if e.AppData == "" {
			return nil
		}
		return []string{filepath.Join(e.AppData, "heroic")}
	case "darwin":
		return []string{filepath.Join(e.Home, "Library", "Application Support", "heroic")}
	}
	return []string{
		filepath.Join(e.ConfigHome, "heroic"),
		filepath.Join(e.Home, ".var", "app", "com.heroicgameslauncher.hgl", "config", "heroic"), // Flatpak
	}
}

type epicItem struct {
	DisplayName       string   `json:"DisplayName"`
	InstallLocation   string   `json:"InstallLocation"`
	LaunchExecutable  string   `json:"LaunchExecutable"`
	AppName           string   `json:"AppName"`
	MainGameAppName   string   `json:"MainGameAppName"`
	CatalogNamespace  string   `json:"CatalogNamespace"`
	CatalogItemID     string   `json:"CatalogItemId"`
	InstallSize       int64    `json:"InstallSize"`
	IncompleteInstall bool     `json:"bIsIncompleteInstall"`
	AppCategories     []string `json:"AppCategories"`
	ProcessNames      []string `json:"ProcessNames"`
}

type keyImage struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// tallImage picks the portrait cover from Epic's key images.
func tallImage(imgs []keyImage) string {
	for _, want := range []string{"DieselGameBoxTall", "OfferImageTall", "Thumbnail"} {
		for _, i := range imgs {
			if i.Type == want && strings.HasPrefix(i.URL, "https://") {
				return i.URL
			}
		}
	}
	return ""
}

// epicCatalog reads cover URLs from the launcher's catalog cache
// (catcache.bin is base64-encoded JSON), keyed by catalog item id.
func epicCatalog(dataDir string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(dataDir, "Catalog", "catcache.bin"))
	if err != nil {
		return out
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return out
	}
	var items []struct {
		ID        string     `json:"id"`
		KeyImages []keyImage `json:"keyImages"`
	}
	if json.Unmarshal(raw, &items) != nil {
		return out
	}
	for _, it := range items {
		if u := tallImage(it.KeyImages); u != "" {
			out[it.ID] = u
		}
	}
	return out
}

func epicNotGame(it epicItem) bool {
	if it.IncompleteInstall || it.AppName == "" || it.DisplayName == "" {
		return true
	}
	if it.MainGameAppName != "" && it.MainGameAppName != it.AppName {
		return true // DLC
	}
	for _, c := range it.AppCategories {
		if c == "plugins" || c == "engines" {
			return true
		}
	}
	return false
}

func scanEpic(e *env) (bool, []Game, error) {
	found := false
	var out []Game
	seen := map[string]bool{}
	if d := epicDataDir(e); d != "" && exists(filepath.Join(d, "Manifests")) {
		found = true
		covers := epicCatalog(d)
		items, _ := filepath.Glob(filepath.Join(d, "Manifests", "*.item"))
		for _, f := range items {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			var it epicItem
			if json.Unmarshal(b, &it) != nil || epicNotGame(it) || seen[it.AppName] {
				continue
			}
			seen[it.AppName] = true
			inst := filepath.FromSlash(it.InstallLocation)
			g := Game{
				ID: "epic:" + it.AppName, Title: it.DisplayName, Launcher: "epic", NativeID: it.AppName,
				Installed: true, InstallPath: inst, SizeBytes: it.InstallSize, Size: humanSize(it.InstallSize),
				Cover: covers[it.CatalogItemID],
				launch: launchSpec{URI: "com.epicgames.launcher://apps/" + url.PathEscape(it.CatalogNamespace) + "%3A" +
					url.PathEscape(it.CatalogItemID) + "%3A" + url.PathEscape(it.AppName) + "?action=launch&silent=true"},
			}
			if it.LaunchExecutable != "" {
				g.Executables = []string{joinNative(inst, it.LaunchExecutable)}
			}
			g.ProcessNames = baseNames(append(append([]string{}, g.Executables...), it.ProcessNames...))
			g.HasCover = g.Cover != ""
			out = append(out, g)
		}
	}
	// Legendary, alone or inside Heroic (Linux, and anywhere else it's used).
	type legendarySrc struct {
		dir    string
		heroic bool
	}
	srcs := []legendarySrc{{filepath.Join(e.ConfigHome, "legendary"), false}}
	if e.GOOS != "linux" {
		srcs = append(srcs, legendarySrc{filepath.Join(e.Home, ".config", "legendary"), false})
	}
	heroicCovers := map[string]string{}
	for _, h := range heroicDirs(e) {
		srcs = append(srcs, legendarySrc{filepath.Join(h, "legendaryConfig", "legendary"), true})
		for k, v := range heroicLibrary(filepath.Join(h, "store_cache", "legendary_library.json")) {
			heroicCovers[k] = v.cover
		}
	}
	// Heroic first: when both are present, launching through Heroic keeps
	// its own settings (Wine version, prefix).
	for i := len(srcs) - 1; i >= 0; i-- {
		s := srcs[i]
		b, err := os.ReadFile(filepath.Join(s.dir, "installed.json"))
		if err != nil {
			continue
		}
		found = true
		var inst map[string]struct {
			AppName     string `json:"app_name"`
			Title       string `json:"title"`
			InstallPath string `json:"install_path"`
			Executable  string `json:"executable"`
			InstallSize int64  `json:"install_size"`
			IsDLC       bool   `json:"is_dlc"`
		}
		if json.Unmarshal(b, &inst) != nil {
			continue
		}
		for key, it := range inst {
			if it.AppName == "" {
				it.AppName = key
			}
			if it.IsDLC || seen[it.AppName] {
				continue
			}
			seen[it.AppName] = true
			g := Game{
				ID: "epic:" + it.AppName, Title: it.Title, Launcher: "epic", NativeID: it.AppName,
				Installed: true, InstallPath: it.InstallPath, SizeBytes: it.InstallSize, Size: humanSize(it.InstallSize),
			}
			if g.Title == "" {
				g.Title = it.AppName
			}
			if it.Executable != "" {
				g.Executables = []string{joinNative(it.InstallPath, it.Executable)}
				g.ProcessNames = baseNames(g.Executables)
			}
			g.Cover = heroicCovers[it.AppName]
			if g.Cover == "" {
				g.Cover = legendaryCover(filepath.Join(s.dir, "metadata", it.AppName+".json"))
			}
			g.HasCover = g.Cover != ""
			if s.heroic {
				g.launch = launchSpec{URI: "heroic://launch?appName=" + url.QueryEscape(it.AppName) + "&runner=legendary"}
			} else {
				g.launch = launchSpec{Exe: "legendary", Args: []string{"launch", it.AppName}}
			}
			out = append(out, g)
		}
	}
	return found, out, nil
}

// legendaryCover reads the portrait image URL from Legendary's metadata.
func legendaryCover(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var m struct {
		Metadata struct {
			KeyImages []keyImage `json:"keyImages"`
		} `json:"metadata"`
	}
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	return tallImage(m.Metadata.KeyImages)
}

type heroicEntry struct {
	title string
	cover string
}

// heroicLibrary reads one of Heroic's store caches ({"library": [...]} or
// {"games": [...]}), keyed by app name.
func heroicLibrary(path string) map[string]heroicEntry {
	out := map[string]heroicEntry{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	type entry struct {
		AppName   string `json:"app_name"`
		Title     string `json:"title"`
		ArtSquare string `json:"art_square"`
		ArtCover  string `json:"art_cover"`
	}
	var v struct {
		Library []entry `json:"library"`
		Games   []entry `json:"games"`
	}
	if json.Unmarshal(b, &v) != nil {
		return out
	}
	for _, e := range append(v.Library, v.Games...) {
		c := e.ArtSquare // Heroic's "square" art is the portrait box art
		if !strings.HasPrefix(c, "https://") {
			c = ""
		}
		out[e.AppName] = heroicEntry{title: e.Title, cover: c}
	}
	return out
}
