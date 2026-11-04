package games

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// riotTitles names Riot's products by their client ids.
var riotTitles = map[string]string{
	"league_of_legends": "League of Legends",
	"valorant":          "VALORANT",
	"bacon":             "Legends of Runeterra",
	"lion":              "2XKO",
}

func riotRoot(e *env) string {
	switch e.GOOS {
	case "windows":
		if e.ProgramData == "" {
			return ""
		}
		return filepath.Join(e.ProgramData, "Riot Games")
	case "darwin":
		return filepath.Join("/Users", "Shared", "Riot Games")
	}
	return ""
}

// readFlatYAML reads the top-level "key: value" lines of a YAML file,
// which is all Riot's product settings need.
func readFlatYAML(path string) map[string]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		out[strings.TrimSpace(k)] = v
	}
	return out
}

func scanRiot(e *env) (bool, []Game, error) {
	root := riotRoot(e)
	if root == "" {
		return false, nil, nil
	}
	b, err := os.ReadFile(filepath.Join(root, "RiotClientInstalls.json"))
	if err != nil {
		return false, nil, nil
	}
	var inst struct {
		Default string `json:"rc_default"`
		Live    string `json:"rc_live"`
	}
	_ = json.Unmarshal(b, &inst)
	client := inst.Default
	if client == "" {
		client = inst.Live
	}
	client = filepath.FromSlash(client)
	var out []Game
	dirs, _ := filepath.Glob(filepath.Join(root, "Metadata", "*"))
	for _, d := range dirs {
		name := filepath.Base(d)
		product, patchline, ok := strings.Cut(name, ".")
		if !ok || product == "riot_client" || product == "" {
			continue
		}
		settings := readFlatYAML(filepath.Join(d, name+".product_settings.yaml"))
		if settings == nil {
			continue
		}
		path := settings["product_install_full_path"]
		if path == "" {
			path = settings["product_install_root"]
		}
		if path == "" {
			continue
		}
		path = filepath.Clean(filepath.FromSlash(path))
		title := riotTitles[product]
		if title == "" {
			title = strings.TrimSuffix(settings["shortcut_name"], ".lnk")
		}
		if title == "" {
			title = product
		}
		id := product
		if patchline != "live" {
			id = product + "." + patchline
		}
		g := Game{
			ID: "riot:" + id, Title: title, Launcher: "riot", NativeID: name, Installed: true, InstallPath: path,
		}
		if client != "" {
			g.launch = launchSpec{Exe: client, Args: []string{"--launch-product=" + product, "--launch-patchline=" + patchline}}
		}
		out = append(out, g)
	}
	return true, out, nil
}
