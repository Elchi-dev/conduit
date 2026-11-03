// Package games reads the local Steam library, launches games and reports
// which ones are running. It reads Steam's own files; a Steam Web API key is
// optional and only adds play time for games that aren't installed.
package games

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/process"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// InstanceID is the single games instance (one per computer).
const InstanceID = "games"

// Config is the games settings.
type Config struct {
	SteamPath string `json:"steamPath"` // auto-detected when empty
	APIKey    string `json:"apiKey"`    // secret:// Steam Web API key (optional)
	SteamID   string `json:"steamId"`   // 64-bit id, needed with apiKey
}

// Module implements sdk.Module.
type Module struct {
	mu   sync.Mutex
	cfg  Config
	host sdk.Host
	// Open launches a URL (tests replace it).
	Open func(url string) error
	HTTP *http.Client
	API  string // Steam Web API base (tests)
}

// New returns the games module.
func New() *Module {
	return &Module{Open: openURL, HTTP: &http.Client{Timeout: 20 * time.Second}, API: "https://api.steampowered.com"}
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "games", Name: "Games", Version: "0.1.0", Category: "Play", Icon: "game",
		Description: "Your Steam library: what's installed, how big it is, launch a game, see what's running.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"steamPath":{"type":"string","description":"Steam's folder; found automatically on most computers"},
			"apiKey":{"type":"string","x-secret":true,"description":"Optional Steam Web API key, for play time and games you don't have installed"},
			"steamId":{"type":"string","description":"Your 64-bit Steam id (with the API key)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "library", Title: "Installed games", Description: "Games on this computer with size and last update.", Risk: sdk.RiskRead},
			{Name: "owned", Title: "Owned games and play time", Description: "Needs a Steam Web API key.", Risk: sdk.RiskRead},
			{Name: "running", Title: "Running games", Risk: sdk.RiskRead},
			{Name: "launch", Title: "Launch a game", Description: "Starts it through Steam.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["appId"],"properties":{"appId":{"type":"integer","description":"Steam app id, from the library"}}}`)},
		},
		Events: []sdk.EventSpec{{Type: "games.started", Description: "A Steam game started"}, {Type: "games.stopped", Description: "It stopped"}},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(ctx context.Context, h sdk.Host, _ string, raw json.RawMessage) error {
	var c Config
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("invalid settings: %w", err)
		}
	}
	if c.APIKey != "" && c.SteamID == "" {
		return errors.New("with an API key, also set your 64-bit Steam id")
	}
	m.mu.Lock()
	m.cfg, m.host = c, h
	m.mu.Unlock()
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(string) error { return nil }

func (m *Module) steamDir() (string, error) {
	m.mu.Lock()
	p := m.cfg.SteamPath
	m.mu.Unlock()
	cands := []string{p}
	if p == "" {
		home, _ := os.UserHomeDir()
		switch runtime.GOOS {
		case "windows":
			cands = []string{`C:\Program Files (x86)\Steam`, `C:\Program Files\Steam`}
		case "darwin":
			cands = []string{filepath.Join(home, "Library", "Application Support", "Steam")}
		default:
			cands = []string{filepath.Join(home, ".steam", "steam"), filepath.Join(home, ".local", "share", "Steam"),
				filepath.Join(home, ".var", "app", "com.valvesoftware.Steam", ".local", "share", "Steam")}
		}
	}
	for _, c := range cands {
		if c == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(c, "steamapps")); err == nil {
			return c, nil
		}
	}
	return "", errors.New("Steam isn't installed here, or set its folder in the settings")
}

// Health implements sdk.Module.
func (m *Module) Health(context.Context, string) sdk.Health {
	dir, err := m.steamDir()
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	gs, err := library(dir)
	if err != nil {
		return sdk.Health{Status: "degraded", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d games installed", len(gs))}
}

// Game is an installed game.
type Game struct {
	AppID   int    `json:"appId"`
	Name    string `json:"name"`
	SizeGB  string `json:"size"`
	Updated string `json:"updated,omitempty"`
	Folder  string `json:"folder"`
	dir     string
}

// parseVDF reads Valve's KeyValues text format into nested maps.
func parseVDF(r io.Reader) (map[string]any, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
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

// library lists installed games across all Steam library folders.
func library(steam string) ([]Game, error) {
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
	out := []Game{}
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
			if id == 0 || name == "" || strings.HasPrefix(name, "Steamworks Common") || strings.HasPrefix(name, "Proton") || strings.HasPrefix(name, "Steam Linux Runtime") {
				continue
			}
			size, _ := strconv.ParseFloat(str(st, "sizeondisk"), 64)
			g := Game{AppID: id, Name: name, SizeGB: fmt.Sprintf("%.1f GB", size/1e9), Folder: d, dir: filepath.Join(d, "steamapps", "common", str(st, "installdir"))}
			if ts, _ := strconv.ParseInt(str(st, "lastupdated"), 10, 64); ts > 0 {
				g.Updated = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// Running is a running game.
type Running struct {
	AppID int    `json:"appId"`
	Name  string `json:"name"`
	PID   int32  `json:"pid"`
	Since string `json:"since"`
}

func running(ctx context.Context, games []Game) []Running {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil
	}
	seen := map[int]bool{}
	out := []Running{}
	for _, p := range procs {
		exe, err := p.ExeWithContext(ctx)
		if err != nil || exe == "" {
			continue
		}
		for _, g := range games {
			if g.dir != "" && !seen[g.AppID] && strings.HasPrefix(strings.ToLower(exe), strings.ToLower(g.dir)+string(filepath.Separator)) {
				seen[g.AppID] = true
				ct, _ := p.CreateTimeWithContext(ctx)
				out = append(out, Running{AppID: g.AppID, Name: g.Name, PID: p.Pid, Since: time.UnixMilli(ct).UTC().Format(time.RFC3339)})
			}
		}
	}
	return out
}

func openURL(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	var p struct {
		AppID int `json:"appId"`
	}
	if err := sdk.Decode(c, &p); err != nil {
		return sdk.Result{}, err
	}
	if c.Action == "owned" {
		return m.owned(ctx)
	}
	dir, err := m.steamDir()
	if err != nil {
		return sdk.Result{}, err
	}
	games, err := library(dir)
	if err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "library":
		return sdk.JSON(games)
	case "running":
		return sdk.JSON(running(ctx, games))
	case "launch":
		name := ""
		for _, g := range games {
			if g.AppID == p.AppID {
				name = g.Name
			}
		}
		if name == "" {
			return sdk.Result{}, fmt.Errorf("app %d isn't installed", p.AppID)
		}
		if err := m.Open(fmt.Sprintf("steam://rungameid/%d", p.AppID)); err != nil {
			return sdk.Result{}, fmt.Errorf("couldn't hand the game to Steam: %w", err)
		}
		return sdk.JSON(map[string]any{"launched": name})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

func (m *Module) owned(ctx context.Context) (sdk.Result, error) {
	m.mu.Lock()
	cfg, h := m.cfg, m.host
	m.mu.Unlock()
	if cfg.APIKey == "" {
		return sdk.Result{}, errors.New("add a Steam Web API key and your Steam id in the settings")
	}
	key, err := h.Secret(ctx, cfg.APIKey)
	if err != nil {
		return sdk.Result{}, err
	}
	q := url.Values{"key": {key}, "steamid": {cfg.SteamID}, "include_appinfo": {"1"}, "format": {"json"}}
	req, _ := http.NewRequestWithContext(ctx, "GET", m.API+"/IPlayerService/GetOwnedGames/v1/?"+q.Encode(), nil)
	res, err := m.HTTP.Do(req)
	if err != nil {
		return sdk.Result{}, errors.New("couldn't reach Steam") // never echo the URL: it holds the key
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return sdk.Result{}, fmt.Errorf("Steam answered %s; check the key and Steam id", res.Status)
	}
	var d struct {
		Response struct {
			Games []struct {
				AppID    int    `json:"appid"`
				Name     string `json:"name"`
				Playtime int    `json:"playtime_forever"`
				Recent   int    `json:"playtime_2weeks"`
			} `json:"games"`
		} `json:"response"`
	}
	if err := json.NewDecoder(res.Body).Decode(&d); err != nil {
		return sdk.Result{}, err
	}
	type row struct {
		AppID  int     `json:"appId"`
		Name   string  `json:"name"`
		Hours  float64 `json:"hours"`
		Recent float64 `json:"lastTwoWeeks"`
	}
	out := []row{}
	for _, g := range d.Response.Games {
		out = append(out, row{AppID: g.AppID, Name: g.Name, Hours: float64(g.Playtime/6) / 10, Recent: float64(g.Recent/6) / 10})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hours > out[j].Hours })
	return sdk.JSON(out)
}

// Watch publishes games.started and games.stopped while ctx lives.
func (m *Module) Watch(ctx context.Context) {
	known := map[int]Running{}
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		dir, err := m.steamDir()
		if err != nil {
			continue
		}
		games, err := library(dir)
		if err != nil {
			continue
		}
		now := map[int]Running{}
		for _, r := range running(ctx, games) {
			now[r.AppID] = r
		}
		m.mu.Lock()
		h := m.host
		m.mu.Unlock()
		if h == nil {
			continue
		}
		for id, r := range now {
			if _, ok := known[id]; !ok {
				b, _ := json.Marshal(r)
				h.Publish(ctx, sdk.Event{Type: "games.started", Instance: InstanceID, Data: b})
			}
		}
		for id, r := range known {
			if _, ok := now[id]; !ok {
				b, _ := json.Marshal(r)
				h.Publish(ctx, sdk.Event{Type: "games.stopped", Instance: InstanceID, Data: b})
			}
		}
		known = now
	}
}
