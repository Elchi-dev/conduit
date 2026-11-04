// Package games is the person's game library across launchers: Steam, Epic
// Games (and Heroic/Legendary), GOG, Riot, Battle.net, EA app, Ubisoft
// Connect, Xbox, itch.io, Lutris, other installed games and games added by
// hand. It reads each launcher's own local files (no accounts), launches and
// stops games, and records play sessions by watching running processes.
package games

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// InstanceID is the single games instance (one per computer).
const InstanceID = "games"

// Config is the games settings.
type Config struct {
	SteamPath string `json:"steamPath"` // auto-detected when empty
	APIKey    string `json:"apiKey"`    // secret:// Steam Web API key (optional)
	SteamID   string `json:"steamId"`   // 64-bit id, needed with apiKey
	// Disabled lists launcher ids not to scan, e.g. ["windows"].
	Disabled []string `json:"disabledLaunchers,omitempty"`
	// Track turns play tracking off when false (default on).
	Track *bool `json:"track,omitempty"`
}

// Module implements sdk.Module.
type Module struct {
	mu       sync.Mutex
	cfg      Config
	host     sdk.Host
	instance string

	// DataDir is where sessions and custom games are kept (set by the
	// daemon). Empty keeps them in memory only.
	DataDir string
	// Open hands a URL to the system (tests replace it).
	Open func(url string) error
	// Exec starts a program (tests replace it).
	Exec func(exe string, args []string, dir string) error
	// Procs lists running processes (tests replace it).
	Procs func(ctx context.Context) ([]proc, error)
	// Signal asks a process to close, or kills it with force.
	Signal func(pid int32, force bool) error
	// Alive reports whether a process still exists.
	Alive func(pid int32) bool
	// Now is the clock; Loc the time zone days are counted in.
	Now func() time.Time
	Loc *time.Location
	// Env overrides where launchers are looked for (tests).
	Env *env
	// Interval is how often the watcher looks at running processes.
	Interval time.Duration
	// StopTimeout is how long stop waits for a game to close by itself.
	StopTimeout time.Duration

	HTTP *http.Client
	API  string // Steam Web API base (tests)
	// allowPrivateCovers lets tests fetch covers from a local server.
	allowPrivateCovers bool

	st      *store
	stErr   error
	cache   []Game
	status  []LauncherStatus
	scanned time.Time

	// tracker state
	active  map[string]*openSession
	resumed bool
	polls   int
}

// New returns the games module.
func New() *Module {
	return &Module{
		Open: openURL, Exec: startProgram, Procs: listProcs, Signal: signalProc, Alive: pidExists,
		Now: time.Now, Loc: time.Local, Interval: 10 * time.Second, StopTimeout: 10 * time.Second,
		HTTP: &http.Client{Timeout: 20 * time.Second}, API: "https://api.steampowered.com",
		active: map[string]*openSession{},
	}
}

var idInput = `{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Game id from the library, e.g. steam:570"}}}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "games", Name: "Games", Version: "0.2.0", Category: "Gaming", Icon: "game",
		Description: "Every game on this computer in one library: Steam, Epic, GOG, Riot, Battle.net, EA, Ubisoft, Xbox, itch.io, Lutris and your own. Play, stop, and play time.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"steamPath":{"type":"string","description":"Steam's folder; found automatically on most computers"},
			"apiKey":{"type":"string","x-secret":true,"description":"Optional Steam Web API key, for games you don't have installed"},
			"steamId":{"type":"string","description":"Your 64-bit Steam id (with the API key)"},
			"disabledLaunchers":{"type":"array","items":{"type":"string","enum":["steam","epic","gog","riot","battlenet","ea","ubisoft","xbox","itch","lutris","windows"]},"description":"Launchers not to look at"},
			"track":{"type":"boolean","default":true,"description":"Record play sessions by watching running games"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "library", Title: "Library", Risk: sdk.RiskRead,
				Description: "Every game found on this computer, with launcher, size, cover, last played and play time.",
				Input: sdk.Schema(`{"type":"object","properties":{
					"launcher":{"type":"string","description":"Only this launcher (steam, epic, gog, riot, battlenet, ea, ubisoft, xbox, itch, lutris, windows, custom)"},
					"installed":{"type":"boolean","description":"Only installed (true) or not installed (false) games"},
					"query":{"type":"string","description":"Words in the title"},
					"sort":{"type":"string","enum":["title","recent","played","size"],"default":"title"},
					"limit":{"type":"integer","minimum":1}}}`)},
			{Name: "game", Title: "Game details", Description: "One game with its play time, last 30 days, recent sessions and whether it's running.",
				Risk: sdk.RiskRead, Input: sdk.Schema(idInput)},
			{Name: "stats", Title: "Play stats", Risk: sdk.RiskRead,
				Description: "Recorded play time per day and per game, top games, streaks and the longest session, over the last N days.",
				Input: sdk.Schema(`{"type":"object","properties":{
					"days":{"type":"integer","minimum":1,"maximum":3660,"default":30},
					"gameId":{"type":"string","description":"Only this game"}}}`)},
			{Name: "running", Title: "Running games", Description: "Games running now, with their processes and how long they've been running.", Risk: sdk.RiskRead},
			{Name: "play", Title: "Play", Description: "Starts a game through its launcher (or its program).", Risk: sdk.RiskWrite,
				Input: sdk.Schema(idInput)},
			{Name: "stop", Title: "Stop a game", Risk: sdk.RiskDestructive, DryRun: true,
				Description: "Asks the game's processes to close, then ends them if they're still running after the timeout. Unsaved progress can be lost.",
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{
					"id":{"type":"string","description":"Game id"},
					"timeoutSeconds":{"type":"integer","minimum":1,"maximum":120,"default":10,"description":"How long to wait before ending it"}}}`)},
			{Name: "add_custom", Title: "Add a game", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Description: "Adds a game by hand: a program (with arguments and working folder) or a launch link. It registers a program Conduit will run on play, so it's as powerful as running that command; the preview shows the full command line.",
				Input: sdk.Schema(`{"type":"object","required":["title"],"properties":{
					"title":{"type":"string"},
					"executable":{"type":"string","description":"Program to run (full path, or a name on PATH)"},
					"args":{"type":"array","items":{"type":"string"}},
					"workingDir":{"type":"string"},
					"uri":{"type":"string","description":"Or a launch link, e.g. steam://rungameid/… or heroic://…"},
					"coverUrl":{"type":"string","description":"https link to a portrait (2:3) cover image"},
					"processNames":{"type":"array","items":{"type":"string"},"description":"Process names that mean it's running, when it isn't the program itself"},
					"installPath":{"type":"string","description":"Folder the game lives in, to recognise it running"}}}`)},
			{Name: "add_link", Title: "Add a game by launch link", Risk: sdk.RiskWrite, Reversible: true,
				Description: "Adds a game by hand that starts through a launcher's link (steam://, heroic://, goggalaxy:// …). Programs need add_custom.",
				Input: sdk.Schema(`{"type":"object","required":["title","uri"],"properties":{
					"title":{"type":"string"},
					"uri":{"type":"string","description":"A launcher link, e.g. steam://rungameid/… or heroic://…"},
					"coverUrl":{"type":"string","description":"https link to a portrait (2:3) cover image"},
					"processNames":{"type":"array","items":{"type":"string"},"description":"Process names that mean it's running"},
					"installPath":{"type":"string","description":"Folder the game lives in, to recognise it running"}}}`)},
			{Name: "remove_custom", Title: "Remove an added game", Risk: sdk.RiskWrite, Reversible: true,
				Description: "Removes a game you added by hand. Its play history stays.", Input: sdk.Schema(idInput)},
			{Name: "refresh", Title: "Look for games again", Description: "Scans every launcher now and says which were found.", Risk: sdk.RiskRead},
			{Name: "owned", Title: "Owned Steam games", Description: "Owned Steam games and hours played. Needs a Steam Web API key.", Risk: sdk.RiskRead},
			{Name: "launch", Title: "Launch a Steam game", Description: "Starts a Steam game by app id. Kept for older automations; use play.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["appId"],"properties":{"appId":{"type":"integer","description":"Steam app id, from the library"}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "game", Title: "Games", ListAction: "library", GetAction: "game", ViewHint: "table"}},
		Events: []sdk.EventSpec{
			{Type: "games.started", Description: "A game started (checked every 10 seconds)"},
			{Type: "games.stopped", Description: "A game stopped; carries the session's length"},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, instance string, raw json.RawMessage) error {
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
	m.instance = instance
	if m.instance == "" {
		m.instance = InstanceID
	}
	m.scanned = time.Time{} // settings may change where to look
	m.mu.Unlock()
	_, err := m.store()
	return err
}

// Close implements sdk.Module.
func (m *Module) Close(string) error {
	m.mu.Lock()
	m.host = nil
	m.mu.Unlock()
	return nil
}

func (m *Module) store() (*store, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil && m.stErr == nil {
		m.st, m.stErr = openStore(m.DataDir)
		if m.stErr != nil {
			m.stErr = fmt.Errorf("couldn't open the games data: %w", m.stErr)
		}
	}
	return m.st, m.stErr
}

func (m *Module) environment() *env {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Env != nil {
		e := *m.Env
		if m.cfg.SteamPath != "" {
			e.SteamPath = m.cfg.SteamPath
		}
		return &e
	}
	return defaultEnv(m.cfg.SteamPath)
}

// cacheFor is how long a scan of the launchers is reused. Play time and
// running state are always current; refresh (and playing a game the cache
// doesn't know yet) scans again at once.
const cacheFor = 5 * time.Minute

// scan returns every game found, using a cache of a few minutes unless
// force is set. Play time and running state are filled in.
func (m *Module) scan(force bool) ([]Game, []LauncherStatus, error) {
	st, err := m.store()
	if err != nil {
		return nil, nil, err
	}
	m.mu.Lock()
	fresh := !force && !m.scanned.IsZero() && m.Now().Sub(m.scanned) < cacheFor
	disabled := map[string]bool{}
	for _, d := range m.cfg.Disabled {
		disabled[d] = true
	}
	m.mu.Unlock()
	var games []Game
	var status []LauncherStatus
	if fresh {
		m.mu.Lock()
		games, status = append([]Game(nil), m.cache...), m.status
		m.mu.Unlock()
	} else {
		e := m.environment()
		seenID := map[string]bool{}
		seenPath := map[string]bool{}
		for _, l := range launchers() {
			ls := LauncherStatus{ID: l.ID, Name: l.Name, Supported: l.supported(e.GOOS), Note: l.Note}
			if !ls.Supported {
				ls.Note = strings.TrimSpace(l.Name + " isn't available on this operating system. " + l.Note)
				status = append(status, ls)
				continue
			}
			if disabled[l.ID] {
				ls.Note = "Turned off in the settings."
				status = append(status, ls)
				continue
			}
			found, gs, err := l.scan(e)
			ls.Detected = found || len(gs) > 0
			if err != nil {
				ls.Error = err.Error()
			}
			for _, g := range gs {
				p := normPath(g.InstallPath, e.GOOS)
				if seenID[g.ID] || (p != "" && seenPath[p]) {
					continue // the first launcher to list a folder owns it
				}
				seenID[g.ID] = true
				if p != "" {
					seenPath[p] = true
				}
				ls.Games++
				games = append(games, g)
			}
			status = append(status, ls)
		}
		for _, c := range st.custom() {
			games = append(games, customGame(c))
		}
		m.mu.Lock()
		m.cache, m.status, m.scanned = append([]Game(nil), games...), status, m.Now()
		m.mu.Unlock()
	}
	m.overlay(games, st.sessions())
	return games, status, nil
}

// overlay fills in recorded play time, last played and running state.
func (m *Module) overlay(games []Game, sessions []Session) {
	secs := map[string]int64{}
	last := map[string]time.Time{}
	for _, s := range sessions {
		secs[s.GameID] += s.Seconds
		if s.End.After(last[s.GameID]) {
			last[s.GameID] = s.End
		}
	}
	m.mu.Lock()
	now := m.Now()
	running := map[string]time.Time{}
	for id, a := range m.active {
		running[id] = a.Start
	}
	m.mu.Unlock()
	for i := range games {
		g := &games[i]
		g.PlaySeconds = secs[g.ID]
		l := last[g.ID]
		if start, ok := running[g.ID]; ok {
			g.Running = true
			g.PlaySeconds += int64(now.Sub(start).Seconds())
			l = now
		}
		if g.launcherLast.After(l) {
			l = g.launcherLast
		}
		if !l.IsZero() {
			g.LastPlayed = l.UTC().Format(time.RFC3339)
		}
		g.TotalPlaySeconds = max(g.PlaySeconds, g.LauncherPlaySeconds)
		if g.coverFile != "" {
			g.HasCover = true
		}
	}
}

func (m *Module) find(id string) (Game, error) {
	games, _, err := m.scan(false)
	if err != nil {
		return Game{}, err
	}
	for _, g := range games {
		if g.ID == id {
			return g, nil
		}
	}
	// A game installed a moment ago isn't in the cache yet.
	games, _, err = m.scan(true)
	if err != nil {
		return Game{}, err
	}
	for _, g := range games {
		if g.ID == id {
			return g, nil
		}
	}
	return Game{}, fmt.Errorf("%w: %q", ErrUnknownGame, id)
}

// ErrUnknownGame means an id isn't in the library.
var ErrUnknownGame = errors.New("there's no such game in the library")

// Health implements sdk.Module.
func (m *Module) Health(context.Context, string) sdk.Health {
	games, status, err := m.scan(false)
	if err != nil {
		return sdk.Health{Status: "degraded", Message: err.Error()}
	}
	detected := 0
	for _, s := range status {
		if s.Detected {
			detected++
		}
	}
	if len(games) == 0 && detected == 0 {
		return sdk.Health{Status: "unconfigured", Message: "No game launchers found here. Add a game by hand, or set Steam's folder in the settings."}
	}
	msg := fmt.Sprintf("%d games installed", len(games))
	for _, g := range games {
		if g.Running {
			msg += "; playing " + g.Title
			break
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
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
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() //nolint:errcheck // reap it
	return nil
}

func startProgram(exe string, args []string, dir string) error {
	path := exe
	if !filepath.IsAbs(exe) {
		p, err := exec.LookPath(exe)
		if err != nil {
			return fmt.Errorf("%s isn't installed or isn't on PATH", exe)
		}
		path = p
	} else if !exists(exe) {
		return fmt.Errorf("%s doesn't exist", exe)
	}
	cmd := exec.Command(path, args...)
	if dir != "" && exists(dir) {
		cmd.Dir = dir
	} else if filepath.IsAbs(path) {
		cmd.Dir = filepath.Dir(path)
	}
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() //nolint:errcheck // reap it
	return nil
}

func (m *Module) start(g Game) error {
	switch {
	case g.launch.URI != "":
		if !validURI(g.launch.URI) {
			return fmt.Errorf("%s has a launch link Conduit won't open (only launcher links such as steam:// are)", g.Title)
		}
		if err := m.Open(g.launch.URI); err != nil {
			return fmt.Errorf("couldn't hand %s to %s: %w", g.Title, launcherName(g.Launcher), err)
		}
	case g.launch.Exe != "":
		if err := m.Exec(g.launch.Exe, g.launch.Args, g.launch.Dir); err != nil {
			return fmt.Errorf("couldn't start %s: %w", g.Title, err)
		}
	default:
		return fmt.Errorf("%s has no known way to start it; start it from %s", g.Title, launcherName(g.Launcher))
	}
	return nil
}

type libraryInput struct {
	Launcher  string `json:"launcher"`
	Installed *bool  `json:"installed"`
	Query     string `json:"query"`
	Sort      string `json:"sort"`
	Limit     int    `json:"limit"`
}

func filterLibrary(games []Game, in libraryInput) []Game {
	out := []Game{}
	q := strings.Fields(strings.ToLower(in.Query))
	for _, g := range games {
		if in.Launcher != "" && g.Launcher != in.Launcher {
			continue
		}
		if in.Installed != nil && g.Installed != *in.Installed {
			continue
		}
		t := strings.ToLower(g.Title)
		ok := true
		for _, w := range q {
			if !strings.Contains(t, w) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, g)
		}
	}
	title := func(i, j int) bool { return strings.ToLower(out[i].Title) < strings.ToLower(out[j].Title) }
	switch in.Sort {
	case "recent":
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Running != out[j].Running {
				return out[i].Running
			}
			if out[i].LastPlayed != out[j].LastPlayed {
				return out[i].LastPlayed > out[j].LastPlayed
			}
			return title(i, j)
		})
	case "played":
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].TotalPlaySeconds != out[j].TotalPlaySeconds {
				return out[i].TotalPlaySeconds > out[j].TotalPlaySeconds
			}
			return title(i, j)
		})
	case "size":
		sort.SliceStable(out, func(i, j int) bool { return out[i].SizeBytes > out[j].SizeBytes })
	default:
		sort.SliceStable(out, title)
	}
	if in.Limit > 0 && len(out) > in.Limit {
		out = out[:in.Limit]
	}
	return out
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	switch c.Action {
	case "owned":
		return m.owned(ctx)
	case "library":
		var in libraryInput
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		games, _, err := m.scan(false)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(filterLibrary(games, in))
	case "refresh":
		games, status, err := m.scan(true)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"games": len(games), "launchers": status, "scannedAt": m.Now().UTC().Format(time.RFC3339)})
	case "game":
		return m.gameDetails(ctx, c)
	case "stats":
		var in struct {
			Days   int    `json:"days"`
			GameID string `json:"gameId"`
		}
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		st, err := m.store()
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(computeStats(m.sessionsWithActive(st), m.Now(), in.Days, in.GameID, m.loc()))
	case "running":
		rs, err := m.running(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(rs)
	case "play", "launch":
		var in struct {
			ID    string `json:"id"`
			AppID int    `json:"appId"`
		}
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		if in.ID == "" && in.AppID > 0 {
			in.ID = fmt.Sprintf("steam:%d", in.AppID)
		}
		if in.ID == "" {
			return sdk.Result{}, errors.New("say which game: id from the library")
		}
		g, err := m.find(in.ID)
		if err != nil {
			if c.Action == "launch" {
				return sdk.Result{}, fmt.Errorf("app %d isn't installed", in.AppID)
			}
			return sdk.Result{}, err
		}
		if g.Running {
			return sdk.Result{}, fmt.Errorf("%s is already running", g.Title)
		}
		if err := m.start(g); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"launched": g.Title, "id": g.ID, "launcher": g.Launcher, "via": g.launch.describe()})
	case "stop":
		return m.stop(ctx, c)
	case "add_custom", "add_link":
		return m.addCustom(c)
	case "remove_custom":
		return m.removeCustom(c)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

func (m *Module) loc() *time.Location {
	if m.Loc == nil {
		return time.Local
	}
	return m.Loc
}

func (m *Module) gameDetails(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	g, err := m.find(in.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	st, _ := m.store()
	all := m.sessionsWithActive(st)
	var mine []Session
	for i := len(all) - 1; i >= 0 && len(mine) < 50; i-- {
		if all[i].GameID == g.ID {
			mine = append(mine, all[i])
		}
	}
	if mine == nil {
		mine = []Session{}
	}
	out := map[string]any{
		"game":     g,
		"stats":    computeStats(all, m.Now(), 30, g.ID, m.loc()),
		"sessions": mine,
		"launch":   g.launch.describe(),
	}
	if g.Running {
		if rs, err := m.running(ctx); err == nil {
			for _, r := range rs {
				if r.ID == g.ID {
					out["running"] = r
				}
			}
		}
	}
	return sdk.JSON(out)
}

// sessionsWithActive returns recorded sessions plus the ones in progress,
// cut at now, so stats include the game being played.
func (m *Module) sessionsWithActive(st *store) []Session {
	all := st.sessions()
	m.mu.Lock()
	now := m.Now()
	for _, a := range m.active {
		all = append(all, Session{GameID: a.GameID, Title: a.Title, Launcher: a.Launcher, Start: a.Start, End: now, Seconds: int64(now.Sub(a.Start).Seconds())})
	}
	m.mu.Unlock()
	return all
}

// Running is a game running now.
type Running struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Launcher  string `json:"launcher"`
	AppID     int    `json:"appId,omitempty"`
	PID       int32  `json:"pid"`
	Processes []proc `json:"processes"`
	Since     string `json:"since"`
	Seconds   int64  `json:"seconds"`
}

// running looks at processes now (not only at the watcher's last look).
func (m *Module) running(ctx context.Context) ([]Running, error) {
	games, _, err := m.scan(false)
	if err != nil {
		return nil, err
	}
	procs, err := m.Procs(ctx)
	if err != nil {
		return nil, fmt.Errorf("couldn't list running programs: %w", err)
	}
	e := m.environment()
	matched := matchProcs(procs, games, e.GOOS, e.Home)
	byID := map[string]Game{}
	for _, g := range games {
		byID[g.ID] = g
	}
	m.mu.Lock()
	now := m.Now()
	starts := map[string]time.Time{}
	for id, a := range m.active {
		starts[id] = a.Start
	}
	m.mu.Unlock()
	out := []Running{}
	for id, ps := range matched {
		g := byID[id]
		since, ok := starts[id]
		if !ok {
			since = earliest(ps, now)
		}
		out = append(out, Running{ID: id, Title: g.Title, Launcher: g.Launcher, AppID: g.AppID, PID: ps[0].PID, Processes: ps,
			Since: since.UTC().Format(time.RFC3339), Seconds: int64(now.Sub(since).Seconds())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out, nil
}

func earliest(ps []proc, now time.Time) time.Time {
	t := now
	for _, p := range ps {
		if !p.Started.IsZero() && p.Started.Before(t) {
			t = p.Started
		}
	}
	return t
}

func (m *Module) stop(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	var in struct {
		ID      string `json:"id"`
		Timeout int    `json:"timeoutSeconds"`
	}
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	g, err := m.find(in.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	rs, err := m.running(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	var r *Running
	for i := range rs {
		if rs[i].ID == g.ID {
			r = &rs[i]
		}
	}
	if r == nil {
		if c.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: g.Title + " isn't running; nothing to stop.", Changes: []sdk.Change{}}}, nil
		}
		return sdk.Result{}, fmt.Errorf("%s isn't running", g.Title)
	}
	timeout := m.StopTimeout
	if in.Timeout > 0 {
		timeout = time.Duration(min(in.Timeout, 120)) * time.Second
	}
	if c.DryRun {
		plan := &sdk.Plan{Summary: fmt.Sprintf("Close %s (%d %s); end it if it's still running after %s. Unsaved progress can be lost.",
			g.Title, len(r.Processes), plural(len(r.Processes), "process", "processes"), timeout)}
		for _, p := range r.Processes {
			after, _ := json.Marshal("stopped")
			before, _ := json.Marshal(fmt.Sprintf("running since %s", r.Since))
			plan.Changes = append(plan.Changes, sdk.Change{Target: fmt.Sprintf("%s (pid %d) of %s", p.Name, p.PID, g.Title), Op: "stop", Before: before, After: after})
		}
		return sdk.Result{Plan: plan}, nil
	}
	for _, p := range r.Processes {
		_ = m.Signal(p.PID, false)
	}
	deadline := m.Now().Add(timeout)
	alive := func() []int32 {
		var left []int32
		for _, p := range r.Processes {
			if m.Alive(p.PID) {
				left = append(left, p.PID)
			}
		}
		return left
	}
	left := alive()
	for len(left) > 0 && m.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return sdk.Result{}, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
		left = alive()
	}
	killed := []int32{}
	for _, pid := range left {
		if err := m.Signal(pid, true); err == nil {
			killed = append(killed, pid)
		}
	}
	return sdk.JSON(map[string]any{"stopped": g.Title, "id": g.ID, "closedGracefully": len(left) == 0, "killed": killed})
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func customGame(c CustomGame) Game {
	g := Game{ID: c.ID, Title: c.Title, Launcher: "custom", NativeID: strings.TrimPrefix(c.ID, "custom:"), Custom: true,
		Installed: true, InstallPath: c.InstallPath, Cover: c.CoverURL, HasCover: c.CoverURL != "",
		ProcessNames: append([]string(nil), c.ProcessNames...)}
	if c.Executable != "" {
		g.Executables = []string{c.Executable}
		if len(g.ProcessNames) == 0 {
			g.ProcessNames = baseNames(g.Executables)
		}
		if filepath.IsAbs(c.Executable) {
			g.Installed = exists(c.Executable)
			if g.InstallPath == "" && filepath.Dir(c.Executable) != filepath.Dir(filepath.Dir(c.Executable)) {
				g.InstallPath = filepath.Dir(c.Executable)
			}
		}
		g.launch = launchSpec{Exe: c.Executable, Args: c.Args, Dir: c.WorkingDir}
	}
	if c.URI != "" {
		g.launch = launchSpec{URI: c.URI}
	}
	return g
}

// launchSchemes are the link schemes the module itself generates for
// launchers. Only these are handed to the system: on Windows rundll32 (and
// xdg-open or open elsewhere) passes any link to its protocol handler, and
// some handlers (ms-msdt:, search-ms:, ms-officecmd: …) run code or open
// remote files.
var launchSchemes = map[string]bool{
	"steam": true, "heroic": true, "com.epicgames.launcher": true, "goggalaxy": true,
	"battlenet": true, "origin2": true, "uplay": true, "msxbox": true, "itch": true, "lutris": true,
}

func validURI(u string) bool {
	scheme, rest, ok := strings.Cut(u, ":")
	if !ok || rest == "" || strings.ContainsAny(u, "\x00\r\n\t ") {
		return false
	}
	return launchSchemes[strings.ToLower(scheme)]
}

// commandLine shows a program and its arguments as one line, quoting any
// argument with spaces or quotes so the preview shows exactly what runs.
func commandLine(exe string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	for _, a := range append([]string{exe}, args...) {
		if a == "" || strings.ContainsAny(a, " \t\r\n\"'\\") {
			a = strconv.Quote(a)
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

func (m *Module) addCustom(c sdk.Call) (sdk.Result, error) {
	var in CustomGame
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	in.Title = strings.TrimSpace(in.Title)
	in.Executable = strings.TrimSpace(in.Executable)
	in.URI = strings.TrimSpace(in.URI)
	if c.Action == "add_link" {
		// add_link is a write: it can't register a program.
		if in.Executable != "" || len(in.Args) > 0 || in.WorkingDir != "" {
			return sdk.Result{}, errors.New("add_link only takes a launch link; a program needs add_custom")
		}
		if in.URI == "" {
			return sdk.Result{}, errors.New("give the launch link (uri)")
		}
	}
	switch {
	case in.Title == "":
		return sdk.Result{}, errors.New("give the game a title")
	case in.Executable == "" && in.URI == "":
		return sdk.Result{}, errors.New("say how to start it: a program or a launch link")
	case in.Executable != "" && in.URI != "":
		return sdk.Result{}, errors.New("give a program or a launch link, not both")
	case in.URI != "" && !validURI(in.URI):
		return sdk.Result{}, errors.New("the launch link must be a launcher link: steam, heroic, com.epicgames.launcher, goggalaxy, battlenet, origin2, uplay, msxbox, itch or lutris")
	case in.CoverURL != "" && !strings.HasPrefix(in.CoverURL, "https://"):
		return sdk.Result{}, errors.New("the cover must be an https link")
	}
	if c.DryRun {
		return addPlan(in), nil
	}
	st, err := m.store()
	if err != nil {
		return sdk.Result{}, err
	}
	st.mu.Lock()
	taken := map[string]bool{}
	for _, x := range st.d.Custom {
		taken[x.ID] = true
	}
	if in.ID != "" && (!strings.HasPrefix(in.ID, "custom:") || taken[in.ID]) {
		in.ID = "" // only undo passes an id back; never overwrite another game
	}
	if in.ID == "" {
		base := "custom:" + slug(in.Title)
		if base == "custom:" {
			base = "custom:game"
		}
		in.ID = base
		for n := 2; taken[in.ID]; n++ {
			in.ID = fmt.Sprintf("%s-%d", base, n)
		}
	}
	if in.Added.IsZero() {
		in.Added = m.Now().UTC()
	}
	st.d.Custom = append(st.d.Custom, in)
	err = st.save()
	st.mu.Unlock()
	if err != nil {
		return sdk.Result{}, fmt.Errorf("couldn't save the game: %w", err)
	}
	m.invalidate()
	r, err := sdk.JSON(customGame(in))
	r.Undo = sdk.UndoWith("remove_custom", map[string]string{"id": in.ID}, "Remove "+in.Title)
	return r, err
}

// addPlan previews add_custom: the full command line, working folder and
// arguments of the program play will run, or the link it will open.
func addPlan(in CustomGame) sdk.Result {
	j := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	target := "game " + strconv.Quote(in.Title)
	if in.Executable == "" {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add %q; play opens the link %s", in.Title, in.URI),
			Changes: []sdk.Change{{Target: target, Op: "create", After: j(map[string]any{"uri": in.URI})}}}}
	}
	dir := in.WorkingDir
	if dir == "" {
		dir = "(the daemon's working folder)"
	}
	args := in.Args
	if args == nil {
		args = []string{}
	}
	cmd := commandLine(in.Executable, in.Args)
	return sdk.Result{Plan: &sdk.Plan{
		Summary: fmt.Sprintf("Add %q; play will run this command on this computer as the daemon's user: %s (in %s)", in.Title, cmd, dir),
		Changes: []sdk.Change{{Target: target, Op: "create", After: j(map[string]any{
			"commandLine": cmd, "executable": in.Executable, "args": args, "workingDir": in.WorkingDir})}}}}
}

func (m *Module) removeCustom(c sdk.Call) (sdk.Result, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	st, err := m.store()
	if err != nil {
		return sdk.Result{}, err
	}
	st.mu.Lock()
	var removed *CustomGame
	keep := st.d.Custom[:0:0]
	for _, x := range st.d.Custom {
		if x.ID == in.ID {
			x := x
			removed = &x
			continue
		}
		keep = append(keep, x)
	}
	if removed == nil {
		st.mu.Unlock()
		return sdk.Result{}, fmt.Errorf("%q isn't a game you added (only those can be removed)", in.ID)
	}
	st.d.Custom = keep
	err = st.save()
	st.mu.Unlock()
	if err != nil {
		return sdk.Result{}, fmt.Errorf("couldn't save: %w", err)
	}
	m.invalidate()
	r, err := sdk.JSON(map[string]string{"removed": removed.Title, "id": removed.ID})
	undo := "add_custom"
	if removed.Executable == "" {
		undo = "add_link"
	}
	r.Undo = sdk.UndoWith(undo, removed, "Add "+removed.Title+" back")
	return r, err
}

func (m *Module) invalidate() {
	m.mu.Lock()
	m.scanned = time.Time{}
	m.mu.Unlock()
}

// hostAndInstance returns the host to publish on, or nil before setup.
func (m *Module) hostAndInstance() (sdk.Host, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.host, m.instance
}
