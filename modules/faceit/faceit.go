// Package faceit reads FACEIT through its Data API with a server-side API
// key: a player looked up by nickname (level, Elo and region per game),
// their lifetime stats in a game and their recent matches. It's read-only.
package faceit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	version   = "0.1.0"
	userAgent = "Conduit/" + version + " (faceit module; +https://github.com/elchi-dev/conduit)"
)

// Config is one FACEIT API key and the default player.
type Config struct {
	APIKey   string `json:"apiKey"`   // secret:// server-side Data API key
	Nickname string `json:"nickname"` // the default player
	Game     string `json:"game"`     // default game id, e.g. cs2
}

type conn struct {
	api      *rest.Client
	nickname string
	game     string
	sleep    func(context.Context, time.Duration) error
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://open.faceit.com/data/v4 and HTTP the client (tests).
	Base string
	HTTP *http.Client
	// sleep waits before the one retry after a 429 (tests replace it).
	sleep func(context.Context, time.Duration) error
}

// New returns the FACEIT module.
func New() *Module { return &Module{} }

var (
	nickRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{2,32}$`)
	idRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	gameRe = regexp.MustCompile(`^[a-z0-9_]{2,32}$`)
	// matchRe is a match id like 1-5ea07280-2399-4c7e-88ab-f2f7db0c449f.
	matchRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	who := `"nickname":{"type":"string","description":"FACEIT nickname (default: yours)"},"playerId":{"type":"string","description":"FACEIT player id, instead of a nickname"}`
	game := `"game":{"type":"string","description":"Game id, e.g. cs2, csgo, dota2 (default: the one in the settings)"}`
	return sdk.Manifest{
		ID: "faceit", Name: "FACEIT", Version: version, Category: "Gaming", Icon: "game",
		Description: "FACEIT players by nickname with their level, Elo and region, lifetime stats per game and recent matches with results.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey","nickname"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"Server-side API key from the FACEIT Developer Portal (App Studio, your app, API keys)"},
			"nickname":{"type":"string","description":"Your FACEIT nickname, used when an action names no player"},
			"game":{"type":"string","default":"cs2","description":"Default game id, e.g. cs2"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "player", Title: "Player", Description: "Nickname, country and, per game, skill level, Elo and region.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + who + `}}`)},
			{Name: "stats", Title: "Lifetime stats", Description: "A player's lifetime stats in one game, as FACEIT reports them (matches, win rate, K/D, headshots, streaks, recent results).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + who + `,` + game + `}}`)},
			{Name: "matches", Title: "Recent matches", Description: "Recent matches in one game, newest first: mode, competition, teams, score and whether the player won.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + who + `,` + game + `,
					"count":{"type":"integer","minimum":1,"maximum":50,"default":10},
					"days":{"type":"integer","minimum":1,"maximum":90,"default":30,"description":"Only matches from the last this many days"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the FACEIT API key in the vault and enter its secret:// reference")
	}
	c.Nickname = strings.TrimSpace(c.Nickname)
	if !nickRe.MatchString(c.Nickname) {
		return errors.New("enter your FACEIT nickname (letters, digits, -, _ and .)")
	}
	c.Game = strings.TrimSpace(c.Game)
	if c.Game == "" {
		c.Game = "cs2"
	}
	if !gameRe.MatchString(c.Game) {
		return errors.New("the game is a FACEIT game id, e.g. cs2")
	}
	base := m.Base
	if base == "" {
		base = "https://open.faceit.com/data/v4"
	}
	ref := c.APIKey
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
		return nil
	})
	api.Header.Set("User-Agent", userAgent)
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second)
	}
	// The key travels in Authorization; never follow it to another host.
	api.HTTP = rest.SameHostOnly(api.HTTP)
	sleep := m.sleep
	if sleep == nil {
		sleep = wait
	}
	m.set.Put(id, &conn{api: api, nickname: c.Nickname, game: c.Game, sleep: sleep})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryAfter is how long a 429 asks to wait, if it says and it's short.
func retryAfter(h http.Header) (time.Duration, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	d := time.Duration(-1)
	if n, err := strconv.Atoi(v); err == nil {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = max(time.Until(t), 0)
	}
	return d, d >= 0 && d <= 30*time.Second
}

// get makes one request, retrying a 429 once after Retry-After.
func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	for try := 0; ; try++ {
		hdr, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
		if rest.IsStatus(err, http.StatusTooManyRequests) {
			if d, ok := retryAfter(hdr); ok && try == 0 {
				if err := c.sleep(ctx, d); err != nil {
					return err
				}
				continue
			}
			return errors.New("FACEIT is limiting requests for this key; try again in a minute")
		}
		switch {
		case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
			return errors.New("FACEIT refused the API key")
		case errors.Is(err, rest.ErrCrossHostRedirect):
			return errors.New("FACEIT redirected to another host; refused")
		}
		return err
	}
}

type gameInfo struct {
	SkillLevel int    `json:"skill_level"`
	Elo        int    `json:"faceit_elo"`
	Region     string `json:"region"`
	Name       string `json:"game_player_name"`
}

type player struct {
	ID       string              `json:"player_id"`
	Nickname string              `json:"nickname"`
	Country  string              `json:"country"`
	Verified bool                `json:"verified"`
	Games    map[string]gameInfo `json:"games"`
	// Avatar, platform ids, friends, settings and infractions aren't decoded.
}

type who struct {
	Nickname string `json:"nickname"`
	PlayerID string `json:"playerId"`
	Game     string `json:"game"`
	Count    int    `json:"count"`
	Days     int    `json:"days"`
}

func (c *conn) player(ctx context.Context, w who) (player, error) {
	var p player
	var err error
	if w.PlayerID != "" {
		err = c.get(ctx, "/players/"+url.PathEscape(w.PlayerID), nil, &p)
	} else {
		err = c.get(ctx, "/players", url.Values{"nickname": {w.Nickname}}, &p)
	}
	if rest.IsStatus(err, http.StatusNotFound) {
		if w.PlayerID != "" {
			return p, errors.New("FACEIT has no player with that id")
		}
		return p, fmt.Errorf("FACEIT has no player named %s", w.Nickname)
	}
	if err != nil {
		return p, err
	}
	if !idRe.MatchString(p.ID) {
		return p, errors.New("unexpected answer from FACEIT")
	}
	p.Nickname = line(p.Nickname, 64)
	return p, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	p, err := c.player(ctx, who{Nickname: c.nickname})
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := p.Nickname
	if g, ok := p.Games[c.game]; ok && g.SkillLevel > 0 {
		msg += fmt.Sprintf(" · %s level %d", c.game, g.SkillLevel)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// line makes FACEIT text one line of at most n bytes (cut on a rune start),
// without control characters.
func line(s string, n int) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)), " ")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// scalar keeps a stat value that's a short string (made one line), number
// or bool.
func scalar(v any) (any, bool) {
	switch x := v.(type) {
	case string:
		if x = line(x, 1<<20); len(x) <= 64 {
			return x, true
		}
	case float64, bool:
		return x, true
	}
	return nil, false
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var w who
	if err := sdk.Decode(call, &w); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "player", "stats", "matches":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	w.Nickname, w.PlayerID, w.Game = strings.TrimSpace(w.Nickname), strings.ToLower(strings.TrimSpace(w.PlayerID)), strings.TrimSpace(w.Game)
	switch {
	case w.PlayerID != "" && !idRe.MatchString(w.PlayerID):
		return sdk.Result{}, errors.New("a FACEIT player id looks like 5ea07280-2399-4c7e-88ab-f2f7db0c449f")
	case w.PlayerID != "" && w.Nickname != "":
		return sdk.Result{}, errors.New("give a nickname or a player id, not both")
	case w.Nickname != "" && !nickRe.MatchString(w.Nickname):
		return sdk.Result{}, errors.New("a FACEIT nickname is letters, digits, -, _ and .")
	case w.Nickname == "" && w.PlayerID == "":
		w.Nickname = c.nickname
	}
	if w.Game == "" {
		w.Game = c.game
	}
	if !gameRe.MatchString(w.Game) {
		return sdk.Result{}, errors.New("the game is a FACEIT game id, e.g. cs2")
	}
	if w.Count == 0 {
		w.Count = 10
	}
	if w.Days == 0 {
		w.Days = 30
	}
	if w.Count < 1 || w.Count > 50 {
		return sdk.Result{}, errors.New("count is 1 to 50")
	}
	if w.Days < 1 || w.Days > 90 {
		return sdk.Result{}, errors.New("days is 1 to 90")
	}

	p, err := c.player(ctx, w)
	if err != nil {
		return sdk.Result{}, err
	}
	pid := url.PathEscape(p.ID)

	switch call.Action {
	case "player":
		games := map[string]any{}
		for k, g := range p.Games {
			if !gameRe.MatchString(k) {
				continue
			}
			row := map[string]any{"level": g.SkillLevel, "elo": g.Elo, "region": line(g.Region, 16)}
			if n := line(g.Name, 64); n != "" {
				row["inGameName"] = n
			}
			games[k] = row
		}
		out := map[string]any{"playerId": p.ID, "nickname": p.Nickname, "country": strings.ToUpper(line(p.Country, 8)), "games": games,
			"url": "https://www.faceit.com/en/players/" + url.PathEscape(p.Nickname)}
		if p.Verified {
			out["verified"] = true
		}
		return sdk.JSON(out)

	case "stats":
		var r struct {
			Lifetime map[string]any `json:"lifetime"`
		}
		err := c.get(ctx, "/players/"+pid+"/stats/"+url.PathEscape(w.Game), nil, &r)
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("%s has no %s stats on FACEIT", p.Nickname, w.Game)
		}
		if err != nil {
			return sdk.Result{}, err
		}
		keys := make([]string, 0, len(r.Lifetime))
		for k := range r.Lifetime {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		stats := map[string]any{}
		for _, k := range keys {
			// A stat name is kept only when it's already one short line.
			name := line(k, 64)
			if len(stats) >= 40 || name != k || name == "" {
				continue
			}
			if v, ok := scalar(r.Lifetime[k]); ok {
				stats[k] = v
			} else if list, ok := r.Lifetime[k].([]any); ok {
				short := []any{}
				for _, x := range list {
					if v, ok := scalar(x); ok && len(short) < 10 {
						short = append(short, v)
					}
				}
				stats[k] = short
			}
		}
		out := map[string]any{"nickname": p.Nickname, "game": w.Game, "lifetime": stats}
		if g, ok := p.Games[w.Game]; ok {
			out["level"], out["elo"] = g.SkillLevel, g.Elo
		}
		return sdk.JSON(out)

	case "matches":
		now := time.Now()
		q := url.Values{"game": {w.Game}, "limit": {strconv.Itoa(w.Count)}, "offset": {"0"},
			"from": {strconv.FormatInt(now.Add(-time.Duration(w.Days)*24*time.Hour).Unix(), 10)}, "to": {strconv.FormatInt(now.Unix(), 10)}}
		type team struct {
			ID       string `json:"team_id"`
			Nickname string `json:"nickname"`
			Players  []struct {
				ID string `json:"player_id"`
			} `json:"players"`
		}
		var r struct {
			Items []struct {
				MatchID     string          `json:"match_id"`
				GameID      string          `json:"game_id"`
				Region      string          `json:"region"`
				MatchType   string          `json:"match_type"`
				GameMode    string          `json:"game_mode"`
				MaxPlayers  int             `json:"max_players"`
				Competition string          `json:"competition_name"`
				Started     int64           `json:"started_at"`
				Finished    int64           `json:"finished_at"`
				Status      string          `json:"status"`
				Teams       map[string]team `json:"teams"`
				Results     struct {
					Winner string         `json:"winner"`
					Score  map[string]int `json:"score"`
				} `json:"results"`
			} `json:"items"`
		}
		if err := c.get(ctx, "/players/"+pid+"/history", q, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		tally := map[string]int{"win": 0, "loss": 0}
		for _, it := range r.Items {
			if len(out) >= w.Count {
				break
			}
			mine := ""
			for faction, t := range it.Teams {
				for _, pl := range t.Players {
					if pl.ID == p.ID {
						mine = faction
					}
				}
			}
			row := map[string]any{"matchId": line(it.MatchID, 64), "mode": line(it.GameMode, 32), "competition": line(it.Competition, 100), "region": line(it.Region, 16), "status": line(it.Status, 20)}
			if s := when(it.Started); s != "" {
				row["started"] = s
			}
			if s := when(it.Finished); s != "" {
				row["finished"] = s
			}
			names := map[string]string{}
			for faction, t := range it.Teams {
				if len(names) < 4 {
					names[line(faction, 16)] = line(t.Nickname, 64)
				}
			}
			row["teams"] = names
			if n := len(it.Results.Score); n > 0 && n <= 4 {
				row["score"] = it.Results.Score
			}
			if mine != "" && it.Results.Winner != "" {
				res := "loss"
				if it.Results.Winner == mine {
					res = "win"
				}
				row["result"] = res
				tally[res]++
				row["team"] = names[mine]
			}
			if matchRe.MatchString(it.MatchID) {
				row["url"] = "https://www.faceit.com/en/" + url.PathEscape(w.Game) + "/room/" + url.PathEscape(it.MatchID)
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"nickname": p.Nickname, "game": w.Game, "days": w.Days, "results": tally, "matches": out})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func when(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}
