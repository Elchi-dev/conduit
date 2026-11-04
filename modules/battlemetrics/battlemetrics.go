// Package battlemetrics reads game servers from BattleMetrics with an API
// token: your servers with players online, rank and status, one server's
// details and its player count over time. It's read-only and has no RCON.
package battlemetrics

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	version   = "0.1.0"
	userAgent = "Conduit/" + version + " (battlemetrics module; +https://github.com/elchi-dev/conduit)"
	// maxServers is how many servers the settings may list.
	maxServers = 25
)

// Config is one BattleMetrics token and the servers to watch.
type Config struct {
	Token   string   `json:"token"`   // secret:// personal access token
	Servers []string `json:"servers"` // BattleMetrics server ids
}

type conn struct {
	api     *rest.Client
	servers []string
	sleep   func(context.Context, time.Duration) error
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://api.battlemetrics.com and HTTP the client (tests).
	Base string
	HTTP *http.Client
	// sleep waits before the one retry after a 429 (tests replace it).
	sleep func(context.Context, time.Duration) error
}

// New returns the BattleMetrics module.
func New() *Module { return &Module{} }

var (
	idRe   = regexp.MustCompile(`^[0-9]{1,12}$`)
	gameRe = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	// detailKeyRe and the words below keep game-specific details to plain
	// settings (map, version, mode), never addresses or credentials.
	detailKeyRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,40}$`)
	secretish   = []string{"ip", "address", "rcon", "password", "token", "key", "secret", "steamid", "owner"}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	server := `"server":{"type":"string","description":"BattleMetrics server id (the number in the server's address on battlemetrics.com)"}`
	return sdk.Manifest{
		ID: "battlemetrics", Name: "BattleMetrics", Version: version, Category: "Gaming", Icon: "game",
		Description: "Your game servers on BattleMetrics: players online, rank and status, server details and player count history. No RCON.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"Personal access token (battlemetrics.com, Account, Developers, New token); read access is enough"},
			"servers":{"type":"array","maxItems":25,"items":{"type":"string"},"description":"Your servers' BattleMetrics ids"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "servers", Title: "Your servers", Description: "Each server in the settings with status, players online and the maximum, rank, game and country, busiest first.", Risk: sdk.RiskRead},
			{Name: "server", Title: "Server details", Description: "One server (any public one): status, players, rank, game, country, last update and game details such as map and version.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["server"],"properties":{` + server + `}}`)},
			{Name: "player_history", Title: "Player count history", Description: "Players online over the last hours or days, with the low, high and average.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["server"],"properties":{` + server + `,"hours":{"type":"integer","minimum":1,"maximum":720,"default":24}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the BattleMetrics token in the vault and enter its secret:// reference")
	}
	if len(c.Servers) > maxServers {
		return fmt.Errorf("list at most %d servers", maxServers)
	}
	var servers []string
	seen := map[string]bool{}
	for _, s := range c.Servers {
		s = strings.TrimSpace(s)
		if !idRe.MatchString(s) {
			return fmt.Errorf("server %q isn't a BattleMetrics server id (a number)", s)
		}
		if !seen[s] {
			seen[s] = true
			servers = append(servers, s)
		}
	}
	base := m.Base
	if base == "" {
		base = "https://api.battlemetrics.com"
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.Header.Set("User-Agent", userAgent)
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second)
	}
	// The token travels in Authorization; never follow it to another host.
	api.HTTP = rest.SameHostOnly(api.HTTP)
	sleep := m.sleep
	if sleep == nil {
		sleep = wait
	}
	m.set.Put(id, &conn{api: api, servers: servers, sleep: sleep})
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
			return errors.New("BattleMetrics is limiting requests for this token; try again in a minute")
		}
		switch {
		case rest.IsStatus(err, http.StatusUnauthorized):
			return errors.New("BattleMetrics refused the token")
		case rest.IsStatus(err, http.StatusForbidden):
			return errors.New("the BattleMetrics token isn't allowed to read this")
		case errors.Is(err, rest.ErrCrossHostRedirect):
			return errors.New("BattleMetrics redirected to another host; refused")
		}
		return err
	}
}

type server struct {
	ID         string `json:"id"`
	Attributes struct {
		Name       string         `json:"name"`
		Players    int            `json:"players"`
		MaxPlayers int            `json:"maxPlayers"`
		Rank       *int           `json:"rank"`
		Status     string         `json:"status"`
		Country    string         `json:"country"`
		UpdatedAt  string         `json:"updatedAt"`
		Private    bool           `json:"private"`
		Details    map[string]any `json:"details"`
		// ip, address and port aren't decoded.
	} `json:"attributes"`
	Relationships struct {
		Game struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		} `json:"game"`
	} `json:"relationships"`
}

func (c *conn) server(ctx context.Context, id string) (server, error) {
	var r struct {
		Data server `json:"data"`
	}
	err := c.get(ctx, "/servers/"+url.PathEscape(id), nil, &r)
	if rest.IsStatus(err, http.StatusNotFound) {
		return server{}, fmt.Errorf("BattleMetrics has no server %s", id)
	}
	if err != nil {
		return server{}, err
	}
	if r.Data.ID != id {
		return server{}, errors.New("unexpected answer from BattleMetrics")
	}
	return r.Data, nil
}

func summary(s server) map[string]any {
	a := s.Attributes
	out := map[string]any{"id": s.ID, "name": a.Name, "status": a.Status, "players": a.Players, "maxPlayers": a.MaxPlayers,
		"url": "https://www.battlemetrics.com/servers/"}
	game := s.Relationships.Game.Data.ID
	if gameRe.MatchString(game) {
		out["game"] = game
		out["url"] = "https://www.battlemetrics.com/servers/" + game + "/" + s.ID
	} else {
		delete(out, "url")
	}
	if a.Rank != nil {
		out["rank"] = *a.Rank
	}
	if a.Country != "" {
		out["country"] = a.Country
	}
	return out
}

func safeDetails(d map[string]any) map[string]any {
	out := map[string]any{}
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
next:
	for _, k := range keys {
		if len(out) >= 20 || !detailKeyRe.MatchString(k) {
			continue
		}
		lk := strings.ToLower(k)
		for _, w := range secretish {
			if strings.Contains(lk, w) {
				continue next
			}
		}
		switch v := d[k].(type) {
		case string:
			if len(v) <= 120 {
				out[k] = rest.Redact(v)
			}
		case float64, bool:
			out[k] = v
		}
	}
	return out
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if len(c.servers) == 0 {
		// Any token can read the game list; it checks the token.
		var g struct {
			Data []json.RawMessage `json:"data"`
		}
		if err := c.get(ctx, "/games", nil, &g); err != nil {
			return sdk.Health{Status: "down", Message: err.Error()}
		}
		return sdk.Health{Status: "ok", Message: "token works; no servers listed in the settings"}
	}
	online, players := 0, 0
	for _, sid := range c.servers {
		s, err := c.server(ctx, sid)
		if err != nil {
			return sdk.Health{Status: "down", Message: err.Error()}
		}
		if s.Attributes.Status == "online" {
			online++
		}
		players += s.Attributes.Players
	}
	msg := fmt.Sprintf("%d of %d servers online · %d players", online, len(c.servers), players)
	if online < len(c.servers) {
		return sdk.Health{Status: "degraded", Message: msg}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Server string `json:"server"`
	Hours  int    `json:"hours"`
}

// resolution picks a point every 30 minutes up to two days, hourly up to a
// week and daily beyond, so history stays a few hundred points.
func resolution(hours int) string {
	switch {
	case hours <= 48:
		return "30"
	case hours <= 168:
		return "60"
	}
	return "1440"
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "servers":
	case "server", "player_history":
		p.Server = strings.TrimSpace(p.Server)
		if !idRe.MatchString(p.Server) {
			return sdk.Result{}, errors.New("the server is its BattleMetrics id, a number")
		}
		if p.Hours == 0 {
			p.Hours = 24
		}
		if p.Hours < 1 || p.Hours > 720 {
			return sdk.Result{}, errors.New("hours is 1 to 720 (30 days)")
		}
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}

	switch call.Action {
	case "servers":
		if len(c.servers) == 0 {
			return sdk.Result{}, errors.New("add your servers' BattleMetrics ids to the settings")
		}
		list := []map[string]any{}
		online, players := 0, 0
		for _, sid := range c.servers {
			s, err := c.server(ctx, sid)
			if err != nil {
				list = append(list, map[string]any{"id": sid, "error": err.Error()})
				continue
			}
			if s.Attributes.Status == "online" {
				online++
			}
			players += s.Attributes.Players
			list = append(list, summary(s))
		}
		sort.SliceStable(list, func(i, j int) bool {
			a, _ := list[i]["players"].(int)
			b, _ := list[j]["players"].(int)
			return a > b
		})
		return sdk.JSON(map[string]any{"servers": list, "online": online, "total": len(c.servers), "players": players})

	case "server":
		s, err := c.server(ctx, p.Server)
		if err != nil {
			return sdk.Result{}, err
		}
		out := summary(s)
		if s.Attributes.UpdatedAt != "" {
			out["updated"] = s.Attributes.UpdatedAt
		}
		if s.Attributes.Private {
			out["private"] = true
		}
		if d := safeDetails(s.Attributes.Details); len(d) > 0 {
			out["details"] = d
		}
		return sdk.JSON(out)

	case "player_history":
		stop := time.Now().UTC().Truncate(time.Minute)
		start := stop.Add(-time.Duration(p.Hours) * time.Hour)
		q := url.Values{"start": {start.Format(time.RFC3339)}, "stop": {stop.Format(time.RFC3339)}, "resolution": {resolution(p.Hours)}}
		var r struct {
			Data []struct {
				Attributes struct {
					Timestamp string   `json:"timestamp"`
					Value     float64  `json:"value"`
					Min       *float64 `json:"min"`
					Max       *float64 `json:"max"`
				} `json:"attributes"`
			} `json:"data"`
		}
		err := c.get(ctx, "/servers/"+url.PathEscape(p.Server)+"/player-count-history", q, &r)
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("BattleMetrics has no server %s", p.Server)
		}
		if err != nil {
			return sdk.Result{}, err
		}
		type point struct {
			Time    string  `json:"time"`
			Players float64 `json:"players"`
		}
		points := []point{}
		lo, hi, sum := 0.0, 0.0, 0.0
		for i, d := range r.Data {
			a := d.Attributes
			if len(points) < 1000 {
				points = append(points, point{Time: a.Timestamp, Players: a.Value})
			}
			l, h := a.Value, a.Value
			if a.Min != nil {
				l = *a.Min
			}
			if a.Max != nil {
				h = *a.Max
			}
			if i == 0 || l < lo {
				lo = l
			}
			if i == 0 || h > hi {
				hi = h
			}
			sum += a.Value
		}
		sort.SliceStable(points, func(i, j int) bool { return points[i].Time < points[j].Time })
		out := map[string]any{"server": p.Server, "from": start.Format(time.RFC3339), "to": stop.Format(time.RFC3339), "points": points}
		out["resolutionMinutes"], _ = strconv.Atoi(resolution(p.Hours))
		if n := len(r.Data); n > 0 {
			out["low"], out["high"], out["average"] = lo, hi, float64(int(sum/float64(n)*10))/10
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
