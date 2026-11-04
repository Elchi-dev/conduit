// Package chesscom reads Chess.com's public data API (no account needed):
// a player's profile, ratings and records per time control, which months
// have games, and a summary of one month's games. It's read-only and never
// returns PGN, chat or anything private.
package chesscom

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
	userAgent = "Conduit/" + version + " (chesscom module; +https://github.com/elchi-dev/conduit)"
)

// Config is one Chess.com player.
type Config struct {
	Username string `json:"username"` // the default player
}

type conn struct {
	api      *rest.Client
	username string
	sleep    func(context.Context, time.Duration) error
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://api.chess.com/pub and HTTP the client (tests).
	Base string
	HTTP *http.Client
	// sleep waits before the one retry after a 429 (tests replace it).
	sleep func(context.Context, time.Duration) error
}

// New returns the Chess.com module.
func New() *Module { return &Module{} }

var (
	userRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{1,49}$`)
	monthRe   = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})$`)
	archiveRe = regexp.MustCompile(`/games/([0-9]{4})/([0-9]{2})$`)
	countryRe = regexp.MustCompile(`/country/([A-Z0-9]{2,3})$`)
)

// Chess.com answers one request at a time from a client without limits, and
// may refuse parallel ones; every instance shares one slot.
var slot = make(chan struct{}, 1)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	user := `"username":{"type":"string","description":"Chess.com username (default: the one in the settings)"}`
	return sdk.Manifest{
		ID: "chesscom", Name: "Chess.com", Version: version, Category: "Gaming", Icon: "game",
		Description: "Chess.com profiles, ratings and win/loss records per time control, and a summary of any month's games. No account needed.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["username"],"properties":{
			"username":{"type":"string","description":"Your Chess.com username, used when an action names no player"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "profile", Title: "Profile", Description: "Username, title, membership, country, followers, when they joined and were last online.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + user + `}}`)},
			{Name: "stats", Title: "Ratings", Description: "Current and best rating with win/loss/draw per time control (daily, rapid, blitz, bullet, 960), puzzles and Puzzle Rush.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + user + `}}`)},
			{Name: "archives", Title: "Months with games", Description: "The months that have games, newest first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + user + `,"count":{"type":"integer","minimum":1,"maximum":120,"default":24}}}`)},
			{Name: "month", Title: "Month of games", Description: "One month's games: totals and results per time control, rating change and the latest games (opponent, result, accuracy). No moves.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + user + `,"month":{"type":"string","pattern":"^[0-9]{4}-[0-9]{2}$","description":"YYYY-MM (default: this month)"},"count":{"type":"integer","minimum":1,"maximum":50,"default":10}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.Username = strings.TrimSpace(c.Username)
	if !userRe.MatchString(c.Username) {
		return errors.New("enter your Chess.com username (letters, digits, - and _)")
	}
	base := m.Base
	if base == "" {
		base = "https://api.chess.com/pub"
	}
	api := rest.New(base, nil)
	api.Header.Set("User-Agent", userAgent)
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(api.HTTP)
	sleep := m.sleep
	if sleep == nil {
		sleep = wait
	}
	m.set.Put(id, &conn{api: api, username: strings.ToLower(c.Username), sleep: sleep})
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

var errBusy = errors.New("Chess.com is limiting requests right now; try again in a minute")

// get makes one request at a time, retrying a 429 once after Retry-After.
func (c *conn) get(ctx context.Context, path, who string, out any) error {
	select {
	case slot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-slot }()
	for try := 0; ; try++ {
		hdr, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, out)
		if rest.IsStatus(err, http.StatusTooManyRequests) {
			if d, ok := retryAfter(hdr); ok && try == 0 {
				if err := c.sleep(ctx, d); err != nil {
					return err
				}
				continue
			}
			return errBusy
		}
		switch {
		case rest.IsStatus(err, http.StatusNotFound), rest.IsStatus(err, http.StatusGone):
			return fmt.Errorf("Chess.com has nothing for %s", who)
		case errors.Is(err, rest.ErrCrossHostRedirect):
			return errors.New("Chess.com redirected to another host; refused")
		}
		return err
	}
}

func userPath(u string) string { return "/player/" + url.PathEscape(u) }

type input struct {
	Username string `json:"username"`
	Month    string `json:"month"`
	Count    int    `json:"count"`
}

func (c *conn) profile(ctx context.Context, u string) (map[string]any, error) {
	var p struct {
		Username   string `json:"username"`
		PlayerID   int64  `json:"player_id"`
		Title      string `json:"title"`
		Status     string `json:"status"`
		Country    string `json:"country"`
		Joined     int64  `json:"joined"`
		LastOnline int64  `json:"last_online"`
		Followers  int    `json:"followers"`
		Streamer   bool   `json:"is_streamer"`
		Verified   bool   `json:"verified"`
		League     string `json:"league"`
		URL        string `json:"url"`
		// Name, location, avatar and links aren't decoded.
	}
	if err := c.get(ctx, userPath(u), "player "+u, &p); err != nil {
		return nil, err
	}
	if p.Username == "" {
		return nil, fmt.Errorf("Chess.com has nothing for player %s", u)
	}
	out := map[string]any{"username": p.Username, "status": p.Status, "followers": p.Followers, "url": "https://www.chess.com/member/" + url.PathEscape(strings.ToLower(p.Username))}
	if p.PlayerID > 0 {
		out["playerId"] = p.PlayerID
	}
	if p.Title != "" {
		out["title"] = p.Title
	}
	if m := countryRe.FindStringSubmatch(p.Country); m != nil {
		out["country"] = m[1]
	}
	if s := when(p.Joined); s != "" {
		out["joined"] = s
	}
	if s := when(p.LastOnline); s != "" {
		out["lastOnline"] = s
	}
	if p.Streamer {
		out["streamer"] = true
	}
	if p.Verified {
		out["verified"] = true
	}
	if p.League != "" {
		out["league"] = p.League
	}
	return out, nil
}

func when(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	p, err := c.profile(ctx, c.username)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprint(p["username"])}
}

type rating struct {
	Rating int   `json:"rating"`
	Date   int64 `json:"date"`
}

var draws = map[string]bool{"agreed": true, "repetition": true, "stalemate": true, "insufficient": true, "50move": true, "timevsinsufficient": true}

func outcome(result string) string {
	switch {
	case result == "win":
		return "win"
	case draws[result]:
		return "draw"
	}
	return "loss"
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
	case "profile", "stats", "archives", "month":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	u := strings.TrimSpace(p.Username)
	if u == "" {
		u = c.username
	}
	if !userRe.MatchString(u) {
		return sdk.Result{}, errors.New("a Chess.com username is letters, digits, - and _")
	}
	u = strings.ToLower(u)
	year, month := 0, 0
	switch call.Action {
	case "archives":
		if p.Count == 0 {
			p.Count = 24
		}
		if p.Count < 1 || p.Count > 120 {
			return sdk.Result{}, errors.New("count is 1 to 120")
		}
	case "month":
		if p.Count == 0 {
			p.Count = 10
		}
		if p.Count < 1 || p.Count > 50 {
			return sdk.Result{}, errors.New("count is 1 to 50")
		}
		now := time.Now().UTC()
		year, month = now.Year(), int(now.Month())
		if s := strings.TrimSpace(p.Month); s != "" {
			mm := monthRe.FindStringSubmatch(s)
			if mm == nil {
				return sdk.Result{}, errors.New("the month is YYYY-MM, e.g. 2026-10")
			}
			year, _ = strconv.Atoi(mm[1])
			month, _ = strconv.Atoi(mm[2])
			if month < 1 || month > 12 || year < 2007 || year*12+month > now.Year()*12+int(now.Month()) {
				return sdk.Result{}, errors.New("the month is between 2007-01 and this month")
			}
		}
	}

	switch call.Action {
	case "profile":
		out, err := c.profile(ctx, u)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(out)

	case "stats":
		var raw map[string]json.RawMessage
		if err := c.get(ctx, userPath(u)+"/stats", "player "+u, &raw); err != nil {
			return sdk.Result{}, err
		}
		ratings := map[string]any{}
		out := map[string]any{"username": u, "ratings": ratings}
		for k, v := range raw {
			switch {
			case strings.HasPrefix(k, "chess"):
				var s struct {
					Last   *rating `json:"last"`
					Best   *rating `json:"best"`
					Record *struct {
						Win  int `json:"win"`
						Loss int `json:"loss"`
						Draw int `json:"draw"`
					} `json:"record"`
				}
				if json.Unmarshal(v, &s) != nil || s.Last == nil {
					continue
				}
				r := map[string]any{"rating": s.Last.Rating}
				if d := when(s.Last.Date); d != "" {
					r["date"] = d
				}
				if s.Best != nil {
					r["best"] = s.Best.Rating
				}
				if s.Record != nil {
					r["win"], r["loss"], r["draw"] = s.Record.Win, s.Record.Loss, s.Record.Draw
				}
				ratings[strings.TrimPrefix(strings.TrimPrefix(k, "chess_"), "chess")] = r
			case k == "tactics":
				var s struct {
					Highest *rating `json:"highest"`
				}
				if json.Unmarshal(v, &s) == nil && s.Highest != nil {
					out["puzzlesHighest"] = s.Highest.Rating
				}
			case k == "puzzle_rush":
				var s struct {
					Best *struct {
						Score int `json:"score"`
					} `json:"best"`
				}
				if json.Unmarshal(v, &s) == nil && s.Best != nil {
					out["puzzleRushBest"] = s.Best.Score
				}
			case k == "fide":
				var n int
				if json.Unmarshal(v, &n) == nil && n > 0 {
					out["fide"] = n
				}
			}
		}
		return sdk.JSON(out)

	case "archives":
		var r struct {
			Archives []string `json:"archives"`
		}
		if err := c.get(ctx, userPath(u)+"/games/archives", "player "+u, &r); err != nil {
			return sdk.Result{}, err
		}
		months := []string{}
		for _, a := range r.Archives {
			if mm := archiveRe.FindStringSubmatch(a); mm != nil {
				months = append(months, mm[1]+"-"+mm[2])
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(months)))
		total := len(months)
		if len(months) > p.Count {
			months = months[:p.Count]
		}
		return sdk.JSON(map[string]any{"username": u, "total": total, "months": months})

	case "month":
		type side struct {
			Username string `json:"username"`
			Rating   int    `json:"rating"`
			Result   string `json:"result"`
		}
		var r struct {
			Games []struct {
				URL         string `json:"url"`
				TimeControl string `json:"time_control"`
				EndTime     int64  `json:"end_time"`
				Rated       bool   `json:"rated"`
				TimeClass   string `json:"time_class"`
				Rules       string `json:"rules"`
				White       side   `json:"white"`
				Black       side   `json:"black"`
				Accuracies  *struct {
					White float64 `json:"white"`
					Black float64 `json:"black"`
				} `json:"accuracies"`
				// pgn, fen and tcn aren't decoded.
			} `json:"games"`
		}
		path := fmt.Sprintf("%s/games/%04d/%02d", userPath(u), year, month)
		label := fmt.Sprintf("%04d-%02d", year, month)
		if err := c.get(ctx, path, "player "+u+" in "+label, &r); err != nil {
			return sdk.Result{}, err
		}
		games := r.Games
		sort.SliceStable(games, func(i, j int) bool { return games[i].EndTime < games[j].EndTime })
		type tally struct {
			Games int `json:"games"`
			Win   int `json:"win"`
			Loss  int `json:"loss"`
			Draw  int `json:"draw"`
			first int
			last  int
		}
		per := map[string]*tally{}
		var latest []map[string]any
		for _, g := range games {
			me, opp, color := g.White, g.Black, "white"
			if strings.ToLower(g.Black.Username) == u {
				me, opp, color = g.Black, g.White, "black"
			} else if strings.ToLower(g.White.Username) != u {
				continue
			}
			res := outcome(me.Result)
			key := g.TimeClass
			if g.Rules != "" && g.Rules != "chess" {
				key = g.Rules
			}
			t := per[key]
			if t == nil {
				t = &tally{first: me.Rating}
				per[key] = t
			}
			t.Games++
			t.last = me.Rating
			switch res {
			case "win":
				t.Win++
			case "loss":
				t.Loss++
			default:
				t.Draw++
			}
			row := map[string]any{"ended": when(g.EndTime), "timeClass": g.TimeClass, "timeControl": g.TimeControl, "rated": g.Rated, "color": color,
				"opponent": opp.Username, "opponentRating": opp.Rating, "rating": me.Rating, "result": res, "how": me.Result}
			if g.Rules != "" && g.Rules != "chess" {
				row["rules"] = g.Rules
			}
			if strings.HasPrefix(g.URL, "https://www.chess.com/") {
				row["url"] = g.URL
			}
			if g.Accuracies != nil {
				if color == "white" && g.Accuracies.White > 0 {
					row["accuracy"] = g.Accuracies.White
				} else if color == "black" && g.Accuracies.Black > 0 {
					row["accuracy"] = g.Accuracies.Black
				}
			}
			latest = append(latest, row)
		}
		summary := map[string]any{}
		total := 0
		for k, t := range per {
			total += t.Games
			summary[k] = map[string]any{"games": t.Games, "win": t.Win, "loss": t.Loss, "draw": t.Draw, "ratingStart": t.first, "ratingEnd": t.last, "ratingChange": t.last - t.first}
		}
		// Newest first, capped.
		for i, j := 0, len(latest)-1; i < j; i, j = i+1, j-1 {
			latest[i], latest[j] = latest[j], latest[i]
		}
		if len(latest) > p.Count {
			latest = latest[:p.Count]
		}
		if latest == nil {
			latest = []map[string]any{}
		}
		return sdk.JSON(map[string]any{"username": u, "month": label, "games": total, "byTimeClass": summary, "latest": latest})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
