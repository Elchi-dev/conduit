// Package lichess reads Lichess through its public API: a player's ratings
// and game counts, recent games as short summaries (no moves or PGN) and,
// with a personal token, your own account and ongoing games. It's
// read-only, and it sends one request at a time as Lichess asks.
package lichess

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	version   = "0.1.0"
	userAgent = "Conduit/" + version + " (lichess module; +https://github.com/elchi-dev/conduit)"
)

// Config is one Lichess player.
type Config struct {
	Username string `json:"username"` // the default player; optional with a token
	Token    string `json:"token"`    // secret:// personal access token, optional
}

type conn struct {
	api      *rest.Client
	username string // lower case; "" until learned from the token's account
	token    bool
	sleep    func(context.Context, time.Duration) error
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://lichess.org and HTTP the client (tests).
	Base string
	HTTP *http.Client
	// sleep waits after a 429 (tests replace it).
	sleep func(context.Context, time.Duration) error
}

// New returns the Lichess module.
func New() *Module { return &Module{} }

var (
	userRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{1,29}$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9]{8}$`)
	perfs  = map[string]bool{"ultraBullet": true, "bullet": true, "blitz": true, "rapid": true, "classical": true, "correspondence": true, "chess960": true,
		"crazyhouse": true, "antichess": true, "atomic": true, "horde": true, "kingOfTheHill": true, "racingKings": true, "threeCheck": true}
)

// Lichess asks for one request at a time from a client, and a full minute's
// pause after a 429. Every instance shares the slot.
var slot = make(chan struct{}, 1)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	user := `"username":{"type":"string","description":"Lichess username (default: yours)"}`
	return sdk.Manifest{
		ID: "lichess", Name: "Lichess", Version: version, Category: "Gaming", Icon: "game",
		Description: "Lichess ratings and game counts for any player, recent games at a glance and, with a token, your ongoing games and whose turn it is.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"username":{"type":"string","description":"Your Lichess username (not needed with a token)"},
			"token":{"type":"string","x-secret":true,"description":"Optional personal access token (lichess.org/account/oauth/token), for your account and ongoing games"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "profile", Title: "Profile and ratings", Description: "Rating, games and progress per speed and variant, puzzle scores, game counts, play time and when the player joined and was last seen.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + user + `}}`)},
			{Name: "games", Title: "Recent games", Description: "The latest games, newest first: opponent, ratings, result, speed, opening and how it ended. No moves.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + user + `,
					"count":{"type":"integer","minimum":1,"maximum":50,"default":10},
					"days":{"type":"integer","minimum":1,"maximum":365,"description":"Only games from the last this many days"},
					"perfType":{"type":"string","description":"Only this speed or variant, e.g. blitz, rapid, chess960"},
					"rated":{"type":"boolean","description":"Only rated (true) or casual (false) games"}}}`)},
			{Name: "ongoing", Title: "Ongoing games", Description: "Your games in progress, most urgent first: opponent, your color, whether it's your turn and time left. Needs the token.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"count":{"type":"integer","minimum":1,"maximum":50,"default":10}}}`)},
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
	if c.Username != "" && !userRe.MatchString(c.Username) {
		return errors.New("a Lichess username is 2 to 30 letters, digits, - and _")
	}
	if c.Token != "" && !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the Lichess token in the vault and enter its secret:// reference")
	}
	if c.Username == "" && c.Token == "" {
		return errors.New("enter your Lichess username, or a token")
	}
	base := m.Base
	if base == "" {
		base = "https://lichess.org"
	}
	var auth func(context.Context, *http.Request) error
	if ref := c.Token; ref != "" {
		auth = func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, ref)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
			return nil
		}
	}
	api := rest.New(base, auth)
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
	m.set.Put(id, &conn{api: api, username: strings.ToLower(c.Username), token: c.Token != "", sleep: sleep})
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

// pause is how long to wait after a 429: Retry-After when given, else the
// full minute Lichess asks for, never more.
func pause(h http.Header) time.Duration {
	if h != nil {
		v := strings.TrimSpace(h.Get("Retry-After"))
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n < 60 {
			return time.Duration(n) * time.Second
		}
		if t, err := http.ParseTime(v); err == nil {
			return min(max(time.Until(t), 0), time.Minute)
		}
	}
	return time.Minute
}

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Lichess refused the token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the Lichess token isn't allowed to read this")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Lichess is limiting requests; wait a minute and try again")
	case errors.Is(err, rest.ErrCrossHostRedirect):
		return errors.New("Lichess redirected to another host; refused")
	}
	return err
}

// call runs one request in the shared slot, and once more after a 429.
func (c *conn) call(ctx context.Context, do func() (http.Header, error)) error {
	select {
	case slot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-slot }()
	hdr, err := do()
	if rest.IsStatus(err, http.StatusTooManyRequests) {
		if err := c.sleep(ctx, pause(hdr)); err != nil {
			return err
		}
		_, err = do()
	}
	return friendly(err)
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	return c.call(ctx, func() (http.Header, error) {
		return c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	})
}

type perf struct {
	Games  int  `json:"games"`
	Rating int  `json:"rating"`
	RD     int  `json:"rd"`
	Prog   int  `json:"prog"`
	Prov   bool `json:"prov"`
	Rank   int  `json:"rank"`
	Runs   int  `json:"runs"`
	Score  int  `json:"score"`
}

type user struct {
	ID        string          `json:"id"`
	Username  string          `json:"username"`
	Title     string          `json:"title"`
	Perfs     map[string]perf `json:"perfs"`
	CreatedAt int64           `json:"createdAt"`
	SeenAt    int64           `json:"seenAt"`
	Disabled  bool            `json:"disabled"`
	TOS       bool            `json:"tosViolation"`
	Patron    bool            `json:"patron"`
	Verified  bool            `json:"verified"`
	Streaming bool            `json:"streaming"`
	PlayTime  *struct {
		Total int `json:"total"`
		TV    int `json:"tv"`
	} `json:"playTime"`
	Count *struct {
		All     int `json:"all"`
		Rated   int `json:"rated"`
		Win     int `json:"win"`
		Loss    int `json:"loss"`
		Draw    int `json:"draw"`
		Playing int `json:"playing"`
	} `json:"count"`
	// The profile (bio, real name, location, links) isn't decoded.
}

func (c *conn) user(ctx context.Context, name string) (user, error) {
	var u user
	var err error
	if name == "" {
		err = c.get(ctx, "/api/account", nil, &u)
	} else {
		err = c.get(ctx, "/api/user/"+url.PathEscape(name), nil, &u)
		if isNotFound(err) {
			return u, fmt.Errorf("Lichess has no player named %s", name)
		}
	}
	if err != nil {
		return u, err
	}
	if !userRe.MatchString(u.Username) {
		return u, errors.New("unexpected answer from Lichess")
	}
	return u, nil
}

func isNotFound(err error) bool { return rest.IsStatus(err, http.StatusNotFound) }

// me is the default player: the configured one, else the token's account.
func (c *conn) me(ctx context.Context) (string, error) {
	if c.username != "" {
		return c.username, nil
	}
	u, err := c.user(ctx, "")
	if err != nil {
		return "", err
	}
	return strings.ToLower(u.Username), nil
}

func when(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

func profileOut(u user) map[string]any {
	out := map[string]any{"username": u.Username, "url": "https://lichess.org/@/" + url.PathEscape(u.Username)}
	if u.Title != "" {
		out["title"] = u.Title
	}
	if s := when(u.CreatedAt); s != "" {
		out["joined"] = s
	}
	if s := when(u.SeenAt); s != "" {
		out["lastSeen"] = s
	}
	if u.Disabled {
		out["closed"] = true
	}
	if u.TOS {
		out["tosViolation"] = true
	}
	if u.Patron {
		out["patron"] = true
	}
	if u.Verified {
		out["verified"] = true
	}
	if u.Streaming {
		out["streaming"] = true
	}
	if u.PlayTime != nil {
		out["hoursPlayed"] = float64(u.PlayTime.Total/360) / 10
	}
	if u.Count != nil {
		out["games"] = map[string]int{"all": u.Count.All, "rated": u.Count.Rated, "win": u.Count.Win, "loss": u.Count.Loss, "draw": u.Count.Draw, "playing": u.Count.Playing}
	}
	ratings, puzzles := map[string]any{}, map[string]any{}
	for k, p := range u.Perfs {
		switch {
		case k == "storm" || k == "racer" || k == "streak":
			if p.Runs > 0 {
				puzzles[k] = map[string]int{"runs": p.Runs, "best": p.Score}
			}
		case p.Rating > 0:
			r := map[string]any{"rating": p.Rating, "games": p.Games, "progress": p.Prog, "deviation": p.RD}
			if p.Prov {
				r["provisional"] = true
			}
			if p.Rank > 0 {
				r["rank"] = p.Rank
			}
			ratings[k] = r
		}
	}
	out["ratings"] = ratings
	if len(puzzles) > 0 {
		out["puzzleModes"] = puzzles
	}
	return out
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	name := ""
	if !c.token {
		name = c.username
	}
	u, err := c.user(ctx, name)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if c.token && c.username != "" && !strings.EqualFold(u.Username, c.username) {
		return sdk.Health{Status: "degraded", Message: "the token belongs to " + u.Username + ", not " + c.username}
	}
	return sdk.Health{Status: "ok", Message: u.Username}
}

type input struct {
	Username string `json:"username"`
	Count    int    `json:"count"`
	Days     int    `json:"days"`
	PerfType string `json:"perfType"`
	Rated    *bool  `json:"rated"`
}

type side struct {
	User *struct {
		Name  string `json:"name"`
		Title string `json:"title"`
	} `json:"user"`
	Rating     int  `json:"rating"`
	RatingDiff *int `json:"ratingDiff"`
	AILevel    int  `json:"aiLevel"`
	Analysis   *struct {
		Accuracy int `json:"accuracy"`
	} `json:"analysis"`
}

func (s side) name() string {
	if s.User != nil {
		return s.User.Name
	}
	if s.AILevel > 0 {
		return fmt.Sprintf("Stockfish level %d", s.AILevel)
	}
	return "anonymous"
}

type game struct {
	ID         string `json:"id"`
	Rated      bool   `json:"rated"`
	Variant    string `json:"variant"`
	Speed      string `json:"speed"`
	Perf       string `json:"perf"`
	CreatedAt  int64  `json:"createdAt"`
	LastMoveAt int64  `json:"lastMoveAt"`
	Status     string `json:"status"`
	Winner     string `json:"winner"`
	Players    struct {
		White side `json:"white"`
		Black side `json:"black"`
	} `json:"players"`
	Opening *struct {
		ECO  string `json:"eco"`
		Name string `json:"name"`
	} `json:"opening"`
	Clock *struct {
		Initial   int `json:"initial"`
		Increment int `json:"increment"`
	} `json:"clock"`
	// Moves, PGN, clocks and analysis aren't requested or decoded.
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
	case "profile", "games", "ongoing":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	p.Username = strings.TrimSpace(p.Username)
	if p.Username != "" && !userRe.MatchString(p.Username) {
		return sdk.Result{}, errors.New("a Lichess username is 2 to 30 letters, digits, - and _")
	}
	if p.Count == 0 {
		p.Count = 10
	}
	if p.Count < 1 || p.Count > 50 {
		return sdk.Result{}, errors.New("count is 1 to 50")
	}
	if p.Days < 0 || p.Days > 365 {
		return sdk.Result{}, errors.New("days is 1 to 365")
	}
	if p.PerfType != "" && !perfs[p.PerfType] {
		return sdk.Result{}, errors.New("perfType is one of ultraBullet, bullet, blitz, rapid, classical, correspondence, chess960 or a variant such as atomic")
	}
	if call.Action == "ongoing" && !c.token {
		return sdk.Result{}, errors.New("ongoing games need a Lichess token in the settings")
	}
	name := strings.ToLower(p.Username)

	switch call.Action {
	case "profile":
		if name == "" && !c.token {
			name = c.username
		}
		u, err := c.user(ctx, name)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(profileOut(u))

	case "games":
		if name == "" {
			if name, err = c.me(ctx); err != nil {
				return sdk.Result{}, err
			}
		}
		q := url.Values{"max": {strconv.Itoa(p.Count)}, "moves": {"false"}, "pgnInJson": {"false"}, "tags": {"false"}, "clocks": {"false"},
			"evals": {"false"}, "opening": {"true"}, "accuracy": {"true"}, "literate": {"false"}}
		if p.Days > 0 {
			q.Set("since", strconv.FormatInt(time.Now().Add(-time.Duration(p.Days)*24*time.Hour).UnixMilli(), 10))
		}
		if p.PerfType != "" {
			q.Set("perfType", p.PerfType)
		}
		if p.Rated != nil {
			q.Set("rated", strconv.FormatBool(*p.Rated))
		}
		var games []game
		err := c.call(ctx, func() (http.Header, error) {
			games = nil
			res, err := c.api.Send(ctx, http.MethodGet, "/api/games/user/"+url.PathEscape(name), q, nil,
				http.Header{"Accept": {"application/x-ndjson"}, "User-Agent": {userAgent}})
			if err != nil {
				return nil, err
			}
			defer res.Body.Close()
			sc := bufio.NewScanner(io.LimitReader(res.Body, 4<<20))
			sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
			for sc.Scan() && len(games) < p.Count {
				var g game
				if json.Unmarshal(sc.Bytes(), &g) == nil && idRe.MatchString(g.ID) {
					games = append(games, g)
				}
			}
			if err := sc.Err(); err != nil {
				return nil, errors.New("Lichess's answer was cut off")
			}
			return res.Header, nil
		})
		if isNotFound(err) {
			return sdk.Result{}, fmt.Errorf("Lichess has no player named %s", name)
		}
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		tally := map[string]int{"win": 0, "loss": 0, "draw": 0}
		for _, g := range games {
			white, black := g.Players.White, g.Players.Black
			me, opp, color := white, black, "white"
			if black.User != nil && strings.EqualFold(black.User.Name, name) {
				me, opp, color = black, white, "black"
			}
			res := "draw"
			switch {
			case g.Winner == color:
				res = "win"
			case g.Winner != "":
				res = "loss"
			case g.Status == "started" || g.Status == "created":
				res = "ongoing"
			case g.Status == "aborted" || g.Status == "noStart":
				res = "aborted"
			}
			if _, ok := tally[res]; ok {
				tally[res]++
			}
			row := map[string]any{"id": g.ID, "url": "https://lichess.org/" + g.ID, "played": when(g.CreatedAt), "rated": g.Rated, "speed": g.Speed, "perf": g.Perf,
				"color": color, "opponent": opp.name(), "result": res, "status": g.Status}
			if g.Variant != "" && g.Variant != "standard" {
				row["variant"] = g.Variant
			}
			if me.Rating > 0 {
				row["rating"] = me.Rating
			}
			if me.RatingDiff != nil {
				row["ratingDiff"] = *me.RatingDiff
			}
			if opp.Rating > 0 {
				row["opponentRating"] = opp.Rating
			}
			if opp.User != nil && opp.User.Title != "" {
				row["opponentTitle"] = opp.User.Title
			}
			if me.Analysis != nil && me.Analysis.Accuracy > 0 {
				row["accuracy"] = me.Analysis.Accuracy
			}
			if g.Opening != nil && g.Opening.Name != "" {
				row["opening"] = g.Opening.Name
				row["eco"] = g.Opening.ECO
			}
			if g.Clock != nil {
				row["timeControl"] = fmt.Sprintf("%d+%d", g.Clock.Initial, g.Clock.Increment)
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"username": name, "games": out, "results": tally})

	case "ongoing":
		var r struct {
			MyTurn  int `json:"nbMyTurn"`
			Playing []struct {
				GameID  string `json:"gameId"`
				Color   string `json:"color"`
				Variant struct {
					Key string `json:"key"`
				} `json:"variant"`
				Speed    string `json:"speed"`
				Perf     string `json:"perf"`
				Rated    bool   `json:"rated"`
				Rating   int    `json:"rating"`
				HasMoved bool   `json:"hasMoved"`
				Opponent struct {
					Username string `json:"username"`
					Rating   int    `json:"rating"`
					AI       int    `json:"ai"`
				} `json:"opponent"`
				MyTurn      bool `json:"isMyTurn"`
				SecondsLeft *int `json:"secondsLeft"`
				// fullId (which lets its holder make moves) isn't decoded.
			} `json:"nowPlaying"`
		}
		if err := c.get(ctx, "/api/account/playing", url.Values{"nb": {strconv.Itoa(p.Count)}}, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, g := range r.Playing {
			if !idRe.MatchString(g.GameID) || len(out) >= p.Count {
				continue
			}
			opp := g.Opponent.Username
			if g.Opponent.AI > 0 {
				opp = fmt.Sprintf("Stockfish level %d", g.Opponent.AI)
			}
			row := map[string]any{"id": g.GameID, "url": "https://lichess.org/" + g.GameID, "color": g.Color, "opponent": opp, "myTurn": g.MyTurn,
				"speed": g.Speed, "perf": g.Perf, "rated": g.Rated}
			if g.Opponent.Rating > 0 {
				row["opponentRating"] = g.Opponent.Rating
			}
			if g.Rating > 0 {
				row["rating"] = g.Rating
			}
			if g.SecondsLeft != nil {
				row["secondsLeft"] = *g.SecondsLeft
			}
			if g.Variant.Key != "" && g.Variant.Key != "standard" {
				row["variant"] = g.Variant.Key
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"myTurn": r.MyTurn, "games": out})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
