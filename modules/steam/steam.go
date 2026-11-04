// Package steam reads a Steam account through the Steam Web API with an API
// key: the profile, friends and what they're playing, recently played games,
// achievements and how many people are playing a game. It's read-only. The
// games module covers the local launchers and the owned-games list with
// hours; this one is the online, social side.
package steam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Config is one Steam account.
type Config struct {
	APIKey  string `json:"apiKey"`  // secret:// Steam Web API key
	SteamID string `json:"steamId"` // 64-bit id
}

type conn struct {
	key, id string
	host    sdk.Host
	http    *http.Client
	api     string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// API replaces https://api.steampowered.com and HTTP the client (tests).
	API  string
	HTTP *http.Client
}

// New returns the Steam module.
func New() *Module { return &Module{} }

var steamIDRe = regexp.MustCompile(`^7656119[0-9]{10}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "steam", Name: "Steam", Version: "0.1.0", Category: "Gaming", Icon: "gamepad",
		Description: "Your Steam profile, which friends are online and what they play, recent games, achievements and player counts.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey","steamId"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"Steam Web API key (steamcommunity.com/dev/apikey). It only reads"},
			"steamId":{"type":"string","description":"Your 64-bit Steam id (17 digits, starts with 7656119)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "profile", Title: "Profile", Description: "Your name, status, what you're playing, Steam level and owned games count.", Risk: sdk.RiskRead},
			{Name: "friends", Title: "Friends", Description: "Friends with their online status and current game, playing first. It names other people, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"onlineOnly":{"type":"boolean","default":false}}}`)},
			{Name: "recent", Title: "Recently played", Description: "Games played in the last two weeks with hours.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"count":{"type":"integer","minimum":1,"maximum":50,"default":10}}}`)},
			{Name: "owned_count", Title: "Owned games count", Description: "How many games the account owns (the games module lists them with hours).", Risk: sdk.RiskRead},
			{Name: "achievements", Title: "Achievements", Description: "Your achievements in one game: progress, the latest unlocked and what's left.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["appId"],"properties":{"appId":{"type":"integer","minimum":1,"description":"Steam app id, e.g. 570 for Dota 2"}}}`)},
			{Name: "player_count", Title: "Players right now", Description: "How many people are playing a game on Steam right now.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["appId"],"properties":{"appId":{"type":"integer","minimum":1}}}`)},
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
		return errors.New("store the Steam Web API key in the vault and enter its secret:// reference")
	}
	c.SteamID = strings.TrimSpace(c.SteamID)
	if !steamIDRe.MatchString(c.SteamID) {
		return errors.New("the Steam id is the 64-bit one: 17 digits starting with 7656119 (shown in your profile's address or on steamid.io)")
	}
	cl := m.HTTP
	if cl == nil {
		cl = sdk.HTTPClient(h, 20*time.Second)
	}
	api := m.API
	if api == "" {
		api = "https://api.steampowered.com"
	}
	// The key travels in the query string; never follow it elsewhere.
	m.set.Put(id, &conn{key: c.APIKey, id: c.SteamID, host: h, http: rest.SameHostOnly(cl), api: strings.TrimRight(api, "/")})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// errKey is a refused API key.
var errKey = errors.New("Steam refused the API key")

// errPrivate is a profile whose details aren't public.
var errPrivate = errors.New("that part of the Steam profile is private (Edit profile, Privacy settings)")

// get calls one Web API method. Errors never carry the request URL, which
// holds the key.
func (c *conn) get(ctx context.Context, method string, q url.Values, out any) error {
	key, err := c.host.Secret(ctx, c.key)
	if err != nil {
		return err
	}
	if q == nil {
		q = url.Values{}
	}
	q.Set("key", strings.TrimSpace(key))
	q.Set("format", "json")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.api+"/"+method+"/?"+q.Encode(), nil)
	if err != nil {
		return errors.New("couldn't build the Steam request")
	}
	req.Header.Set("User-Agent", "Conduit")
	res, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) && errors.Is(ue.Err, rest.ErrCrossHostRedirect) {
			return errors.New("Steam redirected to another host; refused")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("couldn't reach Steam")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return errors.New("Steam's answer was cut off")
	}
	switch {
	case res.StatusCode == http.StatusForbidden:
		return errKey
	case res.StatusCode == http.StatusUnauthorized:
		return errPrivate
	case res.StatusCode == http.StatusTooManyRequests:
		return errors.New("Steam is rate limiting this key; try again in a few minutes")
	case res.StatusCode >= 300 && res.StatusCode != http.StatusBadRequest:
		return fmt.Errorf("Steam answered %s", res.Status)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		if res.StatusCode == http.StatusBadRequest {
			return errors.New("Steam refused the request")
		}
		return errors.New("unexpected answer from Steam")
	}
	return nil
}

type player struct {
	SteamID    string `json:"steamid"`
	Name       string `json:"personaname"`
	ProfileURL string `json:"profileurl"`
	Avatar     string `json:"avatarfull"`
	State      int    `json:"personastate"`
	Visibility int    `json:"communityvisibilitystate"`
	LastLogoff int64  `json:"lastlogoff"`
	Created    int64  `json:"timecreated"`
	Game       string `json:"gameextrainfo"`
	GameID     string `json:"gameid"`
	Country    string `json:"loccountrycode"`
}

var personaStates = []string{"offline", "online", "busy", "away", "snooze", "looking to trade", "looking to play"}

func (p player) status() string {
	if p.State >= 0 && p.State < len(personaStates) {
		return personaStates[p.State]
	}
	return "unknown"
}

func (c *conn) summaries(ctx context.Context, ids []string) ([]player, error) {
	var out []player
	for i := 0; i < len(ids); i += 100 {
		end := min(i+100, len(ids))
		var r struct {
			Response struct {
				Players []player `json:"players"`
			} `json:"response"`
		}
		if err := c.get(ctx, "ISteamUser/GetPlayerSummaries/v2", url.Values{"steamids": {strings.Join(ids[i:end], ",")}}, &r); err != nil {
			return nil, err
		}
		out = append(out, r.Response.Players...)
	}
	return out, nil
}

func (c *conn) me(ctx context.Context) (player, error) {
	ps, err := c.summaries(ctx, []string{c.id})
	if err != nil {
		return player{}, err
	}
	if len(ps) == 0 {
		return player{}, errors.New("Steam doesn't know that Steam id")
	}
	return ps[0], nil
}

func (c *conn) ownedCount(ctx context.Context) (int, bool, error) {
	var r struct {
		Response struct {
			Count *int `json:"game_count"`
		} `json:"response"`
	}
	if err := c.get(ctx, "IPlayerService/GetOwnedGames/v1", url.Values{"steamid": {c.id}, "include_played_free_games": {"1"}}, &r); err != nil {
		return 0, false, err
	}
	if r.Response.Count == nil {
		return 0, false, nil // game details are private
	}
	return *r.Response.Count, true, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	p, err := c.me(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if p.Visibility != 3 {
		return sdk.Health{Status: "degraded", Message: p.Name + " · the profile is private, so friends and games can't be read"}
	}
	return sdk.Health{Status: "ok", Message: p.Name + " · " + p.status()}
}

func when(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

type input struct {
	OnlineOnly bool  `json:"onlineOnly"`
	Count      int   `json:"count"`
	AppID      int64 `json:"appId"`
}

func hours(minutes int) float64 { return float64(minutes/6) / 10 }

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
	case "achievements", "player_count":
		if p.AppID < 1 || p.AppID > 1<<31-1 {
			return sdk.Result{}, errors.New("enter the game's Steam app id, a positive number")
		}
	case "recent":
		if p.Count == 0 {
			p.Count = 10
		}
		if p.Count < 1 || p.Count > 50 {
			return sdk.Result{}, errors.New("count is 1 to 50")
		}
	}
	appID := strconv.FormatInt(p.AppID, 10)

	switch call.Action {
	case "profile":
		me, err := c.me(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"steamId": me.SteamID, "name": me.Name, "profileUrl": me.ProfileURL, "status": me.status(), "public": me.Visibility == 3}
		if me.Game != "" {
			out["playing"], out["playingAppId"] = me.Game, me.GameID
		}
		if me.Country != "" {
			out["country"] = me.Country
		}
		if s := when(me.Created); s != "" {
			out["created"] = s
		}
		if s := when(me.LastLogoff); s != "" && me.State == 0 {
			out["lastOnline"] = s
		}
		var lvl struct {
			Response struct {
				Level *int `json:"player_level"`
			} `json:"response"`
		}
		if c.get(ctx, "IPlayerService/GetSteamLevel/v1", url.Values{"steamid": {c.id}}, &lvl) == nil && lvl.Response.Level != nil {
			out["level"] = *lvl.Response.Level
		}
		if n, ok, err := c.ownedCount(ctx); err == nil && ok {
			out["ownedGames"] = n
		}
		return sdk.JSON(out)

	case "friends":
		var fl struct {
			List struct {
				Friends []struct {
					SteamID string `json:"steamid"`
					Since   int64  `json:"friend_since"`
				} `json:"friends"`
			} `json:"friendslist"`
		}
		if err := c.get(ctx, "ISteamUser/GetFriendList/v1", url.Values{"steamid": {c.id}, "relationship": {"friend"}}, &fl); err != nil {
			return sdk.Result{}, err
		}
		since := map[string]int64{}
		var ids []string
		for _, f := range fl.List.Friends {
			if steamIDRe.MatchString(f.SteamID) && len(ids) < 2000 {
				ids = append(ids, f.SteamID)
				since[f.SteamID] = f.Since
			}
		}
		ps, err := c.summaries(ctx, ids)
		if err != nil {
			return sdk.Result{}, err
		}
		rank := func(p player) int {
			switch {
			case p.Game != "":
				return 0
			case p.State != 0:
				return 1
			}
			return 2
		}
		sort.SliceStable(ps, func(i, j int) bool {
			if a, b := rank(ps[i]), rank(ps[j]); a != b {
				return a < b
			}
			return strings.ToLower(ps[i].Name) < strings.ToLower(ps[j].Name)
		})
		out := []map[string]any{}
		online, playing := 0, 0
		for _, f := range ps {
			if f.State != 0 {
				online++
			}
			if f.Game != "" {
				playing++
			}
			if p.OnlineOnly && f.State == 0 {
				continue
			}
			row := map[string]any{"steamId": f.SteamID, "name": f.Name, "status": f.status()}
			if f.Game != "" {
				row["playing"], row["appId"] = f.Game, f.GameID
			}
			if s := when(f.LastLogoff); s != "" && f.State == 0 {
				row["lastOnline"] = s
			}
			if s := when(since[f.SteamID]); s != "" {
				row["friendSince"] = s
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"total": len(ps), "online": online, "playing": playing, "friends": out})

	case "recent":
		var r struct {
			Response struct {
				Total int `json:"total_count"`
				Games []struct {
					AppID   int    `json:"appid"`
					Name    string `json:"name"`
					Recent  int    `json:"playtime_2weeks"`
					Forever int    `json:"playtime_forever"`
				} `json:"games"`
			} `json:"response"`
		}
		if err := c.get(ctx, "IPlayerService/GetRecentlyPlayedGames/v1", url.Values{"steamid": {c.id}, "count": {strconv.Itoa(p.Count)}}, &r); err != nil {
			return sdk.Result{}, err
		}
		games := []map[string]any{}
		for _, g := range r.Response.Games {
			games = append(games, map[string]any{"appId": g.AppID, "name": g.Name, "lastTwoWeeks": hours(g.Recent), "hours": hours(g.Forever)})
		}
		return sdk.JSON(map[string]any{"total": r.Response.Total, "games": games})

	case "owned_count":
		n, ok, err := c.ownedCount(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if !ok {
			return sdk.Result{}, errPrivate
		}
		return sdk.JSON(map[string]any{"ownedGames": n})

	case "achievements":
		var r struct {
			Stats struct {
				Game    string `json:"gameName"`
				Success bool   `json:"success"`
				Error   string `json:"error"`
				List    []struct {
					API         string `json:"apiname"`
					Achieved    int    `json:"achieved"`
					Unlock      int64  `json:"unlocktime"`
					Name        string `json:"name"`
					Description string `json:"description"`
				} `json:"achievements"`
			} `json:"playerstats"`
		}
		if err := c.get(ctx, "ISteamUserStats/GetPlayerAchievements/v1", url.Values{"steamid": {c.id}, "appid": {appID}, "l": {"english"}}, &r); err != nil {
			return sdk.Result{}, err
		}
		if !r.Stats.Success {
			msg := "Steam has no achievements for that game on this account"
			if r.Stats.Error != "" {
				msg += ": " + rest.Redact(r.Stats.Error)
			}
			return sdk.Result{}, errors.New(msg)
		}
		type ach struct {
			Name        string `json:"name"`
			Description string `json:"description,omitempty"`
			Unlocked    string `json:"unlocked,omitempty"`
			unix        int64
		}
		var done, left []ach
		for _, a := range r.Stats.List {
			name := a.Name
			if name == "" {
				name = a.API
			}
			if a.Achieved == 1 {
				done = append(done, ach{Name: name, Description: a.Description, Unlocked: when(a.Unlock), unix: a.Unlock})
			} else {
				left = append(left, ach{Name: name, Description: a.Description})
			}
		}
		sort.SliceStable(done, func(i, j int) bool { return done[i].unix > done[j].unix })
		total := len(done) + len(left)
		out := map[string]any{"appId": p.AppID, "game": r.Stats.Game, "unlocked": len(done), "total": total}
		if total > 0 {
			out["percent"] = len(done) * 100 / total
		}
		if len(done) > 20 {
			done = done[:20]
		}
		if len(left) > 100 {
			left = left[:100]
		}
		out["latest"], out["remaining"] = nonNil(done), nonNil(left)
		return sdk.JSON(out)

	case "player_count":
		var r struct {
			Response struct {
				Count  int `json:"player_count"`
				Result int `json:"result"`
			} `json:"response"`
		}
		if err := c.get(ctx, "ISteamUserStats/GetNumberOfCurrentPlayers/v1", url.Values{"appid": {appID}}, &r); err != nil {
			return sdk.Result{}, err
		}
		if r.Response.Result != 1 {
			return sdk.Result{}, fmt.Errorf("Steam has no player count for app %s", appID)
		}
		return sdk.JSON(map[string]any{"appId": p.AppID, "players": r.Response.Count})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
