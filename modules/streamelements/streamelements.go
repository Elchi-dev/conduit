// Package streamelements reads a StreamElements channel with its JWT
// token: the activity feed (tips, follows, subs, cheers, raids), the
// loyalty points leaderboard and the chat bot's commands. It's read-only.
package streamelements

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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one StreamElements channel.
type Config struct {
	Token     string `json:"token"`     // secret:// JWT from the dashboard
	ChannelID string `json:"channelId"` // optional; the token's own channel by default
}

type conn struct {
	cfg Config
	api *rest.Client

	mu      sync.Mutex
	channel string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://api.streamelements.com/kappa/v2 and HTTP the
	// client (tests); they aren't settings.
	Base string
	HTTP *http.Client
}

// New returns the StreamElements module.
func New() *Module { return &Module{} }

var (
	channelRe = regexp.MustCompile(`^[a-f0-9]{24}$`)
	jwtRe     = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	// activityTypes are the feed's types Conduit asks for.
	activityTypes = []string{"follow", "tip", "subscriber", "cheer", "raid", "host", "redemption", "merch", "superchat", "sponsor"}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	types := `"` + strings.Join(activityTypes, `","`) + `"`
	return sdk.Manifest{
		ID: "streamelements", Name: "StreamElements", Version: "0.1.0", Category: "Gaming", Icon: "bell",
		Description: "Your StreamElements activity feed (tips, follows, subs), loyalty leaderboard and chat bot commands.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"JWT token: streamelements.com, your avatar, Account, Channels, Show secrets"},
			"channelId":{"type":"string","description":"Optional: the account ID shown next to the token; the token's own channel by default"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "activities", Title: "Recent activity", Description: "Tips, follows, subs, cheers and raids, newest first, with names, amounts and messages. They name viewers and quote them, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"types":{"type":"array","items":{"type":"string","enum":[` + types + `]}},"days":{"type":"integer","minimum":1,"maximum":30,"default":7},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "leaderboard", Title: "Loyalty leaderboard", Description: "Viewers with the most loyalty points now, of all time, or the most watch time. It lists viewers, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"kind":{"type":"string","enum":["points","alltime","watchtime"],"default":"points"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":10}}}`)},
			{Name: "commands", Title: "Bot commands", Description: "The chat bot's custom commands with their replies, cooldowns and who may use them.", Risk: sdk.RiskRead},
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
		return errors.New("store the JWT token in the vault and enter its secret:// reference")
	}
	c.ChannelID = strings.TrimSpace(c.ChannelID)
	if c.ChannelID != "" && !channelRe.MatchString(c.ChannelID) {
		return errors.New("the account ID is 24 hexadecimal characters")
	}
	cl := m.HTTP
	if cl == nil {
		cl = sdk.HTTPClient(h, 20*time.Second)
	}
	base := m.Base
	if base == "" {
		base = "https://api.streamelements.com/kappa/v2"
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		tok, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		tok = strings.TrimPrefix(strings.TrimSpace(tok), "Bearer ")
		if !jwtRe.MatchString(tok) {
			return errors.New("the stored token isn't a JWT; copy the JWT token (not the overlay token) from the StreamElements dashboard")
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		return nil
	})
	api.HTTP = rest.SameHostOnly(cl)
	m.set.Put(id, &conn{cfg: c, api: api, channel: c.ChannelID})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	if rest.IsStatus(err, http.StatusUnauthorized) {
		return &rest.Error{Status: http.StatusUnauthorized, Message: "StreamElements refused the JWT token; copy a fresh one from the dashboard"}
	}
	return err
}

type me struct {
	ID          string `json:"_id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Provider    string `json:"provider"`
}

func (c *conn) me(ctx context.Context) (me, error) {
	var out me
	if _, err := c.api.Do(ctx, "GET", "/channels/me", nil, nil, &out); err != nil {
		return me{}, friendly(err)
	}
	if !channelRe.MatchString(out.ID) {
		return me{}, errors.New("StreamElements didn't name the token's channel")
	}
	return out, nil
}

func (c *conn) channelID(ctx context.Context) (string, error) {
	c.mu.Lock()
	id := c.channel
	c.mu.Unlock()
	if id != "" {
		return id, nil
	}
	m, err := c.me(ctx)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.channel = m.ID
	c.mu.Unlock()
	return m.ID, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	who, err := c.me(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	name := who.DisplayName
	if name == "" {
		name = who.Username
	}
	if who.Provider != "" {
		name += " (" + who.Provider + ")"
	}
	return sdk.Health{Status: "ok", Message: name}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Types []string `json:"types"`
		Days  int      `json:"days"`
		Limit int      `json:"limit"`
		Kind  string   `json:"kind"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	limit := func(def int) (int, error) {
		if p.Limit == 0 {
			return def, nil
		}
		if p.Limit < 1 || p.Limit > 100 {
			return 0, errors.New("limit is 1 to 100")
		}
		return p.Limit, nil
	}
	switch call.Action {
	case "activities":
		n, err := limit(25)
		if err != nil {
			return sdk.Result{}, err
		}
		days := p.Days
		if days == 0 {
			days = 7
		}
		if days < 1 || days > 30 {
			return sdk.Result{}, errors.New("days is 1 to 30")
		}
		types := p.Types
		if len(types) == 0 {
			types = activityTypes
		}
		for _, t := range types {
			if !contains(activityTypes, t) {
				return sdk.Result{}, fmt.Errorf("%q isn't an activity type (%s)", t, strings.Join(activityTypes, ", "))
			}
		}
		ch, err := c.channelID(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		now := time.Now().UTC()
		q := url.Values{"after": {now.AddDate(0, 0, -days).Format(time.RFC3339)}, "before": {now.Format(time.RFC3339)},
			"limit": {strconv.Itoa(n)}, "origin": {"feed"}, "mincheer": {"0"}, "minhost": {"0"}, "minsub": {"0"}, "mintip": {"0"}, "types": types}
		var out []struct {
			Type      string    `json:"type"`
			Provider  string    `json:"provider"`
			CreatedAt time.Time `json:"createdAt"`
			Data      struct {
				Username    string   `json:"username"`
				DisplayName string   `json:"displayName"`
				Amount      *float64 `json:"amount"`
				Currency    string   `json:"currency"`
				Message     string   `json:"message"`
				Tier        string   `json:"tier"`
				Quantity    int      `json:"quantity"`
				Gifted      bool     `json:"gifted"`
				Sender      string   `json:"sender"`
				Item        string   `json:"redemption"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, "GET", "/activities/"+ch, q, nil, &out); err != nil {
			return sdk.Result{}, friendly(err)
		}
		type row struct {
			Type     string    `json:"type"`
			Name     string    `json:"name"`
			Amount   *float64  `json:"amount,omitempty"`
			Currency string    `json:"currency,omitempty"`
			Tier     string    `json:"tier,omitempty"`
			Quantity int       `json:"quantity,omitempty"`
			Gifted   bool      `json:"gifted,omitempty"`
			From     string    `json:"from,omitempty"`
			Message  string    `json:"message,omitempty"`
			Item     string    `json:"item,omitempty"`
			Provider string    `json:"provider,omitempty"`
			At       time.Time `json:"at"`
		}
		rows := []row{}
		for _, a := range out {
			name := a.Data.DisplayName
			if name == "" {
				name = a.Data.Username
			}
			rows = append(rows, row{Type: a.Type, Name: name, Amount: a.Data.Amount, Currency: a.Data.Currency, Tier: a.Data.Tier, Quantity: a.Data.Quantity,
				Gifted: a.Data.Gifted, From: a.Data.Sender, Message: a.Data.Message, Item: a.Data.Item, Provider: a.Provider, At: a.CreatedAt})
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].At.After(rows[j].At) })
		return sdk.JSON(rows)

	case "leaderboard":
		n, err := limit(10)
		if err != nil {
			return sdk.Result{}, err
		}
		kind := p.Kind
		if kind == "" {
			kind = "points"
		}
		path := map[string]string{"points": "top", "alltime": "alltime", "watchtime": "watchtime"}[kind]
		if path == "" {
			return sdk.Result{}, errors.New("kind is points, alltime or watchtime")
		}
		ch, err := c.channelID(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var out struct {
			Total int `json:"_total"`
			Users []struct {
				Username string `json:"username"`
				Points   *int64 `json:"points"`
				Minutes  *int64 `json:"minutes"`
			} `json:"users"`
		}
		if _, err := c.api.Do(ctx, "GET", "/points/"+ch+"/"+path, url.Values{"limit": {strconv.Itoa(n)}, "offset": {"0"}}, nil, &out); err != nil {
			return sdk.Result{}, friendly(err)
		}
		type row struct {
			Rank     int    `json:"rank"`
			Username string `json:"username"`
			Points   *int64 `json:"points,omitempty"`
			Minutes  *int64 `json:"minutes,omitempty"`
		}
		rows := []row{}
		for i, u := range out.Users {
			rows = append(rows, row{Rank: i + 1, Username: u.Username, Points: u.Points, Minutes: u.Minutes})
		}
		return sdk.JSON(map[string]any{"kind": kind, "total": out.Total, "users": rows})

	case "commands":
		ch, err := c.channelID(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var out []struct {
			Command  string   `json:"command"`
			Reply    string   `json:"reply"`
			Enabled  bool     `json:"enabled"`
			Aliases  []string `json:"aliases"`
			Access   int      `json:"accessLevel"`
			Cost     int      `json:"cost"`
			Online   *bool    `json:"enabledOnline"`
			Offline  *bool    `json:"enabledOffline"`
			Cooldown struct {
				User   int `json:"user"`
				Global int `json:"global"`
			} `json:"cooldown"`
		}
		if _, err := c.api.Do(ctx, "GET", "/bot/commands/"+ch, nil, nil, &out); err != nil {
			return sdk.Result{}, friendly(err)
		}
		type row struct {
			Command  string   `json:"command"`
			Reply    string   `json:"reply"`
			Enabled  bool     `json:"enabled"`
			Aliases  []string `json:"aliases,omitempty"`
			Access   string   `json:"access"`
			Cost     int      `json:"cost,omitempty"`
			Cooldown string   `json:"cooldown,omitempty"`
			When     string   `json:"when,omitempty"`
		}
		rows := []row{}
		for _, cm := range out {
			r := row{Command: "!" + strings.TrimPrefix(cm.Command, "!"), Reply: rest.Redact(cm.Reply), Enabled: cm.Enabled, Aliases: cm.Aliases, Access: access(cm.Access), Cost: cm.Cost}
			if cm.Cooldown.User > 0 || cm.Cooldown.Global > 0 {
				r.Cooldown = fmt.Sprintf("%ds per user, %ds global", cm.Cooldown.User, cm.Cooldown.Global)
			}
			if cm.Online != nil && cm.Offline != nil && *cm.Online != *cm.Offline {
				r.When = map[bool]string{true: "online only", false: "offline only"}[*cm.Online]
			}
			rows = append(rows, r)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Command < rows[j].Command })
		return sdk.JSON(rows)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// access names StreamElements' access levels.
func access(level int) string {
	switch {
	case level >= 1500:
		return "broadcaster"
	case level >= 1000:
		return "super moderator"
	case level >= 500:
		return "moderator"
	case level >= 400:
		return "VIP"
	case level >= 300:
		return "subscriber"
	case level >= 250:
		return "regular"
	default:
		return "everyone"
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
