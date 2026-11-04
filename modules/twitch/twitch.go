// Package twitch shows whether channels are live and, with your own token,
// changes your stream's title and category.
package twitch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Twitch connection.
type Config struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"` // secret://
	// UserToken is a user access token with channel:manage:broadcast, for
	// changing your own stream; optional.
	UserToken string   `json:"userToken"` // secret://
	Channels  []string `json:"channels"`  // logins to watch by default
	API       string   `json:"api"`       // default https://api.twitch.tv/helix (tests)
	Auth      string   `json:"auth"`      // default https://id.twitch.tv/oauth2/token (tests)
}

type conn struct {
	cfg  Config
	host sdk.Host
	app  *rest.Client
	user *rest.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Twitch module.
func New() *Module { return &Module{} }

var loginRe = regexp.MustCompile(`^[A-Za-z0-9_]{3,25}$`)
var idRe = regexp.MustCompile(`^[0-9]{1,20}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "twitch", Name: "Twitch", Version: "0.1.0", Category: "Gaming", Icon: "video",
		Description: "See who's live, and change your stream's title and category.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["clientId","clientSecret"],"properties":{
			"clientId":{"type":"string","description":"From dev.twitch.tv, Your Console, Applications"},
			"clientSecret":{"type":"string","x-secret":true},
			"userToken":{"type":"string","x-secret":true,"description":"Optional: a user access token with channel:manage:broadcast, to change your own stream"},
			"channels":{"type":"array","items":{"type":"string"},"description":"Channels to check by default"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "streams", Title: "Who's live", Description: "Live status, title, game and viewers of channels.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"channels":{"type":"array","items":{"type":"string"},"maxItems":100}}}`)},
			{Name: "channel", Title: "Channel info", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["channel"],"properties":{"channel":{"type":"string"}}}`)},
			{Name: "set_stream", Title: "Change your stream", Description: "Title and/or category (needs the user token).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"title":{"type":"string","maxLength":140},"category":{"type":"string","description":"A game or category name, e.g. Just Chatting"},"categoryId":{"type":"string"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.ClientID) == "" || !strings.HasPrefix(c.ClientSecret, "secret://") {
		return errors.New("add the client ID, and the client secret as a vault reference")
	}
	if c.UserToken != "" && !strings.HasPrefix(c.UserToken, "secret://") {
		return errors.New("store the user token in the vault and enter its secret:// reference")
	}
	for _, ch := range c.Channels {
		if !loginRe.MatchString(ch) {
			return fmt.Errorf("%q isn't a Twitch channel name", ch)
		}
	}
	if c.API == "" {
		c.API = "https://api.twitch.tv/helix"
	}
	if c.Auth == "" {
		c.Auth = "https://id.twitch.tv/oauth2/token"
	}
	cn := &conn{cfg: c, host: h}
	cn.app = rest.New(c.API, func(ctx context.Context, r *http.Request) error {
		tok, err := cn.appToken(ctx, m.HTTP)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set("Client-Id", c.ClientID)
		return nil
	})
	if c.UserToken != "" {
		cn.user = rest.New(c.API, func(ctx context.Context, r *http.Request) error {
			tok, err := h.Secret(ctx, c.UserToken)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+strings.TrimPrefix(tok, "oauth:"))
			r.Header.Set("Client-Id", c.ClientID)
			return nil
		})
	}
	if m.HTTP != nil {
		cn.app.HTTP = m.HTTP
		if cn.user != nil {
			cn.user.HTTP = m.HTTP
		}
	}
	m.set.Put(id, cn)
	return nil
}

// appToken gets an app access token (client credentials), cached until it
// is about to expire.
func (c *conn) appToken(ctx context.Context, client *http.Client) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires.Add(-time.Minute)) {
		return c.token, nil
	}
	secret, err := c.host.Secret(ctx, c.cfg.ClientSecret)
	if err != nil {
		return "", err
	}
	form := url.Values{"client_id": {c.cfg.ClientID}, "client_secret": {secret}, "grant_type": {"client_credentials"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Auth, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	res, err := client.Do(req)
	if err != nil {
		return "", rest.TransportError(err)
	}
	defer res.Body.Close()
	var out struct {
		Token   string `json:"access_token"`
		Expires int    `json:"expires_in"`
		Message string `json:"message"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != http.StatusOK || out.Token == "" {
		if out.Message == "" {
			out.Message = res.Status
		}
		return "", errors.New("Twitch refused the client ID or secret: " + out.Message)
	}
	c.token, c.expires = out.Token, time.Now().Add(time.Duration(out.Expires)*time.Second)
	return c.token, nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if _, err := c.appToken(ctx, m.HTTP); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if c.user != nil {
		if _, err := c.me(ctx); err != nil {
			return sdk.Health{Status: "degraded", Message: "the user token doesn't work: " + err.Error()}
		}
	}
	return sdk.Health{Status: "ok"}
}

type user struct {
	ID          string `json:"id"`
	Login       string `json:"login"`
	DisplayName string `json:"display_name"`
}

func (c *conn) me(ctx context.Context) (user, error) {
	var out struct {
		Data []user `json:"data"`
	}
	if _, err := c.user.Do(ctx, "GET", "/users", nil, nil, &out); err != nil {
		return user{}, err
	}
	if len(out.Data) == 0 {
		return user{}, errors.New("the user token belongs to no user")
	}
	return out.Data[0], nil
}

type channelInfo struct {
	BroadcasterID string `json:"broadcaster_id"`
	Login         string `json:"broadcaster_login"`
	Name          string `json:"broadcaster_name"`
	Title         string `json:"title"`
	GameID        string `json:"game_id"`
	GameName      string `json:"game_name"`
}

func (c *conn) channel(ctx context.Context, client *rest.Client, broadcasterID string) (channelInfo, error) {
	var out struct {
		Data []channelInfo `json:"data"`
	}
	if _, err := client.Do(ctx, "GET", "/channels", url.Values{"broadcaster_id": {broadcasterID}}, nil, &out); err != nil {
		return channelInfo{}, err
	}
	if len(out.Data) == 0 {
		return channelInfo{}, errors.New("no such channel")
	}
	return out.Data[0], nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Channels   []string `json:"channels"`
		Channel    string   `json:"channel"`
		Title      *string  `json:"title"`
		Category   string   `json:"category"`
		CategoryID string   `json:"categoryId"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "streams":
		chs := p.Channels
		if len(chs) == 0 {
			chs = c.cfg.Channels
		}
		if len(chs) == 0 || len(chs) > 100 {
			return sdk.Result{}, errors.New("name 1 to 100 channels, or set some in the settings")
		}
		q := url.Values{}
		for _, ch := range chs {
			if !loginRe.MatchString(ch) {
				return sdk.Result{}, fmt.Errorf("%q isn't a Twitch channel name", ch)
			}
			q.Add("user_login", strings.ToLower(ch))
		}
		var out struct {
			Data []struct {
				Login     string    `json:"user_login"`
				Name      string    `json:"user_name"`
				Title     string    `json:"title"`
				Game      string    `json:"game_name"`
				Viewers   int       `json:"viewer_count"`
				StartedAt time.Time `json:"started_at"`
			} `json:"data"`
		}
		if _, err := c.app.Do(ctx, "GET", "/streams", q, nil, &out); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Channel   string     `json:"channel"`
			Live      bool       `json:"live"`
			Title     string     `json:"title,omitempty"`
			Game      string     `json:"game,omitempty"`
			Viewers   int        `json:"viewers,omitempty"`
			StartedAt *time.Time `json:"startedAt,omitempty"`
		}
		live := map[string]row{}
		for _, s := range out.Data {
			t := s.StartedAt
			live[strings.ToLower(s.Login)] = row{Channel: s.Name, Live: true, Title: s.Title, Game: s.Game, Viewers: s.Viewers, StartedAt: &t}
		}
		rows := []row{}
		for _, ch := range chs {
			if r, ok := live[strings.ToLower(ch)]; ok {
				rows = append(rows, r)
			} else {
				rows = append(rows, row{Channel: ch})
			}
		}
		return sdk.JSON(rows)

	case "channel":
		if !loginRe.MatchString(p.Channel) {
			return sdk.Result{}, errors.New("name a channel")
		}
		var us struct {
			Data []user `json:"data"`
		}
		if _, err := c.app.Do(ctx, "GET", "/users", url.Values{"login": {strings.ToLower(p.Channel)}}, nil, &us); err != nil {
			return sdk.Result{}, err
		}
		if len(us.Data) == 0 {
			return sdk.Result{}, errors.New("no such channel")
		}
		ci, err := c.channel(ctx, c.app, us.Data[0].ID)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"channel": ci.Name, "title": ci.Title, "category": ci.GameName, "categoryId": ci.GameID})

	case "set_stream":
		if c.user == nil {
			return sdk.Result{}, errors.New("changing your stream needs a user token in the settings")
		}
		if p.Title == nil && p.Category == "" && p.CategoryID == "" {
			return sdk.Result{}, errors.New("give a new title, a category, or both")
		}
		if p.Title != nil && (len(*p.Title) > 140 || strings.ContainsAny(*p.Title, "\r\n")) {
			return sdk.Result{}, errors.New("a title is one line of up to 140 characters")
		}
		if p.CategoryID != "" && !idRe.MatchString(p.CategoryID) {
			return sdk.Result{}, errors.New("a category id is a number")
		}
		me, err := c.me(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		before, err := c.channel(ctx, c.user, me.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		gameID, gameName := p.CategoryID, ""
		if p.Category != "" {
			var gs struct {
				Data []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"data"`
			}
			if _, err := c.user.Do(ctx, "GET", "/games", url.Values{"name": {p.Category}}, nil, &gs); err != nil {
				return sdk.Result{}, err
			}
			if len(gs.Data) == 0 {
				return sdk.Result{}, fmt.Errorf("Twitch has no category named %q", p.Category)
			}
			gameID, gameName = gs.Data[0].ID, gs.Data[0].Name
		}
		body := map[string]string{}
		after := map[string]string{"title": before.Title, "category": before.GameName}
		if p.Title != nil {
			body["title"] = *p.Title
			after["title"] = *p.Title
		}
		if gameID != "" {
			body["game_id"] = gameID
			after["category"] = gameName
			if gameName == "" {
				after["category"] = "id " + gameID
			}
		}
		if call.DryRun {
			b, _ := json.Marshal(map[string]string{"title": before.Title, "category": before.GameName})
			a, _ := json.Marshal(after)
			return sdk.Result{Plan: &sdk.Plan{Summary: "Change " + me.DisplayName + "'s stream", Changes: []sdk.Change{{Target: "twitch.tv/" + me.Login, Op: "update", Before: b, After: a}}}}, nil
		}
		if _, err := c.user.Do(ctx, "PATCH", "/channels", url.Values{"broadcaster_id": {me.ID}}, body, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(after)
		undo := map[string]any{"title": before.Title}
		if before.GameID != "" {
			undo["categoryId"] = before.GameID
		}
		r.Undo = sdk.UndoWith("set_stream", undo, "Put the previous title and category back")
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
