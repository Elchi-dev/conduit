// Package kick reads Kick channels and livestreams through Kick's public
// API with an app token and, with a user refresh token for your own
// channel, changes your stream's title and category and sends chat
// messages. Both of those are seen by your audience.
package kick

import (
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
	"sync"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Scopes are what the user refresh token needs.
var Scopes = []string{"user:read", "channel:read", "channel:write", "chat:write"}

// Config is one Kick connection.
type Config struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"` // secret://
	// RefreshToken is a user token's refresh token, for your own channel;
	// optional.
	RefreshToken string   `json:"refreshToken"` // secret://
	Channels     []string `json:"channels"`     // slugs to check by default
}

type token struct {
	access  string
	expires time.Time
}

type conn struct {
	cfg  Config
	host sdk.Host
	http *http.Client
	auth string
	app  *rest.Client
	user *rest.Client

	mu      sync.Mutex
	appTok  token
	userTok token
	refresh string // a rotated refresh token not yet saved, if any
	me      *self
}

type self struct {
	ID   int64
	Slug string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://api.kick.com/public/v1, Auth the token
	// endpoint and HTTP the client (tests); they aren't settings.
	Base string
	Auth string
	HTTP *http.Client
}

// New returns the Kick module.
func New() *Module { return &Module{} }

var (
	slugRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)
	clientIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "kick", Name: "Kick", Version: "0.1.0", Category: "Gaming", Icon: "video",
		Description: "Kick channels and who's live; change your stream's title and category and chat in your channel.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["clientId","clientSecret"],"properties":{
			"clientId":{"type":"string","description":"From kick.com, Settings, Developer: your app's client ID"},
			"clientSecret":{"type":"string","x-secret":true},
			"refreshToken":{"type":"string","x-secret":true,"description":"Optional: a user refresh token (scopes user:read channel:read channel:write chat:write) to change your own stream and chat"},
			"channels":{"type":"array","items":{"type":"string"},"maxItems":50,"description":"Channel slugs to check by default"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "channel", Title: "Channel info", Description: "A channel's title, category, description and whether it's live (yours by default with the user token).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"channel":{"type":"string","description":"Channel slug"}}}`)},
			{Name: "livestreams", Title: "Who's live", Description: "Live status, title, category, viewers and start time of up to 50 channels.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"channels":{"type":"array","items":{"type":"string"},"maxItems":50}}}`)},
			{Name: "set_stream", Title: "Change your stream", Description: "Your stream title and/or category, shown to everyone on Kick. Preview first; undo puts the previous ones back. Needs the user token.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","properties":{"title":{"type":"string","minLength":1,"maxLength":140},"category":{"type":"string","description":"Category name, e.g. Just Chatting"},"categoryId":{"type":"integer","minimum":1}}}`)},
			{Name: "send_chat", Title: "Send a chat message", Description: "Posts a message in your own channel's chat, visible to everyone watching. Needs the user token.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["message"],"properties":{"message":{"type":"string","minLength":1,"maxLength":500}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.ClientID = strings.TrimSpace(c.ClientID)
	if !clientIDRe.MatchString(c.ClientID) || !strings.HasPrefix(c.ClientSecret, "secret://") {
		return errors.New("add the app's client ID, and its client secret as a vault reference")
	}
	if c.RefreshToken != "" && !strings.HasPrefix(c.RefreshToken, "secret://") {
		return errors.New("store the refresh token in the vault and enter its secret:// reference")
	}
	if len(c.Channels) > 50 {
		return errors.New("list up to 50 channels")
	}
	for _, ch := range c.Channels {
		if !slugRe.MatchString(ch) {
			return fmt.Errorf("%q isn't a Kick channel slug", ch)
		}
	}
	cl := m.HTTP
	if cl == nil {
		cl = sdk.HTTPClient(h, 20*time.Second)
	}
	cl = rest.SameHostOnly(cl)
	base, auth := m.Base, m.Auth
	if base == "" {
		base = "https://api.kick.com/public/v1"
	}
	if auth == "" {
		auth = "https://id.kick.com/oauth/token"
	}
	cn := &conn{cfg: c, host: h, http: cl, auth: auth}
	cn.app = rest.New(base, func(ctx context.Context, r *http.Request) error {
		tok, err := cn.appToken(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		return nil
	})
	cn.app.HTTP = cl
	if c.RefreshToken != "" {
		cn.user = rest.New(base, func(ctx context.Context, r *http.Request) error {
			tok, err := cn.userToken(ctx)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+tok)
			return nil
		})
		cn.user.HTTP = cl
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// secretWriter is implemented by hosts that can store a value back in the
// vault under an existing reference.
type secretWriter interface {
	SetSecret(ctx context.Context, ref, value string) error
}

type tokenAnswer struct {
	Access    string `json:"access_token"`
	Refresh   string `json:"refresh_token"`
	ExpiresIn int    `json:"expires_in"`
	Error     string `json:"error"`
	Desc      string `json:"error_description"`
	Message   string `json:"message"`
}

func (c *conn) fetchToken(ctx context.Context, form url.Values, what string) (tokenAnswer, error) {
	secret, err := c.host.Secret(ctx, c.cfg.ClientSecret)
	if err != nil {
		return tokenAnswer{}, err
	}
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", strings.TrimSpace(secret))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.auth, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenAnswer{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Conduit")
	res, err := c.http.Do(req)
	if err != nil {
		return tokenAnswer{}, rest.TransportError(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var t tokenAnswer
	_ = json.Unmarshal(body, &t)
	if res.StatusCode != http.StatusOK || t.Access == "" {
		msg := t.Desc
		for _, s := range []string{t.Error, t.Message, res.Status} {
			if msg == "" {
				msg = s
			}
		}
		return tokenAnswer{}, fmt.Errorf("Kick refused the %s (%s)", what, rest.Redact(msg))
	}
	if t.ExpiresIn <= 0 {
		t.ExpiresIn = 3600
	}
	return t, nil
}

// appToken gets an app access token (client credentials), cached until it
// is about to expire.
func (c *conn) appToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.appTok.access != "" && time.Now().Before(c.appTok.expires.Add(-time.Minute)) {
		return c.appTok.access, nil
	}
	t, err := c.fetchToken(ctx, url.Values{"grant_type": {"client_credentials"}}, "client ID or secret")
	if err != nil {
		return "", err
	}
	c.appTok = token{t.Access, time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)}
	return t.Access, nil
}

// userToken refreshes the user's access token. Kick rotates refresh
// tokens; the new one is written back to the vault when the host can.
func (c *conn) userToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.userTok.access != "" && time.Now().Before(c.userTok.expires.Add(-time.Minute)) {
		return c.userTok.access, nil
	}
	refresh := c.refresh
	if refresh == "" {
		v, err := c.host.Secret(ctx, c.cfg.RefreshToken)
		if err != nil {
			return "", err
		}
		refresh = strings.TrimSpace(v)
	}
	t, err := c.fetchToken(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, "refresh token; get a new one as the module docs describe")
	if err != nil {
		return "", err
	}
	c.userTok = token{t.Access, time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)}
	if t.Refresh != "" && t.Refresh != refresh {
		c.refresh = t.Refresh
		if w, ok := c.host.(secretWriter); ok {
			if err := w.SetSecret(ctx, c.cfg.RefreshToken, t.Refresh); err != nil {
				c.host.Log("warn", "Kick rotated the refresh token and it couldn't be saved to the vault", "err", err)
			} else {
				c.refresh = ""
			}
		} else {
			c.host.Log("warn", "Kick rotated the refresh token; it is used until the daemon restarts")
		}
	}
	return t.Access, nil
}

// do calls the API; a 401 drops the cached token and tries once more.
func (c *conn) do(ctx context.Context, cl *rest.Client, method, path string, q url.Values, body, out any) error {
	_, err := cl.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.mu.Lock()
		if cl == c.user {
			c.userTok = token{}
		} else {
			c.appTok = token{}
		}
		c.mu.Unlock()
		_, err = cl.Do(ctx, method, path, q, body, out)
	}
	if rest.IsStatus(err, http.StatusForbidden) && cl == c.user {
		return fmt.Errorf("Kick refused: %w (the user token may lack a scope: %s)", err, strings.Join(Scopes, " "))
	}
	return err
}

func (c *conn) whoami(ctx context.Context) (self, error) {
	c.mu.Lock()
	if c.me != nil {
		me := *c.me
		c.mu.Unlock()
		return me, nil
	}
	c.mu.Unlock()
	var us struct {
		Data []struct {
			ID   int64  `json:"user_id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := c.do(ctx, c.user, "GET", "/users", nil, nil, &us); err != nil {
		return self{}, err
	}
	if len(us.Data) == 0 || us.Data[0].ID <= 0 {
		return self{}, errors.New("the user token belongs to no Kick user")
	}
	var chs struct {
		Data []channelInfo `json:"data"`
	}
	if err := c.do(ctx, c.user, "GET", "/channels", url.Values{"broadcaster_user_id": {strconv.FormatInt(us.Data[0].ID, 10)}}, nil, &chs); err != nil {
		return self{}, err
	}
	me := self{ID: us.Data[0].ID, Slug: us.Data[0].Name}
	if len(chs.Data) > 0 && chs.Data[0].Slug != "" {
		me.Slug = chs.Data[0].Slug
	}
	c.mu.Lock()
	c.me = &me
	c.mu.Unlock()
	return me, nil
}

type category struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// channelInfo is what the module reads of a channel. The API also returns
// the stream key and ingest URL for your own channel; they're never decoded.
type channelInfo struct {
	BroadcasterID int64     `json:"broadcaster_user_id"`
	Slug          string    `json:"slug"`
	Description   string    `json:"channel_description"`
	Title         string    `json:"stream_title"`
	Category      *category `json:"category"`
	Subscribers   *int64    `json:"active_subscribers_count"`
	Stream        *struct {
		Live      bool   `json:"is_live"`
		Viewers   int64  `json:"viewer_count"`
		StartTime string `json:"start_time"`
		Language  string `json:"language"`
		Mature    bool   `json:"is_mature"`
	} `json:"stream"`
}

func (ch channelInfo) categoryName() string {
	if ch.Category == nil {
		return ""
	}
	return ch.Category.Name
}

func (c *conn) channels(ctx context.Context, cl *rest.Client, q url.Values) ([]channelInfo, error) {
	var out struct {
		Data []channelInfo `json:"data"`
	}
	if err := c.do(ctx, cl, "GET", "/channels", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if _, err := c.appToken(ctx); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if c.user != nil {
		me, err := c.whoami(ctx)
		if err != nil {
			return sdk.Health{Status: "degraded", Message: "the user token doesn't work: " + err.Error()}
		}
		return sdk.Health{Status: "ok", Message: "kick.com/" + me.Slug}
	}
	return sdk.Health{Status: "ok", Message: "read-only (no user token)"}
}

func validLine(s string, max int, what string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("the %s can't be empty", what)
	}
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return fmt.Errorf("the %s is one line of up to %d characters", what, max)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return fmt.Errorf("the %s is one line without control characters", what)
		}
	}
	return nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Channel    string   `json:"channel"`
		Channels   []string `json:"channels"`
		Title      *string  `json:"title"`
		Category   string   `json:"category"`
		CategoryID int64    `json:"categoryId"`
		Message    string   `json:"message"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "channel":
		q := url.Values{}
		cl := c.app
		switch {
		case p.Channel != "":
			if !slugRe.MatchString(p.Channel) {
				return sdk.Result{}, fmt.Errorf("%q isn't a Kick channel slug", p.Channel)
			}
			q.Set("slug", strings.ToLower(p.Channel))
		case c.user != nil:
			me, err := c.whoami(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			q.Set("broadcaster_user_id", strconv.FormatInt(me.ID, 10))
			cl = c.user
		case len(c.cfg.Channels) > 0:
			q.Set("slug", strings.ToLower(c.cfg.Channels[0]))
		default:
			return sdk.Result{}, errors.New("name a channel")
		}
		chs, err := c.channels(ctx, cl, q)
		if err != nil {
			return sdk.Result{}, err
		}
		if len(chs) == 0 {
			return sdk.Result{}, errors.New("no such Kick channel")
		}
		ch := chs[0]
		out := map[string]any{"channel": ch.Slug, "title": ch.Title, "category": ch.categoryName(), "description": ch.Description,
			"live": ch.Stream != nil && ch.Stream.Live, "url": "https://kick.com/" + ch.Slug}
		if ch.Category != nil {
			out["categoryId"] = ch.Category.ID
		}
		if ch.Subscribers != nil {
			out["subscribers"] = *ch.Subscribers
		}
		if ch.Stream != nil && ch.Stream.Live {
			out["viewers"] = ch.Stream.Viewers
		}
		return sdk.JSON(out)

	case "livestreams":
		chs := p.Channels
		if len(chs) == 0 {
			chs = c.cfg.Channels
		}
		if len(chs) == 0 || len(chs) > 50 {
			return sdk.Result{}, errors.New("name 1 to 50 channels, or set some in the settings")
		}
		q := url.Values{}
		for _, ch := range chs {
			if !slugRe.MatchString(ch) {
				return sdk.Result{}, fmt.Errorf("%q isn't a Kick channel slug", ch)
			}
			q.Add("slug", strings.ToLower(ch))
		}
		got, err := c.channels(ctx, c.app, q)
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Channel   string `json:"channel"`
			Live      bool   `json:"live"`
			Title     string `json:"title,omitempty"`
			Category  string `json:"category,omitempty"`
			Viewers   int64  `json:"viewers,omitempty"`
			StartedAt string `json:"startedAt,omitempty"`
			Language  string `json:"language,omitempty"`
			Mature    bool   `json:"mature,omitempty"`
		}
		bySlug := map[string]channelInfo{}
		for _, ch := range got {
			bySlug[strings.ToLower(ch.Slug)] = ch
		}
		rows := []row{}
		for _, s := range chs {
			ch, ok := bySlug[strings.ToLower(s)]
			if !ok || ch.Stream == nil || !ch.Stream.Live {
				rows = append(rows, row{Channel: s})
				continue
			}
			rows = append(rows, row{Channel: ch.Slug, Live: true, Title: ch.Title, Category: ch.categoryName(), Viewers: ch.Stream.Viewers,
				StartedAt: ch.Stream.StartTime, Language: ch.Stream.Language, Mature: ch.Stream.Mature})
		}
		return sdk.JSON(rows)

	case "set_stream":
		if c.user == nil {
			return sdk.Result{}, errors.New("changing your stream needs a user refresh token in the settings")
		}
		if p.Title == nil && p.Category == "" && p.CategoryID == 0 {
			return sdk.Result{}, errors.New("give a new title, a category, or both")
		}
		if p.Title != nil {
			if err := validLine(*p.Title, 140, "title"); err != nil {
				return sdk.Result{}, err
			}
		}
		if p.CategoryID < 0 || (p.Category != "" && p.CategoryID != 0) {
			return sdk.Result{}, errors.New("give a category by name or by a positive id, not both")
		}
		if p.Category != "" {
			if err := validLine(p.Category, 100, "category"); err != nil {
				return sdk.Result{}, err
			}
		}
		me, err := c.whoami(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		chs, err := c.channels(ctx, c.user, url.Values{"broadcaster_user_id": {strconv.FormatInt(me.ID, 10)}})
		if err != nil {
			return sdk.Result{}, err
		}
		if len(chs) == 0 {
			return sdk.Result{}, errors.New("Kick didn't return your channel")
		}
		before := chs[0]
		cat := category{ID: p.CategoryID}
		if p.Category != "" {
			var cs struct {
				Data []category `json:"data"`
			}
			if err := c.do(ctx, c.user, "GET", "/categories", url.Values{"q": {p.Category}}, nil, &cs); err != nil {
				return sdk.Result{}, err
			}
			var names []string
			for _, x := range cs.Data {
				if strings.EqualFold(x.Name, p.Category) {
					cat = x
					break
				}
				if len(names) < 5 {
					names = append(names, x.Name)
				}
			}
			if cat.ID == 0 {
				if len(names) > 0 {
					return sdk.Result{}, fmt.Errorf("Kick has no category named %q; did you mean %s?", p.Category, strings.Join(names, ", "))
				}
				return sdk.Result{}, fmt.Errorf("Kick has no category named %q", p.Category)
			}
		}
		body := map[string]any{}
		after := map[string]string{"title": before.Title, "category": before.categoryName()}
		if p.Title != nil {
			body["stream_title"] = *p.Title
			after["title"] = *p.Title
		}
		if cat.ID != 0 {
			body["category_id"] = cat.ID
			after["category"] = cat.Name
			if cat.Name == "" {
				after["category"] = "id " + strconv.FormatInt(cat.ID, 10)
			}
		}
		if call.DryRun {
			b, _ := json.Marshal(map[string]string{"title": before.Title, "category": before.categoryName()})
			a, _ := json.Marshal(after)
			return sdk.Result{Plan: &sdk.Plan{Summary: "Change the stream on kick.com/" + me.Slug + " (seen by your viewers)",
				Changes: []sdk.Change{{Target: "kick.com/" + me.Slug, Op: "update", Before: b, After: a}}}}, nil
		}
		if err := c.do(ctx, c.user, "PATCH", "/channels", nil, body, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(after)
		undo := map[string]any{}
		if before.Title != "" {
			undo["title"] = before.Title
		}
		if before.Category != nil && before.Category.ID > 0 {
			undo["categoryId"] = before.Category.ID
		}
		if len(undo) > 0 {
			r.Undo = sdk.UndoWith("set_stream", undo, "Put the previous title and category back")
		}
		return r, nil

	case "send_chat":
		if c.user == nil {
			return sdk.Result{}, errors.New("chatting needs a user refresh token in the settings")
		}
		if err := validLine(p.Message, 500, "message"); err != nil {
			return sdk.Result{}, err
		}
		me, err := c.whoami(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			a, _ := json.Marshal(map[string]string{"message": p.Message})
			return sdk.Result{Plan: &sdk.Plan{Summary: "Post in kick.com/" + me.Slug + "'s chat (seen by everyone watching)",
				Changes: []sdk.Change{{Target: "kick.com/" + me.Slug + " chat", Op: "create", After: a}}}}, nil
		}
		var out struct {
			Data struct {
				Sent bool   `json:"is_sent"`
				ID   string `json:"message_id"`
			} `json:"data"`
		}
		if err := c.do(ctx, c.user, "POST", "/chat", nil, map[string]any{"broadcaster_user_id": me.ID, "content": p.Message, "type": "user"}, &out); err != nil {
			return sdk.Result{}, err
		}
		if !out.Data.Sent {
			return sdk.Result{}, errors.New("Kick didn't send the message (slow mode, followers-only or a ban may apply)")
		}
		return sdk.JSON(map[string]any{"sent": true, "channel": me.Slug, "messageId": out.Data.ID})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
