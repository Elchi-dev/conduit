// Package spotify knows what a person listens to and plays anything on
// their Spotify devices. It reads through the Web API (currently playing,
// recently played, top tracks and artists, library, playlists, search),
// keeps its own listening history beyond Spotify's 50-item window, and
// controls playback through the Web API (Premium) or, for other accounts,
// the Spotify desktop app on the same computer (MPRIS on Linux, AppleScript
// on macOS).
package spotify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Scopes are what the module asks for; the docs' authorize link uses them.
var Scopes = []string{
	"user-read-playback-state", "user-modify-playback-state", "user-read-currently-playing",
	"user-read-recently-played", "user-top-read",
	"user-library-read", "user-library-modify",
	"playlist-read-private", "playlist-read-collaborative", "playlist-modify-public", "playlist-modify-private",
}

// Config is one Spotify account's settings.
type Config struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"` // secret://
	RefreshToken string `json:"refreshToken"` // secret://
	// Playback is "auto" (Web API, falling back to the desktop app when the
	// account isn't Premium), "web" or "local" (always the desktop app).
	Playback string `json:"playback"`
	// History keeps a local listening log (default on when the Web API is
	// set up); HistoryMinutes is how often it is collected.
	History        *bool  `json:"history"`
	HistoryMinutes int    `json:"historyMinutes"`
	Timezone       string `json:"timezone"` // for per-day stats; default the daemon's
	API            string `json:"api"`      // default https://api.spotify.com/v1 (tests)
	Accounts       string `json:"accounts"` // default https://accounts.spotify.com (tests)
}

type conn struct {
	id    string
	cfg   Config
	host  sdk.Host
	http  *http.Client
	web   bool // Web API credentials are set
	local localPlayer
	tz    *time.Location
	hist  *history

	mu      sync.Mutex
	access  string
	expires time.Time
	refresh string // a rotated refresh token, if Spotify sent one
	scopes  []string
	user    string
	product string // "premium", "free", … when known
	free    bool   // a playback call answered PREMIUM_REQUIRED

	stop context.CancelFunc
	done chan struct{}
}

// Module implements sdk.Module.
type Module struct {
	// Dir holds each instance's listening history. Empty uses the daemon's
	// default data folder.
	Dir  string
	HTTP *http.Client
	// Local overrides the desktop-app controller (tests).
	Local func() localPlayer

	set inst.Set[conn]
}

// New returns the Spotify module.
func New() *Module { return &Module{} }

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.Playback == "" {
		c.Playback = "auto"
	}
	if c.Playback != "auto" && c.Playback != "web" && c.Playback != "local" {
		return fmt.Errorf("playback is auto, web or local, not %q", c.Playback)
	}
	cn := &conn{id: id, cfg: c, host: h, http: rest.SameHostOnly(&http.Client{Timeout: 20 * time.Second}), tz: time.Local}
	if m.HTTP != nil {
		cn.http = m.HTTP
	}
	cn.web = c.ClientID != "" || c.ClientSecret != "" || c.RefreshToken != ""
	if cn.web && (c.ClientID == "" || c.ClientSecret == "" || c.RefreshToken == "") {
		return errors.New("add the app's client id, its client secret and a refresh token (both stored in the vault)")
	}
	if c.Playback != "web" {
		if m.Local != nil {
			cn.local = m.Local()
		} else {
			cn.local = newLocal()
		}
	}
	if !cn.web && cn.local == nil {
		return errors.New("add your Spotify app's client id, client secret and refresh token; without them only the desktop app on Linux or macOS can be controlled")
	}
	if c.Playback == "web" && !cn.web {
		return errors.New("playback through the Web API needs the client id, client secret and refresh token")
	}
	if c.Timezone != "" {
		loc, err := time.LoadLocation(c.Timezone)
		if err != nil {
			return fmt.Errorf("unknown time zone %q", c.Timezone)
		}
		cn.tz = loc
	}
	if c.API == "" {
		c.API = "https://api.spotify.com/v1"
	}
	if c.Accounts == "" {
		c.Accounts = "https://accounts.spotify.com"
	}
	c.API, c.Accounts = strings.TrimRight(c.API, "/"), strings.TrimRight(c.Accounts, "/")
	cn.cfg = c

	if cn.web {
		dir := m.Dir
		if dir == "" {
			if d, ok := h.(interface{ DataDir() string }); ok && d.DataDir() != "" {
				dir = d.DataDir()
			} else if ud, err := os.UserConfigDir(); err == nil {
				dir = filepath.Join(ud, "conduit", "modules", "spotify")
			}
		}
		cn.hist = openHistory(dir, id)
	}
	if old := m.set.Delete(id); old != nil {
		old.close()
	}
	m.set.Put(id, cn)
	if cn.hist != nil && (c.History == nil || *c.History) {
		every := time.Duration(c.HistoryMinutes) * time.Minute
		if every <= 0 {
			every = 10 * time.Minute
		}
		if every < 2*time.Minute {
			every = 2 * time.Minute
		}
		ctx, cancel := context.WithCancel(context.Background())
		cn.stop, cn.done = cancel, make(chan struct{})
		go cn.collect(ctx, every)
	}
	return nil
}

func (c *conn) close() {
	if c.stop != nil {
		c.stop()
		<-c.done
	}
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error {
	if c := m.set.Delete(id); c != nil {
		c.close()
	}
	return nil
}

func (c *conn) log(level, msg string, kv ...any) {
	if c.host != nil {
		c.host.Log(level, msg, kv...)
	}
}

// secretWriter is implemented by hosts that can store a value back in the
// vault under an existing reference.
type secretWriter interface {
	SetSecret(ctx context.Context, ref, value string) error
}

// token returns a valid access token, refreshing it a minute before expiry.
func (c *conn) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.access != "" && time.Now().Before(c.expires.Add(-time.Minute)) {
		return c.access, nil
	}
	secret, err := c.host.Secret(ctx, c.cfg.ClientSecret)
	if err != nil {
		return "", err
	}
	refresh := c.refresh
	if refresh == "" {
		if refresh, err = c.host.Secret(ctx, c.cfg.RefreshToken); err != nil {
			return "", err
		}
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.Accounts+"/api/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.cfg.ClientID+":"+secret)))
	res, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var t struct {
		Access    string `json:"access_token"`
		ExpiresIn int    `json:"expires_in"`
		Refresh   string `json:"refresh_token"`
		Scope     string `json:"scope"`
		Error     string `json:"error"`
		Desc      string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &t)
	if res.StatusCode != 200 || t.Access == "" {
		msg := t.Desc
		if msg == "" {
			msg = res.Status
		}
		return "", fmt.Errorf("Spotify didn't accept the refresh token (%s); get a new one as the module docs describe", msg)
	}
	c.access = t.Access
	if t.ExpiresIn <= 0 {
		t.ExpiresIn = 3600
	}
	c.expires = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	if t.Scope != "" {
		c.scopes = strings.Fields(t.Scope)
	}
	if t.Refresh != "" && t.Refresh != refresh {
		c.refresh = t.Refresh
		// Keep the vault current so a restart doesn't use a revoked token.
		if w, ok := c.host.(secretWriter); ok {
			if err := w.SetSecret(ctx, c.cfg.RefreshToken, t.Refresh); err != nil {
				c.log("warn", "Spotify rotated the refresh token and it couldn't be saved to the vault", "err", err)
			}
		} else {
			c.log("warn", "Spotify rotated the refresh token; it is used until the daemon restarts")
		}
	}
	return c.access, nil
}

func (c *conn) dropToken() {
	c.mu.Lock()
	c.access = ""
	c.mu.Unlock()
}

// apiError is an answer from the Web API that isn't a success.
type apiError struct {
	Status     int
	Message    string
	Reason     string
	RetryAfter int
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("Spotify answered %d", e.Status)
	}
	return e.Message
}

func isStatus(err error, status int) bool {
	var e *apiError
	return errors.As(err, &e) && e.Status == status
}

func isPremiumRequired(err error) bool {
	var e *apiError
	return errors.As(err, &e) && e.Status == 403 && (e.Reason == "PREMIUM_REQUIRED" || strings.Contains(strings.ToLower(e.Message), "premium"))
}

// do calls the Web API. A 401 refreshes the token once; a short 429 waits
// and retries once.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	if !c.web {
		return errNoWeb
	}
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = b
	}
	for attempt := 0; ; attempt++ {
		tok, err := c.token(ctx)
		if err != nil {
			return err
		}
		u := c.cfg.API + path
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, rd)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		} else if method == "PUT" || method == "POST" {
			req.ContentLength = 0
		}
		res, err := c.http.Do(req)
		if err != nil {
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		res.Body.Close()
		if err != nil {
			return err
		}
		if res.StatusCode < 300 {
			if out != nil && len(bytes.TrimSpace(raw)) > 0 {
				if err := json.Unmarshal(raw, out); err != nil {
					return fmt.Errorf("unexpected answer from Spotify: %w", err)
				}
			}
			return nil
		}
		e := parseError(res, raw)
		if attempt == 0 && e.Status == 401 {
			c.dropToken()
			continue
		}
		if attempt == 0 && e.Status == 429 && e.RetryAfter <= 5 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(e.RetryAfter)*time.Second + 100*time.Millisecond):
			}
			continue
		}
		return e
	}
}

func parseError(res *http.Response, raw []byte) *apiError {
	e := &apiError{Status: res.StatusCode}
	var body struct {
		Error json.RawMessage `json:"error"`
		Desc  string          `json:"error_description"`
	}
	if json.Unmarshal(raw, &body) == nil && len(body.Error) > 0 {
		var obj struct {
			Message string `json:"message"`
			Reason  string `json:"reason"`
		}
		var s string
		if json.Unmarshal(body.Error, &obj) == nil {
			e.Message, e.Reason = obj.Message, obj.Reason
		} else if json.Unmarshal(body.Error, &s) == nil {
			e.Message = s
			if body.Desc != "" {
				e.Message = body.Desc
			}
		}
	}
	if e.Message == "" {
		e.Message = res.Status
	}
	if res.StatusCode == 429 {
		e.RetryAfter, _ = strconv.Atoi(res.Header.Get("Retry-After"))
		e.Message = fmt.Sprintf("Spotify is rate limiting this app; try again in %d seconds", max(e.RetryAfter, 1))
	}
	return e
}

var (
	errNoWeb     = errors.New("this needs the Web API: add your Spotify app's client id, client secret and refresh token in the settings")
	errNoPremium = errors.New("playback control through Spotify's Web API needs Premium; on Linux or macOS, Conduit can control the Spotify app on this computer instead (playback: auto or local)")
)

// friendly turns API errors into advice.
func friendly(err error) error {
	var e *apiError
	if !errors.As(err, &e) {
		return err
	}
	switch {
	case e.Status == 404 && (e.Reason == "NO_ACTIVE_DEVICE" || strings.Contains(strings.ToLower(e.Message), "device")):
		return errors.New("no active Spotify device; start playing on a device first, or pick one from devices")
	case isPremiumRequired(err):
		return errNoPremium
	case e.Status == 403:
		return fmt.Errorf("Spotify refused: %s (the refresh token may lack a scope; get a new one with the authorize link from auth_url)", e.Message)
	case e.Status == 404:
		return fmt.Errorf("Spotify doesn't know that: %s", e.Message)
	}
	return err
}

// mode is how playback is controlled right now.
func (c *conn) mode() string {
	c.mu.Lock()
	free := c.free || (c.product != "" && c.product != "premium")
	c.mu.Unlock()
	switch {
	case c.cfg.Playback == "local", !c.web:
		return "local"
	case free && c.local != nil && c.cfg.Playback == "auto":
		return "local"
	}
	return "web"
}

func (c *conn) markFree() {
	c.mu.Lock()
	c.free = true
	c.mu.Unlock()
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var parts []string
	status := "ok"
	if c.web {
		var me struct {
			ID      string `json:"id"`
			Name    string `json:"display_name"`
			Product string `json:"product"` // gone for development-mode apps since 2026
		}
		if err := c.do(ctx, "GET", "/me", nil, nil, &me); err != nil {
			return sdk.Health{Status: "down", Message: friendly(err).Error()}
		}
		c.mu.Lock()
		c.user = me.ID
		if me.Product != "" {
			c.product = me.Product
		}
		free, product, scopes := c.free || (c.product != "" && c.product != "premium"), c.product, c.scopes
		c.mu.Unlock()
		name := me.Name
		if name == "" {
			name = me.ID
		}
		parts = append(parts, "Signed in as "+name)
		if product != "" {
			parts = append(parts, "Spotify "+product)
		}
		if miss := missingScopes(scopes); len(miss) > 0 {
			status = "degraded"
			parts = append(parts, "the token lacks "+strings.Join(miss, ", ")+"; get a new refresh token with auth_url")
		}
		if free && c.mode() == "web" {
			status = "degraded"
			parts = append(parts, "playback control needs Premium"+localHint())
		}
	}
	switch c.mode() {
	case "web":
		parts = append(parts, "playback through the Web API")
	case "local":
		if c.local == nil {
			status = "degraded"
			parts = append(parts, "playback control unavailable"+localHint())
			break
		}
		if _, err := c.local.Status(ctx); err != nil {
			if status == "ok" {
				status = "degraded"
			}
			parts = append(parts, "playback through the Spotify app on this computer ("+c.local.Name()+"), which isn't reachable: "+err.Error())
		} else {
			parts = append(parts, "playback through the Spotify app on this computer ("+c.local.Name()+")")
		}
	}
	if c.hist != nil {
		if n, last := c.hist.stats(); n > 0 {
			parts = append(parts, fmt.Sprintf("history: %d plays since %s", n, last.In(c.tz).Format("2 Jan 2006")))
		}
	}
	return sdk.Health{Status: status, Message: strings.Join(parts, "; ")}
}

func missingScopes(have []string) []string {
	if len(have) == 0 {
		return nil // unknown: Spotify didn't list them
	}
	set := map[string]bool{}
	for _, s := range have {
		set[s] = true
	}
	var miss []string
	for _, s := range Scopes {
		if !set[s] && s != "playlist-read-collaborative" {
			miss = append(miss, s)
		}
	}
	return miss
}
