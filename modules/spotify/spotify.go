// Package spotify controls Spotify playback: what's playing, devices, play
// and pause, skipping, volume, the queue and search. It uses the Web API
// with a refresh token from the Authorization Code flow.
package spotify

import (
	"context"
	"encoding/base64"
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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Spotify account's settings.
type Config struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"` // secret://
	RefreshToken string `json:"refreshToken"` // secret://
	API          string `json:"api"`          // default https://api.spotify.com/v1 (tests)
	Accounts     string `json:"accounts"`     // default https://accounts.spotify.com (tests)
}

type conn struct {
	cfg  Config
	host sdk.Host
	api  *rest.Client
	http *http.Client

	mu      sync.Mutex
	access  string
	expires time.Time
	refresh string // a rotated refresh token, if Spotify sent one
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Spotify module.
func New() *Module { return &Module{} }

var (
	uriRe    = regexp.MustCompile(`^spotify:(track|episode):[A-Za-z0-9]{22}$`)
	deviceRe = regexp.MustCompile(`^[A-Za-z0-9]{8,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	device := `"device":{"type":"string","description":"Device id from Devices; empty uses the active one"}`
	return sdk.Manifest{
		ID: "spotify", Name: "Spotify", Version: "0.1.0", Category: "Media", Icon: "music",
		Description: "See what's playing and control playback on any of your Spotify devices.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["clientId","clientSecret","refreshToken"],"properties":{
			"clientId":{"type":"string","description":"From your app at developer.spotify.com/dashboard"},
			"clientSecret":{"type":"string","x-secret":true},
			"refreshToken":{"type":"string","x-secret":true,"description":"From the Authorization Code flow; see the module docs"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "now_playing", Title: "Now playing", Risk: sdk.RiskRead},
			{Name: "devices", Title: "Devices", Risk: sdk.RiskRead},
			{Name: "play", Title: "Play", Description: "Resume, or play a track.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","properties":{"uri":{"type":"string","description":"spotify:track:… (empty resumes)"},` + device + `}}`)},
			{Name: "pause", Title: "Pause", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(`{"type":"object","properties":{` + device + `}}`)},
			{Name: "next", Title: "Next track", Risk: sdk.RiskWrite, Input: sdk.Schema(`{"type":"object","properties":{` + device + `}}`)},
			{Name: "previous", Title: "Previous track", Risk: sdk.RiskWrite, Input: sdk.Schema(`{"type":"object","properties":{` + device + `}}`)},
			{Name: "volume", Title: "Volume", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["percent"],"properties":{"percent":{"type":"integer","minimum":0,"maximum":100},` + device + `}}`)},
			{Name: "queue", Title: "Add to queue", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["uri"],"properties":{"uri":{"type":"string","description":"spotify:track:…"},` + device + `}}`)},
			{Name: "search", Title: "Search tracks", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},"limit":{"type":"integer","default":10,"maximum":50}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.ClientID == "" || c.ClientSecret == "" || c.RefreshToken == "" {
		return errors.New("add the app's client id, its client secret and a refresh token (both stored in the vault)")
	}
	if c.API == "" {
		c.API = "https://api.spotify.com/v1"
	}
	if c.Accounts == "" {
		c.Accounts = "https://accounts.spotify.com"
	}
	cn := &conn{cfg: c, host: h, http: &http.Client{Timeout: 20 * time.Second}}
	if m.HTTP != nil {
		cn.http = m.HTTP
	}
	cn.api = rest.New(c.API, func(ctx context.Context, r *http.Request) error {
		t, err := cn.token(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = cn.http
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

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
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(c.cfg.Accounts, "/")+"/api/token", strings.NewReader(form.Encode()))
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
	c.expires = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	if t.Refresh != "" {
		c.refresh = t.Refresh
	}
	return c.access, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		Name    string `json:"display_name"`
		Product string `json:"product"`
	}
	if _, err := c.api.Do(ctx, "GET", "/me", nil, nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "Signed in as " + me.Name
	if me.Product != "" && me.Product != "premium" {
		return sdk.Health{Status: "degraded", Message: msg + "; playback control needs Spotify Premium"}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, 404):
		return errors.New("no active Spotify device; start playing on a device first, or pick one from Devices")
	case rest.IsStatus(err, 403):
		return errors.New("Spotify refused: playback control needs Premium, or the token lacks the playback scopes")
	}
	return err
}

type player struct {
	IsPlaying bool `json:"is_playing"`
	Progress  int  `json:"progress_ms"`
	Device    struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Volume *int   `json:"volume_percent"`
	} `json:"device"`
	Item *struct {
		Name     string `json:"name"`
		URI      string `json:"uri"`
		Duration int    `json:"duration_ms"`
		Artists  []struct {
			Name string `json:"name"`
		} `json:"artists"`
		Album struct {
			Name string `json:"name"`
		} `json:"album"`
	} `json:"item"`
}

// state returns the player, or nil when nothing is active (204).
func (c *conn) state(ctx context.Context) (*player, error) {
	var p player
	h, err := c.api.Do(ctx, "GET", "/me/player", nil, nil, &p)
	if err != nil {
		return nil, err
	}
	if h != nil && p.Device.ID == "" && p.Item == nil && !p.IsPlaying {
		return nil, nil
	}
	return &p, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		URI     string `json:"uri"`
		Device  string `json:"device"`
		Percent *int   `json:"percent"`
		Query   string `json:"query"`
		Limit   int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	q := url.Values{}
	if p.Device != "" {
		if !deviceRe.MatchString(p.Device) {
			return sdk.Result{}, errors.New("that isn't a Spotify device id")
		}
		q.Set("device_id", p.Device)
	}
	undoDev := map[string]string{}
	if p.Device != "" {
		undoDev["device"] = p.Device
	}
	switch call.Action {
	case "now_playing":
		st, err := c.state(ctx)
		if err != nil {
			return sdk.Result{}, friendly(err)
		}
		if st == nil || st.Item == nil {
			return sdk.JSON(map[string]any{"playing": false})
		}
		var artists []string
		for _, a := range st.Item.Artists {
			artists = append(artists, a.Name)
		}
		return sdk.JSON(map[string]any{"playing": st.IsPlaying, "track": st.Item.Name, "artists": strings.Join(artists, ", "), "album": st.Item.Album.Name,
			"uri": st.Item.URI, "progressSeconds": st.Progress / 1000, "durationSeconds": st.Item.Duration / 1000, "device": st.Device.Name, "volume": st.Device.Volume})

	case "devices":
		var d struct {
			Devices []struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				Type     string `json:"type"`
				IsActive bool   `json:"is_active"`
				Volume   *int   `json:"volume_percent"`
			} `json:"devices"`
		}
		if _, err := c.api.Do(ctx, "GET", "/me/player/devices", nil, nil, &d); err != nil {
			return sdk.Result{}, friendly(err)
		}
		type dev struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Type   string `json:"type"`
			Active bool   `json:"active"`
			Volume *int   `json:"volume,omitempty"`
		}
		list := []dev{}
		for _, x := range d.Devices {
			list = append(list, dev{x.ID, x.Name, x.Type, x.IsActive, x.Volume})
		}
		return sdk.JSON(list)

	case "play":
		var body any
		if p.URI != "" {
			if !uriRe.MatchString(p.URI) {
				return sdk.Result{}, errors.New("give a track as spotify:track:… (Share, Copy Song Link; the id is the last part)")
			}
			body = map[string]any{"uris": []string{p.URI}}
		}
		if _, err := c.api.Do(ctx, "PUT", "/me/player/play", q, body, nil); err != nil {
			return sdk.Result{}, friendly(err)
		}
		r, _ := sdk.JSON(map[string]bool{"playing": true})
		r.Undo = sdk.UndoWith("pause", undoDev, "Pause")
		return r, nil

	case "pause":
		if _, err := c.api.Do(ctx, "PUT", "/me/player/pause", q, nil, nil); err != nil {
			return sdk.Result{}, friendly(err)
		}
		r, _ := sdk.JSON(map[string]bool{"playing": false})
		r.Undo = sdk.UndoWith("play", undoDev, "Resume")
		return r, nil

	case "next", "previous":
		if _, err := c.api.Do(ctx, "POST", "/me/player/"+call.Action, q, nil, nil); err != nil {
			return sdk.Result{}, friendly(err)
		}
		return sdk.JSON(map[string]string{"skipped": call.Action})

	case "volume":
		if p.Percent == nil || *p.Percent < 0 || *p.Percent > 100 {
			return sdk.Result{}, errors.New("volume is 0 to 100")
		}
		var before *int
		if st, err := c.state(ctx); err == nil && st != nil {
			before = st.Device.Volume
		}
		q.Set("volume_percent", strconv.Itoa(*p.Percent))
		if _, err := c.api.Do(ctx, "PUT", "/me/player/volume", q, nil, nil); err != nil {
			return sdk.Result{}, friendly(err)
		}
		r, _ := sdk.JSON(map[string]int{"volume": *p.Percent})
		if before != nil {
			in := map[string]any{"percent": *before}
			if p.Device != "" {
				in["device"] = p.Device
			}
			r.Undo = sdk.UndoWith("volume", in, fmt.Sprintf("Set the volume back to %d%%", *before))
		}
		return r, nil

	case "queue":
		if !uriRe.MatchString(p.URI) {
			return sdk.Result{}, errors.New("give a track as spotify:track:…")
		}
		q.Set("uri", p.URI)
		if _, err := c.api.Do(ctx, "POST", "/me/player/queue", q, nil, nil); err != nil {
			return sdk.Result{}, friendly(err)
		}
		return sdk.JSON(map[string]string{"queued": p.URI})

	case "search":
		if strings.TrimSpace(p.Query) == "" {
			return sdk.Result{}, errors.New("what should I search for?")
		}
		limit := p.Limit
		if limit <= 0 || limit > 50 {
			limit = 10
		}
		var s struct {
			Tracks struct {
				Items []struct {
					Name    string `json:"name"`
					URI     string `json:"uri"`
					Artists []struct {
						Name string `json:"name"`
					} `json:"artists"`
					Album struct {
						Name string `json:"name"`
					} `json:"album"`
				} `json:"items"`
			} `json:"tracks"`
		}
		if _, err := c.api.Do(ctx, "GET", "/search", url.Values{"q": {p.Query}, "type": {"track"}, "limit": {strconv.Itoa(limit)}}, nil, &s); err != nil {
			return sdk.Result{}, friendly(err)
		}
		type track struct {
			Name    string `json:"name"`
			Artists string `json:"artists"`
			Album   string `json:"album"`
			URI     string `json:"uri"`
		}
		list := []track{}
		for _, x := range s.Tracks.Items {
			var a []string
			for _, ar := range x.Artists {
				a = append(a, ar.Name)
			}
			list = append(list, track{x.Name, strings.Join(a, ", "), x.Album.Name, x.URI})
		}
		return sdk.JSON(list)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
