// Package jellyfin shows what your Jellyfin (or Emby) media server holds and
// who's watching, and scans libraries or messages viewers.
package jellyfin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one media server.
type Config struct {
	URL    string `json:"url"`    // e.g. http://media.local:8096
	APIKey string `json:"apiKey"` // secret://
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Jellyfin module.
func New() *Module { return &Module{} }

var sessionRe = regexp.MustCompile(`^[A-Za-z0-9\-]{1,64}$`)

const session = `"session":{"type":"string","description":"Session id from Who's watching"}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "jellyfin", Name: "Jellyfin", Version: "0.1.0", Category: "Media", Icon: "film",
		Description: "Your media server: what's new, who's watching, library scans. Works with Emby too.",
		Presets:     []string{"homelab", "gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. http://media.local:8096"},
			"apiKey":{"type":"string","x-secret":true,"description":"Dashboard, API Keys, add one for Conduit"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "libraries", Title: "Libraries", Risk: sdk.RiskRead},
			{Name: "recent", Title: "Recently added", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":20,"maximum":100}}}`)},
			{Name: "sessions", Title: "Who's watching", Description: "Active sessions and what's playing.", Risk: sdk.RiskRead},
			{Name: "scan", Title: "Scan libraries", Description: "Look for new and changed files in every library.", Risk: sdk.RiskWrite},
			{Name: "message", Title: "Message a viewer", Description: "Shown on their screen.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["session","text"],"properties":{` + session + `,"text":{"type":"string","maxLength":200}}}`)},
			{Name: "stop", Title: "Stop playback", Description: "Stops what a session is playing.", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["session"],"properties":{` + session + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("the address is like http://media.local:8096")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	key := c.APIKey
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, key)
		if err != nil {
			return err
		}
		r.Header.Set("X-Emby-Token", k) // understood by Jellyfin and Emby
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
	// The key travels in X-Emby-Token, which Go would forward to another host.
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var info struct {
		ServerName string `json:"ServerName"`
		Version    string `json:"Version"`
	}
	if _, err := c.api.Do(ctx, "GET", "/System/Info", nil, nil, &info); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: info.ServerName + " " + info.Version}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Limit   int    `json:"limit"`
		Session string `json:"session"`
		Text    string `json:"text"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	needSession := func() error {
		if !sessionRe.MatchString(p.Session) {
			return errors.New("name a session (from Who's watching)")
		}
		return nil
	}
	switch call.Action {
	case "libraries":
		var libs []struct {
			Name           string   `json:"Name"`
			CollectionType string   `json:"CollectionType"`
			Locations      []string `json:"Locations"`
		}
		if _, err := c.api.Do(ctx, "GET", "/Library/VirtualFolders", nil, nil, &libs); err != nil {
			return sdk.Result{}, err
		}
		type lib struct {
			Name    string   `json:"name"`
			Kind    string   `json:"kind"`
			Folders []string `json:"folders"`
		}
		out := []lib{}
		for _, l := range libs {
			out = append(out, lib{Name: l.Name, Kind: l.CollectionType, Folders: l.Locations})
		}
		return sdk.JSON(out)

	case "recent":
		n := p.Limit
		if n <= 0 || n > 100 {
			n = 20
		}
		q := url.Values{"SortBy": {"DateCreated"}, "SortOrder": {"Descending"}, "Recursive": {"true"},
			"IncludeItemTypes": {"Movie,Episode,MusicAlbum,Book"}, "Limit": {strconv.Itoa(n)}, "Fields": {"DateCreated"}}
		var res struct {
			Items []struct {
				Name        string `json:"Name"`
				Type        string `json:"Type"`
				SeriesName  string `json:"SeriesName"`
				Year        int    `json:"ProductionYear"`
				DateCreated string `json:"DateCreated"`
			} `json:"Items"`
		}
		if _, err := c.api.Do(ctx, "GET", "/Items", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		type item struct {
			Title string `json:"title"`
			Kind  string `json:"kind"`
			Year  int    `json:"year,omitempty"`
			Added string `json:"added"`
		}
		out := []item{}
		for _, it := range res.Items {
			t := it.Name
			if it.SeriesName != "" {
				t = it.SeriesName + ": " + it.Name
			}
			out = append(out, item{Title: t, Kind: it.Type, Year: it.Year, Added: it.DateCreated})
		}
		return sdk.JSON(out)

	case "sessions":
		var ss []struct {
			ID         string `json:"Id"`
			UserName   string `json:"UserName"`
			Client     string `json:"Client"`
			DeviceName string `json:"DeviceName"`
			NowPlaying *struct {
				Name       string `json:"Name"`
				SeriesName string `json:"SeriesName"`
				Type       string `json:"Type"`
				RunTime    int64  `json:"RunTimeTicks"`
			} `json:"NowPlayingItem"`
			PlayState struct {
				IsPaused bool  `json:"IsPaused"`
				Position int64 `json:"PositionTicks"`
			} `json:"PlayState"`
		}
		if _, err := c.api.Do(ctx, "GET", "/Sessions", url.Values{"activeWithinSeconds": {"960"}}, nil, &ss); err != nil {
			return sdk.Result{}, err
		}
		type sess struct {
			ID       string `json:"session"`
			User     string `json:"user"`
			Device   string `json:"device"`
			Playing  string `json:"playing,omitempty"`
			Paused   bool   `json:"paused,omitempty"`
			Progress int    `json:"progressPercent,omitempty"`
		}
		out := []sess{}
		for _, s := range ss {
			x := sess{ID: s.ID, User: s.UserName, Device: strings.TrimSpace(s.DeviceName + " (" + s.Client + ")")}
			if s.NowPlaying != nil {
				x.Playing = s.NowPlaying.Name
				if s.NowPlaying.SeriesName != "" {
					x.Playing = s.NowPlaying.SeriesName + ": " + s.NowPlaying.Name
				}
				x.Paused = s.PlayState.IsPaused
				if s.NowPlaying.RunTime > 0 {
					x.Progress = int(s.PlayState.Position * 100 / s.NowPlaying.RunTime)
				}
			}
			out = append(out, x)
		}
		return sdk.JSON(out)

	case "scan":
		if _, err := c.api.Do(ctx, "POST", "/Library/Refresh", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"status": "scan started"})

	case "message":
		if err := needSession(); err != nil {
			return sdk.Result{}, err
		}
		text := strings.TrimSpace(p.Text)
		if text == "" || len(text) > 200 {
			return sdk.Result{}, errors.New("a message is 1 to 200 characters")
		}
		body := map[string]any{"Header": "Conduit", "Text": text, "TimeoutMs": 10000}
		if _, err := c.api.Do(ctx, "POST", "/Sessions/"+p.Session+"/Message", nil, body, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"session": p.Session, "status": "sent"})

	case "stop":
		if err := needSession(); err != nil {
			return sdk.Result{}, err
		}
		if _, err := c.api.Do(ctx, "POST", "/Sessions/"+p.Session+"/Playing/Stop", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"session": p.Session, "status": "stopped"})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
