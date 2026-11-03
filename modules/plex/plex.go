// Package plex watches a Plex Media Server: libraries, what was added, who
// is watching. It can rescan a library and stop a stream.
package plex

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

// Config is one Plex server.
type Config struct {
	URL   string `json:"url"`   // e.g. http://plex.local:32400
	Token string `json:"token"` // secret:// X-Plex-Token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Plex module.
func New() *Module { return &Module{} }

var (
	sectionRe = regexp.MustCompile(`^[0-9]{1,9}$`)
	sessionRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "plex", Name: "Plex", Version: "0.1.0", Category: "Media", Icon: "play",
		Description: "Your Plex Media Server: libraries, new arrivals and who's watching right now.",
		Presets:     []string{"homelab", "gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. http://plex.local:32400"},
			"token":{"type":"string","x-secret":true,"description":"X-Plex-Token (Plex support article \"Finding an authentication token\")"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "libraries", Title: "Libraries", Risk: sdk.RiskRead},
			{Name: "recent", Title: "Recently added", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":20,"maximum":100},"library":{"type":"string","description":"Library id from libraries; all when empty"}}}`)},
			{Name: "sessions", Title: "Watching now", Description: "Streams in progress: who, what, on which device, and whether it's transcoding.", Risk: sdk.RiskRead},
			{Name: "refresh", Title: "Scan a library", Description: "Looks for new and changed files in a library.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["library"],"properties":{"library":{"type":"string","description":"Library id from libraries"}}}`)},
			{Name: "stop", Title: "Stop a stream", Description: "Ends someone's playback and shows them a message (needs Plex Pass on the server).", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["session"],"properties":{"session":{"type":"string","description":"Session id from sessions"},"message":{"type":"string","default":"Stopped by the server owner."}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return errors.New("the address is like http://plex.local:32400")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the Plex token in the vault and enter its secret:// reference")
	}
	tok := c.Token
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("X-Plex-Token", strings.TrimSpace(t))
		r.Header.Set("X-Plex-Product", "Conduit")
		r.Header.Set("X-Plex-Client-Identifier", "conduit-"+id)
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

type container struct {
	MediaContainer struct {
		Size              int         `json:"size"`
		FriendlyName      string      `json:"friendlyName"`
		Version           string      `json:"version"`
		Directory         []directory `json:"Directory"`
		Metadata          []metadata  `json:"Metadata"`
		MachineIdentifier string      `json:"machineIdentifier"`
	} `json:"MediaContainer"`
}

type directory struct {
	Key        string `json:"key"`
	Title      string `json:"title"`
	Type       string `json:"type"`
	Agent      string `json:"agent"`
	Refreshing bool   `json:"refreshing"`
	ScannedAt  int64  `json:"scannedAt"`
}

type metadata struct {
	RatingKey        string `json:"ratingKey"`
	Type             string `json:"type"`
	Title            string `json:"title"`
	GrandparentTitle string `json:"grandparentTitle"`
	ParentTitle      string `json:"parentTitle"`
	LibrarySection   string `json:"librarySectionTitle"`
	Year             int    `json:"year"`
	AddedAt          int64  `json:"addedAt"`
	Duration         int64  `json:"duration"`
	ViewOffset       int64  `json:"viewOffset"`
	User             *struct {
		Title string `json:"title"`
	} `json:"User"`
	Player *struct {
		Title    string `json:"title"`
		Product  string `json:"product"`
		State    string `json:"state"`
		Local    bool   `json:"local"`
		Platform string `json:"platform"`
	} `json:"Player"`
	Session *struct {
		ID        string `json:"id"`
		Bandwidth int    `json:"bandwidth"`
		Location  string `json:"location"`
	} `json:"Session"`
	TranscodeSession *struct {
		VideoDecision string `json:"videoDecision"`
	} `json:"TranscodeSession"`
}

// fullTitle is "Show – Season – Episode" for episodes and the title otherwise.
func (md metadata) fullTitle() string {
	parts := []string{}
	for _, s := range []string{md.GrandparentTitle, md.ParentTitle, md.Title} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " – ")
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var r container
	if _, err := c.api.Do(ctx, http.MethodGet, "/", nil, nil, &r); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "the server refused the token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: strings.TrimSpace(r.MediaContainer.FriendlyName + " " + r.MediaContainer.Version)}
}

type session struct {
	Session     string `json:"session"`
	User        string `json:"user"`
	Title       string `json:"title"`
	Type        string `json:"type"`
	Player      string `json:"player"`
	State       string `json:"state"`
	Progress    int    `json:"progress"` // percent
	Transcoding bool   `json:"transcoding"`
	Local       bool   `json:"local"`
}

func (m *Module) sessions(ctx context.Context, c *conn) ([]session, error) {
	var r container
	if _, err := c.api.Do(ctx, http.MethodGet, "/status/sessions", nil, nil, &r); err != nil {
		return nil, err
	}
	out := []session{}
	for _, md := range r.MediaContainer.Metadata {
		s := session{Title: md.fullTitle(), Type: md.Type}
		if md.Session != nil {
			s.Session = md.Session.ID
		}
		if md.User != nil {
			s.User = md.User.Title
		}
		if md.Player != nil {
			s.Player = strings.TrimSpace(md.Player.Title + " (" + md.Player.Product + ")")
			s.State = md.Player.State
			s.Local = md.Player.Local
		}
		if md.Duration > 0 {
			s.Progress = int(md.ViewOffset * 100 / md.Duration)
		}
		s.Transcoding = md.TranscodeSession != nil && md.TranscodeSession.VideoDecision == "transcode"
		out = append(out, s)
	}
	return out, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Limit   int    `json:"limit"`
		Library string `json:"library"`
		Session string `json:"session"`
		Message string `json:"message"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if p.Library != "" && !sectionRe.MatchString(p.Library) {
		return sdk.Result{}, errors.New("the library id is a number from libraries")
	}
	switch call.Action {
	case "libraries":
		var r container
		if _, err := c.api.Do(ctx, http.MethodGet, "/library/sections", nil, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range r.MediaContainer.Directory {
			out = append(out, map[string]any{"id": d.Key, "title": d.Title, "type": d.Type, "scanning": d.Refreshing, "scannedAt": d.ScannedAt})
		}
		return sdk.JSON(out)

	case "recent":
		limit := p.Limit
		if limit <= 0 {
			limit = 20
		}
		if limit > 100 {
			limit = 100
		}
		path := "/library/recentlyAdded"
		if p.Library != "" {
			path = "/library/sections/" + p.Library + "/recentlyAdded"
		}
		q := url.Values{"X-Plex-Container-Start": {"0"}, "X-Plex-Container-Size": {strconv.Itoa(limit)}}
		var r container
		if _, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i, md := range r.MediaContainer.Metadata {
			if i >= limit {
				break
			}
			out = append(out, map[string]any{"id": md.RatingKey, "title": md.fullTitle(), "type": md.Type, "year": md.Year, "library": md.LibrarySection, "addedAt": md.AddedAt})
		}
		return sdk.JSON(out)

	case "sessions":
		s, err := m.sessions(ctx, c)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(s)

	case "refresh":
		if p.Library == "" {
			return sdk.Result{}, errors.New("choose a library")
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/library/sections/"+p.Library+"/refresh", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"scanning": p.Library})

	case "stop":
		if !sessionRe.MatchString(p.Session) {
			return sdk.Result{}, errors.New("the session id comes from sessions")
		}
		msg := strings.TrimSpace(p.Message)
		if msg == "" {
			msg = "Stopped by the server owner."
		}
		if len(msg) > 300 {
			return sdk.Result{}, errors.New("keep the message under 300 characters")
		}
		all, err := m.sessions(ctx, c)
		if err != nil {
			return sdk.Result{}, err
		}
		var found *session
		for i := range all {
			if all[i].Session == p.Session {
				found = &all[i]
			}
		}
		if found == nil {
			return sdk.Result{}, errors.New("that stream isn't playing any more")
		}
		if call.DryRun {
			before, _ := json.Marshal(found)
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Stop %s watching %s on %s", found.User, found.Title, found.Player),
				Changes: []sdk.Change{{Target: "session " + p.Session, Op: "stop", Before: before}}}}, nil
		}
		q := url.Values{"sessionId": {p.Session}, "reason": {msg}}
		if _, err := c.api.Do(ctx, http.MethodGet, "/status/sessions/terminate", q, nil, nil); err != nil {
			if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
				return sdk.Result{}, errors.New("the server refused; stopping streams needs Plex Pass and the owner's token")
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"stopped": p.Session, "user": found.User, "title": found.Title})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
