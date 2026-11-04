// Package vlc controls VLC media player through its HTTP interface (Tools,
// Preferences, All, Interface, Main interfaces: Web, with a Lua HTTP
// password): what's playing, play and pause, next and previous, the volume
// and the playlist.
package vlc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

// Config is one VLC.
type Config struct {
	URL      string `json:"url"`      // default http://127.0.0.1:8080
	Password string `json:"password"` // secret://, the Lua HTTP password
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the VLC module.
func New() *Module { return &Module{} }

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	none := sdk.Schema(`{"type":"object","properties":{}}`)
	return sdk.Manifest{
		ID: "vlc", Name: "VLC", Version: "0.1.0", Category: "Media", Icon: "play",
		Description: "VLC media player: what's playing, play and pause, next and previous, volume and the playlist.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["password"],"properties":{
			"url":{"type":"string","default":"http://127.0.0.1:8080","description":"VLC's web interface (start VLC with the Web interface on; port 8080 unless --http-port changes it)"},
			"password":{"type":"string","x-secret":true,"description":"The Lua HTTP password (Preferences, All, Interface, Main interfaces, Lua)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Status", Description: "Playing, paused or stopped, position, volume, shuffle and repeat.", Risk: sdk.RiskRead},
			{Name: "now_playing", Title: "Now playing", Description: "Title, artist, album or stream info of what's playing, with position and length.", Risk: sdk.RiskRead},
			{Name: "play", Title: "Play", Description: "Resumes or starts playback. Undo pauses again if it was paused.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Input: none},
			{Name: "pause", Title: "Pause", Description: "Pauses playback. Undo resumes it.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Input: none},
			{Name: "next", Title: "Next", Description: "Skips to the next playlist item. Undo goes back.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Input: none},
			{Name: "previous", Title: "Previous", Description: "Goes back to the previous playlist item. Undo skips forward again.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Input: none},
			{Name: "set_volume", Title: "Set the volume", Description: "Sets the volume in percent (100 is normal, up to 200). Undo restores it.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["percent"],"properties":{"percent":{"type":"integer","minimum":0,"maximum":200}}}`)},
			{Name: "playlist", Title: "Playlist", Description: "The playlist's items with their length, marking the current one.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":500,"default":100}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = "http://127.0.0.1:8080"
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like http://127.0.0.1:8080")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("VLC's web interface needs a password: store it in the vault and enter its secret:// reference")
	}
	cl := m.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 10 * time.Second, Transport: sdk.Transport(h)}
	}
	ref := c.Password
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/requests")
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.SetBasicAuth("", pw) // VLC has no user name
		return nil
	})
	api.HTTP = rest.SameHostOnly(cl)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

type status struct {
	State    string  `json:"state"`
	Volume   int     `json:"volume"` // 0–512, 256 is 100%
	Time     int     `json:"time"`
	Length   int     `json:"length"`
	Position float64 `json:"position"`
	Random   bool    `json:"random"`
	Loop     bool    `json:"loop"`
	Repeat   bool    `json:"repeat"`
	Version  string  `json:"version"`
	Info     struct {
		Category struct {
			Meta map[string]any `json:"meta"`
		} `json:"category"`
	} `json:"information"`
}

func (s status) meta(k string) string {
	v, _ := s.Info.Category.Meta[k].(string)
	return v
}

func (s status) title() string {
	for _, k := range []string{"title", "now_playing", "filename"} {
		if v := s.meta(k); v != "" {
			return v
		}
	}
	return ""
}

func percent(vol int) int { return int(math.Round(float64(vol) * 100 / 256)) }

func friendly(err error) error {
	if rest.IsStatus(err, http.StatusUnauthorized) {
		return &rest.Error{Status: http.StatusUnauthorized, Message: "VLC refused the password"}
	}
	var re *rest.Error
	if errors.As(err, &re) || errors.Is(err, rest.ErrCrossHostRedirect) || errors.Is(err, rest.ErrInsecureRedirect) || errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("couldn't reach VLC (is it running with the web interface on?): %w", err)
}

// status runs an optional command and returns the status after it.
func (c *conn) status(ctx context.Context, q url.Values) (status, error) {
	var s status
	if _, err := c.api.Do(ctx, "GET", "/requests/status.json", q, nil, &s); err != nil {
		return status{}, friendly(err)
	}
	if s.State == "" {
		return status{}, errors.New("unexpected answer from VLC")
	}
	return s, nil
}

func (c *conn) command(ctx context.Context, cmd string, extra url.Values) (status, error) {
	q := url.Values{"command": {cmd}}
	for k, v := range extra {
		q[k] = v
	}
	if _, err := c.status(ctx, q); err != nil {
		return status{}, err
	}
	// VLC answers before the command takes effect; read it again.
	return c.status(ctx, nil)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.status(ctx, nil)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "VLC"
	if f := strings.Fields(s.Version); len(f) > 0 {
		msg += " " + f[0]
	}
	msg += " · " + s.State
	if t := s.title(); t != "" && s.State != "stopped" {
		msg += ": " + t
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func plan(summary, target string, before, after any) *sdk.Plan {
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	return &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: target, Op: "update", Before: b, After: a}}}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Percent *int `json:"percent"`
		Limit   int  `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "status":
		s, err := c.status(ctx, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"state": s.State, "title": s.title(), "time": s.Time, "length": s.Length,
			"position": math.Round(s.Position*1000) / 10, "volume": percent(s.Volume), "shuffle": s.Random, "loop": s.Loop, "repeat": s.Repeat})

	case "now_playing":
		s, err := c.status(ctx, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"state": s.State}
		if s.State != "stopped" {
			for _, k := range []string{"title", "artist", "album", "genre", "now_playing", "filename"} {
				if v := s.meta(k); v != "" {
					key := k
					if k == "now_playing" {
						key = "nowPlaying"
					}
					out[key] = v
				}
			}
			out["time"], out["length"] = s.Time, s.Length
		}
		return sdk.JSON(out)

	case "play", "pause":
		before, err := c.status(ctx, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		want := map[string]string{"play": "playing", "pause": "paused"}[call.Action]
		if call.DryRun {
			return sdk.Result{Plan: plan(strings.ToUpper(call.Action[:1])+call.Action[1:]+" VLC", "VLC", map[string]string{"state": before.State}, map[string]string{"state": want})}, nil
		}
		if before.State == want {
			return sdk.JSON(map[string]any{"state": before.State, "unchanged": true})
		}
		var cmd string
		switch {
		case call.Action == "pause" && before.State == "stopped":
			return sdk.Result{}, errors.New("VLC is stopped; there's nothing to pause")
		case call.Action == "pause":
			cmd = "pl_forcepause"
		case before.State == "paused":
			cmd = "pl_forceresume"
		default:
			cmd = "pl_play"
		}
		after, err := c.command(ctx, cmd, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"state": after.State, "title": after.title()})
		switch {
		case call.Action == "pause":
			r.Undo = sdk.UndoWith("play", map[string]any{}, "Resume playback")
		case before.State == "paused":
			r.Undo = sdk.UndoWith("pause", map[string]any{}, "Pause again")
		}
		return r, nil

	case "next", "previous":
		before, err := c.status(ctx, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: plan("Skip to the "+call.Action+" item in VLC", "VLC", map[string]string{"title": before.title()}, map[string]string{"title": "(" + call.Action + " item)"})}, nil
		}
		cmd, back := "pl_next", "previous"
		if call.Action == "previous" {
			cmd, back = "pl_previous", "next"
		}
		after, err := c.command(ctx, cmd, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"state": after.State, "title": after.title()})
		r.Undo = sdk.UndoWith(back, map[string]any{}, "Go back to "+strconv.Quote(before.title()))
		if before.title() == "" {
			r.Undo.Description = "Go back"
		}
		return r, nil

	case "set_volume":
		if p.Percent == nil || *p.Percent < 0 || *p.Percent > 200 {
			return sdk.Result{}, errors.New("percent is 0 to 200 (100 is normal)")
		}
		before, err := c.status(ctx, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		old := percent(before.Volume)
		if call.DryRun {
			return sdk.Result{Plan: plan(fmt.Sprintf("Set VLC's volume to %d%%", *p.Percent), "VLC volume", map[string]int{"percent": old}, map[string]int{"percent": *p.Percent})}, nil
		}
		val := int(math.Round(float64(*p.Percent) * 256 / 100))
		after, err := c.command(ctx, "volume", url.Values{"val": {strconv.Itoa(val)}})
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]int{"percent": percent(after.Volume)})
		r.Undo = sdk.UndoWith("set_volume", map[string]int{"percent": min(old, 200)}, fmt.Sprintf("Set the volume back to %d%%", old))
		return r, nil

	case "playlist":
		limit := p.Limit
		if limit == 0 {
			limit = 100
		}
		if limit < 1 || limit > 500 {
			return sdk.Result{}, errors.New("limit is 1 to 500")
		}
		var root node
		if _, err := c.api.Do(ctx, "GET", "/requests/playlist.json", nil, nil, &root); err != nil {
			return sdk.Result{}, friendly(err)
		}
		start := &root
		for i := range root.Children {
			if root.Children[i].Type == "node" && (root.Children[i].ID == "1" || root.Children[i].Name == "Playlist") {
				start = &root.Children[i]
				break
			}
		}
		type item struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Duration int    `json:"duration,omitempty"`
			Current  bool   `json:"current,omitempty"`
		}
		items := []item{}
		total := 0
		var walk func(n *node, depth int)
		walk = func(n *node, depth int) {
			if depth > 20 {
				return
			}
			for i := range n.Children {
				ch := &n.Children[i]
				if ch.Type == "leaf" {
					total++
					if len(items) < limit {
						// The URI is left out: a network share's can hold its password.
						items = append(items, item{ID: ch.ID, Name: ch.Name, Duration: max(ch.Duration, 0), Current: ch.Current == "current"})
					}
					continue
				}
				walk(ch, depth+1)
			}
		}
		walk(start, 0)
		return sdk.JSON(map[string]any{"total": total, "items": items})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type node struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	ID       string `json:"id"`
	Duration int    `json:"duration"`
	Current  string `json:"current"`
	Children []node `json:"children"`
}
