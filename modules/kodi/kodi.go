// Package kodi works with Kodi through its JSON-RPC API over HTTP (Settings
// → Services → Control → Allow remote control via HTTP): what's playing,
// play/pause and stop, the volume, library scans, notifications on the
// screen, and recently added movies and episodes.
package kodi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Kodi.
type Config struct {
	URL                string `json:"url"`      // e.g. http://livingroom.local:8080
	Username           string `json:"username"` // "kodi" by default
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
	id  atomic.Int64
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Kodi module.
func New() *Module { return &Module{} }

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	player := `"player":{"type":"integer","minimum":0,"maximum":100,"description":"Player id (see players); the active one by default"}`
	recent := `{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":100,"default":10}}}`
	return sdk.Manifest{
		ID: "kodi", Name: "Kodi", Version: "0.1.0", Category: "Media", Icon: "play",
		Description: "Kodi: what's playing, play/pause and stop, volume, library scans, notifications on screen, recently added movies and episodes.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Kodi's web server, e.g. http://livingroom.local:8080"},
			"username":{"type":"string","default":"kodi"},
			"password":{"type":"string","x-secret":true,"description":"The web server password (Settings → Services → Control)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the certificate, when Kodi serves HTTPS with its own"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "players", Title: "Now playing", Description: "The active players with what they play, whether paused, position and length; and the volume.", Risk: sdk.RiskRead},
			{Name: "play_pause", Title: "Play or pause", Description: "Pauses or resumes a player (toggles without play). Undo puts it back.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + player + `,"play":{"type":"boolean","description":"true plays, false pauses; leave out to toggle"}}}`)},
			{Name: "stop", Title: "Stop", Description: "Stops a player.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + player + `}}`)},
			{Name: "set_volume", Title: "Set the volume", Description: "Sets the volume (0–100) and/or mutes or unmutes. Undo restores both.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","properties":{"volume":{"type":"integer","minimum":0,"maximum":100},"muted":{"type":"boolean"}}}`)},
			{Name: "scan_library", Title: "Update the library", Description: "Scans the video or music sources for new items.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"library":{"type":"string","enum":["video","audio"],"default":"video"}}}`)},
			{Name: "notify", Title: "Show a notification", Description: "Shows a notification on Kodi's screen.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["title","message"],"properties":{"title":{"type":"string","maxLength":100},"message":{"type":"string","maxLength":500},"seconds":{"type":"integer","minimum":2,"maximum":60,"default":5}}}`)},
			{Name: "recent_movies", Title: "Recently added movies", Description: "Movies added to the library, newest first.", Risk: sdk.RiskRead, Input: sdk.Schema(recent)},
			{Name: "recent_episodes", Title: "Recently added episodes", Description: "TV episodes added to the library, newest first.", Risk: sdk.RiskRead, Input: sdk.Schema(recent)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like http://livingroom.local:8080")
	}
	user := strings.TrimSpace(c.Username)
	if user == "" {
		user = "kodi"
	}
	if len(user) > 256 || strings.ContainsAny(user, ":\x00\r\n") {
		return errors.New("the username can't contain a colon or control characters")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 15 * time.Second, Transport: tr}
	}
	ref := c.Password
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/jsonrpc"), func(ctx context.Context, r *http.Request) error {
		if ref == "" {
			return nil
		}
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, pw)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// rpc calls one JSON-RPC method.
func (c *conn) rpc(ctx context.Context, method string, params, out any) error {
	req := map[string]any{"jsonrpc": "2.0", "method": method, "id": c.id.Add(1)}
	if params != nil {
		req["params"] = params
	}
	var res struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_, err := c.api.Do(ctx, http.MethodPost, "/jsonrpc", nil, req, &res)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Kodi refused the username or password")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no Kodi JSON-RPC at this address (turn on Allow remote control via HTTP)")
	case err != nil:
		return err
	}
	if res.Error != nil {
		return fmt.Errorf("Kodi refused %s: %s", method, res.Error.Message)
	}
	if len(res.Result) == 0 {
		return errors.New("unexpected answer from Kodi")
	}
	if out != nil {
		if err := json.Unmarshal(res.Result, out); err != nil {
			return fmt.Errorf("unexpected answer from Kodi to %s", method)
		}
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var app struct {
		Name    string `json:"name"`
		Version struct {
			Major int    `json:"major"`
			Minor int    `json:"minor"`
			Tag   string `json:"tag"`
		} `json:"version"`
	}
	if err := c.rpc(ctx, "Application.GetProperties", map[string]any{"properties": []string{"name", "version"}}, &app); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%s %d.%d", app.Name, app.Version.Major, app.Version.Minor)
	if app.Version.Tag != "" && app.Version.Tag != "stable" {
		msg += " " + app.Version.Tag
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type activePlayer struct {
	ID   int    `json:"playerid"`
	Type string `json:"type"`
}

type kodiTime struct {
	Hours   int `json:"hours"`
	Minutes int `json:"minutes"`
	Seconds int `json:"seconds"`
}

func (t kodiTime) String() string { return fmt.Sprintf("%d:%02d:%02d", t.Hours, t.Minutes, t.Seconds) }

type playerState struct {
	Speed      float64  `json:"speed"`
	Time       kodiTime `json:"time"`
	TotalTime  kodiTime `json:"totaltime"`
	Percentage float64  `json:"percentage"`
	Shuffled   bool     `json:"shuffled"`
	Repeat     string   `json:"repeat"`
}

type item struct {
	Type      string   `json:"type"`
	Label     string   `json:"label"`
	Title     string   `json:"title"`
	Artist    []string `json:"artist"`
	Album     string   `json:"album"`
	ShowTitle string   `json:"showtitle"`
	Season    int      `json:"season"`
	Episode   int      `json:"episode"`
	Year      int      `json:"year"`
}

func (it item) name() string {
	switch {
	case it.ShowTitle != "" && it.Season > 0:
		return fmt.Sprintf("%s S%02dE%02d %s", it.ShowTitle, it.Season, it.Episode, it.Title)
	case len(it.Artist) > 0 && it.Title != "":
		return strings.Join(it.Artist, ", ") + " – " + it.Title
	case it.Title != "":
		return it.Title
	}
	return it.Label
}

func (it item) out() map[string]any {
	e := map[string]any{"type": it.Type, "name": it.name()}
	if it.Title != "" {
		e["title"] = it.Title
	}
	if len(it.Artist) > 0 {
		e["artist"] = strings.Join(it.Artist, ", ")
	}
	if it.Album != "" {
		e["album"] = it.Album
	}
	if it.ShowTitle != "" {
		e["show"], e["season"], e["episode"] = it.ShowTitle, it.Season, it.Episode
	}
	if it.Year > 0 {
		e["year"] = it.Year
	}
	return e
}

func (c *conn) active(ctx context.Context) ([]activePlayer, error) {
	var ps []activePlayer
	err := c.rpc(ctx, "Player.GetActivePlayers", nil, &ps)
	return ps, err
}

// pick finds the player to act on: the one asked for (which must be
// active) or the first active one.
func (c *conn) pick(ctx context.Context, want *int) (activePlayer, error) {
	if want != nil && (*want < 0 || *want > 100) {
		return activePlayer{}, errors.New("the player id is between 0 and 100 (see players)")
	}
	ps, err := c.active(ctx)
	if err != nil {
		return activePlayer{}, err
	}
	if len(ps) == 0 {
		return activePlayer{}, errors.New("nothing is playing")
	}
	if want == nil {
		return ps[0], nil
	}
	for _, p := range ps {
		if p.ID == *want {
			return p, nil
		}
	}
	return activePlayer{}, fmt.Errorf("player %d isn't active (see players)", *want)
}

func (c *conn) state(ctx context.Context, id int) (playerState, item, error) {
	var st playerState
	var it struct {
		Item item `json:"item"`
	}
	if err := c.rpc(ctx, "Player.GetProperties", map[string]any{"playerid": id, "properties": []string{"speed", "time", "totaltime", "percentage", "shuffled", "repeat"}}, &st); err != nil {
		return st, it.Item, err
	}
	// No "file": paths to network shares can hold their passwords.
	err := c.rpc(ctx, "Player.GetItem", map[string]any{"playerid": id, "properties": []string{"title", "artist", "album", "showtitle", "season", "episode", "year"}}, &it)
	return st, it.Item, err
}

type volume struct {
	Volume int  `json:"volume"`
	Muted  bool `json:"muted"`
}

func (c *conn) volume(ctx context.Context) (volume, error) {
	var v volume
	err := c.rpc(ctx, "Application.GetProperties", map[string]any{"properties": []string{"volume", "muted"}}, &v)
	return v, err
}

type input struct {
	Player  *int   `json:"player"`
	Play    *bool  `json:"play"`
	Volume  *int   `json:"volume"`
	Muted   *bool  `json:"muted"`
	Library string `json:"library"`
	Title   string `json:"title"`
	Message string `json:"message"`
	Seconds int    `json:"seconds"`
	Limit   int    `json:"limit"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func plainText(s string, max int, what string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("enter the %s", what)
	}
	if len([]rune(s)) > max {
		return "", fmt.Errorf("the %s is longer than %d characters", what, max)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("the %s has control characters", what)
		}
	}
	return s, nil
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
	case "players":
		ps, err := c.active(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, pl := range ps {
			st, it, err := c.state(ctx, pl.ID)
			if err != nil {
				return sdk.Result{}, err
			}
			e := map[string]any{"player": pl.ID, "type": pl.Type, "playing": st.Speed != 0, "position": st.Time.String(), "length": st.TotalTime.String(),
				"percent": float64(int(st.Percentage*10+0.5)) / 10, "item": it.out()}
			if st.Speed != 0 && st.Speed != 1 {
				e["speed"] = st.Speed
			}
			out = append(out, e)
		}
		v, err := c.volume(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"volume": v.Volume, "muted": v.Muted, "players": out})

	case "play_pause":
		pl, err := c.pick(ctx, p.Player)
		if err != nil {
			return sdk.Result{}, err
		}
		st, it, err := c.state(ctx, pl.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		was := st.Speed != 0
		want := !was
		if p.Play != nil {
			want = *p.Play
		}
		verb := map[bool]string{true: "Resume", false: "Pause"}[want]
		if call.DryRun {
			sum := verb + " " + it.name()
			if want == was {
				sum = it.name() + " is already " + map[bool]string{true: "playing", false: "paused"}[was] + "; nothing would change"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: fmt.Sprintf("%s player %d", pl.Type, pl.ID), Op: strings.ToLower(verb),
				Before: mustJSON(map[string]bool{"playing": was}), After: mustJSON(map[string]bool{"playing": want})}}}}, nil
		}
		if want == was {
			return sdk.JSON(map[string]any{"player": pl.ID, "playing": was, "changed": false})
		}
		var now struct {
			Speed float64 `json:"speed"`
		}
		if err := c.rpc(ctx, "Player.PlayPause", map[string]any{"playerid": pl.ID, "play": want}, &now); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"player": pl.ID, "playing": now.Speed != 0, "changed": true, "item": it.name()})
		res.Undo = sdk.UndoWith("play_pause", map[string]any{"player": pl.ID, "play": was}, map[bool]string{true: "Resume ", false: "Pause "}[was]+it.name())
		return res, err

	case "stop":
		pl, err := c.pick(ctx, p.Player)
		if err != nil {
			return sdk.Result{}, err
		}
		st, it, err := c.state(ctx, pl.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Stop " + it.name() + " at " + st.Time.String(),
				Changes: []sdk.Change{{Target: fmt.Sprintf("%s player %d", pl.Type, pl.ID), Op: "stop", Before: mustJSON(it.out())}}}}, nil
		}
		if err := c.rpc(ctx, "Player.Stop", map[string]any{"playerid": pl.ID}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"player": pl.ID, "stopped": it.name(), "at": st.Time.String()})

	case "set_volume":
		if p.Volume == nil && p.Muted == nil {
			return sdk.Result{}, errors.New("say what to change: volume or muted")
		}
		if p.Volume != nil && (*p.Volume < 0 || *p.Volume > 100) {
			return sdk.Result{}, errors.New("the volume is between 0 and 100")
		}
		old, err := c.volume(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		next := old
		if p.Volume != nil {
			next.Volume = *p.Volume
		}
		if p.Muted != nil {
			next.Muted = *p.Muted
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Set Kodi's volume to %d%s", next.Volume, map[bool]string{true: " (muted)", false: ""}[next.Muted]),
				Changes: []sdk.Change{{Target: "volume", Op: "update", Before: mustJSON(old), After: mustJSON(next)}}}}, nil
		}
		if p.Volume != nil && next.Volume != old.Volume {
			if err := c.rpc(ctx, "Application.SetVolume", map[string]any{"volume": next.Volume}, nil); err != nil {
				return sdk.Result{}, err
			}
		}
		if p.Muted != nil && next.Muted != old.Muted {
			if err := c.rpc(ctx, "Application.SetMute", map[string]any{"mute": next.Muted}, nil); err != nil {
				return sdk.Result{}, err
			}
		}
		now, err := c.volume(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(now)
		res.Undo = sdk.UndoWith("set_volume", map[string]any{"volume": old.Volume, "muted": old.Muted}, fmt.Sprintf("Set the volume back to %d", old.Volume))
		return res, err

	case "scan_library":
		lib := p.Library
		if lib == "" {
			lib = "video"
		}
		method := map[string]string{"video": "VideoLibrary.Scan", "audio": "AudioLibrary.Scan"}[lib]
		if method == "" {
			return sdk.Result{}, errors.New("library is video or audio")
		}
		name := map[string]string{"video": "video", "audio": "music"}[lib]
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Scan Kodi's " + name + " sources for new items", Changes: []sdk.Change{{Target: name + " library", Op: "scan"}}}}, nil
		}
		if err := c.rpc(ctx, method, map[string]any{"showdialogs": false}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"library": name, "scanStarted": true})

	case "notify":
		title, err := plainText(p.Title, 100, "title")
		if err != nil {
			return sdk.Result{}, err
		}
		msg, err := plainText(p.Message, 500, "message")
		if err != nil {
			return sdk.Result{}, err
		}
		secs := p.Seconds
		if secs == 0 {
			secs = 5
		}
		if secs < 2 || secs > 60 {
			return sdk.Result{}, errors.New("seconds is between 2 and 60")
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Show %q on Kodi's screen for %d seconds", title, secs),
				Changes: []sdk.Change{{Target: "screen", Op: "notify", After: mustJSON(map[string]string{"title": title, "message": msg})}}}}, nil
		}
		if err := c.rpc(ctx, "GUI.ShowNotification", map[string]any{"title": title, "message": msg, "displaytime": secs * 1000}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"shown": true, "title": title})

	case "recent_movies", "recent_episodes":
		n := p.Limit
		if n == 0 {
			n = 10
		}
		if n < 1 || n > 100 {
			return sdk.Result{}, errors.New("limit is between 1 and 100")
		}
		type media struct {
			Title      string   `json:"title"`
			Year       int      `json:"year"`
			Rating     float64  `json:"rating"`
			Runtime    int      `json:"runtime"`
			DateAdded  string   `json:"dateadded"`
			Genre      []string `json:"genre"`
			PlayCount  int      `json:"playcount"`
			ShowTitle  string   `json:"showtitle"`
			Season     int      `json:"season"`
			Episode    int      `json:"episode"`
			FirstAired string   `json:"firstaired"`
			MovieID    int      `json:"movieid"`
			EpisodeID  int      `json:"episodeid"`
		}
		var r struct {
			Movies   []media `json:"movies"`
			Episodes []media `json:"episodes"`
		}
		limits := map[string]int{"start": 0, "end": n}
		if call.Action == "recent_movies" {
			err = c.rpc(ctx, "VideoLibrary.GetRecentlyAddedMovies", map[string]any{"properties": []string{"title", "year", "rating", "runtime", "dateadded", "genre", "playcount"}, "limits": limits}, &r)
		} else {
			err = c.rpc(ctx, "VideoLibrary.GetRecentlyAddedEpisodes", map[string]any{"properties": []string{"title", "showtitle", "season", "episode", "firstaired", "dateadded", "playcount", "runtime"}, "limits": limits}, &r)
		}
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range append(r.Movies, r.Episodes...) {
			e := map[string]any{"title": x.Title, "added": x.DateAdded, "watched": x.PlayCount > 0}
			if x.Runtime > 0 {
				e["minutes"] = (x.Runtime + 30) / 60
			}
			if call.Action == "recent_movies" {
				e["id"] = x.MovieID
				if x.Year > 0 {
					e["year"] = x.Year
				}
				if x.Rating > 0 {
					e["rating"] = float64(int(x.Rating*10+0.5)) / 10
				}
				if len(x.Genre) > 0 {
					e["genres"] = x.Genre
				}
			} else {
				e["id"], e["show"], e["season"], e["episode"] = x.EpisodeID, x.ShowTitle, x.Season, x.Episode
				if x.FirstAired != "" {
					e["aired"] = x.FirstAired
				}
			}
			out = append(out, e)
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
