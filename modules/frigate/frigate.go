// Package frigate works with a Frigate NVR through its HTTP API (and its
// websocket for the switches the HTTP API doesn't have): cameras with their
// detection and recording state and stats, detectors and storage, recent
// tracked objects (events) with labels, scores and snapshot metadata,
// turning detection or recording on or off per camera, and keeping events.
package frigate

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

	"github.com/coder/websocket"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Frigate server.
type Config struct {
	URL                string `json:"url"`      // e.g. https://frigate.local:8971 or http://frigate.local:5000
	Username           string `json:"username"` // for the authenticated port (8971)
	Password           string `json:"password"` // secret://, with username
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api  *rest.Client
	ws   string // websocket address
	http *http.Client
	host sdk.Host
	user string
	pass string

	mu     sync.Mutex
	cookie *http.Cookie // session from /api/login
	// settle is how long to wait for a switch to show in the config.
	settle time.Duration
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Frigate module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	cameraRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	eventRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,80}$`)
	labelRe  = regexp.MustCompile(`^[A-Za-z0-9_ -]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	cam := `"camera":{"type":"string","description":"Camera name as in Frigate's config"}`
	toggle := `{"type":"object","required":["camera","enabled"],"properties":{` + cam + `,"enabled":{"type":"boolean"}}}`
	ev := `{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Event id (see events)"}}}`
	return sdk.Manifest{
		ID: "frigate", Name: "Frigate", Version: "0.1.0", Category: "Home", Icon: "video",
		Description: "Frigate NVR: cameras and stats, recent events with labels and scores, detection and recording switches, keeping events.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Frigate's address: the authenticated port, e.g. https://frigate.local:8971, or the internal unauthenticated one, e.g. http://frigate.local:5000"},
			"username":{"type":"string","description":"A Frigate user (needed on port 8971; admin to change cameras)"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the certificate, to trust Frigate's self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "overview", Title: "Overview", Description: "Version, uptime, cameras with their frame rates and switches, detectors with inference speed, storage use.", Risk: sdk.RiskRead},
			{Name: "cameras", Title: "Cameras", Description: "Each camera with whether it's on, detecting, recording and taking snapshots, the objects it tracks, its zones and frame rates. Stream addresses (which hold passwords) are never shown.", Risk: sdk.RiskRead},
			{Name: "stats", Title: "Stats", Description: "Per-camera camera, process, detection and skipped FPS; detectors; storage; CPU temperatures and GPU use.", Risk: sdk.RiskRead},
			{Name: "events", Title: "Recent events", Description: "Tracked objects, newest first, with camera, label, sub label, top score, zones, times and whether there's a clip and snapshot.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + cam + `,"label":{"type":"string","description":"e.g. person, car"},"zone":{"type":"string"},"hours":{"type":"number","minimum":0,"maximum":720,"description":"Only events from the last hours"},"hasSnapshot":{"type":"boolean"},"inProgress":{"type":"boolean"},"retained":{"type":"boolean"},"limit":{"type":"integer","minimum":1,"maximum":200,"default":25}}}`)},
			{Name: "event", Title: "Event details", Description: "One event with its scores, box and region, attributes and snapshot and clip metadata (not the images).", Risk: sdk.RiskRead, Input: sdk.Schema(ev)},
			{Name: "set_detection", Title: "Turn detection on or off", Description: "Switches object detection for a camera until Frigate restarts. Undo switches it back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(toggle)},
			{Name: "set_recording", Title: "Turn recording on or off", Description: "Switches recording for a camera until Frigate restarts (recording must be enabled for it in the config). Undo switches it back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(toggle)},
			{Name: "retain_event", Title: "Keep an event", Description: "Keeps the event's clip and snapshot regardless of retention. Undo stops keeping it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(ev)},
			{Name: "unretain_event", Title: "Stop keeping an event", Description: "Lets retention delete the event's clip and snapshot again. Undo keeps it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(ev)},
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
		return errors.New("the address is like https://frigate.local:8971")
	}
	user := strings.TrimSpace(c.Username)
	if user != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if user == "" && c.Password != "" {
		return errors.New("enter the username too")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	client = rest.SameHostOnly(client)
	root := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	cn := &conn{http: client, host: h, user: user, pass: c.Password, settle: 4 * time.Second}
	cn.api = rest.New(root+"/api", cn.auth)
	cn.api.HTTP = client
	ws := "ws"
	if u.Scheme == "https" {
		ws = "wss"
	}
	cn.ws = ws + strings.TrimPrefix(root, u.Scheme) + "/ws"
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) auth(ctx context.Context, r *http.Request) error {
	if c.user == "" {
		return nil
	}
	ck, err := c.session(ctx)
	if err != nil {
		return err
	}
	r.AddCookie(ck)
	return nil
}

// session logs in once and keeps the cookie Frigate sets.
func (c *conn) session(ctx context.Context) (*http.Cookie, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cookie != nil {
		return c.cookie, nil
	}
	pw, err := c.host.Secret(ctx, c.pass)
	if err != nil {
		return nil, err
	}
	login := rest.New(c.api.Base, nil)
	login.HTTP = c.http
	hdr, err := login.Do(ctx, http.MethodPost, "/login", nil, map[string]string{"user": c.user, "password": pw}, nil)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusBadRequest):
		return nil, errors.New("Frigate refused the username or password")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return nil, errors.New("Frigate is limiting login attempts; try again later")
	case rest.IsStatus(err, http.StatusNotFound):
		return nil, errors.New("no Frigate login at this address (Frigate 0.14 or later on port 8971; leave the username empty for port 5000)")
	case err != nil:
		return nil, err
	}
	cookies := (&http.Response{Header: hdr}).Cookies()
	if len(cookies) == 0 || cookies[0].Value == "" {
		return nil, errors.New("Frigate accepted the login but sent no session")
	}
	c.cookie = &http.Cookie{Name: cookies[0].Name, Value: cookies[0].Value}
	return c.cookie, nil
}

func (c *conn) forget() {
	c.mu.Lock()
	c.cookie = nil
	c.mu.Unlock()
}

// call makes one API request, logging in again once when the session
// expired.
func (c *conn) call(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) && c.user != "" {
		c.forget()
		_, err = c.api.Do(ctx, method, path, q, body, out)
	}
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		if c.user == "" {
			return errors.New("Frigate asks for a login: enter a username and password")
		}
		return errors.New("Frigate refused the session")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Frigate refused the request: this needs an admin user")
	}
	return err
}

type stats struct {
	Cameras map[string]struct {
		CameraFPS        float64 `json:"camera_fps"`
		ProcessFPS       float64 `json:"process_fps"`
		SkippedFPS       float64 `json:"skipped_fps"`
		DetectionFPS     float64 `json:"detection_fps"`
		DetectionEnabled any     `json:"detection_enabled"`
	} `json:"cameras"`
	Detectors map[string]struct {
		InferenceSpeed float64 `json:"inference_speed"`
	} `json:"detectors"`
	DetectionFPS float64 `json:"detection_fps"`
	Service      struct {
		Uptime        int64  `json:"uptime"`
		Version       string `json:"version"`
		LatestVersion string `json:"latest_version"`
		Storage       map[string]struct {
			Total     float64 `json:"total"`
			Used      float64 `json:"used"`
			Free      float64 `json:"free"`
			MountType string  `json:"mount_type"`
		} `json:"storage"`
		Temperatures map[string]float64 `json:"temperatures"`
	} `json:"service"`
	GPUUsages map[string]map[string]any `json:"gpu_usages"`
}

func (c *conn) stats(ctx context.Context) (stats, error) {
	var s stats
	err := c.call(ctx, http.MethodGet, "/stats", nil, nil, &s)
	return s, err
}

type switchCfg struct {
	Enabled *bool `json:"enabled"`
}

type cameraCfg struct {
	Enabled   *bool     `json:"enabled"`
	Detect    switchCfg `json:"detect"`
	Record    switchCfg `json:"record"`
	Snapshots switchCfg `json:"snapshots"`
	Audio     switchCfg `json:"audio"`
	Objects   struct {
		Track []string `json:"track"`
	} `json:"objects"`
	Zones map[string]json.RawMessage `json:"zones"`
	// ffmpeg (stream addresses with passwords) is deliberately not decoded.
}

func (c *conn) cameras(ctx context.Context) (map[string]cameraCfg, error) {
	var cfg struct {
		Cameras map[string]cameraCfg `json:"cameras"`
	}
	if err := c.call(ctx, http.MethodGet, "/config", nil, nil, &cfg); err != nil {
		return nil, err
	}
	return cfg.Cameras, nil
}

func on(s switchCfg) bool { return s.Enabled != nil && *s.Enabled }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.stats(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Frigate API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if s.Service.Version == "" {
		return sdk.Health{Status: "down", Message: "no Frigate API at this address"}
	}
	msg := fmt.Sprintf("Frigate %s · %d cameras", s.Service.Version, len(s.Cameras))
	var dead []string
	for name, cs := range s.Cameras {
		if cs.CameraFPS == 0 {
			dead = append(dead, name)
		}
	}
	if len(dead) > 0 {
		sort.Strings(dead)
		return sdk.Health{Status: "degraded", Message: msg + " · no frames from " + strings.Join(dead, ", ")}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type event struct {
	ID                string   `json:"id"`
	Camera            string   `json:"camera"`
	Label             string   `json:"label"`
	SubLabel          any      `json:"sub_label"`
	TopScore          *float64 `json:"top_score"`
	Score             *float64 `json:"score"`
	StartTime         float64  `json:"start_time"`
	EndTime           *float64 `json:"end_time"`
	Zones             []string `json:"zones"`
	HasClip           bool     `json:"has_clip"`
	HasSnapshot       bool     `json:"has_snapshot"`
	RetainIndefinitly bool     `json:"retain_indefinitely"`
	FalsePositive     *bool    `json:"false_positive"`
	PlusID            *string  `json:"plus_id"`
	Data              struct {
		TopScore   *float64  `json:"top_score"`
		Score      *float64  `json:"score"`
		Box        []float64 `json:"box"`
		Region     []float64 `json:"region"`
		Attributes []any     `json:"attributes"`
		Type       string    `json:"type"`
	} `json:"data"`
}

func ts(f float64) string {
	if f <= 0 {
		return ""
	}
	return time.Unix(int64(f), int64((f-float64(int64(f)))*1e9)).UTC().Format(time.RFC3339)
}

func round(f float64) float64 { return float64(int(f*1000+0.5)) / 1000 }

func (e event) topScore() *float64 {
	for _, s := range []*float64{e.Data.TopScore, e.TopScore, e.Data.Score, e.Score} {
		if s != nil {
			v := round(*s)
			return &v
		}
	}
	return nil
}

func subLabel(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any: // [name, score] in 0.14+
		if len(x) > 0 {
			s, _ := x[0].(string)
			return s
		}
	}
	return ""
}

func eventOut(e event) map[string]any {
	o := map[string]any{"id": e.ID, "camera": e.Camera, "label": e.Label, "start": ts(e.StartTime),
		"zones": nonNil(e.Zones), "hasClip": e.HasClip, "hasSnapshot": e.HasSnapshot, "retained": e.RetainIndefinitly}
	if s := subLabel(e.SubLabel); s != "" {
		o["subLabel"] = s
	}
	if s := e.topScore(); s != nil {
		o["topScore"] = *s
	}
	if e.EndTime != nil {
		o["end"] = ts(*e.EndTime)
		o["durationSeconds"] = int(*e.EndTime - e.StartTime)
	} else {
		o["inProgress"] = true
	}
	if e.FalsePositive != nil && *e.FalsePositive {
		o["falsePositive"] = true
	}
	return o
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

type input struct {
	Camera      string  `json:"camera"`
	Label       string  `json:"label"`
	Zone        string  `json:"zone"`
	Hours       float64 `json:"hours"`
	HasSnapshot *bool   `json:"hasSnapshot"`
	InProgress  *bool   `json:"inProgress"`
	Retained    *bool   `json:"retained"`
	Limit       int     `json:"limit"`
	ID          string  `json:"id"`
	Enabled     *bool   `json:"enabled"`
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
	case "overview":
		s, err := c.stats(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		cams, err := c.cameras(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, name := range sortedKeys(cams) {
			cc := cams[name]
			e := map[string]any{"name": name, "enabled": cc.Enabled == nil || *cc.Enabled, "detect": on(cc.Detect), "record": on(cc.Record)}
			if cs, ok := s.Cameras[name]; ok {
				e["fps"] = round(cs.CameraFPS)
			}
			list = append(list, e)
		}
		out := map[string]any{"version": s.Service.Version, "uptimeSeconds": s.Service.Uptime, "cameras": list,
			"detectors": detectors(s), "storage": storage(s), "detectionFps": round(s.DetectionFPS)}
		if lv := s.Service.LatestVersion; lv != "" && lv != "disabled" && lv != "unknown" && lv != s.Service.Version {
			out["latestVersion"] = lv
		}
		return sdk.JSON(out)

	case "cameras":
		cams, err := c.cameras(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		s, _ := c.stats(ctx)
		list := []map[string]any{}
		for _, name := range sortedKeys(cams) {
			cc := cams[name]
			zones := make([]string, 0, len(cc.Zones))
			for z := range cc.Zones {
				zones = append(zones, z)
			}
			sort.Strings(zones)
			e := map[string]any{"name": name, "enabled": cc.Enabled == nil || *cc.Enabled, "detect": on(cc.Detect), "record": on(cc.Record),
				"snapshots": on(cc.Snapshots), "audio": on(cc.Audio), "objects": nonNil(cc.Objects.Track), "zones": zones}
			if cs, ok := s.Cameras[name]; ok {
				e["cameraFps"], e["detectionFps"] = round(cs.CameraFPS), round(cs.DetectionFPS)
			}
			list = append(list, e)
		}
		return sdk.JSON(list)

	case "stats":
		s, err := c.stats(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		cams := []map[string]any{}
		for _, name := range sortedKeys(s.Cameras) {
			cs := s.Cameras[name]
			cams = append(cams, map[string]any{"name": name, "cameraFps": round(cs.CameraFPS), "processFps": round(cs.ProcessFPS),
				"detectionFps": round(cs.DetectionFPS), "skippedFps": round(cs.SkippedFPS)})
		}
		gpus := map[string]any{}
		for name, g := range s.GPUUsages {
			gpus[name] = map[string]any{"gpu": g["gpu"], "mem": g["mem"]}
		}
		return sdk.JSON(map[string]any{"version": s.Service.Version, "uptimeSeconds": s.Service.Uptime, "cameras": cams,
			"detectors": detectors(s), "storage": storage(s), "temperatures": s.Service.Temperatures, "gpus": gpus})

	case "events":
		q := url.Values{"include_thumbnails": {"0"}}
		limit := p.Limit
		if limit == 0 {
			limit = 25
		}
		if limit < 1 || limit > 200 {
			return sdk.Result{}, errors.New("limit is between 1 and 200")
		}
		q.Set("limit", strconv.Itoa(limit))
		if p.Camera != "" {
			if !cameraRe.MatchString(p.Camera) {
				return sdk.Result{}, errors.New("the camera is a Frigate camera name (letters, digits, _ and -)")
			}
			q.Set("cameras", p.Camera)
		}
		if p.Label != "" {
			if !labelRe.MatchString(p.Label) {
				return sdk.Result{}, errors.New("the label is an object label, like person")
			}
			q.Set("labels", p.Label)
		}
		if p.Zone != "" {
			if !cameraRe.MatchString(p.Zone) {
				return sdk.Result{}, errors.New("the zone is a Frigate zone name")
			}
			q.Set("zones", p.Zone)
		}
		if p.Hours < 0 || p.Hours > 720 {
			return sdk.Result{}, errors.New("hours is between 0 and 720")
		}
		if p.Hours > 0 {
			q.Set("after", strconv.FormatInt(time.Now().Add(-time.Duration(p.Hours*float64(time.Hour))).Unix(), 10))
		}
		flag := func(k string, v *bool) {
			if v != nil {
				q.Set(k, map[bool]string{true: "1", false: "0"}[*v])
			}
		}
		flag("has_snapshot", p.HasSnapshot)
		flag("in_progress", p.InProgress)
		var list []event
		if err := c.call(ctx, http.MethodGet, "/events", q, nil, &list); err != nil {
			return sdk.Result{}, err
		}
		sort.SliceStable(list, func(i, j int) bool { return list[i].StartTime > list[j].StartTime })
		out := []map[string]any{}
		for _, e := range list {
			if p.Retained != nil && e.RetainIndefinitly != *p.Retained {
				continue
			}
			out = append(out, eventOut(e))
		}
		return sdk.JSON(out)

	case "event":
		e, err := c.event(ctx, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		o := eventOut(e)
		if e.Data.Score != nil {
			o["score"] = round(*e.Data.Score)
		} else if e.Score != nil {
			o["score"] = round(*e.Score)
		}
		if len(e.Data.Box) == 4 {
			o["box"] = e.Data.Box
		}
		if len(e.Data.Region) == 4 {
			o["region"] = e.Data.Region
		}
		if len(e.Data.Attributes) > 0 {
			o["attributes"] = e.Data.Attributes
		}
		if e.Data.Type != "" {
			o["type"] = e.Data.Type
		}
		// Where the images are, for someone who opens Frigate; Conduit
		// doesn't fetch them.
		media := map[string]string{}
		if e.HasSnapshot {
			media["snapshot"] = "/api/events/" + e.ID + "/snapshot.jpg"
		}
		if e.HasClip {
			media["clip"] = "/api/events/" + e.ID + "/clip.mp4"
		}
		o["media"] = media
		o["submittedToFrigatePlus"] = e.PlusID != nil && *e.PlusID != ""
		return sdk.JSON(o)

	case "set_detection", "set_recording":
		return c.toggle(ctx, call, p)

	case "retain_event", "unretain_event":
		e, err := c.event(ctx, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		keep := call.Action == "retain_event"
		what := fmt.Sprintf("%s on %s at %s", e.Label, e.Camera, ts(e.StartTime))
		if e.RetainIndefinitly == keep {
			return sdk.Result{}, fmt.Errorf("the event (%s) is already %s", what, map[bool]string{true: "kept", false: "not kept"}[keep])
		}
		if call.DryRun {
			sum := "Keep the " + what + " regardless of retention"
			if !keep {
				sum = "Stop keeping the " + what + "; retention may delete its clip and snapshot"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "event " + e.ID, Op: "update", Before: mustJSON(map[string]bool{"retained": !keep}), After: mustJSON(map[string]bool{"retained": keep})}}}}, nil
		}
		method := http.MethodPost
		if !keep {
			method = http.MethodDelete
		}
		if err := c.call(ctx, method, "/events/"+e.ID+"/retain", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"id": e.ID, "retained": keep})
		if keep {
			res.Undo = sdk.UndoWith("unretain_event", map[string]string{"id": e.ID}, "Stop keeping the "+what)
		} else {
			res.Undo = sdk.UndoWith("retain_event", map[string]string{"id": e.ID}, "Keep the "+what)
		}
		return res, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) event(ctx context.Context, id string) (event, error) {
	var e event
	id = strings.TrimSpace(id)
	if !eventRe.MatchString(id) || strings.Contains(id, "..") {
		return e, errors.New("enter the event's id (see events)")
	}
	if err := c.call(ctx, http.MethodGet, "/events/"+id, nil, nil, &e); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return e, fmt.Errorf("there's no event %s", id)
		}
		return e, err
	}
	if e.ID != id {
		return e, errors.New("unexpected event from Frigate")
	}
	return e, nil
}

func (c *conn) toggle(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if !cameraRe.MatchString(p.Camera) {
		return sdk.Result{}, errors.New("the camera is a Frigate camera name (letters, digits, _ and -)")
	}
	if p.Enabled == nil {
		return sdk.Result{}, errors.New("enabled is true or false")
	}
	want := *p.Enabled
	cams, err := c.cameras(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	cc, ok := cams[p.Camera]
	if !ok {
		names := sortedKeys(cams)
		return sdk.Result{}, fmt.Errorf("there's no camera %s (cameras: %s)", p.Camera, strings.Join(names, ", "))
	}
	what, topic := "detection", "detect"
	get := func(cc cameraCfg) bool { return on(cc.Detect) }
	if call.Action == "set_recording" {
		what, topic = "recording", "recordings"
		get = func(cc cameraCfg) bool { return on(cc.Record) }
	}
	now := get(cc)
	word := map[bool]string{true: "on", false: "off"}
	if now == want {
		return sdk.Result{}, fmt.Errorf("%s is already %s for %s", what, word[want], p.Camera)
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Turn %s %s for camera %s (until Frigate restarts)", what, word[want], p.Camera),
			Changes: []sdk.Change{{Target: "camera " + p.Camera, Op: "update", Before: mustJSON(map[string]bool{what: now}), After: mustJSON(map[string]bool{what: want})}}}}, nil
	}
	payload := map[bool]string{true: "ON", false: "OFF"}[want]
	if err := c.publish(ctx, p.Camera+"/"+topic+"/set", payload); err != nil {
		return sdk.Result{}, err
	}
	confirmed := false
	deadline := time.Now().Add(c.settle)
	for {
		if cams, err := c.cameras(ctx); err == nil && get(cams[p.Camera]) == want {
			confirmed = true
			break
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return sdk.Result{}, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	if !confirmed {
		if call.Action == "set_recording" && want {
			return sdk.Result{}, fmt.Errorf("Frigate didn't turn recording on for %s; recording must be enabled for the camera in Frigate's config to switch it at runtime", p.Camera)
		}
		return sdk.Result{}, fmt.Errorf("Frigate didn't confirm turning %s %s for %s", what, word[want], p.Camera)
	}
	res, err := sdk.JSON(map[string]any{"camera": p.Camera, what: want})
	res.Undo = sdk.UndoWith(call.Action, map[string]any{"camera": p.Camera, "enabled": now}, fmt.Sprintf("Turn %s %s for %s", what, word[now], p.Camera))
	return res, err
}

// publish sends one command over Frigate's websocket, which takes the same
// topics as its MQTT interface (without the prefix).
func (c *conn) publish(ctx context.Context, topic, payload string) error {
	hdr := http.Header{"User-Agent": {"Conduit"}}
	if c.user != "" {
		ck, err := c.session(ctx)
		if err != nil {
			return err
		}
		hdr.Set("Cookie", ck.String())
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ws, res, err := websocket.Dial(dctx, c.ws, &websocket.DialOptions{HTTPClient: c.http, HTTPHeader: hdr})
	if err != nil {
		if res != nil && res.StatusCode == http.StatusUnauthorized {
			c.forget()
			return errors.New("Frigate refused the session for its websocket")
		}
		if res != nil && res.StatusCode == http.StatusForbidden {
			return errors.New("Frigate refused the request: this needs an admin user")
		}
		return fmt.Errorf("couldn't reach Frigate's websocket: %w", err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "")
	msg, _ := json.Marshal(map[string]any{"topic": topic, "payload": payload, "retain": false})
	return ws.Write(dctx, websocket.MessageText, msg)
}

func detectors(s stats) []map[string]any {
	out := []map[string]any{}
	for _, name := range sortedKeys(s.Detectors) {
		out = append(out, map[string]any{"name": name, "inferenceMs": round(s.Detectors[name].InferenceSpeed)})
	}
	return out
}

func storage(s stats) []map[string]any {
	out := []map[string]any{}
	for _, path := range sortedKeys(s.Service.Storage) {
		st := s.Service.Storage[path]
		e := map[string]any{"path": path, "totalMB": int64(st.Total), "usedMB": int64(st.Used), "freeMB": int64(st.Free)}
		if st.Total > 0 {
			e["usedPercent"] = int(st.Used * 100 / st.Total)
		}
		out = append(out, e)
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
