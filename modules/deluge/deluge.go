// Package deluge works with a Deluge BitTorrent client through its Web UI's
// JSON-RPC interface (Deluge 2): transfer speeds and limits, the torrent
// list, pausing and resuming, adding by magnet link or URL, and deleting.
//
// The Web UI signs in with its password and keeps a session cookie; it
// talks to a Deluge daemon, and when it isn't connected to one and knows
// exactly one, the module connects it.
package deluge

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Deluge Web UI.
type Config struct {
	URL                string `json:"url"`      // e.g. http://nas.lan:8112
	Password           string `json:"password"` // secret:// Web UI password
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	endpoint string
	pass     string // secret:// reference
	h        sdk.Host
	http     *http.Client

	mu      sync.Mutex
	cookies []*http.Cookie // nil until signed in
	ready   bool           // the Web UI is connected to a daemon
	seq     int
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Deluge module.
func New() *Module { return &Module{} }

const maxHashes = 100

var (
	hashRe = regexp.MustCompile(`^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	hostRe = regexp.MustCompile(`^[0-9a-fA-F]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	hashes := `"hashes":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"string","pattern":"^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$"},"description":"Torrent hashes (from torrents)"}`
	return sdk.Manifest{
		ID: "deluge", Name: "Deluge", Version: "0.1.0", Category: "Media", Icon: "download",
		Description: "Deluge: transfer speeds and limits, torrents, pause and resume, add by magnet or URL, delete.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","password"],"properties":{
			"url":{"type":"string","description":"The Web UI's address, e.g. http://nas.lan:8112"},
			"password":{"type":"string","x-secret":true,"description":"Web UI password (Preferences, Interface)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the Web UI's certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "session", Title: "Session", Description: "Version, download and upload speed, speed limits, DHT nodes, whether incoming connections work, and free disk space.", Risk: sdk.RiskRead},
			{Name: "torrents", Title: "Torrents", Description: "Torrents with progress, speed, state, ratio, size, label and ETA; filter by state, label or name.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{
					"state":{"type":"string","enum":["all","downloading","seeding","paused","checking","queued","error","active"],"default":"all"},
					"label":{"type":"string"},"query":{"type":"string","description":"Part of the name"},
					"sort":{"type":"string","enum":["added","name","progress","download","upload","ratio","size"],"default":"added"},
					"limit":{"type":"integer","default":50,"minimum":1,"maximum":500}}}`)},
			{Name: "pause", Title: "Pause torrents", Description: "Pauses torrents. Undo resumes the ones that were running.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["hashes"],"properties":{` + hashes + `}}`)},
			{Name: "resume", Title: "Resume torrents", Description: "Resumes torrents. Undo pauses the ones that were paused.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["hashes"],"properties":{` + hashes + `}}`)},
			{Name: "add", Title: "Add torrents", Description: "Adds torrents by magnet link or http(s) URL of a .torrent file, into the default download folder. Undo deletes the new ones, keeping downloaded files.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["urls"],"properties":{
					"urls":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"string"},"description":"magnet: links or http(s) URLs of .torrent files"},
					"paused":{"type":"boolean","default":false,"description":"Add without starting"}}}`)},
			{Name: "delete", Title: "Delete torrents", Description: "Removes torrents from Deluge, and with deleteFiles also their downloaded data.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["hashes"],"properties":{` + hashes + `,"deleteFiles":{"type":"boolean","default":false,"description":"Also delete the downloaded files"}}}`)},
			{Name: "set_speed_limits", Title: "Set speed limits", Description: "Sets the global download and/or upload limit in KiB/s (0 = unlimited). Undo restores the previous limits.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"downloadKiB":{"type":"integer","minimum":0,"maximum":10000000},"uploadKiB":{"type":"integer","minimum":0,"maximum":10000000}}}`)},
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
		return errors.New("the address is like http://nas.lan:8112")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the Web UI password in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	p := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/json")
	m.set.Put(id, &conn{endpoint: u.Scheme + "://" + u.Host + p + "/json", pass: c.Password, h: h, http: rest.SameHostOnly(client)})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errLogin = errors.New("Deluge refused the Web UI password")

// rpcError is an error answer from the Web UI.
type rpcError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// send makes one JSON-RPC request. Callers hold c.mu.
func (c *conn) send(ctx context.Context, method string, params []any, out any) (*rpcError, error) {
	if params == nil {
		params = []any{}
	}
	c.seq++
	body, err := json.Marshal(map[string]any{"method": method, "params": params, "id": c.seq})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	for _, ck := range c.cookies {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, rest.TransportError(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	switch {
	case res.StatusCode == http.StatusNotFound:
		return nil, errors.New("no Deluge Web UI at this address")
	case res.StatusCode >= 300:
		return nil, fmt.Errorf("Deluge answered %s", res.Status)
	}
	if method == "auth.login" {
		if cks := res.Cookies(); len(cks) > 0 {
			c.cookies = cks
		}
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, errors.New("unexpected answer: is this a Deluge Web UI?")
	}
	if env.Error != nil {
		return env.Error, nil
	}
	if out != nil && len(env.Result) > 0 && string(env.Result) != "null" {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return nil, fmt.Errorf("unexpected answer from Deluge: %w", err)
		}
	}
	return nil, nil
}

func (e *rpcError) err() error {
	msg := strings.TrimSpace(e.Message)
	if i := strings.IndexAny(msg, "\r\n"); i >= 0 {
		msg = msg[:i] // a traceback follows
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if msg == "" {
		msg = fmt.Sprintf("error %d", e.Code)
	}
	return errors.New("Deluge: " + rest.Redact(msg))
}

// login signs in and makes sure the Web UI is connected to a daemon.
// Callers hold c.mu.
func (c *conn) login(ctx context.Context) error {
	pw, err := c.h.Secret(ctx, c.pass)
	if err != nil {
		return err
	}
	c.cookies, c.ready = nil, false
	var ok bool
	e, err := c.send(ctx, "auth.login", []any{pw}, &ok)
	if err != nil {
		return err
	}
	if e != nil || !ok {
		return errLogin
	}
	if c.cookies == nil {
		c.cookies = []*http.Cookie{}
	}
	var connected bool
	if e, err := c.send(ctx, "web.connected", nil, &connected); err != nil || e != nil {
		return errors.Join(err, errOr(e))
	}
	if !connected {
		var hosts [][]any
		if e, err := c.send(ctx, "web.get_hosts", nil, &hosts); err != nil || e != nil {
			return errors.Join(err, errOr(e))
		}
		if len(hosts) != 1 || len(hosts[0]) == 0 {
			return errors.New("the Web UI isn't connected to a Deluge daemon: connect it in the Web UI's Connection Manager")
		}
		hid, _ := hosts[0][0].(string)
		if !hostRe.MatchString(hid) {
			return errors.New("unexpected host id from Deluge")
		}
		if e, err := c.send(ctx, "web.connect", []any{hid}, nil); err != nil || e != nil {
			return errors.Join(err, errOr(e))
		}
	}
	c.ready = true
	return nil
}

func errOr(e *rpcError) error {
	if e == nil {
		return nil
	}
	return e.err()
}

// call runs a method, signing in first and once more when the session has
// expired (Deluge answers error code 1, "Not authenticated").
func (c *conn) call(ctx context.Context, method string, params []any, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if c.cookies == nil || !c.ready {
			if err := c.login(ctx); err != nil {
				return err
			}
		}
		e, err := c.send(ctx, method, params, out)
		if err != nil {
			return err
		}
		if e == nil {
			return nil
		}
		if e.Code == 1 && attempt == 0 {
			c.cookies = nil
			continue
		}
		return e.err()
	}
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	v, err := c.version(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "Deluge " + v
	var s sessionStatus
	if c.call(ctx, "core.get_session_status", []any{sessionKeys}, &s) == nil && !s.Incoming {
		msg += " · no incoming connections"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func (c *conn) version(ctx context.Context) (string, error) {
	var v string
	err := c.call(ctx, "daemon.get_version", nil, &v)
	if err != nil && strings.HasPrefix(err.Error(), "Deluge: ") {
		err = c.call(ctx, "daemon.info", nil, &v) // older daemons
	}
	return v, err
}

type sessionStatus struct {
	Down     float64 `json:"download_rate"`
	Up       float64 `json:"upload_rate"`
	DHT      int     `json:"dht_nodes"`
	Incoming bool    `json:"has_incoming_connections"`
}

var sessionKeys = []string{"download_rate", "upload_rate", "dht_nodes", "has_incoming_connections"}

type torrent struct {
	Hash     string  `json:"hash"`
	Name     string  `json:"name"`
	State    string  `json:"state"`
	Progress float64 `json:"progress"`
	Down     float64 `json:"download_payload_rate"`
	Up       float64 `json:"upload_payload_rate"`
	Ratio    float64 `json:"ratio"`
	Size     int64   `json:"total_size"`
	ETA      float64 `json:"eta"`
	Added    float64 `json:"time_added"`
	Label    string  `json:"label"`
	SavePath string  `json:"save_path"`
	Peers    int     `json:"num_peers"`
	Seeds    int     `json:"num_seeds"`
	Message  string  `json:"message"`
	// Trackers aren't read: their announce URLs carry private trackers'
	// passkeys.
}

var torrentKeys = []string{"hash", "name", "state", "progress", "download_payload_rate", "upload_payload_rate", "ratio", "total_size", "eta",
	"time_added", "label", "save_path", "num_peers", "num_seeds", "message"}

func (t torrent) summary() map[string]any {
	e := map[string]any{"hash": strings.ToLower(t.Hash), "name": t.Name, "state": t.State, "progress": float64(int(t.Progress*10)) / 10,
		"sizeMB": t.Size >> 20, "downKiBs": int64(t.Down) >> 10, "upKiBs": int64(t.Up) >> 10, "ratio": float64(int(t.Ratio*100)) / 100,
		"seeds": t.Seeds, "peers": t.Peers, "added": time.Unix(int64(t.Added), 0).UTC().Format(time.RFC3339), "savePath": t.SavePath}
	if t.ETA > 0 {
		e["etaMinutes"] = int64(t.ETA) / 60
	}
	if t.Label != "" {
		e["label"] = t.Label
	}
	if t.State == "Error" && t.Message != "" && t.Message != "OK" {
		e["error"] = rest.Redact(t.Message)
	}
	return e
}

func (t torrent) paused() bool { return t.State == "Paused" }

func (c *conn) list(ctx context.Context, filter map[string]any) (map[string]torrent, error) {
	got := map[string]torrent{}
	if err := c.call(ctx, "core.get_torrents_status", []any{filter, torrentKeys}, &got); err != nil {
		return nil, err
	}
	out := map[string]torrent{}
	for h, t := range got {
		if t.Hash == "" {
			t.Hash = h
		}
		out[strings.ToLower(h)] = t
	}
	return out, nil
}

type input struct {
	State       string   `json:"state"`
	Label       *string  `json:"label"`
	Query       string   `json:"query"`
	Sort        string   `json:"sort"`
	Limit       int      `json:"limit"`
	Hashes      []string `json:"hashes"`
	DeleteFiles bool     `json:"deleteFiles"`
	URLs        []string `json:"urls"`
	Paused      bool     `json:"paused"`
	DownloadKiB *int64   `json:"downloadKiB"`
	UploadKiB   *int64   `json:"uploadKiB"`
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
	case "session":
		v, err := c.version(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var s sessionStatus
		if err := c.call(ctx, "core.get_session_status", []any{sessionKeys}, &s); err != nil {
			return sdk.Result{}, err
		}
		var cfg map[string]any
		if err := c.call(ctx, "core.get_config_values", []any{[]string{"max_download_speed", "max_upload_speed", "download_location"}}, &cfg); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"version": v, "downKiBs": int64(s.Down) >> 10, "upKiBs": int64(s.Up) >> 10, "dhtNodes": s.DHT,
			"incomingConnections": s.Incoming, "downLimitKiBs": limitOut(num(cfg["max_download_speed"])), "upLimitKiBs": limitOut(num(cfg["max_upload_speed"]))}
		if d, ok := cfg["download_location"].(string); ok {
			out["downloadLocation"] = d
		}
		var free float64
		if c.call(ctx, "core.get_free_space", nil, &free) == nil && free >= 0 {
			out["freeSpaceGB"] = float64(int64(free)>>20) / 1024
		}
		return sdk.JSON(out)
	case "torrents":
		return c.torrents(ctx, p)
	case "pause", "resume":
		return c.pauseResume(ctx, call, p.Hashes)
	case "add":
		return c.add(ctx, call.DryRun, p)
	case "delete":
		hs, err := checkHashes(p.Hashes)
		if err != nil {
			return sdk.Result{}, err
		}
		found, err := c.byHash(ctx, hs)
		if err != nil {
			return sdk.Result{}, err
		}
		op := "delete (files kept)"
		if p.DeleteFiles {
			op = "delete with downloaded files"
		}
		var changes []sdk.Change
		for _, h := range hs {
			changes = append(changes, sdk.Change{Target: fmt.Sprintf("%s (%s)", found[h].Name, h[:8]), Op: op})
		}
		if call.DryRun {
			sum := fmt.Sprintf("Delete %d torrents", len(hs))
			if p.DeleteFiles {
				sum += " and their files"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: changes}}, nil
		}
		var failed []any
		if err := c.call(ctx, "core.remove_torrents", []any{hs, p.DeleteFiles}, &failed); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"deleted": hs, "filesDeleted": p.DeleteFiles}
		if len(failed) > 0 {
			out["note"] = fmt.Sprintf("Deluge couldn't remove %d of them", len(failed))
		}
		return sdk.JSON(out)
	case "set_speed_limits":
		return c.speedLimits(ctx, call.DryRun, p.DownloadKiB, p.UploadKiB)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func num(v any) float64 {
	f, _ := v.(float64)
	return f
}

// limitOut shows a Deluge speed limit (KiB/s, -1 or 0 = unlimited).
func limitOut(v float64) any {
	if v <= 0 {
		return "unlimited"
	}
	return int64(v)
}

func clean(s string, what string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > 200 || strings.ContainsAny(s, "\r\n\x00") {
		return "", fmt.Errorf("the %s is one line of at most 200 characters", what)
	}
	return s, nil
}

func (c *conn) torrents(ctx context.Context, p input) (sdk.Result, error) {
	state := p.State
	if state == "" {
		state = "all"
	}
	match := map[string]func(torrent) bool{
		"all":         func(torrent) bool { return true },
		"downloading": func(t torrent) bool { return t.State == "Downloading" },
		"seeding":     func(t torrent) bool { return t.State == "Seeding" },
		"paused":      func(t torrent) bool { return t.State == "Paused" },
		"checking":    func(t torrent) bool { return t.State == "Checking" || t.State == "Allocating" },
		"queued":      func(t torrent) bool { return t.State == "Queued" },
		"error":       func(t torrent) bool { return t.State == "Error" },
		"active":      func(t torrent) bool { return t.Down > 0 || t.Up > 0 },
	}[state]
	if match == nil {
		return sdk.Result{}, fmt.Errorf("unknown state %q", state)
	}
	key := p.Sort
	if key == "" {
		key = "added"
	}
	less := map[string]func(a, b torrent) bool{
		"added":    func(a, b torrent) bool { return a.Added > b.Added },
		"name":     func(a, b torrent) bool { return strings.ToLower(a.Name) < strings.ToLower(b.Name) },
		"progress": func(a, b torrent) bool { return a.Progress > b.Progress },
		"download": func(a, b torrent) bool { return a.Down > b.Down },
		"upload":   func(a, b torrent) bool { return a.Up > b.Up },
		"ratio":    func(a, b torrent) bool { return a.Ratio > b.Ratio },
		"size":     func(a, b torrent) bool { return a.Size > b.Size },
	}[key]
	if less == nil {
		return sdk.Result{}, fmt.Errorf("unknown sort %q", key)
	}
	var label string
	if p.Label != nil {
		s, err := clean(*p.Label, "label")
		if err != nil {
			return sdk.Result{}, err
		}
		label = strings.ToLower(s)
	}
	limit := p.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	all, err := c.list(ctx, map[string]any{})
	if err != nil {
		return sdk.Result{}, err
	}
	needle := strings.ToLower(strings.TrimSpace(p.Query))
	var list []torrent
	for _, t := range all {
		if match(t) && (needle == "" || strings.Contains(strings.ToLower(t.Name), needle)) && (p.Label == nil || strings.ToLower(t.Label) == label) {
			list = append(list, t)
		}
	}
	sort.SliceStable(list, func(i, j int) bool {
		if less(list[i], list[j]) != less(list[j], list[i]) {
			return less(list[i], list[j])
		}
		return list[i].Hash < list[j].Hash
	})
	out := []map[string]any{}
	for i, t := range list {
		if i >= limit {
			break
		}
		out = append(out, t.summary())
	}
	return sdk.JSON(map[string]any{"total": len(list), "torrents": out})
}

func checkHashes(in []string) ([]string, error) {
	if len(in) == 0 || len(in) > maxHashes {
		return nil, fmt.Errorf("pick 1 to %d torrents", maxHashes)
	}
	seen := map[string]bool{}
	var out []string
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if !hashRe.MatchString(h) {
			return nil, errors.New("a torrent is its hash from torrents (40 or 64 hex digits)")
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out, nil
}

// byHash reads the named torrents and fails when one doesn't exist.
func (c *conn) byHash(ctx context.Context, hs []string) (map[string]torrent, error) {
	found, err := c.list(ctx, map[string]any{"id": hs})
	if err != nil {
		return nil, err
	}
	for _, h := range hs {
		if _, ok := found[h]; !ok {
			return nil, fmt.Errorf("there's no torrent %s", h)
		}
	}
	return found, nil
}

func (c *conn) pauseResume(ctx context.Context, call sdk.Call, in []string) (sdk.Result, error) {
	pausing := call.Action == "pause"
	hs, err := checkHashes(in)
	if err != nil {
		return sdk.Result{}, err
	}
	found, err := c.byHash(ctx, hs)
	if err != nil {
		return sdk.Result{}, err
	}
	var change []string
	var changes []sdk.Change
	for _, h := range hs {
		t := found[h]
		if t.paused() == pausing {
			continue // already there
		}
		change = append(change, h)
		before, _ := json.Marshal(t.State)
		changes = append(changes, sdk.Change{Target: fmt.Sprintf("%s (%s)", t.Name, h[:8]), Op: call.Action, Before: before})
	}
	if len(change) == 0 {
		return sdk.JSON(map[string]any{"changed": []string{}, "note": "nothing to change"})
	}
	verb, back, method := "Pause", "resume", "core.pause_torrents"
	if !pausing {
		verb, back, method = "Resume", "pause", "core.resume_torrents"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %d torrents", verb, len(change)), Changes: changes}}, nil
	}
	if err := c.call(ctx, method, []any{change}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"changed": change})
	res.Undo = sdk.UndoWith(back, map[string]any{"hashes": change}, fmt.Sprintf("%s %d torrents again", strings.ToUpper(back[:1])+back[1:], len(change)))
	return res, err
}

// magnetHash is the info-hash a magnet link names: the v1 hash, or for a
// v2-only magnet its v2 hash cut to 40 digits (as libtorrent lists it).
func magnetHash(u *url.URL) string {
	var v2 string
	for _, xt := range u.Query()["xt"] {
		switch {
		case strings.HasPrefix(xt, "urn:btih:"):
			h := strings.TrimPrefix(xt, "urn:btih:")
			if len(h) == 32 { // base32
				if b, err := base32.StdEncoding.DecodeString(strings.ToUpper(h)); err == nil {
					return hex.EncodeToString(b)
				}
			}
			if len(h) == 40 && hashRe.MatchString(h) {
				return strings.ToLower(h)
			}
		case strings.HasPrefix(xt, "urn:btmh:1220"):
			if h := strings.TrimPrefix(xt, "urn:btmh:1220"); len(h) == 64 && hashRe.MatchString(h) {
				v2 = strings.ToLower(h[:40])
			}
		}
	}
	return v2
}

// display names a URL without its query, which for private trackers holds
// a passkey.
func display(u *url.URL) string {
	if u.Scheme == "magnet" {
		if dn := u.Query().Get("dn"); dn != "" {
			return "magnet " + dn
		}
		return "magnet " + magnetHash(u)
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath()
}

func (c *conn) add(ctx context.Context, dry bool, p input) (sdk.Result, error) {
	if len(p.URLs) == 0 || len(p.URLs) > 20 {
		return sdk.Result{}, errors.New("give 1 to 20 magnet links or URLs")
	}
	type item struct {
		raw, name, hash string
		magnet          bool
	}
	var items []item
	for _, s := range p.URLs {
		s = strings.TrimSpace(s)
		u, err := url.Parse(s)
		if err != nil || strings.ContainsAny(s, "\r\n") || len(s) > 8192 {
			return sdk.Result{}, errors.New("each entry is a magnet: link or an http(s) URL")
		}
		switch u.Scheme {
		case "magnet":
			h := magnetHash(u)
			if h == "" {
				return sdk.Result{}, errors.New("a magnet link needs its xt=urn:btih: (or btmh) hash")
			}
			items = append(items, item{raw: s, name: display(u), hash: h, magnet: true})
		case "http", "https":
			if u.Host == "" {
				return sdk.Result{}, errors.New("each entry is a magnet: link or an http(s) URL")
			}
			items = append(items, item{raw: s, name: display(u)})
		default:
			return sdk.Result{}, errors.New("each entry is a magnet: link or an http(s) URL")
		}
	}
	had, err := c.list(ctx, map[string]any{})
	if err != nil {
		return sdk.Result{}, err
	}
	var changes []sdk.Change
	var todo []item
	for _, it := range items {
		if _, ok := had[it.hash]; it.hash != "" && ok {
			changes = append(changes, sdk.Change{Target: it.name, Op: "skip (already in Deluge)"})
			continue
		}
		after, _ := json.Marshal(map[string]bool{"paused": p.Paused})
		changes = append(changes, sdk.Change{Target: it.name, Op: "add", After: after})
		todo = append(todo, it)
	}
	if len(todo) == 0 {
		return sdk.JSON(map[string]any{"added": []string{}, "note": "nothing to change: all of these are already in Deluge"})
	}
	if dry {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add %d torrents", len(todo)), Changes: changes}}, nil
	}
	opts := map[string]any{"add_paused": p.Paused}
	var added []string
	var failed int
	var lastErr error
	for _, it := range todo {
		var h string
		var err error
		if it.magnet {
			err = c.call(ctx, "core.add_torrent_magnet", []any{it.raw, opts}, &h)
		} else {
			err = c.call(ctx, "core.add_torrent_url", []any{it.raw, opts, map[string]string{}}, &h)
		}
		h = strings.ToLower(h)
		if err != nil || !hashRe.MatchString(h) {
			if err != nil {
				lastErr = fmt.Errorf("adding %s: %w", it.name, err)
			}
			failed++
			continue
		}
		added = append(added, h)
	}
	if len(added) == 0 && lastErr != nil {
		return sdk.Result{}, lastErr
	}
	out := map[string]any{"requested": len(todo), "added": added}
	if failed > 0 {
		out["note"] = fmt.Sprintf("Deluge didn't add %d of them; undo covers the ones listed", failed)
	}
	res, err := sdk.JSON(out)
	if len(added) > 0 {
		res.Undo = sdk.UndoWith("delete", map[string]any{"hashes": added, "deleteFiles": false}, fmt.Sprintf("Delete the %d added torrents (keeping files)", len(added)))
	}
	return res, err
}

func (c *conn) speedLimits(ctx context.Context, dry bool, down, up *int64) (sdk.Result, error) {
	if down == nil && up == nil {
		return sdk.Result{}, errors.New("give downloadKiB, uploadKiB or both (0 = unlimited)")
	}
	for _, v := range []*int64{down, up} {
		if v != nil && (*v < 0 || *v > 10000000) {
			return sdk.Result{}, errors.New("limits are 0 (unlimited) to 10000000 KiB/s")
		}
	}
	var cfg map[string]any
	if err := c.call(ctx, "core.get_config_values", []any{[]string{"max_download_speed", "max_upload_speed"}}, &cfg); err != nil {
		return sdk.Result{}, err
	}
	type lim struct {
		key, label string
		want       *int64
	}
	var changes []sdk.Change
	set := map[string]any{}
	undo := map[string]any{}
	out := map[string]any{}
	for _, l := range []lim{{"max_download_speed", "download", down}, {"max_upload_speed", "upload", up}} {
		if l.want == nil {
			continue
		}
		prev := int64(0)
		if v := num(cfg[l.key]); v > 0 {
			prev = int64(v)
		}
		if prev == *l.want {
			continue
		}
		b, _ := json.Marshal(limitOut(float64(prev)))
		a, _ := json.Marshal(limitOut(float64(*l.want)))
		changes = append(changes, sdk.Change{Target: "global " + l.label + " limit (KiB/s)", Op: "update", Before: b, After: a})
		undo[l.label+"KiB"] = prev
		if *l.want == 0 {
			set[l.key] = -1.0
		} else {
			set[l.key] = float64(*l.want)
		}
		out[l.label+"LimitKiBs"] = limitOut(float64(*l.want))
	}
	if len(changes) == 0 {
		return sdk.JSON(map[string]any{"note": "nothing to change: the limits are already set like this"})
	}
	if dry {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Change Deluge's speed limits", Changes: changes}}, nil
	}
	if err := c.call(ctx, "core.set_config", []any{set}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(out)
	res.Undo = sdk.UndoWith("set_speed_limits", undo, "Restore the previous speed limits")
	return res, err
}
