// Package qbittorrent works with a qBittorrent client through its Web API
// (v2): transfer speeds and limits, the torrent list, pausing and resuming,
// adding by magnet link or URL, and deleting.
//
// The Web API signs in with a username and password and keeps a session
// cookie; it rejects requests whose Referer or Origin names another host
// (its CSRF protection), so every request carries the server's own origin.
package qbittorrent

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one qBittorrent Web UI.
type Config struct {
	URL                string `json:"url"`      // e.g. http://nas.lan:8080
	Username           string `json:"username"` // Web UI user
	Password           string `json:"password"` // secret:// Web UI password
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	base, origin string
	user, pass   string // pass is a secret:// reference
	h            sdk.Host
	http         *http.Client

	mu      sync.Mutex
	cookies []*http.Cookie
	version []int // Web API version, e.g. 2.11.2
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// AddWait is how long add waits for a torrent added by URL to appear,
	// so its undo can name it.
	AddWait time.Duration
}

// New returns the qBittorrent module.
func New() *Module { return &Module{AddWait: 8 * time.Second} }

const maxHashes = 100

var (
	hashRe  = regexp.MustCompile(`^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)
	pathRe  = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	filters = map[string]bool{"all": true, "downloading": true, "seeding": true, "completed": true, "paused": true, "stopped": true,
		"resumed": true, "running": true, "active": true, "inactive": true, "stalled": true, "stalled_uploading": true,
		"stalled_downloading": true, "errored": true, "checking": true, "moving": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	hashes := `"hashes":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"string","pattern":"^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$"},"description":"Torrent hashes (from torrents)"}`
	return sdk.Manifest{
		ID: "qbittorrent", Name: "qBittorrent", Version: "0.1.0", Category: "Media", Icon: "download",
		Description: "qBittorrent: transfer speeds and limits, torrents, pause and resume, add by magnet or URL, delete.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"The Web UI's address, e.g. http://nas.lan:8080"},
			"username":{"type":"string","description":"Web UI username (Tools, Options, Web UI)"},
			"password":{"type":"string","x-secret":true,"description":"Web UI password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the Web UI's certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "transfer", Title: "Transfer info", Description: "Download and upload speed, data this session, speed limits (and whether the alternative limits are on), connection status, DHT nodes.", Risk: sdk.RiskRead},
			{Name: "torrents", Title: "Torrents", Description: "Torrents with progress, speed, state, ratio, size and ETA; filter by state, category or tag.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{
					"filter":{"type":"string","enum":["all","downloading","seeding","completed","paused","stopped","resumed","running","active","inactive","stalled","stalled_uploading","stalled_downloading","errored","checking","moving"],"default":"all"},
					"category":{"type":"string"},"tag":{"type":"string"},"query":{"type":"string","description":"Part of the name"},
					"sort":{"type":"string","enum":["added_on","name","progress","dlspeed","upspeed","ratio","size","eta"],"default":"added_on"},
					"limit":{"type":"integer","default":50,"minimum":1,"maximum":500}}}`)},
			{Name: "pause", Title: "Pause torrents", Description: "Pauses (stops) torrents. Undo resumes the ones that were running.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["hashes"],"properties":{` + hashes + `}}`)},
			{Name: "resume", Title: "Resume torrents", Description: "Resumes (starts) torrents. Undo pauses the ones that were paused.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["hashes"],"properties":{` + hashes + `}}`)},
			{Name: "add", Title: "Add torrents", Description: "Adds torrents by magnet link or http(s) URL of a .torrent file. Undo deletes the new ones, keeping downloaded files.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["urls"],"properties":{
					"urls":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"string"},"description":"magnet: links or http(s) URLs of .torrent files"},
					"savePath":{"type":"string","description":"Download folder (default: qBittorrent's)"},
					"category":{"type":"string"},"tags":{"type":"array","items":{"type":"string"},"maxItems":10},
					"paused":{"type":"boolean","default":false,"description":"Add without starting"}}}`)},
			{Name: "delete", Title: "Delete torrents", Description: "Removes torrents from qBittorrent, and with deleteFiles also their downloaded data.", Risk: sdk.RiskDestructive, DryRun: true,
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
		return errors.New("the address is like http://nas.lan:8080")
	}
	if strings.TrimSpace(c.Username) == "" {
		return errors.New("enter the Web UI username")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the Web UI password in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second) // through the instance's network, if any
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
	origin := u.Scheme + "://" + u.Host
	base := origin + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v2")
	m.set.Put(id, &conn{base: base, origin: origin, user: strings.TrimSpace(c.Username), pass: c.Password, h: h, http: rest.SameHostOnly(client)})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var (
	errLogin  = errors.New("qBittorrent refused the username or password")
	errBanned = errors.New("qBittorrent has banned this address after too many failed sign-ins (it lifts the ban after a while)")
)

// statusError is an error answer from the Web API.
type statusError struct {
	status int
	msg    string
}

func (e *statusError) Error() string { return e.msg }

// send makes one request with the session cookie and CSRF headers.
func (c *conn) send(ctx context.Context, method, path string, body io.Reader, ctype string, cookies []*http.Cookie) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/api/v2"+path, body)
	if err != nil {
		return nil, err
	}
	// The Web API refuses requests whose Referer or Origin is another host.
	req.Header.Set("Referer", c.base+"/")
	req.Header.Set("Origin", c.origin)
	req.Header.Set("User-Agent", "Conduit")
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for _, ck := range cookies {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	return c.http.Do(req)
}

// login signs in and keeps the session cookie. Callers hold c.mu.
func (c *conn) login(ctx context.Context) error {
	pw, err := c.h.Secret(ctx, c.pass)
	if err != nil {
		return err
	}
	form := url.Values{"username": {c.user}, "password": {pw}}
	res, err := c.send(ctx, http.MethodPost, "/auth/login", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	text := strings.TrimSpace(string(raw))
	switch {
	case res.StatusCode == http.StatusForbidden:
		return errBanned
	case res.StatusCode == http.StatusUnauthorized || text == "Fails.":
		return errLogin
	case res.StatusCode >= 300:
		return fmt.Errorf("qBittorrent sign-in failed: %s", res.Status)
	}
	// With "bypass authentication for clients on localhost" there may be no
	// cookie, and every request works without one.
	c.cookies = res.Cookies()
	return nil
}

// call sends a request, signing in first and once more when the session
// has expired (the Web API answers 403 then).
func (c *conn) call(ctx context.Context, method, path string, form url.Values, multi bool) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if c.cookies == nil {
			if err := c.login(ctx); err != nil {
				return nil, err
			}
			if c.cookies == nil {
				c.cookies = []*http.Cookie{} // signed in without a cookie
			}
		}
		var body io.Reader
		ctype := ""
		if form != nil {
			if multi {
				var buf bytes.Buffer
				mw := multipart.NewWriter(&buf)
				keys := make([]string, 0, len(form))
				for k := range form {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					for _, v := range form[k] {
						_ = mw.WriteField(k, v)
					}
				}
				_ = mw.Close()
				body, ctype = &buf, mw.FormDataContentType()
			} else {
				body, ctype = strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"
			}
		}
		res, err := c.send(ctx, method, path, body, ctype, c.cookies)
		if err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
		res.Body.Close()
		if err != nil {
			return nil, err
		}
		if res.StatusCode == http.StatusForbidden && attempt == 0 {
			c.cookies = nil // session expired; sign in again
			continue
		}
		if res.StatusCode >= 300 {
			msg := res.Status
			if t := strings.TrimSpace(string(raw)); t != "" && len(t) < 200 && !strings.HasPrefix(t, "<") {
				msg += ": " + t
			}
			if res.StatusCode == http.StatusForbidden {
				msg = "qBittorrent refused the session (sign-in or CSRF check failed)"
			}
			return nil, &statusError{status: res.StatusCode, msg: msg}
		}
		return raw, nil
	}
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	raw, err := c.call(ctx, http.MethodGet, path, nil, false)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("unexpected answer from qBittorrent: %w", err)
	}
	return nil
}

func (c *conn) post(ctx context.Context, path string, form url.Values) ([]byte, error) {
	if form == nil {
		form = url.Values{}
	}
	return c.call(ctx, http.MethodPost, path, form, false)
}

// apiVersion reads (once) the Web API version: 2.11 (qBittorrent 5) renamed
// pause and resume to stop and start.
func (c *conn) apiVersion(ctx context.Context) ([]int, error) {
	c.mu.Lock()
	v := c.version
	c.mu.Unlock()
	if v != nil {
		return v, nil
	}
	raw, err := c.call(ctx, http.MethodGet, "/app/webapiVersion", nil, false)
	if err != nil {
		return nil, err
	}
	for _, p := range strings.Split(strings.TrimSpace(string(raw)), ".") {
		n, _ := strconv.Atoi(p)
		v = append(v, n)
	}
	c.mu.Lock()
	c.version = v
	c.mu.Unlock()
	return v, nil
}

func atLeast(v []int, want ...int) bool {
	for i, w := range want {
		have := 0
		if i < len(v) {
			have = v[i]
		}
		if have != w {
			return have > w
		}
	}
	return true
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	raw, err := c.call(ctx, http.MethodGet, "/app/version", nil, false)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var t transfer
	msg := "qBittorrent " + strings.TrimSpace(string(raw))
	if err := c.get(ctx, "/transfer/info", nil, &t); err == nil {
		if t.ConnectionStatus == "disconnected" {
			return sdk.Health{Status: "degraded", Message: msg + " · no network connection"}
		}
		if t.ConnectionStatus == "firewalled" {
			msg += " · firewalled"
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type transfer struct {
	DlSpeed          int64  `json:"dl_info_speed"`
	DlData           int64  `json:"dl_info_data"`
	UpSpeed          int64  `json:"up_info_speed"`
	UpData           int64  `json:"up_info_data"`
	DlLimit          int64  `json:"dl_rate_limit"`
	UpLimit          int64  `json:"up_rate_limit"`
	DHTNodes         int    `json:"dht_nodes"`
	ConnectionStatus string `json:"connection_status"`
}

type torrent struct {
	Hash       string  `json:"hash"`
	Name       string  `json:"name"`
	Size       int64   `json:"size"`
	Progress   float64 `json:"progress"`
	DlSpeed    int64   `json:"dlspeed"`
	UpSpeed    int64   `json:"upspeed"`
	State      string  `json:"state"`
	ETA        int64   `json:"eta"`
	Ratio      float64 `json:"ratio"`
	Category   string  `json:"category"`
	Tags       string  `json:"tags"`
	AddedOn    int64   `json:"added_on"`
	Seeds      int     `json:"num_seeds"`
	Leechs     int     `json:"num_leechs"`
	SavePath   string  `json:"save_path"`
	AmountLeft int64   `json:"amount_left"`
}

func (t torrent) paused() bool {
	return strings.HasPrefix(t.State, "paused") || strings.HasPrefix(t.State, "stopped")
}

func (t torrent) summary() map[string]any {
	e := map[string]any{"hash": t.Hash, "name": t.Name, "state": t.State, "progress": float64(int(t.Progress*1000)) / 10,
		"sizeMB": t.Size >> 20, "downKiBs": t.DlSpeed >> 10, "upKiBs": t.UpSpeed >> 10, "ratio": float64(int(t.Ratio*100)) / 100,
		"seeds": t.Seeds, "peers": t.Leechs, "added": time.Unix(t.AddedOn, 0).UTC().Format(time.RFC3339), "savePath": t.SavePath}
	if t.ETA > 0 && t.ETA < 8640000 { // 8640000 means infinity
		e["etaMinutes"] = t.ETA / 60
	}
	if t.Category != "" {
		e["category"] = t.Category
	}
	if t.Tags != "" {
		e["tags"] = strings.Split(t.Tags, ", ")
	}
	return e
}

func kib(b int64) any {
	if b <= 0 {
		return "unlimited"
	}
	return b >> 10
}

type input struct {
	Filter      string   `json:"filter"`
	Category    *string  `json:"category"`
	Tag         *string  `json:"tag"`
	Query       string   `json:"query"`
	Sort        string   `json:"sort"`
	Limit       int      `json:"limit"`
	Hashes      []string `json:"hashes"`
	DeleteFiles bool     `json:"deleteFiles"`
	URLs        []string `json:"urls"`
	SavePath    string   `json:"savePath"`
	Tags        []string `json:"tags"`
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
	case "transfer":
		var t transfer
		if err := c.get(ctx, "/transfer/info", nil, &t); err != nil {
			return sdk.Result{}, err
		}
		raw, err := c.call(ctx, http.MethodGet, "/transfer/speedLimitsMode", nil, false)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"downKiBs": t.DlSpeed >> 10, "upKiBs": t.UpSpeed >> 10,
			"downloadedMB": t.DlData >> 20, "uploadedMB": t.UpData >> 20,
			"downLimitKiBs": kib(t.DlLimit), "upLimitKiBs": kib(t.UpLimit),
			"alternativeLimits": strings.TrimSpace(string(raw)) == "1",
			"connection":        t.ConnectionStatus, "dhtNodes": t.DHTNodes})

	case "torrents":
		return c.torrents(ctx, p)

	case "pause", "resume":
		return c.pauseResume(ctx, call, p.Hashes)

	case "add":
		return c.add(ctx, call.DryRun, p, m.AddWait)

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
		if _, err := c.post(ctx, "/torrents/delete", url.Values{"hashes": {strings.Join(hs, "|")}, "deleteFiles": {strconv.FormatBool(p.DeleteFiles)}}); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": hs, "filesDeleted": p.DeleteFiles})

	case "set_speed_limits":
		return c.speedLimits(ctx, call.DryRun, p.DownloadKiB, p.UploadKiB)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func clean(s string, what string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > 200 || strings.ContainsAny(s, "\r\n\x00") {
		return "", fmt.Errorf("the %s is one line of at most 200 characters", what)
	}
	return s, nil
}

func (c *conn) torrents(ctx context.Context, p input) (sdk.Result, error) {
	f := p.Filter
	if f == "" {
		f = "all"
	}
	if !filters[f] {
		return sdk.Result{}, fmt.Errorf("unknown filter %q", f)
	}
	sortKey := p.Sort
	if sortKey == "" {
		sortKey = "added_on"
	}
	switch sortKey {
	case "added_on", "name", "progress", "dlspeed", "upspeed", "ratio", "size", "eta":
	default:
		return sdk.Result{}, fmt.Errorf("unknown sort %q", sortKey)
	}
	v, err := c.apiVersion(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	// qBittorrent 5 renamed paused/resumed to stopped/running.
	rename := map[string]string{"stopped": "paused", "running": "resumed"}
	if atLeast(v, 2, 11) {
		rename = map[string]string{"paused": "stopped", "resumed": "running"}
	}
	if r, ok := rename[f]; ok {
		f = r
	}
	q := url.Values{"filter": {f}, "sort": {sortKey}, "reverse": {strconv.FormatBool(sortKey != "name" && sortKey != "eta")}}
	if p.Category != nil {
		s, err := clean(*p.Category, "category")
		if err != nil {
			return sdk.Result{}, err
		}
		q.Set("category", s)
	}
	if p.Tag != nil {
		s, err := clean(*p.Tag, "tag")
		if err != nil {
			return sdk.Result{}, err
		}
		q.Set("tag", s)
	}
	var list []torrent
	if err := c.get(ctx, "/torrents/info", q, &list); err != nil {
		return sdk.Result{}, err
	}
	limit := p.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	needle := strings.ToLower(strings.TrimSpace(p.Query))
	out := []map[string]any{}
	n := 0
	for _, t := range list {
		if needle != "" && !strings.Contains(strings.ToLower(t.Name), needle) {
			continue
		}
		n++
		if len(out) < limit {
			out = append(out, t.summary())
		}
	}
	return sdk.JSON(map[string]any{"total": n, "torrents": out})
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
			return nil, fmt.Errorf("%q isn't a torrent hash (40 or 64 hex digits)", h)
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
	var list []torrent
	if err := c.get(ctx, "/torrents/info", url.Values{"hashes": {strings.Join(hs, "|")}}, &list); err != nil {
		return nil, err
	}
	found := map[string]torrent{}
	for _, t := range list {
		found[strings.ToLower(t.Hash)] = t
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
	verb, back := "Pause", "resume"
	if !pausing {
		verb, back = "Resume", "pause"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %d torrents", verb, len(change)), Changes: changes}}, nil
	}
	v, err := c.apiVersion(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	path := "/torrents/" + call.Action
	if atLeast(v, 2, 11) {
		path = map[bool]string{true: "/torrents/stop", false: "/torrents/start"}[pausing]
	}
	if _, err := c.post(ctx, path, url.Values{"hashes": {strings.Join(change, "|")}}); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"changed": change})
	res.Undo = sdk.UndoWith(back, map[string]any{"hashes": change}, fmt.Sprintf("%s %d torrents again", strings.ToUpper(back[:1])+back[1:], len(change)))
	return res, err
}

// magnetHash is the hash qBittorrent will list a magnet's torrent under:
// the v1 info-hash, or for a v2-only magnet its v2 hash cut to 40 digits.
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

func (c *conn) add(ctx context.Context, dry bool, p input, wait time.Duration) (sdk.Result, error) {
	if len(p.URLs) == 0 || len(p.URLs) > 20 {
		return sdk.Result{}, errors.New("give 1 to 20 magnet links or URLs")
	}
	type item struct {
		raw, name, hash string
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
			items = append(items, item{raw: s, name: display(u), hash: h})
		case "http", "https":
			if u.Host == "" {
				return sdk.Result{}, errors.New("each entry is a magnet: link or an http(s) URL")
			}
			items = append(items, item{raw: s, name: display(u)})
		default:
			return sdk.Result{}, errors.New("each entry is a magnet: link or an http(s) URL")
		}
	}
	form := url.Values{}
	if p.SavePath != "" {
		s, err := clean(p.SavePath, "save path")
		if err != nil {
			return sdk.Result{}, err
		}
		form.Set("savepath", s)
	}
	if p.Category != nil && *p.Category != "" {
		s, err := clean(*p.Category, "category")
		if err != nil {
			return sdk.Result{}, err
		}
		form.Set("category", s)
	}
	if len(p.Tags) > 10 {
		return sdk.Result{}, errors.New("at most 10 tags")
	}
	var tags []string
	for _, t := range p.Tags {
		s, err := clean(t, "tag")
		if err != nil || strings.Contains(s, ",") {
			return sdk.Result{}, errors.New("tags are short, one line, without commas")
		}
		if s != "" {
			tags = append(tags, s)
		}
	}
	if len(tags) > 0 {
		form.Set("tags", strings.Join(tags, ","))
	}

	// What's there already: adding a torrent qBittorrent has is a no-op, and
	// its undo mustn't delete the existing one.
	var before []torrent
	if err := c.get(ctx, "/torrents/info", nil, &before); err != nil {
		return sdk.Result{}, err
	}
	had := map[string]bool{}
	for _, t := range before {
		had[strings.ToLower(t.Hash)] = true
	}
	var changes []sdk.Change
	var urls []string
	for _, it := range items {
		if it.hash != "" && had[it.hash] {
			changes = append(changes, sdk.Change{Target: it.name, Op: "skip (already in qBittorrent)"})
			continue
		}
		changes = append(changes, sdk.Change{Target: it.name, Op: "add"})
		urls = append(urls, it.raw)
	}
	if len(urls) == 0 {
		return sdk.JSON(map[string]any{"added": []string{}, "note": "all of these are already in qBittorrent"})
	}
	if dry {
		after, _ := json.Marshal(map[string]any{"savePath": form.Get("savepath"), "category": form.Get("category"), "tags": tags, "paused": p.Paused})
		for i := range changes {
			if changes[i].Op == "add" {
				changes[i].After = after
			}
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add %d torrents", len(urls)), Changes: changes}}, nil
	}
	form.Set("urls", strings.Join(urls, "\n"))
	if p.Paused {
		form.Set("paused", "true")  // qBittorrent 4
		form.Set("stopped", "true") // qBittorrent 5
	}
	raw, err := c.call(ctx, http.MethodPost, "/torrents/add", form, true)
	if err != nil {
		return sdk.Result{}, err
	}
	if strings.TrimSpace(string(raw)) == "Fails." {
		return sdk.Result{}, errors.New("qBittorrent couldn't add these torrents")
	}

	// Find the new torrents for the undo: magnets name their hash; a URL's
	// torrent appears once qBittorrent has fetched the file.
	added := map[string]bool{}
	pending := 0
	for _, it := range items {
		if it.hash != "" && !had[it.hash] {
			added[it.hash] = true
		} else if it.hash == "" {
			pending++
		}
	}
	if pending > 0 {
		deadline := time.Now().Add(wait)
		for {
			var now []torrent
			if err := c.get(ctx, "/torrents/info", nil, &now); err == nil {
				n := 0
				for _, t := range now {
					h := strings.ToLower(t.Hash)
					if !had[h] && !added[h] {
						n++
					}
				}
				if n >= pending || !time.Now().Before(deadline) {
					for _, t := range now {
						if h := strings.ToLower(t.Hash); !had[h] {
							added[h] = true
						}
					}
					break
				}
			}
			if !time.Now().Before(deadline) {
				break
			}
			select {
			case <-ctx.Done():
				return sdk.Result{}, ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	hs := make([]string, 0, len(added))
	for h := range added {
		hs = append(hs, h)
	}
	sort.Strings(hs)
	out := map[string]any{"requested": len(urls), "added": hs}
	if len(hs) < len(urls) {
		out["note"] = "some torrents haven't shown up yet (qBittorrent is still fetching them); undo only covers the ones listed"
	}
	res, err := sdk.JSON(out)
	if len(hs) > 0 {
		res.Undo = sdk.UndoWith("delete", map[string]any{"hashes": hs, "deleteFiles": false}, fmt.Sprintf("Delete the %d added torrents (keeping files)", len(hs)))
	}
	return res, err
}

func (c *conn) limit(ctx context.Context, which string) (int64, error) {
	raw, err := c.call(ctx, http.MethodGet, "/transfer/"+which+"Limit", nil, false)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("unexpected answer from qBittorrent: %q", raw)
	}
	return n, nil
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
	type lim struct {
		which, label string
		want         *int64
		prev         int64
	}
	ls := []*lim{{which: "download", label: "download limit", want: down}, {which: "upload", label: "upload limit", want: up}}
	var changes []sdk.Change
	undo := map[string]any{}
	for _, l := range ls {
		if l.want == nil {
			continue
		}
		prev, err := c.limit(ctx, l.which)
		if err != nil {
			return sdk.Result{}, err
		}
		l.prev = prev
		if prev>>10 == *l.want && (prev == 0) == (*l.want == 0) {
			l.want = nil // unchanged
			continue
		}
		b, _ := json.Marshal(kib(prev))
		a, _ := json.Marshal(kib(*l.want << 10))
		changes = append(changes, sdk.Change{Target: "global " + l.label + " (KiB/s)", Op: "update", Before: b, After: a})
		undo[l.which+"KiB"] = (prev + 1023) >> 10
	}
	if len(changes) == 0 {
		return sdk.JSON(map[string]any{"note": "the limits are already set like this"})
	}
	if dry {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Change qBittorrent's speed limits", Changes: changes}}, nil
	}
	out := map[string]any{}
	for _, l := range ls {
		if l.want == nil {
			continue
		}
		path := "/transfer/setDownloadLimit"
		if l.which == "upload" {
			path = "/transfer/setUploadLimit"
		}
		if _, err := c.post(ctx, path, url.Values{"limit": {strconv.FormatInt(*l.want<<10, 10)}}); err != nil {
			return sdk.Result{}, err
		}
		out[l.which+"LimitKiBs"] = kib(*l.want << 10)
	}
	res, err := sdk.JSON(out)
	res.Undo = sdk.UndoWith("set_speed_limits", undo, "Restore the previous speed limits")
	return res, err
}
