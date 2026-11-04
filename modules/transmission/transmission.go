// Package transmission works with a Transmission BitTorrent client through
// its RPC interface: session speeds and limits, the torrent list, pausing
// and resuming, adding by magnet link or URL, and deleting.
//
// The RPC answers the first request of a session with 409 Conflict and an
// X-Transmission-Session-Id header (its CSRF protection); the client sends
// that id back on every request and fetches a new one whenever it's
// answered 409 again.
package transmission

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

// Config is one Transmission client.
type Config struct {
	URL                string `json:"url"`      // e.g. http://nas.lan:9091
	Username           string `json:"username"` // when RPC authentication is on
	Password           string `json:"password"` // secret:// RPC password
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	endpoint   string
	user, pass string // pass is a secret:// reference
	h          sdk.Host
	http       *http.Client

	mu  sync.Mutex
	sid string // X-Transmission-Session-Id
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Transmission module.
func New() *Module { return &Module{} }

const maxHashes = 100

var (
	hashRe    = regexp.MustCompile(`^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)
	pathRe    = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	sessionRe = regexp.MustCompile(`^[A-Za-z0-9]{1,128}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	hashes := `"hashes":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"string","pattern":"^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$"},"description":"Torrent hashes (from torrents)"}`
	return sdk.Manifest{
		ID: "transmission", Name: "Transmission", Version: "0.1.0", Category: "Media", Icon: "download",
		Description: "Transmission: transfer speeds and limits, torrents, pause and resume, add by magnet or URL, delete.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The web interface's address, e.g. http://nas.lan:9091 (the RPC path /transmission/rpc is added)"},
			"username":{"type":"string","description":"RPC username, when authentication is on (Preferences, Remote)"},
			"password":{"type":"string","x-secret":true,"description":"RPC password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "session", Title: "Session", Description: "Version, download and upload speed, torrent counts, speed limits and whether the alternative (turtle) limits are on.", Risk: sdk.RiskRead},
			{Name: "torrents", Title: "Torrents", Description: "Torrents with progress, speed, status, ratio, size and ETA; filter by status or name.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{
					"status":{"type":"string","enum":["all","downloading","seeding","stopped","checking","queued","active","error"],"default":"all"},
					"query":{"type":"string","description":"Part of the name"},
					"sort":{"type":"string","enum":["added","name","progress","download","upload","ratio","size"],"default":"added"},
					"limit":{"type":"integer","default":50,"minimum":1,"maximum":500}}}`)},
			{Name: "pause", Title: "Pause torrents", Description: "Stops torrents. Undo starts the ones that were running.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["hashes"],"properties":{` + hashes + `}}`)},
			{Name: "resume", Title: "Resume torrents", Description: "Starts torrents. Undo pauses the ones that were stopped.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["hashes"],"properties":{` + hashes + `}}`)},
			{Name: "add", Title: "Add torrents", Description: "Adds torrents by magnet link or http(s) URL of a .torrent file, into the default download folder. Undo deletes the new ones, keeping downloaded files.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["urls"],"properties":{
					"urls":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"string"},"description":"magnet: links or http(s) URLs of .torrent files"},
					"paused":{"type":"boolean","default":false,"description":"Add without starting"}}}`)},
			{Name: "delete", Title: "Delete torrents", Description: "Removes torrents from Transmission, and with deleteFiles also their downloaded data.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["hashes"],"properties":{` + hashes + `,"deleteFiles":{"type":"boolean","default":false,"description":"Also delete the downloaded files"}}}`)},
			{Name: "set_speed_limits", Title: "Set speed limits", Description: "Sets the global download and/or upload limit in kB/s (0 = unlimited). Undo restores the previous limits.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"downloadKBs":{"type":"integer","minimum":0,"maximum":10000000},"uploadKBs":{"type":"integer","minimum":0,"maximum":10000000}}}`)},
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
		return errors.New("the address is like http://nas.lan:9091")
	}
	user := strings.TrimSpace(c.Username)
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the RPC password in the vault and enter its secret:// reference")
	}
	if (user == "") != (c.Password == "") {
		return errors.New("enter both the RPC username and password, or neither (when authentication is off)")
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
	p := strings.TrimRight(u.Path, "/")
	switch {
	case strings.HasSuffix(p, "/rpc"):
	case strings.HasSuffix(p, "/transmission/web"):
		p = strings.TrimSuffix(p, "/web") + "/rpc"
	case strings.HasSuffix(p, "/transmission"):
		p += "/rpc"
	default:
		p += "/transmission/rpc"
	}
	m.set.Put(id, &conn{endpoint: u.Scheme + "://" + u.Host + p, user: user, pass: c.Password, h: h, http: rest.SameHostOnly(client)})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var (
	errLogin     = errors.New("Transmission refused the username or password")
	errWhitelist = errors.New("Transmission refused this address (its RPC whitelist or host whitelist doesn't include Conduit)")
)

// rpc calls one method and decodes its arguments into out.
func (c *conn) rpc(ctx context.Context, method string, args, out any) error {
	if args == nil {
		args = map[string]any{}
	}
	body, err := json.Marshal(map[string]any{"method": method, "arguments": args})
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Conduit")
		c.mu.Lock()
		sid := c.sid
		c.mu.Unlock()
		if sid != "" {
			req.Header.Set("X-Transmission-Session-Id", sid)
		}
		if c.user != "" {
			pw, err := c.h.Secret(ctx, c.pass)
			if err != nil {
				return err
			}
			req.SetBasicAuth(c.user, pw)
		}
		res, err := c.http.Do(req)
		if err != nil {
			return rest.TransportError(err)
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
		res.Body.Close()
		if err != nil {
			return err
		}
		switch {
		case res.StatusCode == http.StatusConflict:
			next := res.Header.Get("X-Transmission-Session-Id")
			if attempt > 0 || !sessionRe.MatchString(next) {
				return errors.New("Transmission didn't accept its own session id (is this the RPC address?)")
			}
			c.mu.Lock()
			c.sid = next
			c.mu.Unlock()
			continue
		case res.StatusCode == http.StatusUnauthorized:
			return errLogin
		case res.StatusCode == http.StatusForbidden || res.StatusCode == 421:
			return errWhitelist
		case res.StatusCode == http.StatusNotFound:
			return errors.New("no Transmission RPC at this address")
		case res.StatusCode >= 300:
			return fmt.Errorf("Transmission answered %s", res.Status)
		}
		var env struct {
			Result    string          `json:"result"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(raw, &env); err != nil || env.Result == "" {
			return errors.New("unexpected answer: is this Transmission's RPC address?")
		}
		if env.Result != "success" {
			msg := env.Result
			if len(msg) > 200 {
				msg = msg[:200]
			}
			return errors.New("Transmission: " + rest.Redact(msg))
		}
		if out != nil && len(env.Arguments) > 0 {
			if err := json.Unmarshal(env.Arguments, out); err != nil {
				return fmt.Errorf("unexpected answer from Transmission: %w", err)
			}
		}
		return nil
	}
}

type session struct {
	Version         string `json:"version"`
	RPCVersion      int    `json:"rpc-version"`
	DownLimit       int64  `json:"speed-limit-down"`
	DownLimitOn     bool   `json:"speed-limit-down-enabled"`
	UpLimit         int64  `json:"speed-limit-up"`
	UpLimitOn       bool   `json:"speed-limit-up-enabled"`
	AltSpeedEnabled bool   `json:"alt-speed-enabled"`
	AltSpeedDown    int64  `json:"alt-speed-down"`
	AltSpeedUp      int64  `json:"alt-speed-up"`
	DownloadDir     string `json:"download-dir"`
}

var sessionFields = []string{"version", "rpc-version", "speed-limit-down", "speed-limit-down-enabled", "speed-limit-up", "speed-limit-up-enabled",
	"alt-speed-enabled", "alt-speed-down", "alt-speed-up", "download-dir"}

type stats struct {
	Active   int   `json:"activeTorrentCount"`
	Paused   int   `json:"pausedTorrentCount"`
	Count    int   `json:"torrentCount"`
	DownRate int64 `json:"downloadSpeed"`
	UpRate   int64 `json:"uploadSpeed"`
}

func (c *conn) session(ctx context.Context) (session, error) {
	var s session
	err := c.rpc(ctx, "session-get", map[string]any{"fields": sessionFields}, &s)
	return s, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.session(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "Transmission"
	if v := strings.Fields(s.Version); len(v) > 0 {
		msg += " " + v[0] // "4.0.6 (38c1649)"
	}
	var st stats
	if c.rpc(ctx, "session-stats", nil, &st) == nil {
		msg += fmt.Sprintf(" · %d torrents, %d active", st.Count, st.Active)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type torrent struct {
	ID          int      `json:"id"`
	Hash        string   `json:"hashString"`
	Name        string   `json:"name"`
	Status      int      `json:"status"`
	PercentDone float64  `json:"percentDone"`
	RateDown    int64    `json:"rateDownload"`
	RateUp      int64    `json:"rateUpload"`
	Ratio       float64  `json:"uploadRatio"`
	TotalSize   int64    `json:"totalSize"`
	ETA         int64    `json:"eta"`
	AddedDate   int64    `json:"addedDate"`
	Error       int      `json:"error"`
	ErrorString string   `json:"errorString"`
	Labels      []string `json:"labels"`
	DownloadDir string   `json:"downloadDir"`
	Peers       int      `json:"peersConnected"`
	// Trackers aren't read: their announce URLs carry private trackers'
	// passkeys.
}

var torrentFields = []string{"id", "hashString", "name", "status", "percentDone", "rateDownload", "rateUpload", "uploadRatio", "totalSize",
	"eta", "addedDate", "error", "errorString", "labels", "downloadDir", "peersConnected"}

// Transmission's status numbers (RPC version 14 and later).
var statusNames = map[int]string{0: "stopped", 1: "check queued", 2: "checking", 3: "download queued", 4: "downloading", 5: "seed queued", 6: "seeding"}

func (t torrent) stopped() bool { return t.Status == 0 }

func (t torrent) state() string {
	if s, ok := statusNames[t.Status]; ok {
		return s
	}
	return fmt.Sprintf("status %d", t.Status)
}

func (t torrent) summary() map[string]any {
	e := map[string]any{"hash": strings.ToLower(t.Hash), "name": t.Name, "status": t.state(), "progress": float64(int(t.PercentDone*1000)) / 10,
		"sizeMB": t.TotalSize >> 20, "downKBs": t.RateDown / 1000, "upKBs": t.RateUp / 1000, "ratio": float64(int(t.Ratio*100)) / 100,
		"peers": t.Peers, "added": time.Unix(t.AddedDate, 0).UTC().Format(time.RFC3339), "downloadDir": t.DownloadDir}
	if t.ETA > 0 {
		e["etaMinutes"] = t.ETA / 60
	}
	if len(t.Labels) > 0 {
		e["labels"] = t.Labels
	}
	if t.Error != 0 && t.ErrorString != "" {
		e["error"] = rest.Redact(t.ErrorString) // tracker messages can quote an announce URL
	}
	return e
}

type input struct {
	Status      string   `json:"status"`
	Query       string   `json:"query"`
	Sort        string   `json:"sort"`
	Limit       int      `json:"limit"`
	Hashes      []string `json:"hashes"`
	DeleteFiles bool     `json:"deleteFiles"`
	URLs        []string `json:"urls"`
	Paused      bool     `json:"paused"`
	DownloadKBs *int64   `json:"downloadKBs"`
	UploadKBs   *int64   `json:"uploadKBs"`
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
		s, err := c.session(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var st stats
		if err := c.rpc(ctx, "session-stats", nil, &st); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"version": s.Version, "rpcVersion": s.RPCVersion,
			"downKBs": st.DownRate / 1000, "upKBs": st.UpRate / 1000,
			"torrents": st.Count, "active": st.Active, "paused": st.Paused,
			"downLimitKBs": limitOut(s.DownLimit, s.DownLimitOn), "upLimitKBs": limitOut(s.UpLimit, s.UpLimitOn),
			"alternativeLimits": s.AltSpeedEnabled, "alternativeDownKBs": s.AltSpeedDown, "alternativeUpKBs": s.AltSpeedUp,
			"downloadDir": s.DownloadDir})
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
		if err := c.rpc(ctx, "torrent-remove", map[string]any{"ids": hs, "delete-local-data": p.DeleteFiles}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": hs, "filesDeleted": p.DeleteFiles})
	case "set_speed_limits":
		return c.speedLimits(ctx, call.DryRun, p.DownloadKBs, p.UploadKBs)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func limitOut(v int64, on bool) any {
	if !on || v <= 0 {
		return "unlimited"
	}
	return v
}

func (c *conn) torrents(ctx context.Context, p input) (sdk.Result, error) {
	status := p.Status
	if status == "" {
		status = "all"
	}
	match := map[string]func(torrent) bool{
		"all":         func(torrent) bool { return true },
		"downloading": func(t torrent) bool { return t.Status == 4 },
		"seeding":     func(t torrent) bool { return t.Status == 6 },
		"stopped":     func(t torrent) bool { return t.Status == 0 },
		"checking":    func(t torrent) bool { return t.Status == 1 || t.Status == 2 },
		"queued":      func(t torrent) bool { return t.Status == 3 || t.Status == 5 },
		"active":      func(t torrent) bool { return t.RateDown > 0 || t.RateUp > 0 },
		"error":       func(t torrent) bool { return t.Error != 0 },
	}[status]
	if match == nil {
		return sdk.Result{}, fmt.Errorf("unknown status %q", status)
	}
	key := p.Sort
	if key == "" {
		key = "added"
	}
	less := map[string]func(a, b torrent) bool{
		"added":    func(a, b torrent) bool { return a.AddedDate > b.AddedDate },
		"name":     func(a, b torrent) bool { return strings.ToLower(a.Name) < strings.ToLower(b.Name) },
		"progress": func(a, b torrent) bool { return a.PercentDone > b.PercentDone },
		"download": func(a, b torrent) bool { return a.RateDown > b.RateDown },
		"upload":   func(a, b torrent) bool { return a.RateUp > b.RateUp },
		"ratio":    func(a, b torrent) bool { return a.Ratio > b.Ratio },
		"size":     func(a, b torrent) bool { return a.TotalSize > b.TotalSize },
	}[key]
	if less == nil {
		return sdk.Result{}, fmt.Errorf("unknown sort %q", key)
	}
	limit := p.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	var got struct {
		Torrents []torrent `json:"torrents"`
	}
	if err := c.rpc(ctx, "torrent-get", map[string]any{"fields": torrentFields}, &got); err != nil {
		return sdk.Result{}, err
	}
	needle := strings.ToLower(strings.TrimSpace(p.Query))
	var list []torrent
	for _, t := range got.Torrents {
		if match(t) && (needle == "" || strings.Contains(strings.ToLower(t.Name), needle)) {
			list = append(list, t)
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return less(list[i], list[j]) })
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
	var got struct {
		Torrents []torrent `json:"torrents"`
	}
	if err := c.rpc(ctx, "torrent-get", map[string]any{"ids": hs, "fields": torrentFields}, &got); err != nil {
		return nil, err
	}
	found := map[string]torrent{}
	for _, t := range got.Torrents {
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
		if t.stopped() == pausing {
			continue // already there
		}
		change = append(change, h)
		before, _ := json.Marshal(t.state())
		changes = append(changes, sdk.Change{Target: fmt.Sprintf("%s (%s)", t.Name, h[:8]), Op: call.Action, Before: before})
	}
	if len(change) == 0 {
		return sdk.JSON(map[string]any{"changed": []string{}, "note": "nothing to change"})
	}
	verb, back, method := "Pause", "resume", "torrent-stop"
	if !pausing {
		verb, back, method = "Resume", "pause", "torrent-start"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %d torrents", verb, len(change)), Changes: changes}}, nil
	}
	if err := c.rpc(ctx, method, map[string]any{"ids": change}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"changed": change})
	res.Undo = sdk.UndoWith(back, map[string]any{"hashes": change}, fmt.Sprintf("%s %d torrents again", strings.ToUpper(back[:1])+back[1:], len(change)))
	return res, err
}

// magnetHash is the info-hash a magnet link names: the v1 hash, or for a
// v2-only magnet its v2 hash.
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
				v2 = strings.ToLower(h)
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
	type item struct{ raw, name, hash string }
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
	var have struct {
		Torrents []torrent `json:"torrents"`
	}
	if err := c.rpc(ctx, "torrent-get", map[string]any{"fields": []string{"id", "hashString"}}, &have); err != nil {
		return sdk.Result{}, err
	}
	had := map[string]bool{}
	for _, t := range have.Torrents {
		had[strings.ToLower(t.Hash)] = true
	}
	var changes []sdk.Change
	var todo []item
	for _, it := range items {
		if it.hash != "" && had[it.hash] {
			changes = append(changes, sdk.Change{Target: it.name, Op: "skip (already in Transmission)"})
			continue
		}
		after, _ := json.Marshal(map[string]bool{"paused": p.Paused})
		changes = append(changes, sdk.Change{Target: it.name, Op: "add", After: after})
		todo = append(todo, it)
	}
	if len(todo) == 0 {
		return sdk.JSON(map[string]any{"added": []string{}, "note": "nothing to change: all of these are already in Transmission"})
	}
	if dry {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add %d torrents", len(todo)), Changes: changes}}, nil
	}
	var added, dupes []string
	for _, it := range todo {
		var got struct {
			Added *torrent `json:"torrent-added"`
			Dupe  *torrent `json:"torrent-duplicate"`
		}
		if err := c.rpc(ctx, "torrent-add", map[string]any{"filename": it.raw, "paused": p.Paused}, &got); err != nil {
			if len(added) > 0 {
				break // keep what was added so the undo covers it
			}
			return sdk.Result{}, fmt.Errorf("adding %s: %w", it.name, err)
		}
		switch {
		case got.Added != nil && hashRe.MatchString(got.Added.Hash):
			added = append(added, strings.ToLower(got.Added.Hash))
		case got.Dupe != nil:
			dupes = append(dupes, it.name)
		}
	}
	out := map[string]any{"requested": len(todo), "added": added}
	if len(dupes) > 0 {
		out["alreadyThere"] = dupes
	}
	if len(added)+len(dupes) < len(todo) {
		out["note"] = "Transmission didn't add every torrent; undo covers the ones listed"
	}
	res, err := sdk.JSON(out)
	if len(added) > 0 {
		res.Undo = sdk.UndoWith("delete", map[string]any{"hashes": added, "deleteFiles": false}, fmt.Sprintf("Delete the %d added torrents (keeping files)", len(added)))
	}
	return res, err
}

func (c *conn) speedLimits(ctx context.Context, dry bool, down, up *int64) (sdk.Result, error) {
	if down == nil && up == nil {
		return sdk.Result{}, errors.New("give downloadKBs, uploadKBs or both (0 = unlimited)")
	}
	for _, v := range []*int64{down, up} {
		if v != nil && (*v < 0 || *v > 10000000) {
			return sdk.Result{}, errors.New("limits are 0 (unlimited) to 10000000 kB/s")
		}
	}
	s, err := c.session(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	type lim struct {
		key, label string
		want       *int64
		prev       int64
		on         bool
	}
	ls := []lim{{"speed-limit-down", "download", down, s.DownLimit, s.DownLimitOn}, {"speed-limit-up", "upload", up, s.UpLimit, s.UpLimitOn}}
	var changes []sdk.Change
	set := map[string]any{}
	undo := map[string]any{}
	out := map[string]any{}
	for _, l := range ls {
		if l.want == nil {
			continue
		}
		prev := int64(0)
		if l.on && l.prev > 0 {
			prev = l.prev
		}
		if prev == *l.want {
			continue
		}
		b, _ := json.Marshal(limitOut(prev, prev > 0))
		a, _ := json.Marshal(limitOut(*l.want, *l.want > 0))
		changes = append(changes, sdk.Change{Target: "global " + l.label + " limit (kB/s)", Op: "update", Before: b, After: a})
		undo[l.label+"KBs"] = prev
		if *l.want == 0 {
			set[l.key+"-enabled"] = false
		} else {
			set[l.key] = *l.want
			set[l.key+"-enabled"] = true
		}
		out[l.label+"LimitKBs"] = limitOut(*l.want, *l.want > 0)
	}
	if len(changes) == 0 {
		return sdk.JSON(map[string]any{"note": "nothing to change: the limits are already set like this"})
	}
	if dry {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Change Transmission's speed limits", Changes: changes}}, nil
	}
	if err := c.rpc(ctx, "session-set", set, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(out)
	res.Undo = sdk.UndoWith("set_speed_limits", undo, "Restore the previous speed limits")
	return res, err
}
