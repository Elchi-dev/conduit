// Package fileflows works with a FileFlows file processing server through
// its signed API: the processing status (queue, files in progress,
// processed), the processing nodes and the libraries.
package fileflows

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one FileFlows server.
type Config struct {
	URL                string `json:"url"`      // e.g. http://nas.lan:19200
	APIToken           string `json:"apiToken"` // secret:// API token (Config, API)
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces the clock (tests).
	Now func() time.Time
}

// New returns the FileFlows module.
func New() *Module { return &Module{} }

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// maxListed caps the files in progress, nodes and libraries in the output.
const maxListed = 100

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "fileflows", Name: "FileFlows", Version: "0.1.0", Category: "Media", Icon: "workflow",
		Description: "FileFlows: processing status with the queue and files in progress, processing nodes, libraries.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiToken"],"properties":{
			"url":{"type":"string","description":"FileFlows' address, e.g. http://nas.lan:19200"},
			"apiToken":{"type":"string","x-secret":true,"description":"The API token (Config, API, with the API enabled)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Processing status", Description: "How many files wait, are being processed and were processed, and each file in progress with its name, library, step and progress.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{}}`)},
			{Name: "nodes", Title: "Nodes", Description: "Each processing node with its name, whether it's enabled, how many files it runs at once, its version and operating system.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{}}`)},
			{Name: "libraries", Title: "Libraries", Description: "Each library with its name, whether it's enabled, its flow, priority, scan interval and last scan.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{}}`)},
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
		return errors.New("the address is like http://nas.lan:19200")
	}
	if !strings.HasPrefix(c.APIToken, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	now := m.Now
	if now == nil {
		now = time.Now
	}
	ref := c.APIToken
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base, func(ctx context.Context, r *http.Request) error {
		tok, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		// The signed path starts at /api/, without a reverse proxy's sub
		// path or the query. Every call here is a GET, so the body hash is
		// empty.
		p := strings.TrimPrefix(r.URL.Path, base)
		ts := strconv.FormatInt(now().Unix(), 10)
		nonce, err := newNonce()
		if err != nil {
			return err
		}
		r.Header.Set("X-Timestamp", ts)
		r.Header.Set("X-Nonce", nonce)
		r.Header.Set("X-Signature", sign(strings.TrimSpace(tok), r.Method+":"+p+":"+ts+":"+nonce+":"))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sign(key, s string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(s))
	return hex.EncodeToString(mac.Sum(nil))
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var (
	errAuth  = errors.New("FileFlows refused the signed request: check the API token and that this computer's clock is right")
	errNoAPI = errors.New("no FileFlows API at this address: enable it in Config, API (it needs a FileFlows license)")
)

func (c *conn) get(ctx context.Context, p string, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, "/api"+p, nil, nil, out)
	err = scrub(err)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errAuth
	case rest.IsStatus(err, http.StatusNotFound):
		return errNoAPI
	case err != nil && strings.Contains(err.Error(), "unexpected answer"):
		// An unknown route answers with the web app's page.
		return errors.New("unexpected answer: is this FileFlows, with the API enabled?")
	}
	return err
}

type status struct {
	Queue      *int64 `json:"queue"`
	Processing int64  `json:"processing"`
	Processed  int64  `json:"processed"`
	Time       string `json:"time"`
	Files      []struct {
		Name     string          `json:"name"`
		Relative string          `json:"relativePath"`
		Library  json.RawMessage `json:"library"`
		Step     string          `json:"step"`
		Percent  float64         `json:"stepPercent"`
	} `json:"processingFiles"`
}

func (c *conn) status(ctx context.Context) (status, error) {
	var s status
	if err := c.get(ctx, "/status", &s); err != nil {
		return s, err
	}
	if s.Queue == nil {
		return s, errors.New("unexpected answer: is this FileFlows?")
	}
	return s, nil
}

// pathRun is a word with a slash or backslash in a server's error text:
// a file or folder (/media/Family/a.mkv, C:\x\y).
var pathRun = regexp.MustCompile(`[^\s"'<>]*[\\/][^\s"'<>]*`)

// scrub keeps folders out of an error FileFlows sent.
func scrub(err error) error {
	var e *rest.Error
	if errors.As(err, &e) {
		return &rest.Error{Status: e.Status, Message: pathRun.ReplaceAllString(e.Message, "[path]")}
	}
	return err
}

// clip redacts a server's text, then keeps it to one line of n bytes.
func clip(s string, n int) string {
	s = rest.Redact(strings.Join(strings.Fields(s), " "))
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// scalar passes on a number, a boolean or a short string, and nothing else:
// a field FileFlows may send as an object could hold a path.
func scalar(v any) (any, bool) {
	switch x := v.(type) {
	case float64, bool:
		return x, true
	case string:
		if x = clip(x, 40); x != "" && !strings.ContainsAny(x, `/\`) {
			return x, true
		}
	}
	return nil, false
}

// shortName keeps only a file's name: paths say where someone keeps what.
func shortName(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, `\`, "/"))
	if p == "" {
		return ""
	}
	return clip(path.Base(p), 200)
}

// refName reads a name sent either as a string or as {"Name": ...}.
func refName(raw json.RawMessage) string {
	return clip(rawName(raw), 100)
}

func rawName(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		Name string `json:"Name"`
		Low  string `json:"name"`
	}
	if json.Unmarshal(raw, &o) == nil {
		if o.Name != "" {
			return o.Name
		}
		return o.Low
	}
	return ""
}

type nodeT struct {
	UID         string `json:"Uid"`
	Name        string `json:"Name"`
	Enabled     bool   `json:"Enabled"`
	FlowRunners int    `json:"FlowRunners"`
	Version     string `json:"Version"`
	OS          any    `json:"OperatingSystem"`
	Priority    any    `json:"Priority"`
	// The address, temp path, path mappings and schedule aren't read.
}

// nodes reads the processing nodes, called agents from FileFlows 26.09 on
// and nodes before.
func (c *conn) nodes(ctx context.Context) ([]nodeT, error) {
	var ns []nodeT
	err := c.get(ctx, "/agent", &ns)
	if err == nil {
		return ns, nil
	}
	if errors.Is(err, errAuth) {
		return nil, err
	}
	ns = nil
	if err := c.get(ctx, "/node", &ns); err != nil {
		return nil, err
	}
	return ns, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.status(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("FileFlows · %d queued, %d processing", *s.Queue, s.Processing)}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct{}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "status":
		s, err := c.status(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		files := []map[string]any{}
		for i, f := range s.Files {
			if i == maxListed {
				break
			}
			n := f.Relative
			if n == "" {
				n = f.Name
			}
			files = append(files, map[string]any{"name": shortName(n), "library": refName(f.Library), "step": clip(f.Step, 100), "percent": float64(int(f.Percent*10)) / 10})
		}
		out := map[string]any{"queued": *s.Queue, "processing": s.Processing, "processed": s.Processed, "files": files}
		if len(s.Files) > maxListed {
			out["note"] = fmt.Sprintf("the first %d files in progress only", maxListed)
		}
		if s.Time != "" && len(s.Time) <= 40 {
			out["processingTime"] = s.Time
		}
		return sdk.JSON(out)

	case "nodes":
		ns, err := c.nodes(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i, n := range ns {
			if i == maxListed {
				break
			}
			e := map[string]any{"id": clip(n.UID, 100), "name": clip(n.Name, 100), "enabled": n.Enabled, "runners": n.FlowRunners}
			if n.Version != "" {
				e["version"] = clip(n.Version, 40)
			}
			if v, ok := scalar(n.OS); ok {
				e["os"] = v
			}
			if v, ok := scalar(n.Priority); ok {
				e["priority"] = v
			}
			out = append(out, e)
		}
		res := map[string]any{"total": len(ns), "nodes": out}
		if len(ns) > maxListed {
			res["note"] = fmt.Sprintf("the first %d nodes only", maxListed)
		}
		return sdk.JSON(res)

	case "libraries":
		var ls []struct {
			UID          string          `json:"Uid"`
			Name         string          `json:"Name"`
			Enabled      bool            `json:"Enabled"`
			Flow         json.RawMessage `json:"Flow"`
			Priority     any             `json:"Priority"`
			ScanInterval int64           `json:"ScanInterval"`
			LastScanned  string          `json:"LastScanned"`
			// The path, filters and schedule aren't read.
		}
		if err := c.get(ctx, "/library", &ls); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i, l := range ls {
			if i == maxListed {
				break
			}
			e := map[string]any{"id": clip(l.UID, 100), "name": clip(l.Name, 100), "enabled": l.Enabled, "flow": refName(l.Flow), "scanIntervalSeconds": l.ScanInterval}
			if v, ok := scalar(l.Priority); ok {
				e["priority"] = v
			}
			for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
				if t, err := time.Parse(layout, l.LastScanned); err == nil {
					if t.Year() > 1 {
						e["lastScanned"] = t.UTC().Format(time.RFC3339)
					}
					break
				}
			}
			out = append(out, e)
		}
		res := map[string]any{"total": len(ls), "libraries": out}
		if len(ls) > maxListed {
			res["note"] = fmt.Sprintf("the first %d libraries only", maxListed)
		}
		return sdk.JSON(res)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
