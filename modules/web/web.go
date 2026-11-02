// Package web watches websites and APIs (uptime, status, content, TLS expiry)
// and makes outgoing HTTP requests.
package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Check is one monitored URL.
type Check struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Status   int    `json:"status"`   // expected status, default any 2xx/3xx
	Contains string `json:"contains"` // text the body must contain
}

// Config is the module's settings.
type Config struct {
	Checks          []Check `json:"checks"`
	IntervalSeconds int     `json:"intervalSeconds"`
	CertWarnDays    int     `json:"certWarnDays"`
}

// Result is the outcome of one check.
type Result struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Up        bool   `json:"up"`
	Status    int    `json:"status"`
	LatencyMS int64  `json:"latencyMs"`
	Problem   string `json:"problem,omitempty"`
	CertDays  *int   `json:"certDaysLeft,omitempty"`
	CheckedAt string `json:"checkedAt"`
	DownSince string `json:"downSince,omitempty"`
}

type watch struct {
	cfg     Config
	host    sdk.Host
	stop    context.CancelFunc
	mu      sync.Mutex
	results map[string]Result
}

// Module implements sdk.Module.
type Module struct {
	mu      sync.Mutex
	watches map[string]*watch
	http    *http.Client
}

// New returns the module.
func New() *Module {
	return &Module{watches: map[string]*watch{}, http: &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "web", Name: "Websites and APIs", Version: "0.1.0", Category: "Infrastructure", Icon: "globe",
		Description: "Uptime, response time, expected content and certificate expiry for your sites, plus outgoing requests.",
		Presets:     []string{"developer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"checks":{"type":"array","items":{"type":"object"},"description":"JSON list of {name, url, status, contains}, e.g. [{\"name\":\"Shop\",\"url\":\"https://shop.example.com\",\"contains\":\"Add to cart\"}]"},
			"intervalSeconds":{"type":"integer","default":60,"minimum":15},
			"certWarnDays":{"type":"integer","default":14,"title":"Warn before certificates expire (days)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Status", Description: "The latest result of every check.", Risk: sdk.RiskRead},
			{Name: "check_now", Title: "Check now", Risk: sdk.RiskRead},
			{Name: "request", Title: "Send a request", Description: "Call any HTTP endpoint from this machine.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["url"],"properties":{"method":{"type":"string","enum":["GET","POST","PUT","PATCH","DELETE","HEAD"],"default":"GET"},"url":{"type":"string"},"headers":{"type":"object"},"body":{"type":"string","x-multiline":true}}}`)},
		},
		Events: []sdk.EventSpec{
			{Type: "web.down", Description: "A check started failing"},
			{Type: "web.up", Description: "A failing check recovered"},
			{Type: "web.cert_expiring", Description: "A certificate expires within the warning window"},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var cfg Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("invalid settings: %w", err)
		}
	}
	for i, c := range cfg.Checks {
		u, err := url.Parse(c.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("check %d: invalid URL %q", i+1, c.URL)
		}
		if c.Name == "" {
			cfg.Checks[i].Name = u.Host
		}
	}
	if cfg.IntervalSeconds < 15 {
		cfg.IntervalSeconds = 60
	}
	if cfg.CertWarnDays == 0 {
		cfg.CertWarnDays = 14
	}
	w := &watch{cfg: cfg, host: h, results: map[string]Result{}}
	ctx, cancel := context.WithCancel(context.Background())
	w.stop = cancel
	m.mu.Lock()
	if old := m.watches[id]; old != nil {
		old.stop()
	}
	m.watches[id] = w
	m.mu.Unlock()
	if len(cfg.Checks) > 0 {
		go m.loop(ctx, id, w)
	}
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error {
	m.mu.Lock()
	if w := m.watches[id]; w != nil {
		w.stop()
	}
	delete(m.watches, id)
	m.mu.Unlock()
	return nil
}

func (m *Module) watch(id string) (*watch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if w := m.watches[id]; w != nil {
		return w, nil
	}
	return nil, errors.New("not configured")
}

func (m *Module) loop(ctx context.Context, id string, w *watch) {
	t := time.NewTicker(time.Duration(w.cfg.IntervalSeconds) * time.Second)
	defer t.Stop()
	for {
		m.runAll(ctx, id, w)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Module) runAll(ctx context.Context, id string, w *watch) []Result {
	var wg sync.WaitGroup
	out := make([]Result, len(w.cfg.Checks))
	for i, c := range w.cfg.Checks {
		wg.Add(1)
		go func(i int, c Check) {
			defer wg.Done()
			out[i] = m.check(ctx, c, w.cfg.CertWarnDays)
		}(i, c)
	}
	wg.Wait()
	w.mu.Lock()
	for _, r := range out {
		prev, seen := w.results[r.Name]
		if !r.Up {
			r.DownSince = r.CheckedAt
			if seen && !prev.Up {
				r.DownSince = prev.DownSince
			}
		}
		w.results[r.Name] = r
		if w.host != nil {
			switch {
			case !r.Up && (!seen || prev.Up):
				w.host.Publish(ctx, sdk.Event{Type: "web.down", Instance: id, Data: mustJSON(r)})
			case r.Up && seen && !prev.Up:
				w.host.Publish(ctx, sdk.Event{Type: "web.up", Instance: id, Data: mustJSON(r)})
			}
			if r.CertDays != nil && *r.CertDays <= w.cfg.CertWarnDays && (!seen || prev.CertDays == nil || *prev.CertDays > w.cfg.CertWarnDays) {
				w.host.Publish(ctx, sdk.Event{Type: "web.cert_expiring", Instance: id, Data: mustJSON(r)})
			}
		}
	}
	w.mu.Unlock()
	return out
}

func (m *Module) check(ctx context.Context, c Check, warnDays int) Result {
	r := Result{Name: c.Name, URL: c.URL, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		r.Problem = err.Error()
		return r
	}
	req.Header.Set("User-Agent", "Conduit uptime check")
	start := time.Now()
	res, err := m.http.Do(req)
	r.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		r.Problem = err.Error()
		return r
	}
	defer res.Body.Close()
	r.Status = res.StatusCode
	if res.TLS != nil && len(res.TLS.PeerCertificates) > 0 {
		days := int(time.Until(res.TLS.PeerCertificates[0].NotAfter).Hours() / 24)
		r.CertDays = &days
	}
	switch {
	case c.Status != 0 && res.StatusCode != c.Status:
		r.Problem = fmt.Sprintf("status %d, expected %d", res.StatusCode, c.Status)
	case c.Status == 0 && res.StatusCode >= 400:
		r.Problem = fmt.Sprintf("status %d", res.StatusCode)
	case c.Contains != "":
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
		if !strings.Contains(string(body), c.Contains) {
			r.Problem = fmt.Sprintf("page doesn't contain %q", c.Contains)
		}
	}
	r.Up = r.Problem == ""
	_ = warnDays
	return r
}

// Health implements sdk.Module.
func (m *Module) Health(_ context.Context, id string) sdk.Health {
	w, err := m.watch(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured"}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.cfg.Checks) == 0 {
		return sdk.Health{Status: "ok", Message: "No checks configured"}
	}
	var down []string
	expiring := 0
	for _, r := range w.results {
		if !r.Up {
			down = append(down, r.Name)
		}
		if r.CertDays != nil && *r.CertDays <= w.cfg.CertWarnDays {
			expiring++
		}
	}
	switch {
	case len(down) > 0:
		return sdk.Health{Status: "down", Message: "Down: " + strings.Join(down, ", ")}
	case expiring > 0:
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%d certificates expire soon", expiring)}
	case len(w.results) == 0:
		return sdk.Health{Status: "ok", Message: "Checking…"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("All %d up", len(w.results))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	w, err := m.watch(c.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "status":
		w.mu.Lock()
		out := []Result{}
		for _, ch := range w.cfg.Checks {
			if r, ok := w.results[ch.Name]; ok {
				out = append(out, r)
			}
		}
		w.mu.Unlock()
		return sdk.JSON(out)
	case "check_now":
		return sdk.JSON(m.runAll(ctx, c.Instance, w))
	case "request":
		var in struct {
			Method  string            `json:"method"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
		}
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		u, err := url.Parse(in.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return sdk.Result{}, errors.New("url must be http or https")
		}
		if in.Method == "" {
			in.Method = http.MethodGet
		}
		req, err := http.NewRequestWithContext(ctx, in.Method, in.URL, strings.NewReader(in.Body))
		if err != nil {
			return sdk.Result{}, err
		}
		for k, v := range in.Headers {
			req.Header.Set(k, v)
		}
		start := time.Now()
		cl := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
		res, err := cl.Do(req)
		if err != nil {
			return sdk.Result{}, err
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		hdr := map[string]string{}
		for k := range res.Header {
			hdr[k] = res.Header.Get(k)
		}
		return sdk.JSON(map[string]any{"status": res.StatusCode, "latencyMs": time.Since(start).Milliseconds(), "headers": hdr, "body": string(body)})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
