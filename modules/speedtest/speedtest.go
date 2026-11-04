// Package speedtest works with a Speedtest Tracker server
// (alexjustesen/speedtest-tracker) through its API v1 and a bearer token:
// the latest result, past results, statistics over a window of days, and
// queueing a new speedtest. Results are read without the network interface
// details Ookla reports (internal and external IP, MAC address).
package speedtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Speedtest Tracker.
type Config struct {
	URL                string `json:"url"`      // e.g. https://speedtest.home.example
	APIToken           string `json:"apiToken"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces the clock (tests).
	Now func() time.Time
}

// New returns the Speedtest Tracker module.
func New() *Module { return &Module{} }

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

const (
	pageSize   = 500  // the API's largest page
	maxResults = 2000 // results read for one history or stats call
	defDays    = 7
	maxDays    = 365
	defLimit   = 50
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "speedtest", Name: "Speedtest Tracker", Version: "0.1.0", Category: "Network", Icon: "gauge",
		Description: "Speedtest Tracker: the latest result, history, download/upload/ping statistics, and running a speedtest.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiToken"],"properties":{
			"url":{"type":"string","description":"Speedtest Tracker's address, e.g. http://speedtest.local:8080"},
			"apiToken":{"type":"string","x-secret":true,"description":"An API token from Speedtest Tracker's API Tokens page (Read results; Run speedtest for the run action)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "latest", Title: "Latest result", Description: "The most recent speedtest: download and upload in Mbit/s, ping, jitter, packet loss, server, ISP, healthy and status.", Risk: sdk.RiskRead},
			{Name: "history", Title: "History", Description: "Past speedtests, newest first, over the last days (up to a year).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":365,"default":7},"limit":{"type":"integer","minimum":1,"maximum":500,"default":50}}}`)},
			{Name: "stats", Title: "Statistics", Description: "Over the last days: how many tests ran and failed, how many were unhealthy (below thresholds), and minimum, average, maximum and 10th percentile download, upload and ping.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":365,"default":7}}}`)},
			{Name: "run", Title: "Run a speedtest", Description: "Queues a speedtest now, optionally against one Ookla server id. It uses bandwidth for about half a minute. The result shows in latest when it's done.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"serverId":{"type":"integer","minimum":1,"description":"Ookla server id; Speedtest Tracker's default servers when left out"}}}`)},
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
		return errors.New("the address is like http://speedtest.local:8080")
	}
	if !strings.HasPrefix(c.APIToken, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h)
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	ref := c.APIToken
	base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1"), "/admin")
	api := rest.New(u.Scheme+"://"+u.Host+base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, method, path, q, nil, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Speedtest Tracker refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		ability := "Read results"
		if method != http.MethodGet {
			ability = "Run speedtest"
		}
		return fmt.Errorf("the API token doesn't have the %q ability", ability)
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no Speedtest Tracker API v1 at this address (it needs Speedtest Tracker 1.0 or later)")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Speedtest Tracker's API rate limit was hit; try again in a minute")
	}
	return err
}

type apiResult struct {
	ID        int64    `json:"id"`
	Service   string   `json:"service"`
	Ping      *float64 `json:"ping"`
	Download  *float64 `json:"download"` // bytes per second
	Upload    *float64 `json:"upload"`
	Healthy   *bool    `json:"healthy"`
	Status    string   `json:"status"`
	Scheduled bool     `json:"scheduled"`
	Comments  string   `json:"comments"`
	CreatedAt string   `json:"created_at"`
	Data      struct {
		ISP  string `json:"isp"`
		Ping struct {
			Jitter *float64 `json:"jitter"`
		} `json:"ping"`
		PacketLoss *float64 `json:"packetLoss"`
		Message    string   `json:"message"`
		Server     struct {
			ID       any    `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
			Country  string `json:"country"`
		} `json:"server"`
		Result struct {
			URL string `json:"url"`
		} `json:"result"`
		// interface (internal/external IP, MAC) is deliberately not decoded.
	} `json:"data"`
}

func mbps(bytesPerSec float64) float64 { return math.Round(bytesPerSec*8/1e4) / 100 }
func r2(f float64) float64             { return math.Round(f*100) / 100 }

func (r apiResult) out() map[string]any {
	o := map[string]any{"id": r.ID, "status": r.Status, "scheduled": r.Scheduled, "at": r.CreatedAt}
	if r.Service != "" {
		o["service"] = r.Service
	}
	if r.Download != nil {
		o["downloadMbps"] = mbps(*r.Download)
	}
	if r.Upload != nil {
		o["uploadMbps"] = mbps(*r.Upload)
	}
	if r.Ping != nil {
		o["pingMs"] = r2(*r.Ping)
	}
	if j := r.Data.Ping.Jitter; j != nil {
		o["jitterMs"] = r2(*j)
	}
	if pl := r.Data.PacketLoss; pl != nil {
		o["packetLossPercent"] = r2(*pl)
	}
	if r.Healthy != nil {
		o["healthy"] = *r.Healthy
	}
	if r.Data.ISP != "" {
		o["isp"] = r.Data.ISP
	}
	if s := r.Data.Server; s.Name != "" || s.ID != nil {
		srv := map[string]any{"name": s.Name}
		if s.ID != nil {
			srv["id"] = s.ID
		}
		if s.Location != "" {
			srv["location"] = s.Location
		}
		if s.Country != "" {
			srv["country"] = s.Country
		}
		o["server"] = srv
	}
	if r.Data.Result.URL != "" && strings.HasPrefix(r.Data.Result.URL, "https://") {
		o["resultUrl"] = r.Data.Result.URL
	}
	if r.Comments != "" {
		o["comments"] = r.Comments
	}
	if r.Status == "failed" && r.Data.Message != "" {
		o["error"] = r.Data.Message
	}
	return o
}

// unwrap accepts a result either bare or as {"data": {...}}.
func unwrap(raw json.RawMessage) (apiResult, error) {
	var w struct {
		Data json.RawMessage `json:"data"`
		ID   *int64          `json:"id"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return apiResult{}, fmt.Errorf("unexpected answer from Speedtest Tracker: %w", err)
	}
	var r apiResult
	if w.ID == nil && len(w.Data) > 0 && w.Data[0] == '{' {
		raw = w.Data
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return apiResult{}, fmt.Errorf("unexpected answer from Speedtest Tracker: %w", err)
	}
	return r, nil
}

func (c *conn) latest(ctx context.Context) (*apiResult, error) {
	var raw json.RawMessage
	err := c.do(ctx, http.MethodGet, "/api/v1/results/latest", nil, &raw)
	if err != nil && strings.HasPrefix(err.Error(), "no Speedtest Tracker API") {
		// The latest-result route answers 404 when there are no results yet;
		// tell that apart from a wrong address.
		var page struct {
			Data []json.RawMessage `json:"data"`
		}
		if c.do(ctx, http.MethodGet, "/api/v1/results", url.Values{"per_page": {"1"}}, &page) == nil && len(page.Data) == 0 {
			return nil, nil
		}
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	r, err := unwrap(raw)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// since reads results newer than cutoff, newest first, up to maxResults.
func (c *conn) since(ctx context.Context, cutoff time.Time, limit int) ([]apiResult, bool, error) {
	var out []apiResult
	for page := 1; len(out) < limit; page++ {
		var res struct {
			Data []apiResult `json:"data"`
			Meta struct {
				LastPage int `json:"last_page"`
			} `json:"meta"`
		}
		q := url.Values{"per_page": {strconv.Itoa(pageSize)}, "page": {strconv.Itoa(page)}, "sort": {"-created_at"}}
		if err := c.do(ctx, http.MethodGet, "/api/v1/results", q, &res); err != nil {
			return nil, false, err
		}
		for _, r := range res.Data {
			t, err := time.Parse(time.RFC3339, r.CreatedAt)
			if err == nil && t.Before(cutoff) {
				return out, false, nil
			}
			out = append(out, r)
			if len(out) >= limit {
				return out, true, nil
			}
		}
		if len(res.Data) < pageSize || (res.Meta.LastPage > 0 && page >= res.Meta.LastPage) {
			return out, false, nil
		}
	}
	return out, true, nil
}

type input struct {
	Days     *int   `json:"days"`
	Limit    *int   `json:"limit"`
	ServerID *int64 `json:"serverId"`
}

func days(p input) (int, error) {
	if p.Days == nil {
		return defDays, nil
	}
	if *p.Days < 1 || *p.Days > maxDays {
		return 0, fmt.Errorf("days is 1 to %d", maxDays)
	}
	return *p.Days, nil
}

func (m *Module) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	r, err := c.latest(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if r == nil {
		return sdk.Health{Status: "ok", Message: "Speedtest Tracker · no results yet"}
	}
	msg := "Speedtest Tracker · latest " + r.CreatedAt
	if r.Download != nil && r.Upload != nil {
		msg = fmt.Sprintf("Speedtest Tracker · %.0f↓ / %.0f↑ Mbit/s", mbps(*r.Download), mbps(*r.Upload))
	}
	switch {
	case r.Status == "failed":
		return sdk.Health{Status: "degraded", Message: "Speedtest Tracker · the latest speedtest failed"}
	case r.Healthy != nil && !*r.Healthy:
		return sdk.Health{Status: "degraded", Message: msg + " · below its thresholds"}
	}
	return sdk.Health{Status: "ok", Message: msg}
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
	case "latest":
		r, err := c.latest(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if r == nil {
			return sdk.JSON(map[string]any{"result": nil, "message": "no speedtests yet"})
		}
		return sdk.JSON(r.out())

	case "history":
		d, err := days(p)
		if err != nil {
			return sdk.Result{}, err
		}
		limit := defLimit
		if p.Limit != nil {
			if *p.Limit < 1 || *p.Limit > pageSize {
				return sdk.Result{}, fmt.Errorf("limit is 1 to %d", pageSize)
			}
			limit = *p.Limit
		}
		rs, more, err := c.since(ctx, m.now().AddDate(0, 0, -d), limit)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, r := range rs {
			out = append(out, r.out())
		}
		return sdk.JSON(map[string]any{"days": d, "results": out, "more": more})

	case "stats":
		d, err := days(p)
		if err != nil {
			return sdk.Result{}, err
		}
		rs, more, err := c.since(ctx, m.now().AddDate(0, 0, -d), maxResults)
		if err != nil {
			return sdk.Result{}, err
		}
		out := stats(rs)
		out["days"] = d
		if more {
			out["truncated"] = fmt.Sprintf("only the newest %d results were counted", maxResults)
		}
		return sdk.JSON(out)

	case "run":
		q := url.Values{}
		target := "Speedtest Tracker's default server"
		if p.ServerID != nil {
			if *p.ServerID < 1 || *p.ServerID > math.MaxInt32 {
				return sdk.Result{}, errors.New("serverId is a positive Ookla server id")
			}
			q.Set("server_id", strconv.FormatInt(*p.ServerID, 10))
			target = "Ookla server " + strconv.FormatInt(*p.ServerID, 10)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Run a speedtest against " + target + " (uses the connection's full bandwidth for about 30 seconds)",
				Changes: []sdk.Change{{Target: target, Op: "speedtest"}}}}, nil
		}
		var raw json.RawMessage
		if err := c.do(ctx, http.MethodPost, "/api/v1/speedtests/run", q, &raw); err != nil {
			return sdk.Result{}, err
		}
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &msg)
		out := map[string]any{"queued": true, "server": target}
		if r, err := unwrap(raw); err == nil && r.ID > 0 {
			out["id"], out["status"] = r.ID, r.Status
		}
		if msg.Message != "" {
			out["message"] = msg.Message
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func stats(rs []apiResult) map[string]any {
	var down, up, ping []float64
	failed, unhealthy, completed := 0, 0, 0
	first, last := "", ""
	for _, r := range rs {
		if first == "" || r.CreatedAt < first {
			first = r.CreatedAt
		}
		if r.CreatedAt > last {
			last = r.CreatedAt
		}
		switch r.Status {
		case "failed":
			failed++
			continue
		case "completed":
			completed++
		default:
			continue // running, queued or skipped
		}
		if r.Healthy != nil && !*r.Healthy {
			unhealthy++
		}
		if r.Download != nil {
			down = append(down, mbps(*r.Download))
		}
		if r.Upload != nil {
			up = append(up, mbps(*r.Upload))
		}
		if r.Ping != nil {
			ping = append(ping, *r.Ping)
		}
	}
	out := map[string]any{"tests": len(rs), "completed": completed, "failed": failed, "unhealthy": unhealthy}
	if first != "" {
		out["from"], out["to"] = first, last
	}
	for name, xs := range map[string][]float64{"downloadMbps": down, "uploadMbps": up, "pingMs": ping} {
		if len(xs) == 0 {
			continue
		}
		sort.Float64s(xs)
		sum := 0.0
		for _, x := range xs {
			sum += x
		}
		s := map[string]float64{"min": r2(xs[0]), "avg": r2(sum / float64(len(xs))), "max": r2(xs[len(xs)-1])}
		// For speeds the slow tail matters; for ping the high one.
		if name == "pingMs" {
			s["p90"] = r2(xs[(len(xs)-1)*9/10])
		} else {
			s["p10"] = r2(xs[(len(xs)-1)/10])
		}
		out[name] = s
	}
	return out
}
