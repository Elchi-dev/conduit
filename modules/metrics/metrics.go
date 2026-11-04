// Package metrics reads Prometheus (or any Prometheus-compatible API such as
// Mimir, Thanos or VictoriaMetrics) and Grafana: queries, alerts, scrape
// targets and dashboards.
package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one metrics stack's settings.
type Config struct {
	Prometheus      string `json:"prometheus"`
	PrometheusToken string `json:"prometheusToken"` // secret:// bearer token
	PrometheusUser  string `json:"prometheusUser"`
	PrometheusPass  string `json:"prometheusPassword"` // secret://
	Grafana         string `json:"grafana"`
	GrafanaToken    string `json:"grafanaToken"` // secret:// service account token
}

type stack struct {
	cfg  Config
	host sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	mu     sync.Mutex
	stacks map[string]*stack
	http   *http.Client
}

// New returns the metrics module.
func New() *Module {
	return &Module{stacks: map[string]*stack{}, http: &http.Client{Timeout: 30 * time.Second}}
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "metrics", Name: "Metrics", Version: "0.1.0", Category: "Infrastructure", Icon: "chart",
		Description: "Prometheus queries, firing alerts and scrape targets, and your Grafana dashboards.",
		Presets:     []string{"developer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"prometheus":{"type":"string","description":"Prometheus URL, e.g. http://prometheus:9090 (or Mimir, Thanos, VictoriaMetrics)"},
			"prometheusToken":{"type":"string","x-secret":true,"description":"Bearer token, if required"},
			"prometheusUser":{"type":"string","description":"Basic-auth user, if required"},
			"prometheusPassword":{"type":"string","x-secret":true},
			"grafana":{"type":"string","description":"Grafana URL, e.g. https://grafana.example.com"},
			"grafanaToken":{"type":"string","x-secret":true,"description":"Grafana service account token (Viewer is enough)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "alerts", Title: "Firing alerts", Risk: sdk.RiskRead},
			{Name: "targets", Title: "Scrape targets", Description: "What Prometheus scrapes, and what's down.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"downOnly":{"type":"boolean","title":"Only targets that are down"}}}`)},
			{Name: "query", Title: "Query now", Description: "A PromQL instant query.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string","description":"e.g. 100 - avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100"}}}`)},
			{Name: "chart", Title: "Chart a query", Description: "A PromQL query over time.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},"hours":{"type":"number","default":6,"maximum":168}}}`)},
			{Name: "dashboards", Title: "Dashboards", Description: "Grafana dashboards, with links.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.Prometheus, c.Grafana = strings.TrimRight(c.Prometheus, "/"), strings.TrimRight(c.Grafana, "/")
	if c.Prometheus == "" && c.Grafana == "" {
		return errors.New("set a Prometheus URL, a Grafana URL, or both")
	}
	for _, u := range []string{c.Prometheus, c.Grafana} {
		if u == "" {
			continue
		}
		p, err := url.Parse(u)
		if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
			return fmt.Errorf("invalid URL %q", u)
		}
	}
	m.mu.Lock()
	m.stacks[id] = &stack{cfg: c, host: h}
	m.mu.Unlock()
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error {
	m.mu.Lock()
	delete(m.stacks, id)
	m.mu.Unlock()
	return nil
}

func (m *Module) stack(id string) (*stack, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.stacks[id]; s != nil {
		return s, nil
	}
	return nil, errors.New("metrics are not configured")
}

func (m *Module) get(ctx context.Context, s *stack, grafana bool, path string, q url.Values, out any) error {
	base := s.cfg.Prometheus
	if grafana {
		base = s.cfg.Grafana
	}
	if base == "" {
		if grafana {
			return errors.New("no Grafana URL configured")
		}
		return errors.New("no Prometheus URL configured")
	}
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	switch {
	case grafana && s.cfg.GrafanaToken != "":
		tok, err := s.host.Secret(ctx, s.cfg.GrafanaToken)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	case !grafana && s.cfg.PrometheusToken != "":
		tok, err := s.host.Secret(ctx, s.cfg.PrometheusToken)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	case !grafana && s.cfg.PrometheusUser != "":
		pw, err := s.host.Secret(ctx, s.cfg.PrometheusPass)
		if err != nil {
			return err
		}
		req.SetBasicAuth(s.cfg.PrometheusUser, pw)
	}
	res, err := m.http.Do(req)
	if err != nil {
		return rest.TransportError(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &e)
		msg := e.Error + e.Message
		if msg == "" {
			msg = res.Status
		}
		return errors.New(msg)
	}
	return json.Unmarshal(body, out)
}

type promResp struct {
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data"`
	Error  string          `json:"error"`
}

func (m *Module) prom(ctx context.Context, s *stack, path string, q url.Values, out any) error {
	var r promResp
	if err := m.get(ctx, s, false, path, q, &r); err != nil {
		return err
	}
	if r.Status != "success" {
		return errors.New(r.Error)
	}
	return json.Unmarshal(r.Data, out)
}

// Alert is a firing or pending alert.
type Alert struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Severity string `json:"severity,omitempty"`
	Summary  string `json:"summary,omitempty"`
	Labels   string `json:"labels"`
	Since    string `json:"since"`
}

func (m *Module) alerts(ctx context.Context, s *stack) ([]Alert, error) {
	var d struct {
		Alerts []struct {
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
			State       string            `json:"state"`
			ActiveAt    string            `json:"activeAt"`
		} `json:"alerts"`
	}
	if err := m.prom(ctx, s, "/api/v1/alerts", nil, &d); err != nil {
		return nil, err
	}
	out := []Alert{}
	for _, a := range d.Alerts {
		var lbl []string
		for k, v := range a.Labels {
			if k != "alertname" && k != "severity" {
				lbl = append(lbl, k+"="+v)
			}
		}
		sort.Strings(lbl)
		sum := a.Annotations["summary"]
		if sum == "" {
			sum = a.Annotations["description"]
		}
		out = append(out, Alert{Name: a.Labels["alertname"], State: a.State, Severity: a.Labels["severity"], Summary: sum, Labels: strings.Join(lbl, " "), Since: a.ActiveAt})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].State > out[j].State || (out[i].State == out[j].State && out[i].Name < out[j].Name)
	})
	return out, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	s, err := m.stack(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if s.cfg.Prometheus == "" {
		var h struct {
			Database string `json:"database"`
		}
		if err := m.get(ctx, s, true, "/api/health", nil, &h); err != nil {
			return sdk.Health{Status: "down", Message: err.Error()}
		}
		return sdk.Health{Status: "ok", Message: "Grafana reachable"}
	}
	alerts, err := m.alerts(ctx, s)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	firing := 0
	for _, a := range alerts {
		if a.State == "firing" {
			firing++
		}
	}
	if firing > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%d alerts firing", firing)}
	}
	return sdk.Health{Status: "ok", Message: "No alerts firing"}
}

// Series is a chartable time series. The UI renders outputs of this shape
// ({"series":[…]}) as a line chart.
type Series struct {
	Name   string       `json:"name"`
	Points [][2]float64 `json:"points"` // [unix seconds, value]
}

func labelName(metric map[string]string) string {
	if len(metric) == 0 {
		return "value"
	}
	keys := make([]string, 0, len(metric))
	for k := range metric {
		if k != "__name__" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+metric[k])
	}
	name := metric["__name__"]
	if len(parts) > 0 {
		name += "{" + strings.Join(parts, ", ") + "}"
	}
	return name
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	s, err := m.stack(c.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "alerts":
		a, err := m.alerts(ctx, s)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(a)

	case "targets":
		var in struct {
			DownOnly bool `json:"downOnly"`
		}
		_ = sdk.Decode(c, &in)
		var d struct {
			Active []struct {
				Labels     map[string]string `json:"labels"`
				ScrapePool string            `json:"scrapePool"`
				ScrapeURL  string            `json:"scrapeUrl"`
				Health     string            `json:"health"`
				LastError  string            `json:"lastError"`
				LastScrape string            `json:"lastScrape"`
			} `json:"activeTargets"`
		}
		if err := m.prom(ctx, s, "/api/v1/targets", url.Values{"state": {"active"}}, &d); err != nil {
			return sdk.Result{}, err
		}
		type target struct {
			Job      string `json:"job"`
			Instance string `json:"instance"`
			Health   string `json:"health"`
			Error    string `json:"error,omitempty"`
		}
		out := []target{}
		for _, t := range d.Active {
			if in.DownOnly && t.Health == "up" {
				continue
			}
			out = append(out, target{Job: t.ScrapePool, Instance: t.Labels["instance"], Health: t.Health, Error: t.LastError})
		}
		sort.Slice(out, func(i, j int) bool {
			return out[i].Health < out[j].Health || (out[i].Health == out[j].Health && out[i].Job < out[j].Job)
		})
		return sdk.JSON(out)

	case "query":
		var in struct {
			Query string `json:"query"`
		}
		if err := sdk.Decode(c, &in); err != nil || strings.TrimSpace(in.Query) == "" {
			return sdk.Result{}, errors.New("query is required")
		}
		var d struct {
			ResultType string          `json:"resultType"`
			Result     json.RawMessage `json:"result"`
		}
		if err := m.prom(ctx, s, "/api/v1/query", url.Values{"query": {in.Query}}, &d); err != nil {
			return sdk.Result{}, err
		}
		switch d.ResultType {
		case "vector":
			var v []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			}
			_ = json.Unmarshal(d.Result, &v)
			out := []map[string]any{}
			for _, x := range v {
				f, _ := strconv.ParseFloat(fmt.Sprint(x.Value[1]), 64)
				out = append(out, map[string]any{"series": labelName(x.Metric), "value": round(f)})
			}
			sort.Slice(out, func(i, j int) bool { return out[i]["value"].(float64) > out[j]["value"].(float64) })
			return sdk.JSON(out)
		case "scalar", "string":
			var v [2]any
			_ = json.Unmarshal(d.Result, &v)
			return sdk.JSON(map[string]any{"value": v[1]})
		}
		return sdk.Result{Output: d.Result}, nil

	case "chart":
		var in struct {
			Query string  `json:"query"`
			Hours float64 `json:"hours"`
		}
		if err := sdk.Decode(c, &in); err != nil || strings.TrimSpace(in.Query) == "" {
			return sdk.Result{}, errors.New("query is required")
		}
		if in.Hours <= 0 || in.Hours > 168 {
			in.Hours = 6
		}
		end := time.Now()
		start := end.Add(-time.Duration(in.Hours * float64(time.Hour)))
		step := time.Duration(in.Hours*float64(time.Hour)) / 240
		if step < 15*time.Second {
			step = 15 * time.Second
		}
		var d struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Values [][2]any          `json:"values"`
			} `json:"result"`
		}
		q := url.Values{"query": {in.Query}, "start": {strconv.FormatInt(start.Unix(), 10)}, "end": {strconv.FormatInt(end.Unix(), 10)}, "step": {strconv.Itoa(int(step.Seconds()))}}
		if err := m.prom(ctx, s, "/api/v1/query_range", q, &d); err != nil {
			return sdk.Result{}, err
		}
		series := []Series{}
		for i, r := range d.Result {
			if i == 8 {
				break // more lines than this can't be told apart; narrow the query
			}
			sr := Series{Name: labelName(r.Metric)}
			for _, p := range r.Values {
				t, _ := strconv.ParseFloat(fmt.Sprint(p[0]), 64)
				v, err := strconv.ParseFloat(fmt.Sprint(p[1]), 64)
				if err == nil {
					sr.Points = append(sr.Points, [2]float64{t, round(v)})
				}
			}
			series = append(series, sr)
		}
		return sdk.JSON(map[string]any{"query": in.Query, "series": series, "truncated": len(d.Result) > 8})

	case "dashboards":
		var in struct {
			Search string `json:"search"`
		}
		_ = sdk.Decode(c, &in)
		var d []struct {
			Title       string   `json:"title"`
			URL         string   `json:"url"`
			FolderTitle string   `json:"folderTitle"`
			Tags        []string `json:"tags"`
		}
		if err := m.get(ctx, s, true, "/api/search", url.Values{"type": {"dash-db"}, "query": {in.Search}, "limit": {"200"}}, &d); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]string{}
		for _, x := range d {
			out = append(out, map[string]string{"title": x.Title, "folder": x.FolderTitle, "tags": strings.Join(x.Tags, ", "), "link": s.cfg.Grafana + x.URL})
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

func round(f float64) float64 {
	if f > 1e6 || f < -1e6 {
		return float64(int64(f))
	}
	return float64(int64(f*1000)) / 1000
}
