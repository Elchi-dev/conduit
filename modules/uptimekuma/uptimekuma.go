// Package uptimekuma reads monitor states from Uptime Kuma, through its
// public status pages and, with an API key, its Prometheus metrics. Uptime
// Kuma has no API for changing monitors, so this module only reads.
package uptimekuma

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Uptime Kuma.
type Config struct {
	URL string `json:"url"`
	// StatusPages are status page slugs to read (the part after /status/).
	StatusPages []string `json:"statusPages"`
	// APIKey (secret://) reads every monitor from /metrics.
	APIKey string `json:"apiKey"`
}

type conn struct {
	cfg  Config
	host sdk.Host
	base string
	http *http.Client
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Uptime Kuma module.
func New() *Module { return &Module{} }

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "uptimekuma", Name: "Uptime Kuma", Version: "0.1.0", Category: "Monitoring", Icon: "pulse",
		Description: "Which of your Uptime Kuma monitors are up, down or in maintenance, with uptime and response times.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"e.g. https://status.example.com"},
			"statusPages":{"type":"array","items":{"type":"string"},"description":"Status page slugs to read (the part after /status/)"},
			"apiKey":{"type":"string","x-secret":true,"description":"An API key (Settings, API Keys) to read every monitor from /metrics"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "monitors", Title: "Monitors", Description: "Every monitor's state, response time and 24-hour uptime.", Risk: sdk.RiskRead},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("the address is like https://status.example.com")
	}
	for _, s := range c.StatusPages {
		if !slugRe.MatchString(s) {
			return fmt.Errorf("%q isn't a status page slug (lowercase letters, digits and dashes)", s)
		}
	}
	if c.APIKey != "" && !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	if c.APIKey == "" && len(c.StatusPages) == 0 {
		return errors.New("add a status page slug, an API key, or both")
	}
	cn := &conn{cfg: c, host: h, base: strings.TrimRight(u.String(), "/"), http: m.HTTP}
	if cn.http == nil {
		cn.http = &http.Client{Timeout: 20 * time.Second}
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Monitor is one monitor's state.
type Monitor struct {
	Name       string   `json:"name"`
	Type       string   `json:"type,omitempty"`
	Target     string   `json:"target,omitempty"`
	Status     string   `json:"status"` // up, down, pending, maintenance
	ResponseMS *float64 `json:"responseMs,omitempty"`
	Uptime24h  *float64 `json:"uptime24h,omitempty"` // percent
	Message    string   `json:"message,omitempty"`
	Page       string   `json:"page,omitempty"`
}

var statusName = map[int]string{0: "down", 1: "up", 2: "pending", 3: "maintenance"}

func (c *conn) fromStatusPage(ctx context.Context, slug string) ([]Monitor, error) {
	r := rest.New(c.base, nil)
	r.HTTP = c.http
	var page struct {
		PublicGroupList []struct {
			MonitorList []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"monitorList"`
		} `json:"publicGroupList"`
	}
	if _, err := r.Do(ctx, "GET", "/api/status-page/"+slug, nil, nil, &page); err != nil {
		return nil, fmt.Errorf("status page %s: %w", slug, err)
	}
	var beats struct {
		HeartbeatList map[string][]struct {
			Status int     `json:"status"`
			Msg    string  `json:"msg"`
			Ping   float64 `json:"ping"`
		} `json:"heartbeatList"`
		UptimeList map[string]float64 `json:"uptimeList"`
	}
	if _, err := r.Do(ctx, "GET", "/api/status-page/heartbeat/"+slug, nil, nil, &beats); err != nil {
		return nil, fmt.Errorf("status page %s: %w", slug, err)
	}
	var out []Monitor
	for _, g := range page.PublicGroupList {
		for _, mon := range g.MonitorList {
			id := strconv.Itoa(mon.ID)
			x := Monitor{Name: mon.Name, Type: mon.Type, Status: "pending", Page: slug}
			if hb := beats.HeartbeatList[id]; len(hb) > 0 {
				last := hb[len(hb)-1]
				x.Status = statusName[last.Status]
				x.Message = last.Msg
				if last.Ping > 0 {
					p := last.Ping
					x.ResponseMS = &p
				}
			}
			if u, ok := beats.UptimeList[id+"_24"]; ok {
				pct := u * 100
				x.Uptime24h = &pct
			}
			out = append(out, x)
		}
	}
	return out, nil
}

var metricRe = regexp.MustCompile(`^(\w+)\{(.*)\}\s+(\S+)`)
var labelRe = regexp.MustCompile(`(\w+)="((?:[^"\\]|\\.)*)"`)

func (c *conn) fromMetrics(ctx context.Context) ([]Monitor, error) {
	key, err := c.host.Secret(ctx, c.cfg.APIKey)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", c.base+"/metrics", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth("", key)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("Uptime Kuma refused the API key")
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/metrics answered %s", res.Status)
	}
	byName := map[string]*Monitor{}
	sc := bufio.NewScanner(io.LimitReader(res.Body, 8<<20))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		mm := metricRe.FindStringSubmatch(sc.Text())
		if mm == nil || (mm[1] != "monitor_status" && mm[1] != "monitor_response_time") {
			continue
		}
		labels := map[string]string{}
		for _, l := range labelRe.FindAllStringSubmatch(mm[2], -1) {
			labels[l[1]] = strings.ReplaceAll(l[2], `\"`, `"`)
		}
		name := labels["monitor_name"]
		if name == "" {
			continue
		}
		x := byName[name]
		if x == nil {
			target := labels["monitor_url"]
			if target == "" || target == "null" || target == "https://" {
				target = labels["monitor_hostname"]
				if target == "null" {
					target = ""
				}
			}
			x = &Monitor{Name: name, Type: labels["monitor_type"], Target: target, Status: "pending"}
			byName[name] = x
		}
		v, _ := strconv.ParseFloat(mm[3], 64)
		if mm[1] == "monitor_status" {
			x.Status = statusName[int(v)]
		} else if v >= 0 {
			x.ResponseMS = &v
		}
	}
	out := make([]Monitor, 0, len(byName))
	for _, x := range byName {
		out = append(out, *x)
	}
	return out, sc.Err()
}

func (c *conn) monitors(ctx context.Context) ([]Monitor, error) {
	var out []Monitor
	seen := map[string]int{}
	if c.cfg.APIKey != "" {
		ms, err := c.fromMetrics(ctx)
		if err != nil {
			return nil, err
		}
		for _, x := range ms {
			seen[x.Name] = len(out)
			out = append(out, x)
		}
	}
	for _, slug := range c.cfg.StatusPages {
		ms, err := c.fromStatusPage(ctx, slug)
		if err != nil {
			return nil, err
		}
		for _, x := range ms {
			if i, ok := seen[x.Name]; ok {
				// Metrics are current; status pages add uptime.
				if out[i].Uptime24h == nil {
					out[i].Uptime24h = x.Uptime24h
				}
				out[i].Page = x.Page
				continue
			}
			seen[x.Name] = len(out)
			out = append(out, x)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		rank := map[string]int{"down": 0, "pending": 1, "maintenance": 2, "up": 3}
		if rank[out[i].Status] != rank[out[j].Status] {
			return rank[out[i].Status] < rank[out[j].Status]
		}
		return out[i].Name < out[j].Name
	})
	if out == nil {
		out = []Monitor{}
	}
	return out, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ms, err := c.monitors(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var down []string
	for _, x := range ms {
		if x.Status == "down" {
			down = append(down, x.Name)
		}
	}
	if len(down) > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%d of %d down: %s", len(down), len(ms), strings.Join(down, ", "))}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d monitors up", len(ms))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.Action != "monitors" {
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	ms, err := c.monitors(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(ms)
}
