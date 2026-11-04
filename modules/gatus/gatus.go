// Package gatus reads a Gatus status page through its API: every endpoint
// with its latest result and recent success rate, and one endpoint's
// recent results and events.
package gatus

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
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Gatus.
type Config struct {
	URL                string `json:"url"`
	Username           string `json:"username"` // optional basic-auth user (security.basic)
	Password           string `json:"password"` // secret://, with username
	Token              string `json:"token"`    // optional secret:// bearer token, for a proxy in front
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Gatus module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// Gatus keys are the group and name with separators turned into -,
	// joined by _; anything that could change the request path is refused.
	keyRe = regexp.MustCompile(`^[^/?#%\\\s\x00-\x1f\x7f]{1,256}$`)
)

// Limits.
const (
	maxEndpoints = 500
	maxResults   = 100
	maxText      = 300
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "gatus", Name: "Gatus", Version: "0.1.0", Category: "Monitoring", Icon: "heartbeat",
		Description: "Gatus: every endpoint's health, latest result and recent success rate, and one endpoint's results and events.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The status page's address, e.g. http://gatus:8080"},
			"username":{"type":"string","description":"Basic-auth user, if security.basic is set"},
			"password":{"type":"string","x-secret":true,"description":"Basic-auth password (the plain one, not the bcrypt hash)"},
			"token":{"type":"string","x-secret":true,"description":"Bearer token, if a proxy in front asks for one"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "endpoints", Title: "Endpoints", Description: "Every endpoint, at most 500: key, group, name, healthy, the latest result's status code, response time, time, failed conditions and errors, and the success rate of its last 20 checks. Only failing ones, or one group, when asked.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"failingOnly":{"type":"boolean","default":false},"group":{"type":"string"}}}`)},
			{Name: "endpoint", Title: "Endpoint history", Description: "One endpoint's recent results, newest first (default 20, at most 100), and its events (when it went up or down).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["key"],"properties":{"key":{"type":"string","description":"Endpoint key (from endpoints), e.g. core_api"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
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
		return errors.New("the address is like http://gatus:8080")
	}
	auth, err := authFunc(h, c.Token, c.Username, c.Password)
	if err != nil {
		return err
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
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), auth)
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// authFunc checks the optional credentials (references only) and returns
// what sets them on a request: a bearer token, or a basic-auth user and
// password, or nothing.
func authFunc(h sdk.Host, token, user, pass string) (func(context.Context, *http.Request) error, error) {
	token, user, pass = strings.TrimSpace(token), strings.TrimSpace(user), strings.TrimSpace(pass)
	for _, s := range []string{token, pass} {
		if s != "" && !strings.HasPrefix(s, "secret://") {
			return nil, errors.New("store the token or password in the vault and enter its secret:// reference")
		}
	}
	switch {
	case token != "" && (user != "" || pass != ""):
		return nil, errors.New("use a token or a user and password, not both")
	case (user == "") != (pass == ""):
		return nil, errors.New("basic auth needs both the user and the password")
	case token != "":
		return func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, token)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
			return nil
		}, nil
	case user != "":
		return func(ctx context.Context, r *http.Request) error {
			p, err := h.Secret(ctx, pass)
			if err != nil {
				return err
			}
			r.SetBasicAuth(user, p)
			return nil
		}, nil
	}
	return nil, nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Gatus refused the credentials")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("these credentials aren't allowed to read the status page")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err)
}

type result struct {
	Status     int      `json:"status"`
	Hostname   string   `json:"hostname"`
	Duration   int64    `json:"duration"` // nanoseconds
	Success    bool     `json:"success"`
	Timestamp  string   `json:"timestamp"`
	Errors     []string `json:"errors"`
	Conditions []struct {
		Condition string `json:"condition"`
		Success   bool   `json:"success"`
	} `json:"conditionResults"`
}

type status struct {
	Name    string   `json:"name"`
	Group   string   `json:"group"`
	Key     string   `json:"key"`
	Results []result `json:"results"`
	Events  []struct {
		Type      string `json:"type"`
		Timestamp string `json:"timestamp"`
	} `json:"events"`
}

// text passes on what a check reported, cut short and with anything that
// looks like a credential redacted: conditions and errors can quote
// response bodies and URLs.
func text(s string) string {
	if len(s) > maxText {
		cut := maxText
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return rest.Redact(rest.StripUserinfo(s))
}

func (r result) row() map[string]any {
	row := map[string]any{"time": r.Timestamp, "success": r.Success, "responseMs": math.Round(float64(r.Duration)/1e5) / 10}
	if r.Status != 0 {
		row["statusCode"] = r.Status
	}
	if r.Hostname != "" {
		row["hostname"] = r.Hostname
	}
	failed := []string{}
	for _, c := range r.Conditions {
		if !c.Success {
			failed = append(failed, text(c.Condition))
		}
	}
	if len(failed) > 0 {
		row["failedConditions"] = failed
	}
	if len(r.Errors) > 0 {
		errs := []string{}
		for i, e := range r.Errors {
			if i >= 5 {
				break
			}
			errs = append(errs, text(e))
		}
		row["errors"] = errs
	}
	return row
}

// latest is the newest result: Gatus lists them oldest first.
func (s status) latest() (result, bool) {
	if len(s.Results) == 0 {
		return result{}, false
	}
	best := s.Results[len(s.Results)-1]
	for _, r := range s.Results {
		if r.Timestamp > best.Timestamp {
			best = r
		}
	}
	return best, true
}

func (c *conn) statuses(ctx context.Context) ([]status, error) {
	var ss []status
	err := c.get(ctx, "/api/v1/endpoints/statuses", url.Values{"page": {"1"}, "pageSize": {"20"}}, &ss)
	return ss, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ss, err := c.statuses(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Gatus API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	failing := 0
	for _, s := range ss {
		if r, ok := s.latest(); ok && !r.Success {
			failing++
		}
	}
	msg := fmt.Sprintf("%d endpoints, %d failing", len(ss), failing)
	if failing > 0 {
		return sdk.Health{Status: "degraded", Message: msg}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	FailingOnly bool   `json:"failingOnly"`
	Group       string `json:"group"`
	Key         string `json:"key"`
	Limit       int    `json:"limit"`
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
	case "endpoints":
		ss, err := c.statuses(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		group := strings.TrimSpace(p.Group)
		out := []map[string]any{}
		total := 0
		for _, s := range ss {
			if group != "" && !strings.EqualFold(s.Group, group) {
				continue
			}
			r, ok := s.latest()
			if p.FailingOnly && (!ok || r.Success) {
				continue
			}
			total++
			if len(out) >= maxEndpoints {
				continue
			}
			row := map[string]any{"key": s.Key, "name": s.Name, "group": s.Group, "checks": len(s.Results)}
			if ok {
				row["healthy"] = r.Success
				row["latest"] = r.row()
				good := 0
				for _, x := range s.Results {
					if x.Success {
						good++
					}
				}
				row["successRate"] = math.Round(float64(good)*1000/float64(len(s.Results))) / 10
			}
			out = append(out, row)
		}
		sort.SliceStable(out, func(i, j int) bool {
			if out[i]["group"] != out[j]["group"] {
				return fmt.Sprint(out[i]["group"]) < fmt.Sprint(out[j]["group"])
			}
			return fmt.Sprint(out[i]["name"]) < fmt.Sprint(out[j]["name"])
		})
		return sdk.JSON(map[string]any{"endpoints": out, "truncated": total > len(out)})
	case "endpoint":
		p.Key = strings.TrimSpace(p.Key)
		if !keyRe.MatchString(p.Key) || p.Key == "." || p.Key == ".." {
			return sdk.Result{}, errors.New("an endpoint is its key from endpoints, e.g. core_api")
		}
		limit := p.Limit
		if limit == 0 {
			limit = 20
		}
		if limit < 1 || limit > maxResults {
			return sdk.Result{}, fmt.Errorf("the limit is 1 to %d", maxResults)
		}
		var s status
		if err := c.get(ctx, "/api/v1/endpoints/"+url.PathEscape(p.Key)+"/statuses", url.Values{"page": {"1"}, "pageSize": {strconv.Itoa(limit)}}, &s); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no endpoint %s", p.Key)
			}
			return sdk.Result{}, err
		}
		rs := append([]result(nil), s.Results...)
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].Timestamp > rs[j].Timestamp })
		results := []map[string]any{}
		for i, r := range rs {
			if i >= limit {
				break
			}
			results = append(results, r.row())
		}
		events := []map[string]any{}
		for i := len(s.Events) - 1; i >= 0 && len(events) < maxResults; i-- {
			events = append(events, map[string]any{"type": s.Events[i].Type, "time": s.Events[i].Timestamp})
		}
		return sdk.JSON(map[string]any{"key": s.Key, "name": s.Name, "group": s.Group, "results": results, "events": events})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
