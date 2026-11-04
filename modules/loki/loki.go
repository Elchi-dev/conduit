// Package loki reads Grafana Loki through its HTTP API: LogQL log and
// metric queries over a bounded time range, and label names and values.
package loki

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
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Loki.
type Config struct {
	URL                string `json:"url"`
	Tenant             string `json:"tenant"`   // X-Scope-OrgID, for a multi-tenant Loki
	Token              string `json:"token"`    // optional secret:// bearer token
	Username           string `json:"username"` // optional basic-auth user (Grafana Cloud: the user id)
	Password           string `json:"password"` // secret://, with username
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	now  func() time.Time
}

// New returns the Loki module.
func New() *Module { return &Module{now: time.Now} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	labelRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	tenantRe = regexp.MustCompile(`^[A-Za-z0-9!._*'()|-]{1,150}$`)
)

// Limits on what a query asks for and what comes back.
const (
	// QueryTimeout bounds one query.
	QueryTimeout = 20 * time.Second
	maxQuery     = 4000
	maxMinutes   = 7 * 24 * 60
	maxLimit     = 1000
	maxPoints    = 1000 // steps per series of a metric query
	maxSeries    = 100
	maxLine      = 2000      // bytes of one log line
	maxOutput    = 256 << 10 // bytes of log lines in one answer
	maxValues    = 1000
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "loki", Name: "Loki", Version: "0.1.0", Category: "Monitoring", Icon: "document",
		Description: "Grafana Loki: LogQL log and metric queries over a bounded time range, label names and values.",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Loki's address, e.g. http://loki:3100 (Grafana Cloud: https://logs-prod-012.grafana.net)"},
			"tenant":{"type":"string","description":"Tenant (X-Scope-OrgID), for a multi-tenant Loki"},
			"token":{"type":"string","x-secret":true,"description":"Bearer token, if a proxy in front asks for one"},
			"username":{"type":"string","description":"Basic-auth user, if required (Grafana Cloud: the Loki user id)"},
			"password":{"type":"string","x-secret":true,"description":"Basic-auth password (Grafana Cloud: an access policy token with logs:read)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "query", Title: "Query logs", Description: "One LogQL query over the last minutes (default 60, at most 7 days). A log query returns at most 1000 lines (default 100), newest first, each cut at 2000 characters; a metric query returns at most 100 series of at most 1000 steps. Ranges ([5m]) and offsets in the query reach back at most 7 days together. At most 20 seconds. Logs can hold passwords and tokens, so results stay out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{
					"query":{"type":"string","x-multiline":true,"description":"e.g. {app=\"nginx\"} |= \"error\", or sum by (level) (count_over_time({app=\"nginx\"} | logfmt [5m]))"},
					"sinceMinutes":{"type":"integer","minimum":1,"maximum":10080,"default":60},
					"limit":{"type":"integer","minimum":1,"maximum":1000,"default":100,"description":"Log lines, for a log query"},
					"stepSeconds":{"type":"integer","minimum":1,"maximum":604800,"description":"Step of a metric query (default: the range in 250 steps)"},
					"direction":{"type":"string","enum":["backward","forward"],"default":"backward","description":"Newest (backward) or oldest (forward) lines first"}}}`)},
			{Name: "labels", Title: "Labels", Description: "Label names seen in the last minutes (default 60).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"sinceMinutes":{"type":"integer","minimum":1,"maximum":10080,"default":60}}}`)},
			{Name: "label_values", Title: "Label values", Description: "One label's values seen in the last minutes (default 60), at most 1000.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["label"],"properties":{"label":{"type":"string","description":"e.g. app"},"sinceMinutes":{"type":"integer","minimum":1,"maximum":10080,"default":60}}}`)},
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
		return errors.New("the address is like http://loki:3100")
	}
	c.Tenant = strings.TrimSpace(c.Tenant)
	if c.Tenant != "" && !tenantRe.MatchString(c.Tenant) {
		return errors.New("the tenant is letters, digits and !._*'()|-")
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
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/loki/api/v1")
	api := rest.New(u.Scheme+"://"+u.Host+base, auth)
	api.HTTP = rest.SameHostOnly(client)
	if c.Tenant != "" {
		api.Header.Set("X-Scope-OrgID", c.Tenant)
	}
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
			r.SetBasicAuth(user, strings.TrimSpace(p))
			return nil
		}, nil
	}
	return nil, nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	var e *rest.Error
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Loki refused the credentials")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("these credentials aren't allowed to read these logs")
	case errors.As(err, &e) && e.Status == http.StatusBadRequest:
		return &rest.Error{Status: e.Status, Message: "Loki couldn't run the query: " + e.Message}
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	// Labels need the credentials and a working read path; build info
	// isn't served everywhere (Grafana Cloud), so it's only a bonus.
	var r struct {
		Status string   `json:"status"`
		Data   []string `json:"data"`
	}
	end := m.clock()
	q := url.Values{"start": {ns(end.Add(-time.Hour))}, "end": {ns(end)}}
	if err := c.get(ctx, "/loki/api/v1/labels", q, &r); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Loki API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%d labels in the last hour", len(r.Data))
	var b struct {
		Version string `json:"version"`
	}
	if c.get(ctx, "/loki/api/v1/status/buildinfo", nil, &b) == nil && b.Version != "" {
		msg = "Loki " + b.Version + " · " + msg
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func ns(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) }

type input struct {
	Query        string `json:"query"`
	SinceMinutes int    `json:"sinceMinutes"`
	Limit        int    `json:"limit"`
	StepSeconds  int    `json:"stepSeconds"`
	Direction    string `json:"direction"`
	Label        string `json:"label"`
}

func (p input) since() (time.Duration, error) {
	mins := p.SinceMinutes
	if mins == 0 {
		mins = 60
	}
	if mins < 1 || mins > maxMinutes {
		return 0, errors.New("the range is 1 minute to 7 days (10080 minutes)")
	}
	return time.Duration(mins) * time.Minute, nil
}

// CheckQuery accepts a LogQL query of bounded length made of printable
// text. LogQL only reads (Loki has no writing or outbound functions), and
// Loki parses the query itself and refuses one that selects no stream, so
// nothing more is needed here than keeping control characters and very
// long input out.
func CheckQuery(q string) error {
	if strings.TrimSpace(q) == "" {
		return errors.New("enter a LogQL query, e.g. {app=\"nginx\"} |= \"error\"")
	}
	if len(q) > maxQuery {
		return fmt.Errorf("the query is longer than %d characters", maxQuery)
	}
	if !utf8.ValidString(q) {
		return errors.New("the query isn't valid UTF-8")
	}
	for _, r := range q {
		if r < 0x20 && r != '\n' && r != '\t' && r != '\r' || r == 0x7f {
			return errors.New("the query holds a control character")
		}
	}
	return checkLookback(q)
}

// maxLookback bounds a range ([5m]) plus an offset (offset 1h) in a query:
// Loki reads that far back before the query's start, so without it
// count_over_time({app="x"}[365d]) or offset 1y would scan a year of logs
// whatever the time range.
const maxLookback = time.Duration(maxMinutes) * time.Minute

// checkLookback reads every range and offset in a query, outside string
// literals and # comments, and refuses one it can't read or that reaches
// back more than maxLookback.
func checkLookback(q string) error {
	var ranges, offsets []time.Duration
	for i := 0; i < len(q); i++ {
		switch ch := q[i]; {
		case ch == '"' || ch == '`':
			j := i + 1
			for j < len(q) && q[j] != ch {
				if ch == '"' && q[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(q) {
				return errors.New("the query has a string that isn't closed")
			}
			i = j
		case ch == '#':
			for i < len(q) && q[i] != '\n' {
				i++
			}
		case ch == '[':
			j := strings.IndexByte(q[i:], ']')
			if j < 0 {
				return errors.New("the query has a [ that isn't closed")
			}
			body := strings.TrimSpace(q[i+1 : i+j])
			if k := strings.IndexByte(body, ':'); k >= 0 { // [range:step]
				body = strings.TrimSpace(body[:k])
			}
			d, ok := duration(body)
			if !ok {
				return fmt.Errorf("can't read the range [%s]; write it like [5m]", clip(body, 40))
			}
			ranges = append(ranges, d)
			i += j
		case isWordStart(ch) && (i == 0 || !isWord(q[i-1])):
			j := i
			for j < len(q) && isWord(q[j]) {
				j++
			}
			if strings.EqualFold(q[i:j], "offset") {
				k := j
				for k < len(q) && (q[k] == ' ' || q[k] == '\t' || q[k] == '\n' || q[k] == '\r') {
					k++
				}
				if k < len(q) && (q[k] == '-' || (q[k] >= '0' && q[k] <= '9')) {
					e := k + 1
					for e < len(q) && (isWord(q[e]) || q[e] == '.' || q[e] == 0xC2 || q[e] == 0xB5) {
						e++
					}
					d, ok := duration(strings.TrimPrefix(q[k:e], "-"))
					if !ok {
						return fmt.Errorf("can't read the offset %s", clip(q[k:e], 40))
					}
					offsets = append(offsets, d)
					j = e
				}
			}
			i = j - 1
		}
	}
	longest := func(ds []time.Duration) time.Duration {
		var m time.Duration
		for _, d := range ds {
			if d > m {
				m = d
			}
		}
		return m
	}
	if longest(ranges)+longest(offsets) > maxLookback {
		return errors.New("ranges and offsets in the query reach back at most 7 days together")
	}
	return nil
}

func isWordStart(c byte) bool { return c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z') }
func isWord(c byte) bool      { return isWordStart(c) || (c >= '0' && c <= '9') }

// durationUnits are the units LogQL reads in a duration (Prometheus' and
// Go's).
var durationUnits = map[string]time.Duration{
	"y": 365 * 24 * time.Hour, "w": 7 * 24 * time.Hour, "d": 24 * time.Hour, "h": time.Hour, "m": time.Minute,
	"s": time.Second, "ms": time.Millisecond, "us": time.Microsecond, "µs": time.Microsecond, "ns": time.Nanosecond,
}

var durationPart = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)(ms|us|µs|ns|y|w|d|h|m|s)`)

// duration reads a duration like 5m, 1h30m, 1.5h or 2d; false when it
// isn't one, or is beyond any bound (so it's refused, not wrapped).
func duration(s string) (time.Duration, bool) {
	if s == "" {
		return 0, false
	}
	var total float64
	for s != "" {
		m := durationPart.FindStringSubmatch(s)
		if m == nil {
			return 0, false
		}
		n, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, false
		}
		total += n * float64(durationUnits[m[2]])
		if total > float64(100*365*24*time.Hour) {
			return 0, false
		}
		s = s[len(m[0]):]
	}
	return time.Duration(total), true
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
	since, err := p.since()
	if err != nil {
		return sdk.Result{}, err
	}
	end := m.clock()
	start := end.Add(-since)
	switch call.Action {
	case "query":
		return c.query(ctx, p, start, end)
	case "labels", "label_values":
		path := "/loki/api/v1/labels"
		if call.Action == "label_values" {
			p.Label = strings.TrimSpace(p.Label)
			if !labelRe.MatchString(p.Label) {
				return sdk.Result{}, errors.New("a label name is letters, digits and _ (not starting with a digit)")
			}
			path = "/loki/api/v1/label/" + url.PathEscape(p.Label) + "/values"
		}
		var r struct {
			Data []string `json:"data"`
		}
		if err := c.get(ctx, path, url.Values{"start": {ns(start)}, "end": {ns(end)}}, &r); err != nil {
			return sdk.Result{}, err
		}
		sort.Strings(r.Data)
		truncated := len(r.Data) > maxValues
		if truncated {
			r.Data = r.Data[:maxValues]
		}
		if r.Data == nil {
			r.Data = []string{}
		}
		return sdk.JSON(map[string]any{"values": r.Data, "truncated": truncated})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// queryAnswer is Loki's query_range answer: streams for a log query,
// a matrix for a metric query.
type queryAnswer struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string            `json:"resultType"`
		Result     []json.RawMessage `json:"result"`
	} `json:"data"`
}

func (c *conn) query(ctx context.Context, p input, start, end time.Time) (sdk.Result, error) {
	if err := CheckQuery(p.Query); err != nil {
		return sdk.Result{}, err
	}
	limit := p.Limit
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > maxLimit {
		return sdk.Result{}, fmt.Errorf("the limit is 1 to %d lines", maxLimit)
	}
	dir := p.Direction
	if dir == "" {
		dir = "backward"
	}
	if dir != "backward" && dir != "forward" {
		return sdk.Result{}, errors.New("the direction is backward or forward")
	}
	span := end.Sub(start)
	step := time.Duration(p.StepSeconds) * time.Second
	if p.StepSeconds < 0 || p.StepSeconds > maxMinutes*60 {
		return sdk.Result{}, errors.New("the step is 1 second to 7 days")
	}
	if step == 0 {
		step = span / 250
		if step < time.Second {
			step = time.Second
		}
	}
	if span/step > maxPoints {
		return sdk.Result{}, fmt.Errorf("that's more than %d steps; make the step at least %d seconds or the range shorter", maxPoints, int(span/time.Second)/maxPoints+1)
	}
	q := url.Values{"query": {p.Query}, "start": {ns(start)}, "end": {ns(end)}, "limit": {strconv.Itoa(limit)}, "direction": {dir},
		"step": {strconv.FormatFloat(step.Seconds(), 'f', -1, 64)}}
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	var r queryAnswer
	if err := c.get(ctx, "/loki/api/v1/query_range", q, &r); err != nil {
		return sdk.Result{}, err
	}
	switch r.Data.ResultType {
	case "streams":
		return logLines(r, limit, dir)
	case "matrix":
		return series(r)
	}
	return sdk.Result{}, fmt.Errorf("unexpected answer from Loki (result type %q)", r.Data.ResultType)
}

// logLines merges the streams into one list of lines in the asked order,
// each with its labels, cut to maxLine bytes and maxOutput in all.
func logLines(r queryAnswer, limit int, dir string) (sdk.Result, error) {
	type line struct {
		ts     int64
		labels map[string]string
		text   string
	}
	var all []line
	for _, raw := range r.Data.Result {
		var s struct {
			Stream map[string]string `json:"stream"`
			Values [][]string        `json:"values"`
		}
		if json.Unmarshal(raw, &s) != nil {
			continue
		}
		for _, v := range s.Values {
			if len(v) < 2 {
				continue
			}
			ts, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				continue
			}
			all = append(all, line{ts: ts, labels: s.Stream, text: v[1]})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if dir == "forward" {
			return all[i].ts < all[j].ts
		}
		return all[i].ts > all[j].ts
	})
	out := []map[string]any{}
	size, truncated := 0, false
	for _, l := range all {
		if len(out) >= limit {
			truncated = true
			break
		}
		text := l.text
		cut := false
		if len(text) > maxLine {
			text, cut = clip(text, maxLine), true
		}
		if size+len(text) > maxOutput {
			truncated = true
			break
		}
		size += len(text)
		row := map[string]any{"time": time.Unix(0, l.ts).UTC().Format(time.RFC3339Nano), "line": text, "labels": l.labels}
		if cut {
			row["cut"] = true
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"type": "logs", "lines": out, "truncated": truncated})
}

// series returns a metric query's matrix, at most maxSeries series.
func series(r queryAnswer) (sdk.Result, error) {
	out := []map[string]any{}
	for i, raw := range r.Data.Result {
		if i >= maxSeries {
			break
		}
		var s struct {
			Metric map[string]string `json:"metric"`
			Values [][2]any          `json:"values"`
		}
		if json.Unmarshal(raw, &s) != nil {
			continue
		}
		points := [][2]any{}
		for j, v := range s.Values {
			if j >= maxPoints+1 {
				break
			}
			ts, _ := v[0].(float64)
			val, _ := v[1].(string)
			points = append(points, [2]any{time.Unix(int64(ts), 0).UTC().Format(time.RFC3339), val})
		}
		out = append(out, map[string]any{"labels": s.Metric, "points": points})
	}
	return sdk.JSON(map[string]any{"type": "metric", "series": out, "truncated": len(r.Data.Result) > maxSeries})
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func (m *Module) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}
