// Package influxdb looks into an InfluxDB 2 server through its API: health,
// buckets, Flux queries (functions that write or reach outside refused),
// tasks with their runs, and enabling or disabling a task.
package influxdb

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one InfluxDB server and organization.
type Config struct {
	URL                string `json:"url"`   // e.g. https://influx.example.com:8086
	Token              string `json:"token"` // secret://
	Org                string `json:"org"`   // organization name
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

// Limits for queries.
const (
	QueryTimeout = 15 * time.Second
	MaxRows      = 1000
	MaxBytes     = 8 << 20
	maxFlux      = 32 << 10
)

type conn struct {
	cfg  Config
	api  *rest.Client
	base string
	http *http.Client
	host sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the InfluxDB module.
func New() *Module { return &Module{} }

var (
	orgRe    = regexp.MustCompile(`^[^\x00-\x1f]{1,256}$`)
	taskIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	task := `{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Task ID (16 hex characters)"}}}`
	return sdk.Manifest{
		ID: "influxdb", Name: "InfluxDB", Version: "0.1.0", Category: "Infrastructure", Icon: "chart",
		Description: "InfluxDB 2: health, buckets, read-only Flux queries, tasks and their runs, enabling or disabling a task.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token","org"],"properties":{
			"url":{"type":"string","description":"e.g. https://influx.example.com:8086"},
			"token":{"type":"string","x-secret":true,"description":"An API token. Best one with read access to the buckets, plus write on tasks only if you want to enable and disable them"},
			"org":{"type":"string","description":"Organization name"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "health", Title: "Health", Description: "Status and version of the server.", Risk: sdk.RiskRead},
			{Name: "buckets", Title: "Buckets", Description: "Buckets with retention and type, at most 100.", Risk: sdk.RiskRead},
			{Name: "query", Title: "Run a Flux query", Description: "One read-only Flux query, at most 15 seconds and 1000 rows. to(), experimental.to, http, sql, secrets, notification endpoints and other functions that write or reach outside are refused. Results can hold private data, so they stay out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["flux"],"properties":{"flux":{"type":"string","x-multiline":true,"description":"e.g. from(bucket: \"telegraf\") |> range(start: -1h) |> filter(fn: (r) => r._measurement == \"cpu\") |> limit(n: 10)"}}}`)},
			{Name: "tasks", Title: "Tasks", Description: "Tasks with status (active or inactive), schedule and the last run's time and status.", Risk: sdk.RiskRead},
			{Name: "task_runs", Title: "Task runs", Description: "A task's recent runs with status and times.", Risk: sdk.RiskRead, Input: sdk.Schema(task)},
			{Name: "enable_task", Title: "Enable a task", Description: "Sets a task active so it runs on its schedule. Undo disables it again.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Input: sdk.Schema(task)},
			{Name: "disable_task", Title: "Disable a task", Description: "Sets a task inactive so it stops running on its schedule (a run in progress finishes). Undo enables it again.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Input: sdk.Schema(task)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the url is like https://influx.example.com:8086")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	c.Org = strings.TrimSpace(c.Org)
	if !orgRe.MatchString(c.Org) {
		return errors.New("enter the organization's name")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	client = rest.SameHostOnly(client)
	base := u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
	tok := c.Token
	auth := func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Token "+strings.TrimSpace(t))
		return nil
	}
	api := rest.New(base, auth)
	api.HTTP = client
	m.set.Put(id, &conn{cfg: c, api: api, base: base, http: client, host: h})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("InfluxDB refused the token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("InfluxDB refused: the token isn't allowed to do this")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any, what string) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err, what)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var h health
	if err := c.do(ctx, http.MethodGet, "/health", nil, nil, &h, "health endpoint"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if h.Status != "pass" {
		return sdk.Health{Status: "down", Message: "InfluxDB says " + h.Status + ": " + rest.Redact(h.Message)}
	}
	// /health needs no token: check it and the organization too.
	var orgs struct {
		Orgs []struct {
			ID string `json:"id"`
		} `json:"orgs"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v2/orgs", url.Values{"org": {c.cfg.Org}}, nil, &orgs, "organization "+c.cfg.Org); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if len(orgs.Orgs) == 0 {
		return sdk.Health{Status: "down", Message: "there's no organization " + c.cfg.Org}
	}
	return sdk.Health{Status: "ok", Message: "InfluxDB " + h.Version + " · " + c.cfg.Org}
}

type health struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type task struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	Every           string `json:"every"`
	Cron            string `json:"cron"`
	Offset          string `json:"offset"`
	LatestCompleted string `json:"latestCompleted"`
	LastRunStatus   string `json:"lastRunStatus"`
	LastRunError    string `json:"lastRunError"`
	UpdatedAt       string `json:"updatedAt"`
}

func (t task) summary() map[string]any {
	e := map[string]any{"id": t.ID, "name": t.Name, "status": t.Status, "latestCompleted": t.LatestCompleted, "lastRunStatus": t.LastRunStatus}
	switch {
	case t.Every != "":
		e["every"] = t.Every
	case t.Cron != "":
		e["cron"] = t.Cron
	}
	if t.LastRunError != "" {
		e["lastRunError"] = clip(rest.Redact(t.LastRunError), 300)
	}
	return e
}

func clip(s string, k int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > k {
		return string(r[:k]) + "…"
	}
	return string(r)
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Flux string `json:"flux"`
		ID   string `json:"id"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "task_runs", "enable_task", "disable_task":
		if !taskIDRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("give a task ID: 16 hex characters, from Tasks")
		}
	}
	switch call.Action {
	case "health":
		var h health
		if err := c.do(ctx, http.MethodGet, "/health", nil, nil, &h, "health endpoint"); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"status": h.Status, "version": h.Version, "commit": h.Commit, "message": rest.Redact(h.Message)})
	case "buckets":
		var r struct {
			Buckets []struct {
				ID             string `json:"id"`
				Name           string `json:"name"`
				Type           string `json:"type"`
				Description    string `json:"description"`
				CreatedAt      string `json:"createdAt"`
				RetentionRules []struct {
					EverySeconds int64 `json:"everySeconds"`
				} `json:"retentionRules"`
			} `json:"buckets"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/v2/buckets", url.Values{"org": {c.cfg.Org}, "limit": {"100"}}, nil, &r, "organization "+c.cfg.Org); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, b := range r.Buckets {
			var ret int64
			if len(b.RetentionRules) > 0 {
				ret = b.RetentionRules[0].EverySeconds
			}
			out = append(out, map[string]any{"id": b.ID, "name": b.Name, "type": b.Type, "description": b.Description, "retentionSeconds": ret, "createdAt": b.CreatedAt})
		}
		return sdk.JSON(out)
	case "query":
		if err := CheckFlux(p.Flux); err != nil {
			return sdk.Result{}, err
		}
		return c.query(ctx, p.Flux)
	case "tasks":
		var r struct {
			Tasks []task `json:"tasks"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/v2/tasks", url.Values{"org": {c.cfg.Org}, "limit": {"100"}}, nil, &r, "organization "+c.cfg.Org); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range r.Tasks {
			out = append(out, t.summary())
		}
		return sdk.JSON(out)
	case "task_runs":
		var r struct {
			Runs []struct {
				ID           string `json:"id"`
				Status       string `json:"status"`
				ScheduledFor string `json:"scheduledFor"`
				StartedAt    string `json:"startedAt"`
				FinishedAt   string `json:"finishedAt"`
			} `json:"runs"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/v2/tasks/"+p.ID+"/runs", url.Values{"limit": {"20"}}, nil, &r, "task "+p.ID); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r.Runs)
	case "enable_task", "disable_task":
		want, verb, undo := "active", "Enable", "disable_task"
		if call.Action == "disable_task" {
			want, verb, undo = "inactive", "Disable", "enable_task"
		}
		var t task
		if err := c.do(ctx, http.MethodGet, "/api/v2/tasks/"+p.ID, nil, nil, &t, "task "+p.ID); err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			sum := fmt.Sprintf("%s task %s (%s)", verb, t.Name, t.ID)
			if t.Status == want {
				sum = fmt.Sprintf("Task %s is already %s: nothing changes", t.Name, want)
			}
			before, _ := json.Marshal(t.Status)
			after, _ := json.Marshal(want)
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "task " + t.Name, Op: "update", Before: before, After: after}}}}, nil
		}
		if t.Status == want {
			return sdk.JSON(map[string]any{"id": t.ID, "name": t.Name, "status": want, "changed": false})
		}
		var after task
		if err := c.do(ctx, http.MethodPatch, "/api/v2/tasks/"+p.ID, nil, map[string]string{"status": want}, &after, "task "+p.ID); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"id": t.ID, "name": t.Name, "status": after.Status, "changed": true})
		if err == nil {
			res.Undo = sdk.UndoWith(undo, map[string]string{"id": t.ID}, fmt.Sprintf("Set task %s %s again", t.Name, t.Status))
		}
		return res, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// query runs a Flux query and returns its tables as rows of named columns.
func (c *conn) query(ctx context.Context, flux string) (sdk.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	body, _ := json.Marshal(map[string]any{
		"query": flux, "type": "flux",
		"dialect": map[string]any{"header": true, "annotations": []string{}, "delimiter": ",", "commentPrefix": "#"},
	})
	hdr := http.Header{"Content-Type": {"application/json"}, "Accept": {"application/csv"}}
	res, err := c.api.Send(ctx, http.MethodPost, "/api/v2/query", url.Values{"org": {c.cfg.Org}}, strings.NewReader(string(body)), hdr)
	if err != nil {
		var e *rest.Error
		if errors.As(err, &e) && e.Status == http.StatusBadRequest {
			return sdk.Result{}, &rest.Error{Status: e.Status, Message: "InfluxDB couldn't run the query: " + e.Message}
		}
		return sdk.Result{}, friendly(err, "organization "+c.cfg.Org)
	}
	defer res.Body.Close()
	cols, rows, truncated, err := ParseCSV(io.LimitReader(res.Body, MaxBytes))
	if err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"columns": cols, "rows": rows, "truncated": truncated})
}

// ParseCSV reads InfluxDB's CSV answer (header rows, no annotations; a
// blank line between tables, whose columns may differ) into the union of
// the columns and one row per record, at most MaxRows. The "result" and
// "table" bookkeeping columns are kept, the leading empty one dropped.
func ParseCSV(r io.Reader) ([]string, [][]string, bool, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = false
	var cols []string
	index := map[string]int{}
	var header []string
	rows := [][]string{}
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			if len(rows) > 0 {
				// The answer was cut at the size limit.
				return cols, rows, true, nil
			}
			return nil, nil, false, fmt.Errorf("unexpected answer from InfluxDB: %w", err)
		}
		if len(rec) == 0 || (len(rec) == 1 && rec[0] == "") {
			header = nil
			continue
		}
		if header == nil {
			header = rec
			for _, h := range header {
				if h == "" {
					continue
				}
				if _, ok := index[h]; !ok {
					index[h] = len(cols)
					cols = append(cols, h)
				}
			}
			continue
		}
		// csv.Reader skips blank lines, so a new table shows as a row whose
		// first fields are "", "result" and "table" again.
		if len(rec) > 2 && rec[0] == "" && rec[1] == "result" && rec[2] == "table" {
			header = rec
			for _, h := range header {
				if _, ok := index[h]; !ok && h != "" {
					index[h] = len(cols)
					cols = append(cols, h)
				}
			}
			continue
		}
		if len(rows) >= MaxRows {
			return cols, rows, true, nil
		}
		row := make([]string, len(cols))
		for i, v := range rec {
			if i < len(header) && header[i] != "" {
				j := index[header[i]]
				for len(row) <= j {
					row = append(row, "")
				}
				row[j] = v
			}
		}
		rows = append(rows, row)
	}
	if cols == nil {
		cols = []string{}
	}
	for i := range rows {
		for len(rows[i]) < len(cols) {
			rows[i] = append(rows[i], "")
		}
	}
	return cols, rows, false, nil
}

// allowedImports are the Flux packages a query may import: computation,
// strings and time, schema exploration. Everything that writes (to, sql,
// mqtt, monitor), reaches other servers (http, sql, csv and prometheus
// fetching URLs, socket, notification endpoints) or reads secrets is left
// out.
var allowedImports = map[string]bool{
	"array": true, "strings": true, "regexp": true, "math": true, "date": true, "timezone": true,
	"dict": true, "types": true, "join": true, "interpolate": true, "universe": true, "runtime": true, "system": true,
	"sampledata": true, "influxdata/influxdb/schema": true, "influxdata/influxdb/v1": true,
	"experimental": true, "experimental/aggregate": true, "experimental/array": true, "experimental/table": true,
	"experimental/query": true, "experimental/date/boundaries": true, "date/boundaries": true,
}

var (
	importRe = regexp.MustCompile(`^import\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"\\]*)"$`)
	wordRe   = regexp.MustCompile(`(^|[^A-Za-z0-9_])import([^A-Za-z0-9_]|$)`)
	// deniedFlux is matched against the query with strings and comments
	// blanked: to() (also as experimental.to or through an alias), and from()
	// or other functions pointed at another host or given a token.
	deniedFlux = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"experimental.to", regexp.MustCompile(`experimental\s*\.\s*to\b`)},
		{"http.post", regexp.MustCompile(`\bhttp\s*\.`)},
		{"sql.to", regexp.MustCompile(`\bsql\s*\.`)},
		{"secrets", regexp.MustCompile(`\bsecrets\s*\.`)},
	}
	// namedArg finds host: and token: arguments, which point from(),
	// buckets() and the schema functions at another server.
	toWord   = regexp.MustCompile(`\bto\b`)
	namedArg = regexp.MustCompile(`(^|[^A-Za-z0-9_.])(host|token)\s*:`)
)

// CheckFlux accepts a Flux query whose imports are all on the allow list
// and which calls no function that writes or reaches outside. Strings and
// comments are blanked before looking for calls, and string interpolation
// (${…}), which would hide an expression inside a string, is refused.
func CheckFlux(q string) error {
	if strings.TrimSpace(q) == "" {
		return errors.New("enter a Flux query")
	}
	if len(q) > maxFlux {
		return errors.New("the query is too long")
	}
	code, imports, err := stripFlux(q)
	if err != nil {
		return err
	}
	for _, line := range imports {
		m := importRe.FindStringSubmatch(line)
		if m == nil {
			return fmt.Errorf("can't read the import %q", line)
		}
		if !allowedImports[m[1]] {
			return fmt.Errorf("the %q package isn't allowed here (it can write, reach other servers or read secrets)", m[1])
		}
	}
	if wordRe.MatchString(code) {
		return errors.New("imports go at the top of the query, one per line")
	}
	for _, d := range deniedFlux {
		if d.re.MatchString(code) {
			return fmt.Errorf("%s isn't allowed here", d.name)
		}
	}
	// to() writes; it's refused wherever the name is used as a value
	// (to(…), universe.to, an alias such as w = to), not as a record key.
	for _, m := range toWord.FindAllStringIndex(code, -1) {
		if !strings.HasPrefix(strings.TrimLeft(code[m[1]:], " \t\r\n"), ":") {
			return errors.New("to() (writing) isn't allowed here")
		}
	}
	// host: and token: as a function's argument (inside parentheses) are
	// refused; as a record's field (inside braces: {r with host: …}) they
	// are fine.
	for _, m := range namedArg.FindAllStringSubmatchIndex(code, -1) {
		if innermostOpen(code[:m[4]]) == '(' {
			return fmt.Errorf("the %s: argument (querying another server) isn't allowed here", code[m[4]:m[5]])
		}
	}
	return nil
}

// innermostOpen returns the innermost bracket still open at the end of s,
// or 0.
func innermostOpen(s string) byte {
	var stack []byte
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '{', '[':
			stack = append(stack, s[i])
		case ')', '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	if len(stack) == 0 {
		return 0
	}
	return stack[len(stack)-1]
}

// stripFlux returns the query with comments removed and string contents
// blanked, plus the import lines at its top (taken out of the code).
func stripFlux(q string) (string, []string, error) {
	var b strings.Builder
	var imports []string
	lines := strings.Split(q, "\n")
	// Leading import lines, with blank and comment lines between them.
	start := 0
	for ; start < len(lines); start++ {
		l := strings.TrimSpace(lines[start])
		if l == "" || strings.HasPrefix(l, "//") {
			continue
		}
		if strings.HasPrefix(l, "import") && (len(l) == len("import") || l[len("import")] == ' ' || l[len("import")] == '\t') {
			if i := strings.Index(l, "//"); i >= 0 && strings.Count(l[:i], `"`)%2 == 0 {
				l = strings.TrimSpace(l[:i])
			}
			imports = append(imports, l)
			continue
		}
		break
	}
	rest := strings.Join(lines[start:], "\n")
	for i := 0; i < len(rest); i++ {
		ch := rest[i]
		switch {
		case ch == '/' && i+1 < len(rest) && rest[i+1] == '/':
			for i < len(rest) && rest[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case ch == '"':
			i++
			for i < len(rest) && rest[i] != '"' {
				if rest[i] == '\\' {
					i++
				} else if rest[i] == '$' && i+1 < len(rest) && rest[i+1] == '{' {
					return "", nil, errors.New("string interpolation (${…}) isn't allowed here")
				}
				i++
			}
			if i >= len(rest) {
				return "", nil, errors.New("a string isn't closed")
			}
			b.WriteString(`""`)
		default:
			b.WriteByte(ch)
		}
	}
	return b.String(), imports, nil
}
