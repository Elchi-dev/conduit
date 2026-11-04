// Package dependencytrack works with OWASP Dependency-Track through its REST
// API and an API key: projects, vulnerability metrics by severity, a
// project's findings, and auditing or suppressing a finding.
package dependencytrack

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
	"unicode"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Dependency-Track.
type Config struct {
	URL                string `json:"url"`    // the API server, e.g. https://dtrack.example.com
	APIKey             string `json:"apiKey"` // secret:// team API key
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

// New returns the Dependency-Track module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	searchRe = regexp.MustCompile(`^[\pL\pN _.:@/+-]{1,100}$`)
)

var (
	severities     = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED"}
	states         = []string{"NOT_SET", "EXPLOITABLE", "IN_TRIAGE", "RESOLVED", "FALSE_POSITIVE", "NOT_AFFECTED"}
	justifications = []string{"NOT_SET", "CODE_NOT_PRESENT", "CODE_NOT_REACHABLE", "REQUIRES_CONFIGURATION", "REQUIRES_DEPENDENCY", "REQUIRES_ENVIRONMENT",
		"PROTECTED_BY_COMPILER", "PROTECTED_AT_RUNTIME", "PROTECTED_AT_PERIMETER", "PROTECTED_BY_MITIGATING_CONTROL"}
	responses = []string{"NOT_SET", "CAN_NOT_FIX", "WILL_NOT_FIX", "UPDATE", "ROLLBACK", "WORKAROUND_AVAILABLE"}
)

const maxPages = 10

func enum(vs []string) string {
	b, _ := json.Marshal(vs)
	return string(b)
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	project := `"project":{"type":"string","description":"Project UUID (from projects)"}`
	return sdk.Manifest{
		ID: "dependencytrack", Name: "Dependency-Track", Version: "0.1.0", Category: "Security", Icon: "package",
		Description: "OWASP Dependency-Track: projects, vulnerability metrics by severity, a project's findings, and auditing or suppressing a finding.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"The API server's address, e.g. https://dtrack-api.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"A team's API key (Administration, Access Management, Teams): VIEW_PORTFOLIO to read, VIEW_VULNERABILITY and VULNERABILITY_ANALYSIS to audit"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Active projects with UUID, name, version, classifier, last BOM import and vulnerabilities by severity.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Only projects whose name contains this"},"includeInactive":{"type":"boolean","default":false}}}`)},
			{Name: "metrics", Title: "Vulnerability metrics", Description: "Vulnerabilities by severity for the whole portfolio or one project, with vulnerable components and projects, suppressed and audited findings, policy violations and the risk score.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `}}`)},
			{Name: "findings", Title: "Findings", Description: "A project's findings, most severe first: vulnerability id and aliases, severity, CVSS and EPSS, the component and version, and the analysis state. Each has a finding id for audit_finding.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + project + `,"severity":{"type":"string","enum":` + enum(severities) + `},"includeSuppressed":{"type":"boolean","default":false},"limit":{"type":"integer","minimum":1,"maximum":500,"default":100}}}`)},
			{Name: "audit_finding", Title: "Audit or suppress a finding", Description: "Records an analysis (state, justification, response, details, a comment) and can suppress the finding, which takes it out of metrics and findings. Undo sets the previous state and suppression back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["finding"],"properties":{
					"finding":{"type":"string","description":"Finding id from findings (project:component:vulnerability)"},
					"state":{"type":"string","enum":` + enum(states) + `},
					"justification":{"type":"string","enum":` + enum(justifications) + `},
					"response":{"type":"string","enum":` + enum(responses) + `},
					"details":{"type":"string","description":"Analysis details"},
					"comment":{"type":"string","description":"A comment added to the audit trail"},
					"suppressed":{"type":"boolean","description":"Suppress (true) or unsuppress (false) the finding"}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) || strings.Contains(u.Path, "..") {
		return errors.New("the address is like https://dtrack-api.example.com")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
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
	ref := c.APIKey
	base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-Api-Key", strings.TrimSpace(k))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) (http.Header, error) {
	hdr, err := c.api.Do(ctx, method, path, q, body, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return nil, errors.New("Dependency-Track refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return nil, errors.New("the API key's team lacks the permission for this in Dependency-Track")
	}
	return hdr, err
}

// clean makes text from Dependency-Track safe to show: credentials masked
// first, then control characters dropped and the result cut to n characters.
func clean(s string, n int) string { return clip(rest.Redact(s), n) }

func clip(s string, n int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s))
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n]) + "…"
	}
	return s
}

func projectID(s string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(s))
	if !uuidRe.MatchString(p) {
		return "", errors.New("the project is its UUID (from projects)")
	}
	return p, nil
}

type metrics struct {
	Critical             int     `json:"critical"`
	High                 int     `json:"high"`
	Medium               int     `json:"medium"`
	Low                  int     `json:"low"`
	Unassigned           int     `json:"unassigned"`
	Vulnerabilities      int     `json:"vulnerabilities"`
	VulnerableComponents int     `json:"vulnerableComponents"`
	Components           int     `json:"components"`
	Projects             int     `json:"projects"`
	VulnerableProjects   int     `json:"vulnerableProjects"`
	Suppressed           int     `json:"suppressed"`
	FindingsTotal        int     `json:"findingsTotal"`
	FindingsAudited      int     `json:"findingsAudited"`
	FindingsUnaudited    int     `json:"findingsUnaudited"`
	PolicyViolations     int     `json:"policyViolationsTotal"`
	RiskScore            float64 `json:"inheritedRiskScore"`
	LastOccurrence       int64   `json:"lastOccurrence"`
}

func (x metrics) bySeverity() map[string]int {
	return map[string]int{"critical": x.Critical, "high": x.High, "medium": x.Medium, "low": x.Low, "unassigned": x.Unassigned}
}

func millis(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Version string `json:"version"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/version", nil, nil, &v); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Dependency-Track API server at this address (enter the API server's, not the frontend's)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var ps []json.RawMessage
	hdr, err := c.do(ctx, http.MethodGet, "/v1/project", url.Values{"pageSize": {"1"}, "pageNumber": {"1"}}, nil, &ps)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "Dependency-Track " + clip(v.Version, 20)
	if n, err := strconv.Atoi(hdr.Get("X-Total-Count")); err == nil {
		msg += fmt.Sprintf(", %d projects", n)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Project           string  `json:"project"`
		Search            string  `json:"search"`
		IncludeInactive   bool    `json:"includeInactive"`
		IncludeSuppressed bool    `json:"includeSuppressed"`
		Severity          string  `json:"severity"`
		Limit             int     `json:"limit"`
		Finding           string  `json:"finding"`
		State             string  `json:"state"`
		Justification     string  `json:"justification"`
		Response          string  `json:"response"`
		Details           *string `json:"details"`
		Comment           string  `json:"comment"`
		Suppressed        *bool   `json:"suppressed"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "projects":
		return c.projects(ctx, p.Search, p.IncludeInactive)
	case "metrics":
		path := "/v1/metrics/portfolio/current"
		var pid string
		if strings.TrimSpace(p.Project) != "" {
			if pid, err = projectID(p.Project); err != nil {
				return sdk.Result{}, err
			}
			path = "/v1/metrics/project/" + url.PathEscape(pid) + "/current"
		}
		var x metrics
		if _, err := c.do(ctx, http.MethodGet, path, nil, nil, &x); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) && pid != "" {
				return sdk.Result{}, fmt.Errorf("there's no project %s", pid)
			}
			return sdk.Result{}, err
		}
		out := map[string]any{"bySeverity": x.bySeverity(), "vulnerabilities": x.Vulnerabilities, "vulnerableComponents": x.VulnerableComponents, "components": x.Components,
			"suppressed": x.Suppressed, "findingsTotal": x.FindingsTotal, "findingsAudited": x.FindingsAudited, "findingsUnaudited": x.FindingsUnaudited,
			"policyViolations": x.PolicyViolations, "riskScore": x.RiskScore, "measured": millis(x.LastOccurrence)}
		if pid != "" {
			out["project"] = pid
		} else {
			out["projects"], out["vulnerableProjects"] = x.Projects, x.VulnerableProjects
		}
		return sdk.JSON(out)
	case "findings":
		pid, err := projectID(p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		if p.Severity != "" && !in(severities, p.Severity) {
			return sdk.Result{}, errors.New("severity is CRITICAL, HIGH, MEDIUM, LOW, INFO or UNASSIGNED")
		}
		limit := p.Limit
		if limit == 0 {
			limit = 100
		}
		if limit < 1 || limit > 500 {
			return sdk.Result{}, errors.New("limit is between 1 and 500")
		}
		return c.findings(ctx, pid, p.Severity, p.IncludeSuppressed, limit)
	case "audit_finding":
		return c.audit(ctx, call, p.Finding, p.State, p.Justification, p.Response, p.Details, p.Comment, p.Suppressed)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func in(vs []string, s string) bool {
	for _, v := range vs {
		if v == s {
			return true
		}
	}
	return false
}

func (c *conn) projects(ctx context.Context, search string, inactive bool) (sdk.Result, error) {
	q := url.Values{"pageSize": {"100"}, "sortName": {"name"}, "sortOrder": {"asc"}}
	if !inactive {
		q.Set("excludeInactive", "true")
	}
	if s := strings.TrimSpace(search); s != "" {
		if !searchRe.MatchString(s) {
			return sdk.Result{}, errors.New("search is up to 100 letters, digits, spaces and . _ - : @ / +")
		}
		q.Set("searchText", s)
	}
	type project struct {
		UUID          string   `json:"uuid"`
		Name          string   `json:"name"`
		Version       string   `json:"version"`
		Classifier    string   `json:"classifier"`
		Active        *bool    `json:"active"`
		LastBomImport int64    `json:"lastBomImport"`
		Metrics       *metrics `json:"metrics"`
	}
	rows := []map[string]any{}
	total, more := 0, false
	for page := 1; ; page++ {
		if page > maxPages {
			more = true
			break
		}
		q.Set("pageNumber", strconv.Itoa(page))
		var ps []project
		hdr, err := c.do(ctx, http.MethodGet, "/v1/project", q, nil, &ps)
		if err != nil {
			return sdk.Result{}, err
		}
		total, _ = strconv.Atoi(hdr.Get("X-Total-Count"))
		for _, x := range ps {
			row := map[string]any{"uuid": x.UUID, "name": clip(x.Name, 200), "version": clip(x.Version, 60), "classifier": clip(x.Classifier, 30)}
			if x.Active != nil {
				row["active"] = *x.Active
			}
			if t := millis(x.LastBomImport); t != "" {
				row["lastBomImport"] = t
			}
			if x.Metrics != nil {
				row["vulnerabilities"] = x.Metrics.bySeverity()
				row["riskScore"] = x.Metrics.RiskScore
			}
			rows = append(rows, row)
		}
		if len(ps) < 100 || len(rows) >= total {
			break
		}
	}
	if total < len(rows) {
		total = len(rows)
	}
	return sdk.JSON(map[string]any{"total": total, "projects": rows, "truncated": more})
}

type dtFinding struct {
	Component struct {
		UUID    string `json:"uuid"`
		Name    string `json:"name"`
		Group   string `json:"group"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
		Project string `json:"project"`
	} `json:"component"`
	Vulnerability struct {
		UUID     string   `json:"uuid"`
		VulnID   string   `json:"vulnId"`
		Source   string   `json:"source"`
		Severity string   `json:"severity"`
		CVSSv3   float64  `json:"cvssV3BaseScore"`
		CVSSv2   float64  `json:"cvssV2BaseScore"`
		EPSS     float64  `json:"epssScore"`
		CWEs     []any    `json:"cwes"`
		Aliases  []any    `json:"aliases"`
		Title    string   `json:"title"`
		Patched  []string `json:"patchedVersions"`
	} `json:"vulnerability"`
	Analysis struct {
		State      string `json:"state"`
		Suppressed bool   `json:"isSuppressed"`
	} `json:"analysis"`
	Matrix string `json:"matrix"`
}

// aliasIDs reads the aliases Dependency-Track lists in either shape: objects
// of ids (cveId, ghsaId, ...) or plain strings.
func aliasIDs(as []any, self string) []string {
	seen := map[string]bool{self: true}
	out := []string{}
	for _, a := range as {
		var ids []string
		switch x := a.(type) {
		case string:
			ids = []string{x}
		case map[string]any:
			for k, v := range x {
				if s, ok := v.(string); ok && strings.HasSuffix(k, "Id") {
					ids = append(ids, s)
				}
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			id = clip(id, 40)
			if !seen[id] && len(out) < 10 {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

func rank(s string) int {
	for i, v := range severities {
		if v == s {
			return i
		}
	}
	return len(severities)
}

func (c *conn) findings(ctx context.Context, pid, severity string, suppressed bool, limit int) (sdk.Result, error) {
	var fs []dtFinding
	if _, err := c.do(ctx, http.MethodGet, "/v1/finding/project/"+url.PathEscape(pid), url.Values{"suppressed": {strconv.FormatBool(suppressed)}}, nil, &fs); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no project %s", pid)
		}
		return sdk.Result{}, err
	}
	by := map[string]int{}
	for _, s := range severities {
		by[strings.ToLower(s)] = 0
	}
	var keep []dtFinding
	for _, f := range fs {
		sev := strings.ToUpper(f.Vulnerability.Severity)
		if rank(sev) < len(severities) {
			by[strings.ToLower(sev)]++
		}
		if severity == "" || sev == severity {
			keep = append(keep, f)
		}
	}
	sort.SliceStable(keep, func(i, j int) bool {
		a, b := keep[i].Vulnerability, keep[j].Vulnerability
		if rank(strings.ToUpper(a.Severity)) != rank(strings.ToUpper(b.Severity)) {
			return rank(strings.ToUpper(a.Severity)) < rank(strings.ToUpper(b.Severity))
		}
		return a.CVSSv3 > b.CVSSv3
	})
	rows := []map[string]any{}
	for _, f := range keep {
		if len(rows) == limit {
			break
		}
		v := f.Vulnerability
		comp := clip(f.Component.Name, 200)
		if f.Component.Group != "" {
			comp = clip(f.Component.Group, 100) + "/" + comp
		}
		row := map[string]any{"finding": pid + ":" + f.Component.UUID + ":" + v.UUID, "vulnerability": clip(v.VulnID, 60), "source": clip(v.Source, 20),
			"severity": clip(v.Severity, 12), "component": comp, "version": clip(f.Component.Version, 60), "analysis": clip(f.Analysis.State, 20)}
		if f.Analysis.State == "" {
			row["analysis"] = "NOT_SET"
		}
		if v.CVSSv3 > 0 {
			row["cvss"] = v.CVSSv3
		} else if v.CVSSv2 > 0 {
			row["cvss"] = v.CVSSv2
		}
		if v.EPSS > 0 {
			row["epss"] = v.EPSS
		}
		if as := aliasIDs(v.Aliases, v.VulnID); len(as) > 0 {
			row["aliases"] = as
		}
		if v.Title != "" {
			row["title"] = clean(v.Title, 200)
		}
		if f.Analysis.Suppressed {
			row["suppressed"] = true
		}
		rows = append(rows, row)
	}
	return sdk.JSON(map[string]any{"project": pid, "total": len(fs), "bySeverity": by, "findings": rows, "truncated": len(keep) > len(rows), "includesSuppressed": suppressed})
}

type analysis struct {
	State         string `json:"analysisState"`
	Justification string `json:"analysisJustification"`
	Response      string `json:"analysisResponse"`
	Details       string `json:"analysisDetails"`
	Suppressed    bool   `json:"isSuppressed"`
}

func (a analysis) view() map[string]any {
	v := map[string]any{"state": a.State, "justification": a.Justification, "response": a.Response, "suppressed": a.Suppressed}
	if a.Details != "" {
		v["details"] = clean(a.Details, 500)
	}
	return v
}

func orNotSet(s string) string {
	if s == "" {
		return "NOT_SET"
	}
	return s
}

func (c *conn) audit(ctx context.Context, call sdk.Call, finding, state, just, resp string, details *string, comment string, suppressed *bool) (sdk.Result, error) {
	parts := strings.Split(strings.TrimSpace(finding), ":")
	if len(parts) != 3 || !uuidRe.MatchString(parts[0]) || !uuidRe.MatchString(parts[1]) || !uuidRe.MatchString(parts[2]) {
		return sdk.Result{}, errors.New("the finding is its id from findings: three UUIDs, project:component:vulnerability")
	}
	for i := range parts {
		parts[i] = strings.ToLower(parts[i])
	}
	for _, x := range []struct {
		v, name string
		vs      []string
	}{{state, "state", states}, {just, "justification", justifications}, {resp, "response", responses}} {
		if x.v != "" && !in(x.vs, x.v) {
			return sdk.Result{}, fmt.Errorf("%s is one of %s", x.name, strings.Join(x.vs, ", "))
		}
	}
	if state == "" && just == "" && resp == "" && details == nil && comment == "" && suppressed == nil {
		return sdk.Result{}, errors.New("give a state, justification, response, details, comment or suppressed")
	}
	if utf8.RuneCountInString(comment) > 2000 || (details != nil && utf8.RuneCountInString(*details) > 4000) {
		return sdk.Result{}, errors.New("the comment is up to 2000 characters and the details up to 4000")
	}
	q := url.Values{"project": {parts[0]}, "component": {parts[1]}, "vulnerability": {parts[2]}}
	var cur analysis
	if _, err := c.do(ctx, http.MethodGet, "/v1/analysis", q, nil, &cur); err != nil && !rest.IsStatus(err, http.StatusNotFound) {
		return sdk.Result{}, err
	}
	cur.State, cur.Justification, cur.Response = orNotSet(cur.State), orNotSet(cur.Justification), orNotSet(cur.Response)
	want := cur
	if state != "" {
		want.State = state
	}
	if just != "" {
		want.Justification = just
	}
	if resp != "" {
		want.Response = resp
	}
	if suppressed != nil {
		want.Suppressed = *suppressed
	}
	if details != nil {
		want.Details = *details
	}
	if want == cur && comment == "" {
		return sdk.JSON(map[string]any{"finding": strings.Join(parts, ":"), "analysis": cur.view(), "note": "nothing to change"})
	}
	verb := "Audit"
	if want.Suppressed && !cur.Suppressed {
		verb = "Suppress"
	} else if !want.Suppressed && cur.Suppressed {
		verb = "Unsuppress"
	}
	if call.DryRun {
		b, _ := json.Marshal(cur.view())
		a, _ := json.Marshal(want.view())
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " a finding", Changes: []sdk.Change{{Target: "finding " + strings.Join(parts, ":"), Op: strings.ToLower(verb), Before: b, After: a}}}}, nil
	}
	body := map[string]any{"project": parts[0], "component": parts[1], "vulnerability": parts[2],
		"analysisState": want.State, "analysisJustification": want.Justification, "analysisResponse": want.Response, "isSuppressed": want.Suppressed}
	if details != nil {
		body["analysisDetails"] = *details
	}
	if comment != "" {
		body["comment"] = comment
	}
	var got analysis
	if _, err := c.do(ctx, http.MethodPut, "/v1/analysis", nil, body, &got); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, errors.New("Dependency-Track has no such finding (the project, component or vulnerability isn't there)")
		}
		return sdk.Result{}, err
	}
	got.State, got.Justification, got.Response = orNotSet(got.State), orNotSet(got.Justification), orNotSet(got.Response)
	if got.State != want.State || got.Suppressed != want.Suppressed {
		return sdk.Result{}, errors.New("Dependency-Track kept the finding's analysis as it was")
	}
	res, err := sdk.JSON(map[string]any{"finding": strings.Join(parts, ":"), "analysis": got.view()})
	if cur != want {
		back := map[string]any{"finding": strings.Join(parts, ":"), "state": cur.State, "justification": cur.Justification,
			"response": cur.Response, "suppressed": cur.Suppressed}
		if cur.Details != want.Details {
			back["details"] = cur.Details
		}
		res.Undo = sdk.UndoWith("audit_finding", back, "Set the finding's analysis back")
	}
	return res, err
}
