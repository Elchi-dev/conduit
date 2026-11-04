// Package semgrep works with the Semgrep AppSec Platform through its web API
// and an API token: the token's deployment, projects, findings counted by
// severity, and triaging a finding (ignored, reviewing, fixing or reopened).
// It never returns code: no snippets, autofix suggestions or rule messages
// (which can quote the matched code), only rule, path, line and severity.
package semgrep

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
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Semgrep deployment.
type Config struct {
	Token      string `json:"token"`      // secret:// API token with the Web API scope
	Deployment string `json:"deployment"` // deployment slug; the token's own when empty
}

type conn struct {
	api  *rest.Client
	slug string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://semgrep.dev (tests).
	Base string
}

// New returns the Semgrep module.
func New() *Module { return &Module{} }

var (
	slugRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
	severities = []string{"critical", "high", "medium", "low"}
	statuses   = []string{"open", "fixed", "ignored", "reviewing", "fixing", "provisionally_ignored"}
	targets    = []string{"ignored", "reviewing", "fixing", "reopened"}
	reasons    = []string{"acceptable_risk", "false_positive", "no_time", "no_triage_reason", "duplicate"}
	types      = []string{"sast", "sca"}
)

const (
	maxPages   = 10
	pageSize   = 500
	findPages  = 5
	findSize   = 3000
	maxID      = 1 << 53
	maxRepoLen = 300
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	dep := `"deployment":{"type":"string","description":"Deployment slug (the configured one when empty; see deployments)"}`
	typ := `"issue_type":{"type":"string","enum":["sast","sca"],"default":"sast","description":"Code (sast) or Supply Chain (sca) findings"}`
	return sdk.Manifest{
		ID: "semgrep", Name: "Semgrep", Version: "0.1.0", Category: "Security", Icon: "shield",
		Description: "Semgrep AppSec Platform: deployments, projects and findings by severity; triage a finding as ignored, reviewing, fixing or reopened. Never code snippets.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An API token with the Web API scope (Settings, Tokens)"},
			"deployment":{"type":"string","description":"Deployment slug (Settings, Deployment); the token's own deployment when empty"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "deployments", Title: "Deployments", Description: "The deployments the token can access, with id, name and slug.", Risk: sdk.RiskRead},
			{Name: "projects", Title: "Projects", Description: "A deployment's projects (repositories) with id, name, tags, primary branch and when last scanned.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + dep + `}}`)},
			{Name: "findings", Title: "Findings", Description: "Findings counted by severity, and the most severe with id, rule, repository, path, line, confidence and triage state (Supply Chain: the advisory and package). Never code.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + dep + `,` + typ + `,"repo":{"type":"string","description":"Only this repository (its name, from projects)"},
					"status":{"type":"string","enum":["open","fixed","ignored","reviewing","fixing","provisionally_ignored"],"default":"open"},
					"severity":{"type":"string","enum":["critical","high","medium","low"]},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}}}`)},
			{Name: "triage_finding", Title: "Triage a finding", Description: "Sets a finding's triage state: ignored (with a reason) or provisionally hiding it while reviewing or fixing, or reopened. Ignoring hides it from open findings and can stop it blocking pull requests. Undo sets the previous state back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["finding","repo","state"],"properties":{` + dep + `,` + typ + `,
					"finding":{"type":"integer","description":"Finding id (from findings)"},
					"repo":{"type":"string","description":"The finding's repository name (from findings)"},
					"state":{"type":"string","enum":["ignored","reviewing","fixing","reopened"]},
					"reason":{"type":"string","enum":["acceptable_risk","false_positive","no_time","no_triage_reason","duplicate"],"description":"Why it's ignored (state ignored only)"},
					"note":{"type":"string","maxLength":3000,"description":"A note kept on the finding"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	slug := strings.TrimSpace(c.Deployment)
	if slug != "" && !slugRe.MatchString(slug) {
		return errors.New("the deployment is its slug, like my-org (Settings, Deployment)")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	base := "https://semgrep.dev"
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Token
	api := rest.New(base+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, slug: slug})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Semgrep refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Semgrep refused: the token needs the Web API scope, or can't see this deployment")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no such deployment (or the token can't see it; see deployments)")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Semgrep's rate limit was hit; try again in a minute")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

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

func oneOf(s string, set []string) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

// num is an int64 that the API may send as a number or as a string.
type num int64

func (n *num) UnmarshalJSON(b []byte) error {
	var x json.Number
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v, err := x.Int64()
	*n = num(v)
	return err
}

type deployment struct {
	ID   num    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (c *conn) deployments(ctx context.Context) ([]deployment, error) {
	var d struct {
		Deployments []deployment `json:"deployments"`
	}
	if err := c.do(ctx, http.MethodGet, "/deployments", nil, nil, &d); err != nil {
		return nil, err
	}
	return d.Deployments, nil
}

// deployment picks the slug asked for, the configured one, or the token's
// only deployment.
func (c *conn) deployment(ctx context.Context, s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = c.slug
	}
	if s != "" {
		if !slugRe.MatchString(s) {
			return "", errors.New("the deployment is its slug (see deployments)")
		}
		return s, nil
	}
	ds, err := c.deployments(ctx)
	if err != nil {
		return "", err
	}
	if len(ds) != 1 || !slugRe.MatchString(ds[0].Slug) {
		return "", errors.New("enter the deployment slug (see deployments), or set it in the settings")
	}
	return ds[0].Slug, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ds, err := c.deployments(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	for _, d := range ds {
		if c.slug == "" || d.Slug == c.slug {
			return sdk.Health{Status: "ok", Message: "deployment " + clip(d.Name, 100)}
		}
	}
	if c.slug != "" {
		return sdk.Health{Status: "down", Message: "the token can't access deployment " + c.slug}
	}
	return sdk.Health{Status: "down", Message: "the token has no deployment"}
}

type finding struct {
	ID           num    `json:"id"`
	Ref          string `json:"ref"`
	Status       string `json:"status"`
	TriageState  string `json:"triage_state"`
	TriageReason string `json:"triage_reason"`
	Severity     string `json:"severity"`
	Confidence   string `json:"confidence"`
	RuleName     string `json:"rule_name"`
	Rule         struct {
		Name string `json:"name"`
	} `json:"rule"`
	Repository struct {
		Name string `json:"name"`
	} `json:"repository"`
	Location struct {
		Path string `json:"file_path"`
		Line int    `json:"line"`
	} `json:"location"`
	RelevantSince string `json:"relevant_since"`
	Vuln          string `json:"vulnerability_identifier"`
	Dependency    struct {
		Package string `json:"package"`
		Version string `json:"version"`
	} `json:"found_dependency"`
	// rule.message and rule_message (they can quote the matched code),
	// triage_comment, assistant (autofix code) and line_of_code_url
	// aren't decoded.
}

func (f finding) rule() string {
	if f.Rule.Name != "" {
		return f.Rule.Name
	}
	return f.RuleName
}

func (f finding) row() map[string]any {
	r := map[string]any{"id": f.ID, "rule": clip(f.rule(), 200), "severity": clip(f.Severity, 10), "repo": clip(f.Repository.Name, 200),
		"path": clip(f.Location.Path, 300), "status": clip(f.Status, 25), "triage": f.state()}
	if f.Location.Line > 0 {
		r["line"] = f.Location.Line
	}
	if f.Confidence != "" {
		r["confidence"] = clip(f.Confidence, 10)
	}
	if f.TriageReason != "" && f.state() == "ignored" {
		r["reason"] = clip(f.TriageReason, 30)
	}
	if f.Ref != "" {
		r["ref"] = clip(f.Ref, 100)
	}
	if f.Vuln != "" {
		r["vulnerability"] = clip(f.Vuln, 60)
	}
	if f.Dependency.Package != "" {
		r["package"] = clip(f.Dependency.Package, 100)
		r["version"] = clip(f.Dependency.Version, 40)
	}
	return r
}

// state is the triage state with every "not triaged" spelling as open.
func (f finding) state() string {
	switch s := strings.ToLower(f.TriageState); s {
	case "", "untriaged", "open", "reopened":
		return "open"
	default:
		return clip(s, 30)
	}
}

func rank(sev string) int {
	for i, s := range severities {
		if s == sev {
			return i
		}
	}
	return len(severities)
}

func checkRepo(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxRepoLen || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", errors.New("the repo is a repository name from projects or findings, like acme/api")
	}
	return s, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Deployment string `json:"deployment"`
		IssueType  string `json:"issue_type"`
		Repo       string `json:"repo"`
		Status     string `json:"status"`
		Severity   string `json:"severity"`
		Limit      int    `json:"limit"`
		Finding    int64  `json:"finding"`
		State      string `json:"state"`
		Reason     string `json:"reason"`
		Note       string `json:"note"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if p.IssueType == "" {
		p.IssueType = "sast"
	}
	if !oneOf(p.IssueType, types) {
		return sdk.Result{}, errors.New("issue_type is sast or sca")
	}
	if p.Deployment = strings.TrimSpace(p.Deployment); p.Deployment != "" && !slugRe.MatchString(p.Deployment) {
		return sdk.Result{}, errors.New("the deployment is its slug (see deployments)")
	}
	switch call.Action {
	case "deployments":
		ds, err := c.deployments(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for _, d := range ds {
			row := map[string]any{"id": d.ID, "name": clip(d.Name, 200), "slug": clip(d.Slug, 100)}
			if d.Slug == c.slug {
				row["default"] = true
			}
			rows = append(rows, row)
		}
		return sdk.JSON(map[string]any{"deployments": rows})
	case "projects":
		slug, err := c.deployment(ctx, p.Deployment)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.projects(ctx, slug)
	case "findings":
		if p.Limit == 0 {
			p.Limit = 50
		}
		if p.Limit < 1 || p.Limit > 200 {
			return sdk.Result{}, errors.New("limit is between 1 and 200")
		}
		if p.Status == "" {
			p.Status = "open"
		}
		if !oneOf(p.Status, statuses) {
			return sdk.Result{}, errors.New("status is open, fixed, ignored, reviewing, fixing or provisionally_ignored")
		}
		if p.Severity != "" && !oneOf(p.Severity, severities) {
			return sdk.Result{}, errors.New("severity is critical, high, medium or low")
		}
		if p.Repo != "" {
			if p.Repo, err = checkRepo(p.Repo); err != nil {
				return sdk.Result{}, err
			}
		}
		slug, err := c.deployment(ctx, p.Deployment)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.findings(ctx, slug, p.IssueType, p.Repo, p.Status, p.Severity, p.Limit)
	case "triage_finding":
		if p.Finding < 1 || p.Finding > maxID {
			return sdk.Result{}, errors.New("the finding is its id, a positive number (from findings)")
		}
		if p.Repo, err = checkRepo(p.Repo); err != nil {
			return sdk.Result{}, err
		}
		if !oneOf(p.State, targets) {
			return sdk.Result{}, errors.New("state is ignored, reviewing, fixing or reopened")
		}
		if p.Reason != "" && (p.State != "ignored" || !oneOf(p.Reason, reasons)) {
			return sdk.Result{}, errors.New("a reason goes with state ignored: acceptable_risk, false_positive, no_time, no_triage_reason or duplicate")
		}
		if utf8.RuneCountInString(p.Note) > 3000 {
			return sdk.Result{}, errors.New("the note is at most 3000 characters")
		}
		slug, err := c.deployment(ctx, p.Deployment)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.triage(ctx, call, slug, p.IssueType, p.Repo, p.Finding, p.State, p.Reason, strings.TrimSpace(p.Note))
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) projects(ctx context.Context, slug string) (sdk.Result, error) {
	type project struct {
		ID         num      `json:"id"`
		Name       string   `json:"name"`
		Tags       []string `json:"tags"`
		LatestScan string   `json:"latest_scan_at"`
		Primary    string   `json:"primary_branch"`
		Default    string   `json:"default_branch"`
		Created    string   `json:"created_at"`
	}
	rows := []map[string]any{}
	more := true
	for i := 0; i < maxPages && more; i++ {
		var pg struct {
			Projects []project `json:"projects"`
		}
		q := url.Values{"page": {strconv.Itoa(i)}, "page_size": {"100"}}
		if err := c.do(ctx, http.MethodGet, "/deployments/"+url.PathEscape(slug)+"/projects", q, nil, &pg); err != nil {
			return sdk.Result{}, err
		}
		for _, x := range pg.Projects {
			tags := []string{}
			for n, t := range x.Tags {
				if n == 10 {
					break
				}
				tags = append(tags, clip(t, 40))
			}
			branch := x.Primary
			if branch == "" {
				branch = x.Default
			}
			rows = append(rows, map[string]any{"id": x.ID, "name": clip(x.Name, 200), "tags": tags, "branch": clip(branch, 100),
				"lastScan": clip(x.LatestScan, 40), "created": clip(x.Created, 40)})
		}
		more = len(pg.Projects) == 100
	}
	return sdk.JSON(map[string]any{"deployment": slug, "projects": rows, "truncated": more})
}

// list pages through findings; it reports whether it stopped early.
func (c *conn) list(ctx context.Context, slug string, q url.Values, size, pages int) ([]finding, bool, error) {
	var out []finding
	q.Set("page_size", strconv.Itoa(size))
	for i := 0; i < pages; i++ {
		q.Set("page", strconv.Itoa(i))
		var pg struct {
			Findings []finding `json:"findings"`
		}
		if err := c.do(ctx, http.MethodGet, "/deployments/"+url.PathEscape(slug)+"/findings", q, nil, &pg); err != nil {
			return nil, false, err
		}
		out = append(out, pg.Findings...)
		if len(pg.Findings) < size {
			return out, false, nil
		}
	}
	return out, true, nil
}

func (c *conn) findings(ctx context.Context, slug, typ, repo, status, severity string, limit int) (sdk.Result, error) {
	q := url.Values{"issue_type": {typ}, "status": {status}, "dedup": {"true"}}
	if repo != "" {
		q.Set("repos", repo)
	}
	if severity != "" {
		q.Set("severities", severity)
	}
	fs, more, err := c.list(ctx, slug, q, pageSize, maxPages)
	if err != nil {
		return sdk.Result{}, err
	}
	by := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, f := range fs {
		if oneOf(f.Severity, severities) {
			by[f.Severity]++
		}
	}
	sort.SliceStable(fs, func(i, j int) bool { return rank(fs[i].Severity) < rank(fs[j].Severity) })
	rows := []map[string]any{}
	for i, f := range fs {
		if i == limit {
			break
		}
		rows = append(rows, f.row())
	}
	out := map[string]any{"deployment": slug, "issueType": typ, "status": status, "total": len(fs), "bySeverity": by, "findings": rows, "truncated": more || len(fs) > len(rows)}
	if repo != "" {
		out["repo"] = repo
	}
	return sdk.JSON(out)
}

// find looks a finding up among its repository's findings (the API has no
// call for one finding).
func (c *conn) find(ctx context.Context, slug, typ, repo string, id int64) (finding, error) {
	fs, more, err := c.list(ctx, slug, url.Values{"issue_type": {typ}, "repos": {repo}}, findSize, findPages)
	if err != nil {
		return finding{}, err
	}
	for _, f := range fs {
		if int64(f.ID) == id {
			return f, nil
		}
	}
	if more {
		return finding{}, fmt.Errorf("finding %d isn't among the first %d %s findings of %s; triage it in Semgrep", id, findSize*findPages, typ, repo)
	}
	return finding{}, fmt.Errorf("there's no %s finding %d in %s", typ, id, repo)
}

func (c *conn) triage(ctx context.Context, call sdk.Call, slug, typ, repo string, id int64, state, reason, note string) (sdk.Result, error) {
	f, err := c.find(ctx, slug, typ, repo, id)
	if err != nil {
		return sdk.Result{}, err
	}
	cur := f.state()
	want := state
	if want == "reopened" {
		want = "open"
	}
	curReason := ""
	if cur == "ignored" {
		curReason = f.TriageReason
	}
	if cur == want && (want != "ignored" || reason == "" || reason == curReason) {
		return sdk.JSON(map[string]any{"finding": id, "triage": cur, "note": "nothing to change"})
	}
	undoIn := map[string]any{"finding": id, "repo": repo, "issue_type": typ, "deployment": slug}
	var undo *sdk.Undo
	switch cur {
	case "open":
		undoIn["state"] = "reopened"
	case "reviewing", "fixing":
		undoIn["state"] = cur
	case "ignored":
		undoIn["state"] = "ignored"
		if oneOf(curReason, reasons) {
			undoIn["reason"] = curReason
		}
	}
	if undoIn["state"] != nil {
		undo = sdk.UndoWith("triage_finding", undoIn, fmt.Sprintf("Set finding %d back to %s", id, cur))
	}
	before := map[string]string{"triage": cur}
	if curReason != "" {
		before["reason"] = clip(curReason, 30)
	}
	after := map[string]string{"triage": want}
	if reason != "" {
		after["reason"] = reason
	}
	label := fmt.Sprintf("finding %d (%s: %s in %s, %s line %d)", id, clip(f.Severity, 10), clip(f.rule(), 120), clip(repo, 100), clip(f.Location.Path, 200), f.Location.Line)
	if call.DryRun {
		b, _ := json.Marshal(before)
		a, _ := json.Marshal(after)
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Set finding %d to %s", id, state), Changes: []sdk.Change{{Target: label, Op: "triage", Before: b, After: a}}}}, nil
	}
	// limit 1 keeps the change to this finding should the ids ever be
	// ignored (Semgrep still triages its copies on other branches).
	body := map[string]any{"issue_type": typ, "issue_ids": []int64{id}, "new_triage_state": state, "limit": 1}
	if reason != "" {
		body["new_triage_reason"] = reason
	}
	if note != "" {
		body["new_note"] = note
	}
	var res struct {
		Num     json.Number   `json:"num_triaged"`
		Triaged []json.Number `json:"triaged_issues"`
	}
	if err := c.do(ctx, http.MethodPost, "/deployments/"+url.PathEscape(slug)+"/triage", nil, body, &res); err != nil {
		return sdk.Result{}, err
	}
	ok := false
	for _, t := range res.Triaged {
		if t.String() == strconv.FormatInt(id, 10) {
			ok = true
		}
	}
	if !ok {
		return sdk.Result{}, fmt.Errorf("Semgrep didn't triage finding %d", id)
	}
	out := map[string]any{"finding": id, "triage": want, "triaged": len(res.Triaged)}
	if len(res.Triaged) > 1 {
		out["note"] = "Semgrep also triaged the same finding on other branches"
	}
	if undo == nil {
		out["note"] = "no undo: the finding's earlier state (" + cur + ") can't be set back from here"
	}
	r, err := sdk.JSON(out)
	r.Undo = undo
	return r, err
}
