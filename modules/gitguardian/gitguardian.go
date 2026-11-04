// Package gitguardian works with GitGuardian secret incidents through its
// public API and an API key: incidents (leaked secrets) with severity,
// status, validity and occurrence counts, one incident's occurrences, and
// resolving, ignoring and reopening incidents. It never reads the leaked
// secret: no value, hash, matched text or share link.
package gitguardian

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one GitGuardian workspace.
type Config struct {
	Token  string `json:"token"`  // secret:// API key (personal access token or service account)
	Region string `json:"region"` // us (default) or eu
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces the region's API address, e.g. https://api.gitguardian.com (tests).
	Base string
}

// New returns the GitGuardian module.
func New() *Module { return &Module{} }

var (
	regions    = map[string]string{"us": "https://api.gitguardian.com", "eu": "https://api.eu1.gitguardian.com"}
	statuses   = []string{"TRIGGERED", "ASSIGNED", "RESOLVED", "IGNORED"}
	severities = []string{"critical", "high", "medium", "low", "info", "unknown"}
	reasons    = []string{"test_credential", "false_positive", "low_risk", "invalid"}
)

const maxID = 1 << 53

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	incident := `"incident":{"type":"integer","description":"Incident id (from incidents)"}`
	return sdk.Manifest{
		ID: "gitguardian", Name: "GitGuardian", Version: "0.1.0", Category: "Security", Icon: "key",
		Description: "GitGuardian: secret leak incidents with severity, status, validity and occurrences; resolve, ignore or reopen an incident. Never the secret itself.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An API key (API, Personal access tokens, or a service account) with the incidents:read scope, and incidents:write to resolve, ignore or reopen"},
			"region":{"type":"string","enum":["us","eu"],"default":"us","description":"Where the workspace is hosted: us (dashboard.gitguardian.com) or eu (dashboard.eu1.gitguardian.com)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "incidents", Title: "Secret incidents", Description: "Secret leak incidents, newest first: id, secret type, severity, status, validity, how many occurrences, when found, and when resolved or ignored and why. Never the secret.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["TRIGGERED","ASSIGNED","RESOLVED","IGNORED"]},"severity":{"type":"string","enum":["critical","high","medium","low","info","unknown"]},"limit":{"type":"integer","minimum":1,"maximum":100,"default":50}}}`)},
			{Name: "incident", Title: "Incident detail", Description: "One incident and where the secret was found: repository, file, short commit, date and whether it's still present. Never the secret, its hash or the matched text.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["incident"],"properties":{` + incident + `}}`)},
			{Name: "resolve_incident", Title: "Resolve an incident", Description: "Marks an open incident resolved (say whether the secret was revoked), which takes the leak out of the open incidents. Undo reopens it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["incident","revoked"],"properties":{` + incident + `,"revoked":{"type":"boolean","description":"Whether the secret has been revoked (rotated) at its provider"}}}`)},
			{Name: "ignore_incident", Title: "Ignore an incident", Description: "Ignores an open incident with a reason (test_credential, false_positive, low_risk, invalid), which hides the leak from the open incidents. Undo reopens it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["incident","reason"],"properties":{` + incident + `,"reason":{"type":"string","enum":["test_credential","false_positive","low_risk","invalid"]}}}`)},
			{Name: "reopen_incident", Title: "Reopen an incident", Description: "Makes a resolved or ignored incident open again. Undo resolves or ignores it as it was.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["incident"],"properties":{` + incident + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	region := strings.TrimSpace(c.Region)
	if region == "" {
		region = "us"
	}
	base, ok := regions[region]
	if !ok {
		return errors.New("the region is us or eu")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Token
	api := rest.New(base+"/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Token "+strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("GitGuardian refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API key lacks the scope for this (incidents:read, or incidents:write to change incidents)")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("GitGuardian's rate limit was hit; try again in a minute")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) (http.Header, error) {
	h, err := c.api.Do(ctx, method, path, q, body, out)
	return h, friendly(err)
}

// clean makes text from GitGuardian safe to show: credentials masked first,
// then control characters dropped and the result cut to n characters.
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

func oneOf(s string, set []string) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if _, err := c.do(ctx, http.MethodGet, "/health", nil, nil, nil); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var open []json.RawMessage
	h, err := c.do(ctx, http.MethodGet, "/incidents/secrets", url.Values{"status": {"TRIGGERED"}, "per_page": {"100"}}, nil, &open)
	if err != nil {
		// The key is valid but may lack incidents:read.
		return sdk.Health{Status: "ok", Message: "API key valid; can't list incidents: " + err.Error()}
	}
	n := strconv.Itoa(len(open))
	if hasNext(h) {
		n = "over " + n
	}
	return sdk.Health{Status: "ok", Message: n + " untriaged incidents"}
}

// hasNext reports whether a cursor-paginated answer has another page.
func hasNext(h http.Header) bool {
	for _, l := range h.Values("Link") {
		if strings.Contains(l, `rel="next"`) {
			return true
		}
	}
	return false
}

// incident is decoded field by field: secret_hash, hmsl_hash and share_url
// (a public link to the leak) are never read.
type incident struct {
	ID       int64  `json:"id"`
	Date     string `json:"date"`
	Detector struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Family      string `json:"family"`
	} `json:"detector"`
	Status        string   `json:"status"`
	Severity      string   `json:"severity"`
	Validity      string   `json:"validity"`
	Occurrences   int      `json:"occurrences_count"`
	IgnoreReason  string   `json:"ignore_reason"`
	IgnoredAt     string   `json:"ignored_at"`
	ResolvedAt    string   `json:"resolved_at"`
	SecretRevoked bool     `json:"secret_revoked"`
	Regression    bool     `json:"regression"`
	Tags          []string `json:"tags"`
	Dashboard     string   `json:"gitguardian_url"`
	Occurrence    []struct {
		Kind     string `json:"kind"`
		SHA      string `json:"sha"`
		Date     string `json:"date"`
		Presence string `json:"presence"`
		Filepath string `json:"filepath"`
		Source   struct {
			Type     string `json:"type"`
			FullName string `json:"full_name"`
		} `json:"source"`
		// matches (the secret's text and position), url, author_name and
		// author_info aren't decoded.
	} `json:"occurrences"`
}

func (i incident) kind() string {
	if i.Detector.DisplayName != "" {
		return clip(i.Detector.DisplayName, 100)
	}
	return clip(i.Detector.Name, 100)
}

func (i incident) row() map[string]any {
	r := map[string]any{"id": i.ID, "type": i.kind(), "severity": clip(i.Severity, 10), "status": clip(i.Status, 12), "validity": clip(i.Validity, 20),
		"occurrences": i.Occurrences, "date": clip(i.Date, 40)}
	if i.Detector.Family != "" {
		r["family"] = clip(i.Detector.Family, 30)
	}
	if i.Regression {
		r["regression"] = true
	}
	switch i.Status {
	case "IGNORED":
		r["ignoreReason"] = clip(i.IgnoreReason, 30)
		r["ignoredAt"] = clip(i.IgnoredAt, 40)
	case "RESOLVED":
		r["resolvedAt"] = clip(i.ResolvedAt, 40)
		r["secretRevoked"] = i.SecretRevoked
	}
	if len(i.Tags) > 0 {
		tags := []string{}
		for n, t := range i.Tags {
			if n == 10 {
				break
			}
			tags = append(tags, clip(t, 40))
		}
		r["tags"] = tags
	}
	return r
}

func shortSHA(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return ""
		}
	}
	if len(s) > 7 {
		s = s[:7]
	}
	return s
}

func checkID(n int64) error {
	if n < 1 || n > maxID {
		return errors.New("the incident is its id, a positive number (from incidents)")
	}
	return nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Status   string `json:"status"`
		Severity string `json:"severity"`
		Limit    int    `json:"limit"`
		Incident int64  `json:"incident"`
		Revoked  *bool  `json:"revoked"`
		Reason   string `json:"reason"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "incidents":
		return c.incidents(ctx, p.Status, p.Severity, p.Limit)
	case "incident":
		if err := checkID(p.Incident); err != nil {
			return sdk.Result{}, err
		}
		return c.detail(ctx, p.Incident)
	case "resolve_incident", "ignore_incident", "reopen_incident":
		if err := checkID(p.Incident); err != nil {
			return sdk.Result{}, err
		}
		if call.Action == "resolve_incident" && p.Revoked == nil {
			return sdk.Result{}, errors.New("say whether the secret was revoked (revoked: true or false)")
		}
		if call.Action == "ignore_incident" && !oneOf(p.Reason, reasons) {
			return sdk.Result{}, errors.New("the reason is test_credential, false_positive, low_risk or invalid")
		}
		return c.change(ctx, call, p.Incident, p.Revoked, p.Reason)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) incidents(ctx context.Context, status, severity string, limit int) (sdk.Result, error) {
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 {
		return sdk.Result{}, errors.New("limit is between 1 and 100")
	}
	if status != "" && !oneOf(status, statuses) {
		return sdk.Result{}, errors.New("status is TRIGGERED, ASSIGNED, RESOLVED or IGNORED")
	}
	if severity != "" && !oneOf(severity, severities) {
		return sdk.Result{}, errors.New("severity is critical, high, medium, low, info or unknown")
	}
	q := url.Values{"per_page": {strconv.Itoa(limit)}, "ordering": {"-date"}}
	if status != "" {
		q.Set("status", status)
	}
	if severity != "" {
		q.Set("severity", severity)
	}
	var is []incident
	h, err := c.do(ctx, http.MethodGet, "/incidents/secrets", q, nil, &is)
	if err != nil {
		return sdk.Result{}, err
	}
	rows := []map[string]any{}
	by := map[string]int{}
	for n, i := range is {
		if n == limit {
			break
		}
		rows = append(rows, i.row())
		by[clip(i.Severity, 10)]++
	}
	return sdk.JSON(map[string]any{"incidents": rows, "bySeverity": by, "truncated": hasNext(h) || len(is) > limit})
}

func (c *conn) get(ctx context.Context, id int64, occurrences int) (incident, error) {
	var i incident
	var q url.Values
	if occurrences > 0 {
		q = url.Values{"with_occurrences": {strconv.Itoa(occurrences)}}
	}
	if _, err := c.do(ctx, http.MethodGet, "/incidents/secrets/"+strconv.FormatInt(id, 10), q, nil, &i); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return incident{}, fmt.Errorf("there's no incident %d", id)
		}
		return incident{}, err
	}
	if i.ID != id {
		return incident{}, fmt.Errorf("there's no incident %d", id)
	}
	return i, nil
}

func (c *conn) detail(ctx context.Context, id int64) (sdk.Result, error) {
	i, err := c.get(ctx, id, 50)
	if err != nil {
		return sdk.Result{}, err
	}
	out := i.row()
	if i.Dashboard != "" {
		if u, err := url.Parse(i.Dashboard); err == nil && dashboardLink(u) {
			out["dashboard"] = u.Scheme + "://" + u.Host + u.EscapedPath()
		}
	}
	occ := []map[string]any{}
	for n, o := range i.Occurrence {
		if n == 50 {
			break
		}
		r := map[string]any{"file": clean(o.Filepath, 300), "date": clip(o.Date, 40), "presence": clip(o.Presence, 20)}
		if s := shortSHA(o.SHA); s != "" {
			r["commit"] = s
		}
		if o.Source.FullName != "" {
			r["repository"] = clip(o.Source.FullName, 200)
		}
		if o.Source.Type != "" {
			r["source"] = clip(o.Source.Type, 30)
		}
		if o.Kind != "" {
			r["kind"] = clip(o.Kind, 20)
		}
		occ = append(occ, r)
	}
	out["locations"] = occ
	out["locationsTruncated"] = i.Occurrences > len(occ)
	return sdk.JSON(out)
}

// dashboardLink accepts only an incident page on a GitGuardian dashboard
// host: not a look-alike host (evilgitguardian.com) or a public share link.
func dashboardLink(u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h != "gitguardian.com" && !strings.HasSuffix(h, ".gitguardian.com") || strings.HasPrefix(h, "share.") {
		return false
	}
	return !strings.Contains(strings.ToLower(u.Path), "/share")
}

func open(status string) bool { return status == "TRIGGERED" || status == "ASSIGNED" }

func (c *conn) change(ctx context.Context, call sdk.Call, id int64, revoked *bool, reason string) (sdk.Result, error) {
	i, err := c.get(ctx, id, 0)
	if err != nil {
		return sdk.Result{}, err
	}
	path := "/incidents/secrets/" + strconv.FormatInt(id, 10)
	label := fmt.Sprintf("incident %d (%s, %s, %d occurrences)", id, i.kind(), clip(i.Severity, 10), i.Occurrences)
	before := map[string]any{"status": clip(i.Status, 12)}
	after := map[string]any{}
	var (
		verb, endpoint string
		body           map[string]any
		done           func(incident) bool
		undo           *sdk.Undo
	)
	switch call.Action {
	case "resolve_incident":
		if i.Status == "RESOLVED" && i.SecretRevoked == *revoked {
			return sdk.JSON(map[string]any{"incident": id, "status": i.Status, "secretRevoked": i.SecretRevoked, "note": "nothing to change"})
		}
		if !open(i.Status) {
			return sdk.Result{}, fmt.Errorf("incident %d is %s; reopen it first", id, strings.ToLower(clip(i.Status, 12)))
		}
		verb, endpoint = "Resolve", "/resolve"
		body = map[string]any{"secret_revoked": *revoked}
		after["status"], after["secretRevoked"] = "RESOLVED", *revoked
		want := *revoked
		done = func(x incident) bool { return x.Status == "RESOLVED" && x.SecretRevoked == want }
		undo = sdk.UndoWith("reopen_incident", map[string]int64{"incident": id}, fmt.Sprintf("Reopen incident %d", id))
	case "ignore_incident":
		if i.Status == "IGNORED" && i.IgnoreReason == reason {
			return sdk.JSON(map[string]any{"incident": id, "status": i.Status, "ignoreReason": reason, "note": "nothing to change"})
		}
		if !open(i.Status) {
			return sdk.Result{}, fmt.Errorf("incident %d is %s; reopen it first", id, strings.ToLower(clip(i.Status, 12)))
		}
		verb, endpoint = "Ignore", "/ignore"
		body = map[string]any{"ignore_reason": reason}
		after["status"], after["ignoreReason"] = "IGNORED", reason
		done = func(x incident) bool { return x.Status == "IGNORED" && x.IgnoreReason == reason }
		undo = sdk.UndoWith("reopen_incident", map[string]int64{"incident": id}, fmt.Sprintf("Reopen incident %d", id))
	case "reopen_incident":
		if open(i.Status) {
			return sdk.JSON(map[string]any{"incident": id, "status": i.Status, "note": "nothing to change"})
		}
		verb, endpoint = "Reopen", "/reopen"
		after["status"] = "TRIGGERED"
		done = func(x incident) bool { return open(x.Status) }
		switch {
		case i.Status == "RESOLVED":
			before["secretRevoked"] = i.SecretRevoked
			undo = sdk.UndoWith("resolve_incident", map[string]any{"incident": id, "revoked": i.SecretRevoked}, fmt.Sprintf("Resolve incident %d again", id))
		case i.Status == "IGNORED" && oneOf(i.IgnoreReason, reasons):
			before["ignoreReason"] = i.IgnoreReason
			undo = sdk.UndoWith("ignore_incident", map[string]any{"incident": id, "reason": i.IgnoreReason}, fmt.Sprintf("Ignore incident %d again (%s)", id, i.IgnoreReason))
		}
	}
	if call.DryRun {
		b, _ := json.Marshal(before)
		a, _ := json.Marshal(after)
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " incident " + strconv.FormatInt(id, 10), Changes: []sdk.Change{{Target: label, Op: strings.ToLower(verb), Before: b, After: a}}}}, nil
	}
	if _, err := c.do(ctx, http.MethodPost, path+endpoint, nil, body, nil); err != nil {
		return sdk.Result{}, err
	}
	now, err := c.get(ctx, id, 0)
	if err != nil {
		return sdk.Result{}, err
	}
	if !done(now) {
		return sdk.Result{}, fmt.Errorf("GitGuardian didn't apply the change to incident %d (now %s)", id, strings.ToLower(clip(now.Status, 12)))
	}
	out := map[string]any{"incident": id, "type": i.kind(), "status": clip(now.Status, 12)}
	if undo == nil {
		out["note"] = "no undo: the incident's earlier ignore reason can't be set back from here"
	}
	res, err := sdk.JSON(out)
	res.Undo = undo
	return res, err
}
