// Package defectdojo works with DefectDojo through its API v2 and an API
// token: products, engagements, open findings by severity, and closing,
// verifying, risk-accepting and reopening findings.
package defectdojo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
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

// Config is one DefectDojo.
type Config struct {
	URL                string `json:"url"`   // e.g. https://defectdojo.example.com
	Token              string `json:"token"` // secret:// API v2 key
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

// New returns the DefectDojo module.
func New() *Module { return &Module{} }

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// severities in DefectDojo's order and spelling.
var severities = []string{"Critical", "High", "Medium", "Low", "Info"}

const (
	maxPages = 10
	maxID    = 1 << 31
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	finding := `"finding":{"type":"integer","description":"Finding id (from findings)"}`
	return sdk.Manifest{
		ID: "defectdojo", Name: "DefectDojo", Version: "0.1.0", Category: "Security", Icon: "check",
		Description: "DefectDojo: products, engagements and open findings by severity; close, verify, risk-accept or reopen a finding.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"DefectDojo's address, e.g. https://defectdojo.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API v2 key (your user menu, API v2 Key); it acts with that user's permissions"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "products", Title: "Products", Description: "Products with id, name, type, criticality, lifecycle and how many findings each has.", Risk: sdk.RiskRead},
			{Name: "engagements", Title: "Engagements", Description: "Engagements with id, name, product, type, status and dates; for one product when given.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"product":{"type":"integer","description":"Product id (from products)"}}}`)},
			{Name: "findings", Title: "Open findings", Description: "Open findings (active, not mitigated, duplicate, false positive or risk-accepted) counted by severity, and the most severe with title, CVE, component, file and whether verified.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"product":{"type":"integer"},"engagement":{"type":"integer"},"severity":{"type":"string","enum":["Critical","High","Medium","Low","Info"]},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}}}`)},
			{Name: "close_finding", Title: "Close a finding", Description: "Marks a finding mitigated and inactive, which takes it out of open findings and metrics. Undo reopens it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["finding"],"properties":{` + finding + `,"note":{"type":"string","description":"Why it's closed, kept as a note on the finding"}}}`)},
			{Name: "verify_finding", Title: "Verify a finding", Description: "Marks a finding verified (or, with verified false, unverified), which changes how it's triaged and reported. Undo sets it back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["finding"],"properties":{` + finding + `,"verified":{"type":"boolean","default":true}}}`)},
			{Name: "risk_accept_finding", Title: "Risk-accept a finding", Description: "Accepts a finding's risk (simple risk acceptance, which must be on for the product), which takes it out of open findings. Undo reopens it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["finding"],"properties":{` + finding + `}}`)},
			{Name: "reopen_finding", Title: "Reopen a finding", Description: "Makes a closed or risk-accepted finding active and open again. Undo closes or risk-accepts it as it was.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["finding"],"properties":{` + finding + `}}`)},
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
		return errors.New("the address is like https://defectdojo.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
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
	ref := c.Token
	base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v2"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api/v2", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Token "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("DefectDojo refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API key's user isn't allowed to do this in DefectDojo")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

type page[T any] struct {
	Count   int    `json:"count"`
	Next    string `json:"next"`
	Results []T    `json:"results"`
}

// list pages through a collection by offset (never following the answer's
// next address). It reports whether it stopped early.
func list[T any](ctx context.Context, c *conn, path string, q url.Values) ([]T, int, bool, error) {
	var out []T
	for i := 0; i < maxPages; i++ {
		q.Set("limit", "100")
		q.Set("offset", strconv.Itoa(i*100))
		var p page[T]
		if err := c.do(ctx, http.MethodGet, path, q, nil, &p); err != nil {
			return nil, 0, false, err
		}
		out = append(out, p.Results...)
		if p.Next == "" || len(p.Results) == 0 || len(out) >= p.Count {
			return out, p.Count, false, nil
		}
	}
	return out, len(out), true, nil
}

// clean makes text from DefectDojo safe to show: credentials masked first,
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

func checkID(n int64, what string, required bool) error {
	if n == 0 && !required {
		return nil
	}
	if n < 1 || n > maxID {
		return fmt.Errorf("the %s is its id, a positive number (from %ss)", what, what)
	}
	return nil
}

// open is the filter for findings still needing attention.
func open(product, engagement int64) url.Values {
	q := url.Values{"active": {"true"}, "is_mitigated": {"false"}, "duplicate": {"false"}, "false_p": {"false"}, "out_of_scope": {"false"}, "risk_accepted": {"false"}}
	if product > 0 {
		q.Set("test__engagement__product", strconv.FormatInt(product, 10))
	}
	if engagement > 0 {
		q.Set("test__engagement", strconv.FormatInt(engagement, 10))
	}
	return q
}

func (c *conn) count(ctx context.Context, path string, q url.Values) (int, error) {
	q.Set("limit", "1")
	var p page[json.RawMessage]
	if err := c.do(ctx, http.MethodGet, path, q, nil, &p); err != nil {
		return 0, err
	}
	return p.Count, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	products, err := c.count(ctx, "/products/", url.Values{})
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no DefectDojo API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	findings, err := c.count(ctx, "/findings/", open(0, 0))
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d products, %d open findings", products, findings)}
}

type finding struct {
	ID              int64   `json:"id"`
	Title           string  `json:"title"`
	Severity        string  `json:"severity"`
	Active          bool    `json:"active"`
	Verified        bool    `json:"verified"`
	IsMitigated     bool    `json:"is_mitigated"`
	RiskAccepted    bool    `json:"risk_accepted"`
	FalsePositive   bool    `json:"false_p"`
	Duplicate       bool    `json:"duplicate"`
	OutOfScope      bool    `json:"out_of_scope"`
	Date            string  `json:"date"`
	CWE             int     `json:"cwe"`
	Component       string  `json:"component_name"`
	ComponentVer    string  `json:"component_version"`
	FilePath        string  `json:"file_path"`
	Line            int     `json:"line"`
	Test            int64   `json:"test"`
	CVSS            float64 `json:"cvssv3_score"`
	VulnerabilityID []struct {
		ID string `json:"vulnerability_id"`
	} `json:"vulnerability_ids"`
	// Description, mitigation, steps to reproduce and request/response
	// pairs aren't decoded: they hold scanner payloads.
}

func (f finding) row() map[string]any {
	ids := []string{}
	for i, v := range f.VulnerabilityID {
		if i == 10 {
			break
		}
		ids = append(ids, clip(v.ID, 40))
	}
	r := map[string]any{"id": f.ID, "title": clean(f.Title, 200), "severity": clip(f.Severity, 10), "verified": f.Verified, "date": clip(f.Date, 20), "test": f.Test}
	if len(ids) > 0 {
		r["vulnerabilityIds"] = ids
	}
	if f.CWE > 0 {
		r["cwe"] = f.CWE
	}
	if f.CVSS > 0 {
		r["cvss"] = f.CVSS
	}
	if f.Component != "" {
		r["component"] = clip(f.Component, 200)
		r["componentVersion"] = clip(f.ComponentVer, 60)
	}
	if f.FilePath != "" {
		r["file"] = clean(f.FilePath, 300)
		if f.Line > 0 {
			r["line"] = f.Line
		}
	}
	return r
}

func (f finding) state() map[string]bool {
	return map[string]bool{"active": f.Active, "verified": f.Verified, "mitigated": f.IsMitigated, "riskAccepted": f.RiskAccepted,
		"falsePositive": f.FalsePositive, "duplicate": f.Duplicate, "outOfScope": f.OutOfScope}
}

// isOpen is the state reopen_finding sets: active, neither mitigated nor
// risk-accepted. Only from there is reopening an exact undo.
func (f finding) isOpen() bool { return f.Active && !f.IsMitigated && !f.RiskAccepted }

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Product    int64  `json:"product"`
		Engagement int64  `json:"engagement"`
		Severity   string `json:"severity"`
		Limit      int    `json:"limit"`
		Finding    int64  `json:"finding"`
		Note       string `json:"note"`
		Verified   *bool  `json:"verified"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if err := checkID(p.Product, "product", false); err != nil {
		return sdk.Result{}, err
	}
	if err := checkID(p.Engagement, "engagement", false); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "products":
		type product struct {
			ID          int64  `json:"id"`
			Name        string `json:"name"`
			Type        int64  `json:"prod_type"`
			Criticality string `json:"business_criticality"`
			Lifecycle   string `json:"lifecycle"`
			Findings    int    `json:"findings_count"`
			Created     string `json:"created"`
		}
		ps, total, more, err := list[product](ctx, c, "/products/", url.Values{"o": {"name"}})
		if err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for _, x := range ps {
			rows = append(rows, map[string]any{"id": x.ID, "name": clip(x.Name, 200), "type": x.Type, "criticality": clip(x.Criticality, 20), "lifecycle": clip(x.Lifecycle, 20),
				"findings": x.Findings, "created": clip(x.Created, 40)})
		}
		return sdk.JSON(map[string]any{"total": total, "products": rows, "truncated": more})
	case "engagements":
		type engagement struct {
			ID      int64  `json:"id"`
			Name    string `json:"name"`
			Product int64  `json:"product"`
			Type    string `json:"engagement_type"`
			Status  string `json:"status"`
			Start   string `json:"target_start"`
			End     string `json:"target_end"`
			Active  bool   `json:"active"`
		}
		q := url.Values{"o": {"-target_start"}}
		if p.Product > 0 {
			q.Set("product", strconv.FormatInt(p.Product, 10))
		}
		es, total, more, err := list[engagement](ctx, c, "/engagements/", q)
		if err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for _, x := range es {
			rows = append(rows, map[string]any{"id": x.ID, "name": clip(x.Name, 200), "product": x.Product, "type": clip(x.Type, 20), "status": clip(x.Status, 30),
				"start": clip(x.Start, 20), "end": clip(x.End, 20), "active": x.Active})
		}
		return sdk.JSON(map[string]any{"total": total, "engagements": rows, "truncated": more})
	case "findings":
		return c.findings(ctx, p.Product, p.Engagement, p.Severity, p.Limit)
	case "close_finding", "verify_finding", "risk_accept_finding", "reopen_finding":
		if err := checkID(p.Finding, "finding", true); err != nil {
			return sdk.Result{}, err
		}
		verified := true
		if p.Verified != nil {
			verified = *p.Verified
		}
		return c.change(ctx, call, p.Finding, verified, clip(p.Note, 2000))
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) findings(ctx context.Context, product, engagement int64, severity string, limit int) (sdk.Result, error) {
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 200 {
		return sdk.Result{}, errors.New("limit is between 1 and 200")
	}
	if severity != "" {
		ok := false
		for _, s := range severities {
			if s == severity {
				ok = true
			}
		}
		if !ok {
			return sdk.Result{}, errors.New("severity is Critical, High, Medium, Low or Info")
		}
	}
	by := map[string]int{}
	total := 0
	for _, s := range severities {
		q := open(product, engagement)
		q.Set("severity", s)
		n, err := c.count(ctx, "/findings/", q)
		if err != nil {
			return sdk.Result{}, err
		}
		by[s] = n
		total += n
	}
	q := open(product, engagement)
	if severity != "" {
		q.Set("severity", severity)
	}
	// numerical_severity is S0 for critical to S4 for info.
	q.Set("o", "numerical_severity,-date")
	q.Set("limit", strconv.Itoa(limit))
	var pg page[finding]
	if err := c.do(ctx, http.MethodGet, "/findings/", q, nil, &pg); err != nil {
		return sdk.Result{}, err
	}
	rows := []map[string]any{}
	for i, f := range pg.Results {
		if i == limit {
			break
		}
		rows = append(rows, f.row())
	}
	out := map[string]any{"open": total, "bySeverity": by, "findings": rows, "truncated": pg.Count > len(rows)}
	if product > 0 {
		out["product"] = product
	}
	if engagement > 0 {
		out["engagement"] = engagement
	}
	return sdk.JSON(out)
}

func (c *conn) get(ctx context.Context, id int64) (finding, error) {
	var f finding
	if err := c.do(ctx, http.MethodGet, "/findings/"+strconv.FormatInt(id, 10)+"/", nil, nil, &f); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return finding{}, fmt.Errorf("there's no finding %d", id)
		}
		return finding{}, err
	}
	if f.ID != id {
		return finding{}, fmt.Errorf("there's no finding %d", id)
	}
	return f, nil
}

func (c *conn) change(ctx context.Context, call sdk.Call, id int64, verified bool, note string) (sdk.Result, error) {
	f, err := c.get(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	path := "/findings/" + strconv.FormatInt(id, 10) + "/"
	var (
		done   func(finding) bool
		verb   string
		send   func() error
		undo   *sdk.Undo
		after  = f.state()
		closed = !f.Active && (f.IsMitigated || f.RiskAccepted)
	)
	switch call.Action {
	case "close_finding":
		verb = "Close"
		done = func(x finding) bool { return !x.Active && x.IsMitigated }
		after["active"], after["mitigated"] = false, true
		send = func() error {
			// DefectDojo's close sets false_p, out_of_scope and duplicate
			// to what's sent, false when left out: send them as they are.
			body := map[string]any{"is_mitigated": true, "mitigated": time.Now().UTC().Format(time.RFC3339), "false_p": f.FalsePositive, "out_of_scope": f.OutOfScope, "duplicate": f.Duplicate}
			if note != "" {
				body["note"] = note
			}
			return c.do(ctx, http.MethodPost, path+"close/", nil, body, nil)
		}
		if f.isOpen() {
			undo = sdk.UndoWith("reopen_finding", map[string]int64{"finding": id}, fmt.Sprintf("Reopen finding %d", id))
		}
	case "verify_finding":
		verb = "Verify"
		if !verified {
			verb = "Unverify"
		}
		done = func(x finding) bool { return x.Verified == verified }
		after["verified"] = verified
		send = func() error { return c.do(ctx, http.MethodPatch, path, nil, map[string]any{"verified": verified}, nil) }
		undo = sdk.UndoWith("verify_finding", map[string]any{"finding": id, "verified": f.Verified}, fmt.Sprintf("Set finding %d back to %s", id, map[bool]string{true: "verified", false: "unverified"}[f.Verified]))
	case "risk_accept_finding":
		verb = "Risk-accept"
		done = func(x finding) bool { return x.RiskAccepted }
		after["riskAccepted"], after["active"] = true, false
		send = func() error {
			err := c.do(ctx, http.MethodPatch, path, nil, map[string]any{"risk_accepted": true}, nil)
			if rest.IsStatus(err, http.StatusBadRequest) {
				return errors.New("DefectDojo refused: turn on simple risk acceptance for the finding's product (Edit product), or accept it in the web interface")
			}
			return err
		}
		if f.isOpen() {
			undo = sdk.UndoWith("reopen_finding", map[string]int64{"finding": id}, fmt.Sprintf("Reopen finding %d", id))
		}
	case "reopen_finding":
		verb = "Reopen"
		done = func(x finding) bool { return x.Active && !x.IsMitigated && !x.RiskAccepted }
		after["active"], after["mitigated"], after["riskAccepted"] = true, false, false
		send = func() error {
			return c.do(ctx, http.MethodPatch, path, nil, map[string]any{"active": true, "is_mitigated": false, "mitigated": nil, "risk_accepted": false}, nil)
		}
		switch {
		case f.isOpen():
		case !closed:
			// Inactive without being closed or accepted (a false
			// positive, a duplicate, or set inactive by hand): reopening
			// would have no undo, and isn't what this action is for.
			return sdk.Result{}, fmt.Errorf("finding %d is inactive but neither closed nor risk-accepted; change it in DefectDojo", id)
		case f.RiskAccepted && f.IsMitigated:
			// Undo can't set both back.
		case f.RiskAccepted:
			undo = sdk.UndoWith("risk_accept_finding", map[string]int64{"finding": id}, fmt.Sprintf("Risk-accept finding %d again", id))
		default:
			undo = sdk.UndoWith("close_finding", map[string]int64{"finding": id}, fmt.Sprintf("Close finding %d again", id))
		}
	}
	label := fmt.Sprintf("finding %d (%s: %s)", id, clip(f.Severity, 10), clean(f.Title, 120))
	if done(f) {
		return sdk.JSON(map[string]any{"finding": id, "state": f.state(), "note": "nothing to change"})
	}
	if call.DryRun {
		b, _ := json.Marshal(f.state())
		a, _ := json.Marshal(after)
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " finding " + strconv.FormatInt(id, 10), Changes: []sdk.Change{{Target: label, Op: strings.ToLower(verb), Before: b, After: a}}}}, nil
	}
	if err := send(); err != nil {
		return sdk.Result{}, err
	}
	now, err := c.get(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	if !done(now) {
		return sdk.Result{}, fmt.Errorf("DefectDojo kept finding %d as it was", id)
	}
	out := map[string]any{"finding": id, "title": clean(f.Title, 200), "state": now.state()}
	if undo == nil {
		out["note"] = "no undo: the finding's earlier state can't be set back exactly from here"
	}
	res, err := sdk.JSON(out)
	res.Undo = undo
	return res, err
}
