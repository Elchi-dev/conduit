// Package sonarqube reads code quality from a SonarQube server or
// SonarCloud through its web API with a token: projects, the quality gate of
// a project or branch, open issues by severity and type, recent analyses and
// security hotspots to review. It never changes anything.
package sonarqube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// Config is one SonarQube server or SonarCloud organization.
type Config struct {
	Address            string `json:"address"`      // e.g. https://sonar.example.com or https://sonarcloud.io
	Token              string `json:"token"`        // secret:// user or project analysis token
	Organization       string `json:"organization"` // SonarCloud only
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api   *rest.Client
	org   string
	cloud bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the SonarQube module.
func New() *Module { return &Module{} }

var (
	keyRe    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,400}$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9_./+@-]{1,255}$`)
	prRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	orgRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,254}$`)
	searchRe = regexp.MustCompile(`^[A-Za-z0-9 _.:-]{2,100}$`)
	prefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	target := `"project":{"type":"string","description":"Project key"},"branch":{"type":"string","description":"Branch (the main branch when empty)"},"pullRequest":{"type":"string","description":"Pull request ID, instead of a branch"}`
	return sdk.Manifest{
		ID: "sonarqube", Name: "SonarQube", Version: "0.1.0", Category: "Development", Icon: "check",
		Description: "SonarQube or SonarCloud: projects, quality gate status per branch, open issues by severity, recent analyses, security hotspots to review. Read only.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["address","token"],"properties":{
			"address":{"type":"string","description":"The server, e.g. https://sonar.example.com, or https://sonarcloud.io"},
			"token":{"type":"string","x-secret":true,"description":"A user token (My Account, Security) with Browse on the projects"},
			"organization":{"type":"string","description":"Organization key (SonarCloud only)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Projects with key, name and, where the token may see it, the last analysis date.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Name or key containing this (2 characters or more)"}}}`)},
			{Name: "quality_gate", Title: "Quality gate", Description: "Whether a project (branch or pull request) passes its quality gate, with each condition's metric, threshold and actual value.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + target + `}}`)},
			{Name: "issues", Title: "Issues summary", Description: "Open issues of a project counted by severity and by type (bug, vulnerability, code smell).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + target + `}}`)},
			{Name: "analyses", Title: "Recent analyses", Description: "A project's latest analyses with date, version, revision and events (quality gate changes, new versions).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{"project":{"type":"string"},"branch":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":50,"default":10}}}`)},
			{Name: "hotspots", Title: "Security hotspots", Description: "Security hotspots to review, counted by vulnerability probability, and how many are reviewed.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + target + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.Address))
	prefix := ""
	if err == nil {
		prefix = strings.TrimRight(u.Path, "/")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return errors.New("the address is like https://sonar.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the token in the vault and enter its secret:// reference")
	}
	cloud := strings.EqualFold(u.Hostname(), "sonarcloud.io") || strings.HasSuffix(strings.ToLower(u.Hostname()), ".sonarcloud.io")
	org := strings.TrimSpace(c.Organization)
	if org != "" && !orgRe.MatchString(org) {
		return errors.New("the organization is its key, like my-org")
	}
	if cloud && org == "" {
		return errors.New("SonarCloud needs the organization key")
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
	ref := c.Token
	api := rest.New(u.Scheme+"://"+u.Host+prefix, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		// Token as the user name with no password works on every version.
		r.SetBasicAuth(strings.TrimSpace(t), "")
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, org: org, cloud: cloud})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("SonarQube refused the token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("SonarQube refused: the token lacks Browse permission on this")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	}
	return err
}

func (c *conn) do(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return err
}

func (c *conn) q() url.Values {
	q := url.Values{}
	if c.org != "" {
		q.Set("organization", c.org)
	}
	return q
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Valid bool `json:"valid"`
	}
	if err := c.do(ctx, "/api/authentication/validate", nil, &v); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "API here").Error()}
	}
	if !v.Valid {
		return sdk.Health{Status: "down", Message: "SonarQube refused the token"}
	}
	if c.cloud {
		return sdk.Health{Status: "ok", Message: "SonarCloud · " + c.org}
	}
	var st struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := c.do(ctx, "/api/system/status", nil, &st); err != nil {
		return sdk.Health{Status: "ok", Message: "token valid"}
	}
	if st.Status != "UP" {
		return sdk.Health{Status: "degraded", Message: "server status " + st.Status}
	}
	return sdk.Health{Status: "ok", Message: "up · " + st.Version}
}

type input struct {
	Search      string `json:"search"`
	Project     string `json:"project"`
	Branch      string `json:"branch"`
	PullRequest string `json:"pullRequest"`
	Limit       int    `json:"limit"`
}

// target checks the project, branch and pull request and adds them to q
// under the project parameter's name.
func target(p input, q url.Values, projectParam string) (string, error) {
	key := strings.TrimSpace(p.Project)
	if !keyRe.MatchString(key) {
		return "", errors.New("the project is its key (see projects)")
	}
	q.Set(projectParam, key)
	b, pr := strings.TrimSpace(p.Branch), strings.TrimSpace(p.PullRequest)
	switch {
	case b != "" && pr != "":
		return "", errors.New("give a branch or a pull request, not both")
	case b != "":
		if !branchRe.MatchString(b) || strings.Contains(b, "..") {
			return "", errors.New("the branch is its name, like main")
		}
		q.Set("branch", b)
	case pr != "":
		if !prRe.MatchString(pr) {
			return "", errors.New("the pull request is its ID, like 42")
		}
		q.Set("pullRequest", pr)
	}
	return key, nil
}

type facet struct {
	Property string `json:"property"`
	Values   []struct {
		Val   string `json:"val"`
		Count int    `json:"count"`
	} `json:"values"`
}

type paging struct {
	Total int `json:"total"`
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
	case "projects":
		q := c.q()
		q.Set("ps", "100")
		if s := strings.TrimSpace(p.Search); s != "" {
			if !searchRe.MatchString(s) {
				return sdk.Result{}, errors.New("the search is 2 to 100 letters, digits or _ . : -")
			}
			q.Set("q", s)
		}
		var ps struct {
			Paging     paging `json:"paging"`
			Components []struct {
				Key          string `json:"key"`
				Name         string `json:"name"`
				Visibility   string `json:"visibility"`
				LastAnalysis string `json:"lastAnalysisDate"`
			} `json:"components"`
		}
		// projects/search has the last analysis but needs Administer; components/search
		// works with Browse.
		err := c.do(ctx, "/api/projects/search", q, &ps)
		if rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusNotFound) {
			q.Set("qualifiers", "TRK")
			err = c.do(ctx, "/api/components/search", q, &ps)
		}
		if err != nil {
			return sdk.Result{}, friendly(err, "project")
		}
		list := []map[string]any{}
		for _, pr := range ps.Components {
			e := map[string]any{"key": pr.Key, "name": pr.Name}
			if pr.Visibility != "" {
				e["visibility"] = pr.Visibility
			}
			if pr.LastAnalysis != "" {
				e["lastAnalysis"] = pr.LastAnalysis
			}
			list = append(list, e)
		}
		return sdk.JSON(map[string]any{"total": ps.Paging.Total, "projects": list})

	case "quality_gate":
		q := url.Values{}
		key, err := target(p, q, "projectKey")
		if err != nil {
			return sdk.Result{}, err
		}
		var st struct {
			ProjectStatus struct {
				Status     string `json:"status"`
				Conditions []struct {
					Status     string `json:"status"`
					Metric     string `json:"metricKey"`
					Comparator string `json:"comparator"`
					Threshold  string `json:"errorThreshold"`
					Actual     string `json:"actualValue"`
				} `json:"conditions"`
				CaycStatus string `json:"caycStatus"`
			} `json:"projectStatus"`
		}
		if err := c.do(ctx, "/api/qualitygates/project_status", q, &st); err != nil {
			return sdk.Result{}, friendly(err, "project "+key+" (or branch)")
		}
		conds := []map[string]any{}
		failing := []string{}
		for _, cd := range st.ProjectStatus.Conditions {
			conds = append(conds, map[string]any{"metric": cd.Metric, "status": cd.Status, "comparator": cd.Comparator, "threshold": cd.Threshold, "actual": cd.Actual})
			if cd.Status == "ERROR" {
				failing = append(failing, cd.Metric)
			}
		}
		out := map[string]any{"project": key, "status": st.ProjectStatus.Status, "passed": st.ProjectStatus.Status == "OK", "conditions": conds, "failing": failing}
		for _, k := range []string{"branch", "pullRequest"} {
			if v := q.Get(k); v != "" {
				out[k] = v
			}
		}
		if st.ProjectStatus.Status == "NONE" {
			out["note"] = "no quality gate result yet (not analyzed, or no gate)"
		}
		return sdk.JSON(out)

	case "issues":
		q := c.q()
		key, err := target(p, q, "componentKeys")
		if err != nil {
			return sdk.Result{}, err
		}
		q.Set("resolved", "false")
		q.Set("ps", "1")
		q.Set("facets", "severities,types")
		var is struct {
			Total  int     `json:"total"`
			Paging *paging `json:"paging"`
			Facets []facet `json:"facets"`
		}
		if err := c.do(ctx, "/api/issues/search", q, &is); err != nil {
			return sdk.Result{}, friendly(err, "project "+key)
		}
		total := is.Total
		if is.Paging != nil && is.Paging.Total > total {
			total = is.Paging.Total
		}
		out := map[string]any{"project": key, "open": total}
		for _, f := range is.Facets {
			counts := map[string]int{}
			for _, v := range f.Values {
				counts[strings.ToLower(v.Val)] = v.Count
			}
			switch f.Property {
			case "severities":
				out["bySeverity"] = counts
			case "types":
				out["byType"] = counts
			}
		}
		return sdk.JSON(out)

	case "analyses":
		if p.PullRequest != "" {
			return sdk.Result{}, errors.New("analyses are per branch")
		}
		limit := p.Limit
		if limit == 0 {
			limit = 10
		}
		if limit < 1 || limit > 50 {
			return sdk.Result{}, errors.New("the limit is between 1 and 50")
		}
		q := c.q()
		key, err := target(p, q, "project")
		if err != nil {
			return sdk.Result{}, err
		}
		q.Set("ps", fmt.Sprint(limit))
		var as struct {
			Analyses []struct {
				Key      string `json:"key"`
				Date     string `json:"date"`
				Version  string `json:"projectVersion"`
				Revision string `json:"revision"`
				Events   []struct {
					Category string `json:"category"`
					Name     string `json:"name"`
				} `json:"events"`
			} `json:"analyses"`
		}
		if err := c.do(ctx, "/api/project_analyses/search", q, &as); err != nil {
			return sdk.Result{}, friendly(err, "project "+key)
		}
		list := []map[string]any{}
		for _, a := range as.Analyses {
			var ev []string
			for _, e := range a.Events {
				ev = append(ev, strings.ToLower(e.Category)+": "+e.Name)
			}
			list = append(list, map[string]any{"date": a.Date, "version": a.Version, "revision": a.Revision, "events": ev})
		}
		return sdk.JSON(map[string]any{"project": key, "analyses": list})

	case "hotspots":
		q := url.Values{}
		key, err := target(p, q, "projectKey")
		if err != nil {
			return sdk.Result{}, err
		}
		q.Set("status", "TO_REVIEW")
		q.Set("ps", "500")
		var hs struct {
			Paging   paging `json:"paging"`
			Hotspots []struct {
				Probability string `json:"vulnerabilityProbability"`
			} `json:"hotspots"`
		}
		if err := c.do(ctx, "/api/hotspots/search", q, &hs); err != nil {
			return sdk.Result{}, friendly(err, "project "+key)
		}
		by := map[string]int{}
		for _, h := range hs.Hotspots {
			by[strings.ToLower(h.Probability)]++
		}
		out := map[string]any{"project": key, "toReview": hs.Paging.Total, "byProbability": by}
		if hs.Paging.Total > len(hs.Hotspots) {
			out["note"] = fmt.Sprintf("probabilities counted over the first %d", len(hs.Hotspots))
		}
		q.Set("status", "REVIEWED")
		q.Set("ps", "1")
		var rv struct {
			Paging paging `json:"paging"`
		}
		if c.do(ctx, "/api/hotspots/search", q, &rv) == nil {
			out["reviewed"] = rv.Paging.Total
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
