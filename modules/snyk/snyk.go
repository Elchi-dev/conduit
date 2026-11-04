// Package snyk reads security findings from Snyk through its REST API (and,
// for test history, the v1 API) with an API token: organizations, projects
// with their latest issue counts, open issues by severity, and a project's
// recent test results. It never changes anything.
package snyk

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Snyk account.
type Config struct {
	Token        string `json:"token"`        // secret:// API token or service account token
	Region       string `json:"region"`       // us (default), eu or au
	Organization string `json:"organization"` // default organization ID
}

type conn struct {
	api *rest.Client
	org string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces the region's API address, e.g. https://api.snyk.io (tests).
	Base string
}

// New returns the Snyk module.
func New() *Module { return &Module{} }

// version is the REST API version asked for.
const version = "2024-10-15"

const maxPages = 20

var (
	regions  = map[string]string{"us": "https://api.snyk.io", "eu": "https://api.eu.snyk.io", "au": "https://api.au.snyk.io"}
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	severity = []string{"critical", "high", "medium", "low"}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	org := `"org":{"type":"string","description":"Organization ID (the configured one when empty; see orgs)"}`
	project := `"project":{"type":"string","description":"Project ID (see projects)"}`
	return sdk.Manifest{
		ID: "snyk", Name: "Snyk", Version: "0.1.0", Category: "Development", Icon: "shield",
		Description: "Snyk: organizations, projects, open issues by severity and recent test results. Read only.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An API token (Account settings) or a service account token"},
			"region":{"type":"string","enum":["us","eu","au"],"default":"us","description":"Where the Snyk tenant is hosted"},
			"organization":{"type":"string","description":"Default organization ID (Organization settings, General)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "orgs", Title: "Organizations", Description: "Organizations the token can see, with ID, name and slug.", Risk: sdk.RiskRead},
			{Name: "projects", Title: "Projects", Description: "An organization's projects with type, target file, branch, status, when last tested and the issue counts of that test.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + org + `}}`)},
			{Name: "issues", Title: "Issues summary", Description: "Open, unignored issues counted by severity: for one project (also by type, with the most severe titles) or the whole organization (from each project's latest test).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + org + `,` + project + `}}`)},
			{Name: "tests", Title: "Recent test results", Description: "A project's latest test snapshots: when, how it was tested (CLI, recurring, web), dependencies and issues by severity.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + org + `,` + project + `,"limit":{"type":"integer","minimum":1,"maximum":50,"default":10}}}`)},
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
		return errors.New("the region is us, eu or au")
	}
	org := strings.ToLower(strings.TrimSpace(c.Organization))
	if org != "" && !uuidRe.MatchString(org) {
		return errors.New("the organization is its ID, a UUID (Organization settings, General)")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "token "+strings.TrimSpace(t))
		if strings.HasPrefix(r.URL.Path, "/rest/") {
			r.Header.Set("Accept", "application/vnd.api+json")
		}
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, org: org})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Snyk refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Snyk refused: the token can't see this (or the API isn't in your plan)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("no %s (or the token can't see it)", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Snyk's rate limit was hit; try again in a minute")
	}
	return err
}

type resource[T any] struct {
	ID         string `json:"id"`
	Attributes T      `json:"attributes"`
	Meta       struct {
		Counts *struct {
			Critical int     `json:"critical"`
			High     int     `json:"high"`
			Medium   int     `json:"medium"`
			Low      int     `json:"low"`
			Updated  *string `json:"updated_at"`
		} `json:"latest_issue_counts"`
	} `json:"meta"`
}

type page[T any] struct {
	Data  []resource[T] `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

// list pages through a REST collection, following only the cursor of
// links.next (never its address). It reports whether it stopped early.
func list[T any](ctx context.Context, c *conn, path string, q url.Values, what string) ([]resource[T], bool, error) {
	if q == nil {
		q = url.Values{}
	}
	q.Set("version", version)
	q.Set("limit", "100")
	var out []resource[T]
	for i := 0; i < maxPages; i++ {
		var p page[T]
		if _, err := c.api.Do(ctx, http.MethodGet, "/rest"+path, q, nil, &p); err != nil {
			return nil, false, friendly(err, what)
		}
		out = append(out, p.Data...)
		if p.Links.Next == "" {
			return out, false, nil
		}
		u, err := url.Parse(p.Links.Next)
		cur := ""
		if err == nil {
			cur = u.Query().Get("starting_after")
		}
		if cur == "" || cur == q.Get("starting_after") {
			return out, false, nil
		}
		q.Set("starting_after", cur)
	}
	return out, true, nil
}

func (c *conn) orgID(s string) (string, error) {
	o := strings.ToLower(strings.TrimSpace(s))
	if o == "" {
		o = c.org
	}
	if o == "" {
		return "", errors.New("enter the organization ID (see orgs), or set a default organization in the settings")
	}
	if !uuidRe.MatchString(o) {
		return "", errors.New("the organization is its ID, a UUID (see orgs)")
	}
	return o, nil
}

func projectID(s string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(s))
	if !uuidRe.MatchString(p) {
		return "", errors.New("the project is its ID, a UUID (see projects)")
	}
	return p, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var self struct {
		Data struct {
			Type       string `json:"type"`
			Attributes struct {
				Name     string `json:"name"`
				Username string `json:"username"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/rest/self", url.Values{"version": {version}}, nil, &self); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "user").Error()}
	}
	who := self.Data.Attributes.Username
	if who == "" {
		who = self.Data.Attributes.Name
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + who}
}

type projectAttrs struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	TargetFile  string   `json:"target_file"`
	TargetRef   string   `json:"target_reference"`
	Origin      string   `json:"origin"`
	Status      string   `json:"status"`
	Created     string   `json:"created"`
	Criticality []string `json:"business_criticality"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Org     string `json:"org"`
		Project string `json:"project"`
		Limit   int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "orgs":
		type orgAttrs struct {
			Name       string `json:"name"`
			Slug       string `json:"slug"`
			IsPersonal bool   `json:"is_personal"`
			GroupID    string `json:"group_id"`
		}
		os, more, err := list[orgAttrs](ctx, c, "/orgs", nil, "organizations")
		if err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for _, o := range os {
			row := map[string]any{"id": o.ID, "name": o.Attributes.Name, "slug": o.Attributes.Slug, "personal": o.Attributes.IsPersonal}
			if o.ID == c.org {
				row["default"] = true
			}
			rows = append(rows, row)
		}
		return sdk.JSON(map[string]any{"orgs": rows, "truncated": more})

	case "projects", "issues", "tests":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	org, err := c.orgID(p.Org)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "projects":
		ps, more, err := list[projectAttrs](ctx, c, "/orgs/"+org+"/projects", url.Values{"meta.latest_issue_counts": {"true"}}, "organization "+org)
		if err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for _, x := range ps {
			a := x.Attributes
			row := map[string]any{"id": x.ID, "name": a.Name, "type": a.Type, "targetFile": a.TargetFile, "branch": a.TargetRef, "origin": a.Origin, "status": a.Status, "created": a.Created}
			if n := x.Meta.Counts; n != nil {
				row["issues"] = map[string]int{"critical": n.Critical, "high": n.High, "medium": n.Medium, "low": n.Low}
				if n.Updated != nil {
					row["lastTested"] = *n.Updated
				}
			}
			rows = append(rows, row)
		}
		return sdk.JSON(map[string]any{"org": org, "projects": rows, "truncated": more})

	case "issues":
		if strings.TrimSpace(p.Project) == "" {
			ps, more, err := list[projectAttrs](ctx, c, "/orgs/"+org+"/projects", url.Values{"meta.latest_issue_counts": {"true"}}, "organization "+org)
			if err != nil {
				return sdk.Result{}, err
			}
			total := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
			type worst struct {
				name            string
				crit, high, sum int
			}
			var ws []worst
			for _, x := range ps {
				if n := x.Meta.Counts; n != nil {
					total["critical"] += n.Critical
					total["high"] += n.High
					total["medium"] += n.Medium
					total["low"] += n.Low
					if s := n.Critical + n.High + n.Medium + n.Low; s > 0 {
						ws = append(ws, worst{x.Attributes.Name, n.Critical, n.High, s})
					}
				}
			}
			sort.SliceStable(ws, func(i, j int) bool {
				if ws[i].crit != ws[j].crit {
					return ws[i].crit > ws[j].crit
				}
				if ws[i].high != ws[j].high {
					return ws[i].high > ws[j].high
				}
				return ws[i].sum > ws[j].sum
			})
			top := []map[string]any{}
			for i, w := range ws {
				if i == 10 {
					break
				}
				top = append(top, map[string]any{"project": w.name, "critical": w.crit, "high": w.high, "total": w.sum})
			}
			return sdk.JSON(map[string]any{"org": org, "projects": len(ps), "bySeverity": total, "mostAffected": top, "truncated": more,
				"note": "counts from each project's latest test"})
		}
		pid, err := projectID(p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		type issueAttrs struct {
			Title    string `json:"title"`
			Type     string `json:"type"`
			Severity string `json:"effective_severity_level"`
		}
		is, more, err := list[issueAttrs](ctx, c, "/orgs/"+org+"/issues", url.Values{"scan_item.id": {pid}, "scan_item.type": {"project"}, "status": {"open"}, "ignored": {"false"}}, "project "+pid)
		if err != nil {
			return sdk.Result{}, err
		}
		bySev := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
		byType := map[string]int{}
		titles := map[string]map[string]int{}
		for _, x := range is {
			a := x.Attributes
			bySev[a.Severity]++
			byType[a.Type]++
			if a.Severity == "critical" || a.Severity == "high" {
				if titles[a.Severity] == nil {
					titles[a.Severity] = map[string]int{}
				}
				titles[a.Severity][a.Title]++
			}
		}
		top := []map[string]any{}
		for _, sev := range severity[:2] {
			var ts []string
			for t := range titles[sev] {
				ts = append(ts, t)
			}
			sort.Slice(ts, func(i, j int) bool {
				if titles[sev][ts[i]] != titles[sev][ts[j]] {
					return titles[sev][ts[i]] > titles[sev][ts[j]]
				}
				return ts[i] < ts[j]
			})
			for _, t := range ts {
				if len(top) == 10 {
					break
				}
				top = append(top, map[string]any{"severity": sev, "title": t, "count": titles[sev][t]})
			}
		}
		return sdk.JSON(map[string]any{"org": org, "project": pid, "open": len(is), "bySeverity": bySev, "byType": byType, "top": top, "truncated": more})

	case "tests":
		pid, err := projectID(p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		limit := p.Limit
		if limit == 0 {
			limit = 10
		}
		if limit < 1 || limit > 50 {
			return sdk.Result{}, errors.New("limit is between 1 and 50")
		}
		type counts struct {
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
		}
		var h struct {
			Snapshots []struct {
				ID          string `json:"id"`
				Created     string `json:"created"`
				Method      string `json:"method"`
				Deps        int    `json:"totalDependencies"`
				ImageTag    string `json:"imageTag"`
				IssueCounts struct {
					Vuln    counts `json:"vuln"`
					License counts `json:"license"`
				} `json:"issueCounts"`
			} `json:"snapshots"`
			Total int `json:"total"`
		}
		q := url.Values{"perPage": {strconv.Itoa(limit)}, "page": {"1"}}
		if _, err := c.api.Do(ctx, http.MethodPost, "/v1/org/"+org+"/project/"+pid+"/history", q, map[string]any{}, &h); err != nil {
			return sdk.Result{}, friendly(err, "project "+pid)
		}
		if len(h.Snapshots) > limit {
			h.Snapshots = h.Snapshots[:limit]
		}
		rows := []map[string]any{}
		for _, s := range h.Snapshots {
			row := map[string]any{"tested": s.Created, "method": s.Method, "dependencies": s.Deps,
				"vulnerabilities": s.IssueCounts.Vuln, "licenseIssues": s.IssueCounts.License}
			if s.ImageTag != "" {
				row["imageTag"] = s.ImageTag
			}
			rows = append(rows, row)
		}
		return sdk.JSON(map[string]any{"org": org, "project": pid, "total": h.Total, "tests": rows})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
