// Package railway works with Railway projects through its public GraphQL
// API: projects, environments, services and deployments with their status,
// a bounded tail of a deployment's logs, redeploying and restarting.
//
// Every query is a constant; ids are checked and sent only as GraphQL
// variables.
package railway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Railway token.
type Config struct {
	Token     string `json:"token"`     // secret:// account, workspace or project token
	TokenType string `json:"tokenType"` // account (default), team or project
}

type conn struct {
	api  *rest.Client
	kind string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://backboard.railway.com/graphql/v2 (tests).
	Base string
}

// New returns the Railway module.
func New() *Module { return &Module{} }

const defaultBase = "https://backboard.railway.com/graphql/v2"

var idRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func checkID(what, s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !idRe.MatchString(s) {
		return "", fmt.Errorf("the %s is its id (a UUID), see %ss", what, what)
	}
	return s, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	project := `"project":{"type":"string","description":"Project id (see projects)"}`
	service := `"service":{"type":"string","description":"Service id (see services)"}`
	env := `"environment":{"type":"string","description":"Environment id (see environments)"}`
	deployment := `"deployment":{"type":"string","description":"Deployment id (see deployments)"}`
	return sdk.Manifest{
		ID: "railway", Name: "Railway", Version: "0.1.0", Category: "Development", Icon: "train",
		Description: "Railway projects: services, environments, deployments and their logs; redeploy and restart.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"Account or workspace token (Account settings, Tokens), or a project token (Project settings, Tokens)"},
			"tokenType":{"type":"string","enum":["account","team","project"],"default":"account","description":"What kind of token it is; a project token sees one project and environment"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Projects with their environments and services.", Risk: sdk.RiskRead},
			{Name: "environments", Title: "Environments", Description: "A project's environments.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + project + `}}`)},
			{Name: "services", Title: "Services", Description: "A project's services with the latest deployment's status in each environment.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + project + `}}`)},
			{Name: "deployments", Title: "Deployments", Description: "Recent deployments of a service: status, commit, branch, address.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project","service"],"properties":{` + project + `,` + service + `,` + env + `,"limit":{"type":"integer","default":10,"maximum":50}}}`)},
			{Name: "logs", Title: "Deployment logs", Description: "The last lines of a deployment's runtime (or build) logs. Logs can hold secrets and personal data.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["deployment"],"properties":{` + deployment + `,"lines":{"type":"integer","default":100,"maximum":500},"build":{"type":"boolean","description":"Build logs instead of runtime logs"}}}`)},
			{Name: "redeploy", Title: "Redeploy", Description: "Builds and deploys a deployment again (the latest of a service in an environment when no deployment is given). Destructive: an older deployment ships its older code to the environment.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + deployment + `,` + project + `,` + service + `,` + env + `}}`)},
			{Name: "restart", Title: "Restart", Description: "Restarts a running deployment's containers without rebuilding; it drops connections while it comes back.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["deployment"],"properties":{` + deployment + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the token in the vault and enter its secret:// reference")
	}
	kind := c.TokenType
	switch kind {
	case "":
		kind = "account"
	case "account", "team", "project":
	default:
		return errors.New("tokenType is account, team or project")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	tok := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if t == "" || strings.ContainsAny(t, " \t\r\n") {
			return errors.New("the stored token isn't valid")
		}
		if kind == "project" {
			r.Header.Set("Project-Access-Token", t)
		} else {
			r.Header.Set("Authorization", "Bearer "+t)
		}
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api, kind: kind})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// gqlError is an error the GraphQL API answered with.
type gqlError struct{ msg string }

func (e *gqlError) Error() string { return "Railway: " + e.msg }

func unauthorized(err error) bool {
	if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
		return true
	}
	var g *gqlError
	return errors.As(err, &g) && strings.Contains(strings.ToLower(g.msg), "not authorized")
}

// gql runs one query with variables and decodes data into out.
func (c *conn) gql(ctx context.Context, query string, vars map[string]any, out any) error {
	var res struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	body := map[string]any{"query": query}
	if len(vars) > 0 {
		body["variables"] = vars
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "", nil, body, &res); err != nil {
		return err
	}
	if len(res.Errors) > 0 {
		return &gqlError{msg: res.Errors[0].Message}
	}
	if out != nil {
		if err := json.Unmarshal(res.Data, out); err != nil {
			return errors.New("unexpected answer from Railway")
		}
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var msg string
	switch c.kind {
	case "account":
		var d struct {
			Me struct {
				Name string `json:"name"`
			} `json:"me"`
		}
		err = c.gql(ctx, qMe, nil, &d)
		msg = "signed in as " + d.Me.Name
	case "team":
		var d projectsData
		err = c.gql(ctx, qProjects, nil, &d)
		msg = fmt.Sprintf("%d projects", len(d.Projects.Edges))
	default:
		var d struct {
			ProjectToken struct {
				ProjectID string `json:"projectId"`
			} `json:"projectToken"`
		}
		err = c.gql(ctx, qProjectToken, nil, &d)
		msg = "project " + d.ProjectToken.ProjectID
	}
	if err != nil {
		if unauthorized(err) {
			return sdk.Health{Status: "down", Message: "Railway refused the token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

const (
	qMe           = `query { me { name } }`
	qProjectToken = `query { projectToken { projectId environmentId } }`
	projectFields = `id name description updatedAt environments { edges { node { id name } } } services { edges { node { id name } } }`
	qProjects     = `query { projects(first: 100) { edges { node { ` + projectFields + ` } } } }`
	qProject      = `query($id: String!) { project(id: $id) { ` + projectFields + ` } }`
	qServices     = `query($id: String!) { project(id: $id) { id name environments { edges { node { id name } } } services { edges { node { id name updatedAt serviceInstances { edges { node { environmentId latestDeployment { id status createdAt staticUrl } } } } } } } } }`
	qDeployments  = `query($n: Int!, $input: DeploymentListInput!) { deployments(first: $n, input: $input) { edges { node { id status createdAt staticUrl meta } } } }`
	qDeployment   = `query($id: String!) { deployment(id: $id) { id status createdAt staticUrl projectId serviceId environmentId service { name } environment { name } } }`
	qLogs         = `query($id: String!, $n: Int!) { deploymentLogs(deploymentId: $id, limit: $n) { timestamp message severity } }`
	qBuildLogs    = `query($id: String!, $n: Int!) { buildLogs(deploymentId: $id, limit: $n) { timestamp message severity } }`
	mRedeploy     = `mutation($id: String!) { deploymentRedeploy(id: $id) { id status } }`
	mRestart      = `mutation($id: String!) { deploymentRestart(id: $id) }`
)

type named struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type edges[T any] struct {
	Edges []struct {
		Node T `json:"node"`
	} `json:"edges"`
}

type project struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Description  string       `json:"description"`
	UpdatedAt    string       `json:"updatedAt"`
	Environments edges[named] `json:"environments"`
	Services     edges[named] `json:"services"`
}

type projectsData struct {
	Projects edges[project] `json:"projects"`
}

type deployment struct {
	ID            string          `json:"id"`
	Status        string          `json:"status"`
	CreatedAt     string          `json:"createdAt"`
	StaticURL     string          `json:"staticUrl"`
	ProjectID     string          `json:"projectId"`
	ServiceID     string          `json:"serviceId"`
	EnvironmentID string          `json:"environmentId"`
	Meta          json.RawMessage `json:"meta"`
	Service       *named          `json:"service"`
	Environment   *named          `json:"environment"`
}

func names(e edges[named]) []map[string]any {
	out := []map[string]any{}
	for _, n := range e.Edges {
		out = append(out, map[string]any{"id": n.Node.ID, "name": n.Node.Name})
	}
	return out
}

func projectOut(p project) map[string]any {
	out := map[string]any{"id": p.ID, "name": p.Name, "updated": p.UpdatedAt, "environments": names(p.Environments), "services": names(p.Services)}
	if p.Description != "" {
		out["description"] = p.Description
	}
	return out
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func deploymentOut(d deployment) map[string]any {
	out := map[string]any{"id": d.ID, "status": d.Status, "created": d.CreatedAt}
	if d.StaticURL != "" {
		out["url"] = "https://" + d.StaticURL
	}
	var meta map[string]any
	if json.Unmarshal(d.Meta, &meta) == nil {
		for k, key := range map[string]string{"commitHash": "commit", "branch": "branch", "commitMessage": "message", "commitAuthor": "author", "reason": "reason"} {
			if s, ok := meta[k].(string); ok && s != "" {
				if key == "message" {
					s, _, _ = strings.Cut(s, "\n")
					s = clip(s, 200)
				}
				out[key] = s
			}
		}
	}
	if d.Service != nil {
		out["service"] = d.Service.Name
	}
	if d.Environment != nil {
		out["environment"] = d.Environment.Name
	}
	return out
}

type input struct {
	Project     string `json:"project"`
	Service     string `json:"service"`
	Environment string `json:"environment"`
	Deployment  string `json:"deployment"`
	Limit       int    `json:"limit"`
	Lines       int    `json:"lines"`
	Build       bool   `json:"build"`
}

func (c *conn) project(ctx context.Context, raw string) (project, error) {
	var d struct {
		Project *project `json:"project"`
	}
	id, err := checkID("project", raw)
	if err != nil {
		return project{}, err
	}
	if err := c.gql(ctx, qProject, map[string]any{"id": id}, &d); err != nil {
		return project{}, err
	}
	if d.Project == nil {
		return project{}, fmt.Errorf("there's no project %s (or the token can't see it)", id)
	}
	return *d.Project, nil
}

func (c *conn) deployment(ctx context.Context, raw string) (deployment, error) {
	var d struct {
		Deployment *deployment `json:"deployment"`
	}
	id, err := checkID("deployment", raw)
	if err != nil {
		return deployment{}, err
	}
	if err := c.gql(ctx, qDeployment, map[string]any{"id": id}, &d); err != nil {
		return deployment{}, err
	}
	if d.Deployment == nil || d.Deployment.ID != id {
		return deployment{}, fmt.Errorf("there's no deployment %s (or the token can't see it)", id)
	}
	return *d.Deployment, nil
}

func (c *conn) deployments(ctx context.Context, p input, n int) ([]deployment, error) {
	proj, err := checkID("project", p.Project)
	if err != nil {
		return nil, err
	}
	svc, err := checkID("service", p.Service)
	if err != nil {
		return nil, err
	}
	in := map[string]any{"projectId": proj, "serviceId": svc}
	if p.Environment != "" {
		env, err := checkID("environment", p.Environment)
		if err != nil {
			return nil, err
		}
		in["environmentId"] = env
	}
	var d struct {
		Deployments edges[deployment] `json:"deployments"`
	}
	if err := c.gql(ctx, qDeployments, map[string]any{"n": n, "input": in}, &d); err != nil {
		return nil, err
	}
	out := []deployment{}
	for _, e := range d.Deployments.Edges {
		out = append(out, e.Node)
	}
	return out, nil
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
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
		if c.kind == "project" {
			var t struct {
				ProjectToken struct {
					ProjectID string `json:"projectId"`
				} `json:"projectToken"`
			}
			if err := c.gql(ctx, qProjectToken, nil, &t); err != nil {
				return sdk.Result{}, err
			}
			pr, err := c.project(ctx, t.ProjectToken.ProjectID)
			if err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON([]map[string]any{projectOut(pr)})
		}
		var d projectsData
		if err := c.gql(ctx, qProjects, nil, &d); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range d.Projects.Edges {
			out = append(out, projectOut(e.Node))
		}
		return sdk.JSON(out)

	case "environments":
		pr, err := c.project(ctx, p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(names(pr.Environments))

	case "services":
		id, err := checkID("project", p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		var d struct {
			Project *struct {
				Environments edges[named] `json:"environments"`
				Services     edges[struct {
					ID               string `json:"id"`
					Name             string `json:"name"`
					UpdatedAt        string `json:"updatedAt"`
					ServiceInstances edges[struct {
						EnvironmentID    string      `json:"environmentId"`
						LatestDeployment *deployment `json:"latestDeployment"`
					}] `json:"serviceInstances"`
				}] `json:"services"`
			} `json:"project"`
		}
		if err := c.gql(ctx, qServices, map[string]any{"id": id}, &d); err != nil {
			return sdk.Result{}, err
		}
		if d.Project == nil {
			return sdk.Result{}, fmt.Errorf("there's no project %s (or the token can't see it)", id)
		}
		envName := map[string]string{}
		for _, e := range d.Project.Environments.Edges {
			envName[e.Node.ID] = e.Node.Name
		}
		out := []map[string]any{}
		for _, s := range d.Project.Services.Edges {
			insts := []map[string]any{}
			for _, in := range s.Node.ServiceInstances.Edges {
				o := map[string]any{"environment": envName[in.Node.EnvironmentID], "environmentId": in.Node.EnvironmentID}
				if ld := in.Node.LatestDeployment; ld != nil {
					o["deployment"], o["status"], o["deployed"] = ld.ID, ld.Status, ld.CreatedAt
					if ld.StaticURL != "" {
						o["url"] = "https://" + ld.StaticURL
					}
				}
				insts = append(insts, o)
			}
			out = append(out, map[string]any{"id": s.Node.ID, "name": s.Node.Name, "updated": s.Node.UpdatedAt, "environments": insts})
		}
		return sdk.JSON(out)

	case "deployments":
		n := p.Limit
		if n <= 0 || n > 50 {
			n = 10
		}
		ds, err := c.deployments(ctx, p, n)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range ds {
			out = append(out, deploymentOut(d))
		}
		return sdk.JSON(out)

	case "logs":
		id, err := checkID("deployment", p.Deployment)
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.Lines
		if n <= 0 || n > 500 {
			n = 100
		}
		q, field := qLogs, "deploymentLogs"
		if p.Build {
			q, field = qBuildLogs, "buildLogs"
		}
		var d map[string][]struct {
			Timestamp string `json:"timestamp"`
			Message   string `json:"message"`
			Severity  string `json:"severity"`
		}
		if err := c.gql(ctx, q, map[string]any{"id": id, "n": n}, &d); err != nil {
			return sdk.Result{}, err
		}
		lines := d[field]
		if len(lines) > n {
			lines = lines[len(lines)-n:]
		}
		out := []map[string]any{}
		for _, l := range lines {
			o := map[string]any{"time": l.Timestamp, "message": clip(l.Message, 2000)}
			if l.Severity != "" && l.Severity != "info" {
				o["severity"] = l.Severity
			}
			out = append(out, o)
		}
		return sdk.JSON(map[string]any{"deployment": id, "lines": out})

	case "redeploy":
		return c.redeploy(ctx, call, p)
	case "restart":
		return c.restart(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func label(d deployment) string {
	s := "deployment " + d.ID
	if d.Service != nil && d.Service.Name != "" {
		s = d.Service.Name
		if d.Environment != nil && d.Environment.Name != "" {
			s += " in " + d.Environment.Name
		}
		s += " (deployment " + d.ID + ")"
	}
	return s
}

func (c *conn) redeploy(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	id := p.Deployment
	if id == "" {
		if p.Project == "" || p.Service == "" || p.Environment == "" {
			return sdk.Result{}, errors.New("give a deployment, or a project, service and environment to redeploy the latest one")
		}
		ds, err := c.deployments(ctx, p, 1)
		if err != nil {
			return sdk.Result{}, err
		}
		if len(ds) == 0 {
			return sdk.Result{}, errors.New("that service has no deployments in that environment yet")
		}
		id = ds[0].ID
	}
	d, err := c.deployment(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Build and deploy " + label(d) + " again", Changes: []sdk.Change{{Target: label(d), Op: "redeploy", Before: mustJSON(map[string]any{"status": d.Status})}}}}, nil
	}
	var r struct {
		DeploymentRedeploy struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"deploymentRedeploy"`
	}
	if err := c.gql(ctx, mRedeploy, map[string]any{"id": d.ID}, &r); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"from": d.ID, "deployment": r.DeploymentRedeploy.ID, "status": r.DeploymentRedeploy.Status})
}

func (c *conn) restart(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	d, err := c.deployment(ctx, p.Deployment)
	if err != nil {
		return sdk.Result{}, err
	}
	if d.Status != "SUCCESS" && d.Status != "SLEEPING" && d.Status != "CRASHED" {
		return sdk.Result{}, fmt.Errorf("deployment %s is %s; only a deployed (or crashed) one can be restarted", d.ID, d.Status)
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Restart " + label(d) + "; open connections drop while it comes back", Changes: []sdk.Change{{Target: label(d), Op: "restart", Before: mustJSON(map[string]any{"status": d.Status})}}}}, nil
	}
	var r struct {
		DeploymentRestart bool `json:"deploymentRestart"`
	}
	if err := c.gql(ctx, mRestart, map[string]any{"id": d.ID}, &r); err != nil {
		return sdk.Result{}, err
	}
	if !r.DeploymentRestart {
		return sdk.Result{}, errors.New("Railway didn't restart the deployment")
	}
	return sdk.JSON(map[string]any{"deployment": d.ID, "restarted": true})
}
