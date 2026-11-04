// Package dokploy works with a Dokploy server through its API and an API
// key (x-api-key): projects with their environments, applications and
// compose services, their deployments, and deploying, stopping and starting
// them. Environment variables, build arguments, registry passwords and SSH
// keys are never read.
package dokploy

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

// Config is one Dokploy server.
type Config struct {
	URL                string `json:"url"`    // the dashboard, e.g. https://dokploy.example.com
	APIKey             string `json:"apiKey"` // secret:// API key
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

// New returns the Dokploy module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// kind is an application or a compose service: the API names and fields
// differ only by this word.
type kind struct {
	name, field, status, byDeployments string
}

var (
	appKind     = kind{name: "application", field: "applicationId", status: "applicationStatus", byDeployments: "/deployment.all"}
	composeKind = kind{name: "compose", field: "composeId", status: "composeStatus", byDeployments: "/deployment.allByCompose"}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	app := `{"type":"object","required":["application"],"properties":{"application":{"type":"string","description":"Application id (from projects)"}}}`
	cmp := `{"type":"object","required":["compose"],"properties":{"compose":{"type":"string","description":"Compose service id (from projects)"}}}`
	return sdk.Manifest{
		ID: "dokploy", Name: "Dokploy", Version: "0.1.0", Category: "Infrastructure", Icon: "deploy",
		Description: "Dokploy: projects, applications, compose services and deployments; deploy, stop and start them.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"Your Dokploy dashboard's address, e.g. https://dokploy.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"An API key (Settings, Profile, API/CLI, Generate). It acts with its user's permissions"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Projects with their environments, and each one's applications and compose services with their status.", Risk: sdk.RiskRead},
			{Name: "application", Title: "Application", Description: "One application: status, source (repository, branch or image), build type, replicas, domains and latest deployments. Never environment variables or credentials.", Risk: sdk.RiskRead, Input: sdk.Schema(app)},
			{Name: "compose", Title: "Compose service", Description: "One compose service: status, source, compose type, domains and latest deployments. Never environment variables or credentials.", Risk: sdk.RiskRead, Input: sdk.Schema(cmp)},
			{Name: "deployments", Title: "Deployments", Description: "Deployments of an application or a compose service, newest first. Never their logs.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"application":{"type":"string"},"compose":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":10}}}`)},
			{Name: "deploy_application", Title: "Deploy an application", Description: "Builds the application from its source and replaces what runs. Can't be undone.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(app)},
			{Name: "stop_application", Title: "Stop an application", Description: "Stops the application. Undo starts it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(app)},
			{Name: "start_application", Title: "Start an application", Description: "Starts a stopped application from what was last deployed, without a new build, as one instance (Dokploy's start ignores replicas; a deploy runs them all). Refused for an application with more replicas that may be running. Undo stops it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(app)},
			{Name: "deploy_compose", Title: "Deploy a compose service", Description: "Pulls the compose service's source and recreates its containers. Can't be undone.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(cmp)},
			{Name: "stop_compose", Title: "Stop a compose service", Description: "Stops every container of the compose service. Undo starts it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(cmp)},
			{Name: "start_compose", Title: "Start a compose service", Description: "Starts a stopped compose service from what was last deployed. Undo stops it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(cmp)},
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
		return errors.New("the address is like https://dokploy.example.com")
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
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("x-api-key", strings.TrimSpace(t))
		return nil
	})
	// The key travels in x-api-key, which Go would forward to another host.
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Dokploy refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API key's user isn't allowed to do this in Dokploy")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err)
}

// service is an application or compose service, decoded field by field:
// Dokploy's answer also carries env, build args, registry passwords and
// SSH keys.
type service struct {
	ApplicationID string `json:"applicationId"`
	ComposeID     string `json:"composeId"`
	Name          string `json:"name"`
	AppName       string `json:"appName"`
	Description   string `json:"description"`
	AppStatus     string `json:"applicationStatus"`
	ComposeStatus string `json:"composeStatus"`
	SourceType    string `json:"sourceType"`
	Repository    string `json:"repository"`
	Owner         string `json:"owner"`
	Branch        string `json:"branch"`
	CustomGitURL  string `json:"customGitUrl"`
	CustomBranch  string `json:"customGitBranch"`
	DockerImage   string `json:"dockerImage"`
	BuildType     string `json:"buildType"`
	ComposeType   string `json:"composeType"`
	Replicas      *int   `json:"replicas"`
	CreatedAt     string `json:"createdAt"`
	Domains       []struct {
		Host  string `json:"host"`
		HTTPS bool   `json:"https"`
		Port  int    `json:"port"`
		Path  string `json:"path"`
	} `json:"domains"`
	Deployments []deployment `json:"deployments"`
}

func (s service) id() string {
	if s.ApplicationID != "" {
		return s.ApplicationID
	}
	return s.ComposeID
}

func (s service) status() string {
	if s.AppStatus != "" {
		return s.AppStatus
	}
	return s.ComposeStatus
}

func (s service) label() string {
	if s.Name != "" {
		return s.Name
	}
	return s.id()
}

func (s service) brief() map[string]any {
	return map[string]any{"id": s.id(), "name": s.label(), "status": s.status()}
}

func (s service) summary() map[string]any {
	row := map[string]any{"id": s.id(), "name": s.label(), "appName": s.AppName, "status": s.status(), "source": s.SourceType}
	if s.Description != "" {
		row["description"] = s.Description
	}
	switch {
	case s.CustomGitURL != "":
		row["repository"] = rest.StripUserinfo(s.CustomGitURL)
		row["branch"] = s.CustomBranch
	case s.Repository != "":
		repo := s.Repository
		if s.Owner != "" {
			repo = s.Owner + "/" + repo
		}
		row["repository"] = repo
		row["branch"] = s.Branch
	}
	if s.DockerImage != "" {
		row["image"] = s.DockerImage
	}
	if s.BuildType != "" {
		row["buildType"] = s.BuildType
	}
	if s.ComposeType != "" {
		row["composeType"] = s.ComposeType
	}
	if s.Replicas != nil {
		row["replicas"] = *s.Replicas
	}
	if s.CreatedAt != "" {
		row["created"] = s.CreatedAt
	}
	domains := []string{}
	for _, d := range s.Domains {
		scheme := "http"
		if d.HTTPS {
			scheme = "https"
		}
		domains = append(domains, scheme+"://"+d.Host+d.Path)
	}
	row["domains"] = domains
	if len(s.Deployments) > 0 {
		row["deployments"] = deployments(s.Deployments, 5)
	}
	return row
}

// deployment is decoded field by field: the log path isn't read.
type deployment struct {
	ID          string `json:"deploymentId"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`
	CreatedAt   string `json:"createdAt"`
}

func deployments(ds []deployment, limit int) []map[string]any {
	out := []map[string]any{}
	for i, d := range ds {
		if i >= limit {
			break
		}
		row := map[string]any{"id": d.ID, "title": strings.SplitN(d.Title, "\n", 2)[0], "status": d.Status, "created": d.CreatedAt}
		out = append(out, row)
	}
	return out
}

type environment struct {
	Name         string    `json:"name"`
	Applications []service `json:"applications"`
	Compose      []service `json:"compose"`
}

type project struct {
	ProjectID   string `json:"projectId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	environment
	Environments []environment `json:"environments"`
}

// envs returns a project's environments; Dokploy before environments put
// the services on the project itself.
func (p project) envs() []environment {
	if len(p.Environments) > 0 {
		return p.Environments
	}
	e := p.environment
	e.Name = "production"
	return []environment{e}
}

func (c *conn) projects(ctx context.Context) ([]project, error) {
	var ps []project
	err := c.get(ctx, "/project.all", nil, &ps)
	return ps, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ps, err := c.projects(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Dokploy API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	n, failed := 0, 0
	for _, p := range ps {
		for _, e := range p.envs() {
			for _, s := range append(append([]service{}, e.Applications...), e.Compose...) {
				n++
				if s.status() == "error" {
					failed++
				}
			}
		}
	}
	msg := fmt.Sprintf("%d projects, %d services", len(ps), n)
	if failed > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s · %d failed their last deployment", msg, failed)}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Application string `json:"application"`
	Compose     string `json:"compose"`
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
	p.Application, p.Compose = strings.TrimSpace(p.Application), strings.TrimSpace(p.Compose)
	switch call.Action {
	case "projects":
		ps, err := c.projects(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, pr := range ps {
			envs := []map[string]any{}
			for _, e := range pr.envs() {
				apps, cmps := []map[string]any{}, []map[string]any{}
				for _, s := range e.Applications {
					apps = append(apps, s.brief())
				}
				for _, s := range e.Compose {
					cmps = append(cmps, s.brief())
				}
				envs = append(envs, map[string]any{"name": e.Name, "applications": apps, "compose": cmps})
			}
			row := map[string]any{"id": pr.ProjectID, "name": pr.Name, "environments": envs}
			if pr.Description != "" {
				row["description"] = pr.Description
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	case "deployments":
		if p.Limit < 0 || p.Limit > 100 {
			return sdk.Result{}, errors.New("the limit is between 1 and 100")
		}
		if p.Limit == 0 {
			p.Limit = 10
		}
		k, id, err := which(p)
		if err != nil {
			return sdk.Result{}, err
		}
		var ds []deployment
		if err := c.get(ctx, k.byDeployments, url.Values{k.field: {id}}, &ds); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(deployments(ds, p.Limit))
	}
	k, verb := appKind, ""
	switch call.Action {
	case "application", "deploy_application", "stop_application", "start_application":
		if !idRe.MatchString(p.Application) {
			return sdk.Result{}, errors.New("an application is its id from projects")
		}
		verb = strings.TrimSuffix(call.Action, "_application")
	case "compose", "deploy_compose", "stop_compose", "start_compose":
		if !idRe.MatchString(p.Compose) {
			return sdk.Result{}, errors.New("a compose service is its id from projects")
		}
		k, verb = composeKind, strings.TrimSuffix(call.Action, "_compose")
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	id := p.Application
	if k == composeKind {
		id = p.Compose
	}
	s, err := c.service(ctx, k, id)
	if err != nil {
		return sdk.Result{}, err
	}
	if verb == "application" || verb == "compose" {
		return sdk.JSON(s.summary())
	}
	return c.act(ctx, call, k, verb, s)
}

func which(p input) (kind, string, error) {
	switch {
	case p.Application != "" && p.Compose != "":
		return kind{}, "", errors.New("enter an application or a compose service, not both")
	case p.Application != "":
		if !idRe.MatchString(p.Application) {
			return kind{}, "", errors.New("an application is its id from projects")
		}
		return appKind, p.Application, nil
	case p.Compose != "":
		if !idRe.MatchString(p.Compose) {
			return kind{}, "", errors.New("a compose service is its id from projects")
		}
		return composeKind, p.Compose, nil
	}
	return kind{}, "", errors.New("enter an application or a compose service")
}

func (c *conn) service(ctx context.Context, k kind, id string) (service, error) {
	var s service
	if err := c.get(ctx, "/"+k.name+".one", url.Values{k.field: {id}}, &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
			return s, fmt.Errorf("there's no %s %s", k.name, id)
		}
		return s, err
	}
	if s.id() == "" {
		return s, fmt.Errorf("there's no %s %s", k.name, id)
	}
	return s, nil
}

func (c *conn) act(ctx context.Context, call sdk.Call, k kind, verb string, s service) (sdk.Result, error) {
	what := "application"
	if k == composeKind {
		what = "compose service"
	}
	st := s.status()
	// Dokploy records "idle" once stopped (or never deployed, or after a
	// cancelled deployment), "done" after a deployment or a start, "running"
	// while a deployment runs. It's a record, not what runs: an "idle"
	// service may still be up, so it's stopped anyway (stopping is
	// harmless twice), without an undo that would start what may have been
	// stopped before.
	if verb == "start" && (st == "done" || st == "running") {
		return sdk.JSON(map[string]any{k.name: s.id(), "name": s.label(), "status": st, "note": "nothing to change"})
	}
	// Dokploy starts an application as one instance (docker service scale
	// to 1), whatever its replicas: starting one that may be running more
	// would cut it down.
	replicas := 1
	if k == appKind && s.Replicas != nil {
		replicas = *s.Replicas
	}
	if verb == "start" && replicas > 1 && st != "idle" {
		return sdk.Result{}, fmt.Errorf("application %s is %s with %d replicas, and Dokploy's start would set it to one instance; deploy it instead", s.label(), st, replicas)
	}
	noUndo := verb == "stop" && st == "idle"
	if call.DryRun {
		before, _ := json.Marshal(map[string]any{"status": st})
		after := map[string]any{"deploy": map[string]any{"build": "from its source"}, "stop": map[string]any{"status": "idle"}, "start": map[string]any{"status": "done"}}[verb]
		a, _ := json.Marshal(after)
		summary := upper(verb) + " " + what + " " + s.label()
		switch {
		case verb == "deploy":
			summary += ": build it from its source and replace what runs"
		case noUndo:
			summary += " (Dokploy already records it as stopped)"
		case verb == "start" && replicas > 1:
			summary += fmt.Sprintf(" as one instance (it has %d replicas; a deploy starts them all)", replicas)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: what + " " + s.label(), Op: verb, Before: before, After: a}}}}, nil
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/"+k.name+"."+verb, nil, map[string]string{k.field: s.id()}, nil); err != nil {
		return sdk.Result{}, friendly(err)
	}
	res := map[string]any{k.name: s.id(), "name": s.label(), "done": verb}
	if verb == "start" && replicas > 1 {
		res["note"] = fmt.Sprintf("Dokploy started one instance; deploy it to run all %d replicas", replicas)
	}
	r, err := sdk.JSON(res)
	suffix := "_application"
	if k == composeKind {
		suffix = "_compose"
	}
	undo := map[string]string{k.name: s.id()}
	switch {
	case noUndo:
	case verb == "stop" && replicas > 1:
		r.Undo = sdk.UndoWith("start"+suffix, undo, fmt.Sprintf("Start %s again (as one instance; a deploy runs all %d)", s.label(), replicas))
	case verb == "stop":
		r.Undo = sdk.UndoWith("start"+suffix, undo, "Start "+s.label()+" again")
	case verb == "start":
		r.Undo = sdk.UndoWith("stop"+suffix, undo, "Stop "+s.label()+" again")
	}
	return r, err
}

func upper(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
