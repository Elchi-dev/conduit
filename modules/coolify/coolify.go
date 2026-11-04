// Package coolify works with a Coolify server (self-hosted or Coolify
// Cloud) through its API and an API token: servers, projects, applications
// and their deployments, and deploying, restarting, stopping and starting
// applications. Environment variables, keys and passwords are never read.
package coolify

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Coolify server.
type Config struct {
	URL                string `json:"url"`   // default https://app.coolify.io; self-hosted: the dashboard address
	Token              string `json:"token"` // secret:// API token
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

// New returns the Coolify module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	uuidRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	app := `{"type":"object","required":["application"],"properties":{"application":{"type":"string","description":"Application uuid (from applications)"}}}`
	return sdk.Manifest{
		ID: "coolify", Name: "Coolify", Version: "0.1.0", Category: "Infrastructure", Icon: "deploy",
		Description: "Coolify: servers, projects, applications and deployments; deploy, restart, stop and start applications.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"url":{"type":"string","default":"https://app.coolify.io","description":"Coolify Cloud, or your Coolify dashboard's address, e.g. https://coolify.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API token (Keys & Tokens, API tokens). Read-only is enough to look; deploy rights are needed to deploy, restart or stop"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "servers", Title: "Servers", Description: "Servers with their address, SSH port and user, whether they're reachable and usable, build server, and proxy.", Risk: sdk.RiskRead},
			{Name: "projects", Title: "Projects", Description: "Projects with their environments.", Risk: sdk.RiskRead},
			{Name: "applications", Title: "Applications", Description: "Applications: name, status, domains, build pack, Git repository and branch, image, last online. Never environment variables or keys.", Risk: sdk.RiskRead},
			{Name: "application", Title: "Application", Description: "One application's details (the same fields as applications).", Risk: sdk.RiskRead, Input: sdk.Schema(app)},
			{Name: "deployments", Title: "Deployments", Description: "Deployments running or queued now, or the latest deployments of one application. Never their logs.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"application":{"type":"string","description":"Only this application's deployments, newest first"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":10}}}`)},
			{Name: "deploy_application", Title: "Deploy an application", Description: "Queues a deployment: Coolify builds the application's current source and replaces what runs. Can't be undone.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["application"],"properties":{"application":{"type":"string","description":"Application uuid"},"force":{"type":"boolean","default":false,"description":"Rebuild without the build cache"}}}`)},
			{Name: "restart_application", Title: "Restart an application", Description: "Restarts the application's containers without a new build.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(app)},
			{Name: "stop_application", Title: "Stop an application", Description: "Stops the application's containers. Undo starts it again, which in Coolify is a deployment that may build newer source.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(app)},
			{Name: "start_application", Title: "Start an application", Description: "Starts a stopped application; Coolify queues a deployment to do so, which may build its current source. Undo stops it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(app)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = "https://app.coolify.io"
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://coolify.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/v1"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
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
		return errors.New("Coolify refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API token isn't allowed to do this (or the API is turned off in Coolify's settings)")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err)
}

// application is decoded field by field: Coolify's answer also carries
// webhook secrets, basic-auth passwords and registry settings.
type application struct {
	UUID         string `json:"uuid"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	FQDN         string `json:"fqdn"`
	Status       string `json:"status"`
	BuildPack    string `json:"build_pack"`
	GitRepo      string `json:"git_repository"`
	GitBranch    string `json:"git_branch"`
	GitCommit    string `json:"git_commit_sha"`
	Image        string `json:"docker_registry_image_name"`
	ImageTag     string `json:"docker_registry_image_tag"`
	Ports        string `json:"ports_exposes"`
	LastOnlineAt string `json:"last_online_at"`
	UpdatedAt    string `json:"updated_at"`
}

func (a application) label() string {
	if a.Name != "" {
		return a.Name
	}
	return a.UUID
}

func (a application) summary() map[string]any {
	row := map[string]any{"uuid": a.UUID, "name": a.label(), "status": a.Status, "buildPack": a.BuildPack}
	if a.Description != "" {
		row["description"] = a.Description
	}
	if a.FQDN != "" {
		ds := []string{}
		for _, d := range strings.Split(a.FQDN, ",") {
			if d = strings.TrimSpace(d); d != "" {
				ds = append(ds, rest.StripUserinfo(d))
			}
		}
		row["domains"] = ds
	}
	if a.GitRepo != "" {
		row["gitRepository"] = rest.StripUserinfo(a.GitRepo)
		row["gitBranch"] = a.GitBranch
	}
	if a.GitCommit != "" && a.GitCommit != "HEAD" {
		row["gitCommit"] = a.GitCommit
	}
	if a.Image != "" {
		img := a.Image
		if a.ImageTag != "" {
			img += ":" + a.ImageTag
		}
		row["image"] = img
	}
	if a.Ports != "" {
		row["ports"] = a.Ports
	}
	if a.LastOnlineAt != "" {
		row["lastOnline"] = a.LastOnlineAt
	}
	if a.UpdatedAt != "" {
		row["updated"] = a.UpdatedAt
	}
	return row
}

// running reports whether a Coolify status ("running:healthy",
// "exited:unhealthy", "restarting", ...) means the app is up.
func running(status string) bool {
	return strings.HasPrefix(status, "running") || strings.HasPrefix(status, "restarting") || strings.HasPrefix(status, "degraded")
}

func stopped(status string) bool { return strings.HasPrefix(status, "exited") }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var apps []application
	if err := c.get(ctx, "/applications", nil, &apps); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Coolify API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	up, failing := 0, 0
	for _, a := range apps {
		if running(a.Status) {
			up++
		}
		if strings.Contains(a.Status, "unhealthy") && running(a.Status) {
			failing++
		}
	}
	msg := fmt.Sprintf("%d applications, %d running", len(apps), up)
	var v string
	if _, err := c.api.Do(ctx, http.MethodGet, "/version", nil, nil, &v); err == nil && v != "" && len(v) < 40 {
		msg += " · Coolify " + v
	}
	if failing > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s · %d unhealthy", msg, failing)}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Application string `json:"application"`
	Force       bool   `json:"force"`
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
	p.Application = strings.TrimSpace(p.Application)
	switch call.Action {
	case "servers":
		return c.servers(ctx)
	case "projects":
		return c.projects(ctx)
	case "applications":
		var apps []application
		if err := c.get(ctx, "/applications", nil, &apps); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, a := range apps {
			out = append(out, a.summary())
		}
		return sdk.JSON(out)
	case "deployments":
		if p.Application != "" && !uuidRe.MatchString(p.Application) {
			return sdk.Result{}, errors.New("an application is its uuid from applications")
		}
		if p.Limit < 0 || p.Limit > 100 {
			return sdk.Result{}, errors.New("the limit is between 1 and 100")
		}
		return c.deployments(ctx, p.Application, p.Limit)
	case "application", "deploy_application", "restart_application", "stop_application", "start_application":
		if !uuidRe.MatchString(p.Application) {
			return sdk.Result{}, errors.New("an application is its uuid from applications")
		}
		a, err := c.application(ctx, p.Application)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.Action == "application" {
			return sdk.JSON(a.summary())
		}
		return c.act(ctx, call, a, p.Force)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) application(ctx context.Context, id string) (application, error) {
	var a application
	if err := c.get(ctx, "/applications/"+url.PathEscape(id), nil, &a); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return a, fmt.Errorf("there's no application %s", id)
		}
		return a, err
	}
	if a.UUID == "" {
		return a, fmt.Errorf("there's no application %s", id)
	}
	return a, nil
}

func (c *conn) act(ctx context.Context, call sdk.Call, a application, force bool) (sdk.Result, error) {
	verb := strings.TrimSuffix(call.Action, "_application")
	switch {
	case verb == "stop" && stopped(a.Status), verb == "start" && running(a.Status):
		return sdk.JSON(map[string]any{"application": a.UUID, "name": a.label(), "status": a.Status, "note": "nothing to change"})
	}
	if call.DryRun {
		before, _ := json.Marshal(map[string]any{"status": a.Status})
		var after []byte
		summary := upper(verb) + " " + a.label()
		switch verb {
		case "deploy":
			after, _ = json.Marshal(map[string]any{"build": "current source", "force": force})
			summary = "Deploy " + a.label() + ": build its current source and replace what runs"
		case "stop":
			after, _ = json.Marshal(map[string]any{"status": "exited"})
		case "start":
			after, _ = json.Marshal(map[string]any{"status": "running"})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "application " + a.label(), Op: verb, Before: before, After: after}}}}, nil
	}
	var out struct {
		Message        string `json:"message"`
		DeploymentUUID string `json:"deployment_uuid"`
		Deployments    []struct {
			DeploymentUUID string `json:"deployment_uuid"`
		} `json:"deployments"`
	}
	var err error
	if verb == "deploy" {
		err = c.get(ctx, "/deploy", url.Values{"uuid": {a.UUID}, "force": {strconv.FormatBool(force)}}, &out)
	} else {
		err = c.get(ctx, "/applications/"+url.PathEscape(a.UUID)+"/"+verb, nil, &out)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	res := map[string]any{"application": a.UUID, "name": a.label(), "done": verb}
	dep := out.DeploymentUUID
	if dep == "" && len(out.Deployments) > 0 {
		dep = out.Deployments[0].DeploymentUUID
	}
	if dep != "" {
		res["deployment"] = dep
	}
	r, err := sdk.JSON(res)
	undo := map[string]string{"application": a.UUID}
	switch verb {
	case "stop":
		r.Undo = sdk.UndoWith("start_application", undo, "Start "+a.label()+" again (Coolify deploys it, which may build newer source)")
	case "start":
		r.Undo = sdk.UndoWith("stop_application", undo, "Stop "+a.label()+" again")
	}
	return r, err
}

func (c *conn) servers(ctx context.Context) (sdk.Result, error) {
	type settings struct {
		Reachable   *bool `json:"is_reachable"`
		Usable      *bool `json:"is_usable"`
		BuildServer bool  `json:"is_build_server"`
	}
	// The private key and its id aren't decoded.
	var ss []struct {
		UUID        string `json:"uuid"`
		Name        string `json:"name"`
		Description string `json:"description"`
		IP          string `json:"ip"`
		Port        int    `json:"port"`
		User        string `json:"user"`
		settings
		Settings settings `json:"settings"`
		Proxy    struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"proxy"`
	}
	if err := c.get(ctx, "/servers", nil, &ss); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, s := range ss {
		row := map[string]any{"uuid": s.UUID, "name": s.Name, "ip": s.IP, "port": s.Port, "user": s.User, "buildServer": s.BuildServer || s.Settings.BuildServer}
		for k, v := range map[string][2]*bool{"reachable": {s.Reachable, s.Settings.Reachable}, "usable": {s.Usable, s.Settings.Usable}} {
			if v[1] != nil {
				row[k] = *v[1]
			} else if v[0] != nil {
				row[k] = *v[0]
			}
		}
		if s.Description != "" {
			row["description"] = s.Description
		}
		if s.Proxy.Type != "" {
			row["proxy"] = s.Proxy.Type
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

func (c *conn) projects(ctx context.Context) (sdk.Result, error) {
	type project struct {
		UUID         string `json:"uuid"`
		Name         string `json:"name"`
		Description  string `json:"description"`
		Environments []struct {
			Name string `json:"name"`
		} `json:"environments"`
	}
	var ps []project
	if err := c.get(ctx, "/projects", nil, &ps); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, p := range ps {
		if len(p.Environments) == 0 && uuidRe.MatchString(p.UUID) {
			// The list leaves environments out; the project itself has them.
			var full project
			if c.get(ctx, "/projects/"+url.PathEscape(p.UUID), nil, &full) == nil {
				p.Environments = full.Environments
			}
		}
		envs := []string{}
		for _, e := range p.Environments {
			envs = append(envs, e.Name)
		}
		row := map[string]any{"uuid": p.UUID, "name": p.Name, "environments": envs}
		if p.Description != "" {
			row["description"] = p.Description
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

// deployment is decoded field by field: the logs aren't read.
type deployment struct {
	UUID          string `json:"deployment_uuid"`
	Application   string `json:"application_name"`
	Status        string `json:"status"`
	Commit        string `json:"commit"`
	CommitMessage string `json:"commit_message"`
	Server        string `json:"server_name"`
	ForceRebuild  bool   `json:"force_rebuild"`
	Rollback      bool   `json:"rollback"`
	RestartOnly   bool   `json:"restart_only"`
	IsWebhook     bool   `json:"is_webhook"`
	IsAPI         bool   `json:"is_api"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

func (c *conn) deployments(ctx context.Context, app string, limit int) (sdk.Result, error) {
	if limit == 0 {
		limit = 10
	}
	var ds []deployment
	if app == "" {
		if err := c.get(ctx, "/deployments", nil, &ds); err != nil {
			return sdk.Result{}, err
		}
	} else {
		var page struct {
			Deployments []deployment `json:"deployments"`
		}
		if err := c.get(ctx, "/deployments/applications/"+url.PathEscape(app), url.Values{"skip": {"0"}, "take": {strconv.Itoa(limit)}}, &page); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no application %s (or this Coolify is too old to list its deployments)", app)
			}
			return sdk.Result{}, err
		}
		ds = page.Deployments
	}
	out := []map[string]any{}
	for i, d := range ds {
		if i >= limit {
			break
		}
		trigger := "dashboard"
		switch {
		case d.IsWebhook:
			trigger = "webhook"
		case d.IsAPI:
			trigger = "api"
		}
		row := map[string]any{"uuid": d.UUID, "application": d.Application, "status": d.Status, "trigger": trigger, "created": d.CreatedAt, "updated": d.UpdatedAt}
		if d.Commit != "" && d.Commit != "HEAD" {
			row["commit"] = d.Commit
		}
		if msg := strings.SplitN(strings.TrimSpace(d.CommitMessage), "\n", 2)[0]; msg != "" {
			row["commitMessage"] = msg
		}
		if d.Server != "" {
			row["server"] = d.Server
		}
		if d.ForceRebuild {
			row["forceRebuild"] = true
		}
		if d.Rollback {
			row["rollback"] = true
		}
		if d.RestartOnly {
			row["restartOnly"] = true
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

func upper(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
