// Package render works with Render services through an API key: services
// and their state, deploys and their status, recent events, triggering a
// deploy, and suspending or resuming a service.
package render

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
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Render account (optionally narrowed to one workspace).
type Config struct {
	Token     string `json:"token"`     // secret:// API key
	Workspace string `json:"workspace"` // owner id (tea-… or usr-…); empty for every workspace
}

type conn struct {
	api   *rest.Client
	owner string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.render.com/v1 (tests).
	Base string
}

// New returns the Render module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.render.com/v1"

var (
	serviceRe = regexp.MustCompile(`^(srv|crn)-[a-z0-9]{10,40}$`)
	deployRe  = regexp.MustCompile(`^dep-[a-z0-9]{10,40}$`)
	ownerRe   = regexp.MustCompile(`^(tea|usr)-[a-z0-9]{10,40}$`)
	commitRe  = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
)

func serviceID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !serviceRe.MatchString(s) {
		return "", errors.New("the service is its id, srv-… (or crn-… for a cron job), see services")
	}
	return s, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	svc := `"service":{"type":"string","description":"Service id (srv-…, crn-…), see services"}`
	in := sdk.Schema(`{"type":"object","required":["service"],"properties":{` + svc + `}}`)
	return sdk.Manifest{
		ID: "render", Name: "Render", Version: "0.1.0", Category: "Development", Icon: "cloud",
		Description: "Render services: state, deploys and events; trigger a deploy, suspend and resume.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"API key (Account settings, API keys)"},
			"workspace":{"type":"string","description":"Workspace (owner) id, tea-… or usr-…, to see only its services; empty for every workspace"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "services", Title: "Services", Description: "Every service with its type, address, repository, branch and whether it's suspended.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":50,"maximum":100},"suspended":{"type":"boolean","description":"Only suspended services"}}}`)},
			{Name: "service", Title: "Service details", Description: "One service's settings and state.", Risk: sdk.RiskRead, Input: in},
			{Name: "deploys", Title: "Deploys", Description: "A service's recent deploys: status, trigger, commit and timing.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["service"],"properties":{` + svc + `,"limit":{"type":"integer","default":20,"maximum":100}}}`)},
			{Name: "deploy", Title: "Deploy status", Description: "One deploy's status, commit and timing.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["service","deploy"],"properties":{` + svc + `,"deploy":{"type":"string","description":"Deploy id (dep-…)"}}}`)},
			{Name: "events", Title: "Recent events", Description: "A service's recent events: deploys started and ended, builds, crashes, restarts, suspensions.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["service"],"properties":{` + svc + `,"limit":{"type":"integer","default":20,"maximum":100}}}`)},
			{Name: "trigger_deploy", Title: "Trigger a deploy", Description: "Deploys the service again from its branch (or a given commit), optionally clearing the build cache. Destructive: it ships whatever revision is named to production.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["service"],"properties":{` + svc + `,"clearCache":{"type":"boolean"},"commit":{"type":"string","description":"Commit SHA to deploy instead of the branch head"}}}`)},
			{Name: "suspend", Title: "Suspend a service", Description: "Stops a service: it stops answering and billing until resumed. Undo resumes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: in},
			{Name: "resume", Title: "Resume a service", Description: "Starts a suspended service again. Undo suspends it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: in},
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
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	owner := strings.TrimSpace(c.Workspace)
	if owner != "" && !ownerRe.MatchString(owner) {
		return errors.New("the workspace is its owner id, tea-… or usr-… (Workspace settings)")
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
			return errors.New("the stored API key isn't valid")
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api, owner: owner})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var os []struct {
		Owner struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"owner"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/owners", url.Values{"limit": {"100"}}, nil, &os); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "Render refused the API key"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if c.owner != "" {
		for _, o := range os {
			if o.Owner.ID == c.owner {
				return sdk.Health{Status: "ok", Message: "workspace " + o.Owner.Name}
			}
		}
		return sdk.Health{Status: "degraded", Message: "the API key can't see workspace " + c.owner}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d workspaces", len(os))}
}

type service struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Repo           string `json:"repo"`
	Branch         string `json:"branch"`
	AutoDeploy     string `json:"autoDeploy"`
	Suspended      string `json:"suspended"`
	OwnerID        string `json:"ownerId"`
	DashboardURL   string `json:"dashboardUrl"`
	UpdatedAt      string `json:"updatedAt"`
	CreatedAt      string `json:"createdAt"`
	ServiceDetails *struct {
		URL     string `json:"url"`
		Region  string `json:"region"`
		Plan    string `json:"plan"`
		Runtime string `json:"runtime"`
		Env     string `json:"env"`
	} `json:"serviceDetails"`
}

func (s service) suspended() bool { return s.Suspended == "suspended" }

func serviceOut(s service) map[string]any {
	out := map[string]any{"id": s.ID, "name": s.Name, "type": s.Type, "suspended": s.suspended(), "updated": s.UpdatedAt, "dashboard": s.DashboardURL}
	if s.Repo != "" {
		out["repo"], out["branch"] = s.Repo, s.Branch
	}
	if s.AutoDeploy != "" {
		out["autoDeploy"] = s.AutoDeploy == "yes"
	}
	if d := s.ServiceDetails; d != nil {
		if d.URL != "" {
			out["url"] = d.URL
		}
		if d.Region != "" {
			out["region"] = d.Region
		}
		if d.Plan != "" {
			out["plan"] = d.Plan
		}
		if rt := d.Runtime; rt != "" {
			out["runtime"] = rt
		} else if d.Env != "" {
			out["runtime"] = d.Env
		}
	}
	return out
}

type deploy struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Trigger string `json:"trigger"`
	Commit  *struct {
		ID      string `json:"id"`
		Message string `json:"message"`
	} `json:"commit"`
	Image *struct {
		Ref string `json:"ref"`
	} `json:"image"`
	CreatedAt  string `json:"createdAt"`
	FinishedAt string `json:"finishedAt"`
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func deployOut(d deploy) map[string]any {
	out := map[string]any{"id": d.ID, "status": d.Status, "created": d.CreatedAt}
	if d.Trigger != "" {
		out["trigger"] = d.Trigger
	}
	if d.FinishedAt != "" {
		out["finished"] = d.FinishedAt
		if a, err1 := time.Parse(time.RFC3339, d.CreatedAt); err1 == nil {
			if b, err2 := time.Parse(time.RFC3339, d.FinishedAt); err2 == nil && b.After(a) {
				out["seconds"] = int(b.Sub(a).Seconds())
			}
		}
	}
	if d.Commit != nil {
		out["commit"] = d.Commit.ID
		if first, _, _ := strings.Cut(d.Commit.Message, "\n"); first != "" {
			out["message"] = clip(first, 200)
		}
	}
	if d.Image != nil && d.Image.Ref != "" {
		out["image"] = d.Image.Ref
	}
	return out
}

func (c *conn) service(ctx context.Context, raw string) (service, error) {
	var s service
	id, err := serviceID(raw)
	if err != nil {
		return s, err
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/services/"+id, nil, nil, &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return s, fmt.Errorf("there's no service %s (or the API key can't see it)", id)
		}
		return s, err
	}
	if s.ID != id {
		return s, errors.New("unexpected service from Render")
	}
	if c.owner != "" && s.OwnerID != c.owner {
		return s, fmt.Errorf("service %s isn't in this instance's workspace", id)
	}
	return s, nil
}

type input struct {
	Service    string `json:"service"`
	Deploy     string `json:"deploy"`
	Limit      int    `json:"limit"`
	Suspended  bool   `json:"suspended"`
	ClearCache bool   `json:"clearCache"`
	Commit     string `json:"commit"`
}

func limitOf(n, def int) string {
	if n <= 0 || n > 100 {
		n = def
	}
	return strconv.Itoa(n)
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
	case "services":
		q := url.Values{"limit": {limitOf(p.Limit, 50)}}
		if c.owner != "" {
			q.Set("ownerId", c.owner)
		}
		if p.Suspended {
			q.Set("suspended", "suspended")
		}
		var ss []struct {
			Cursor  string  `json:"cursor"`
			Service service `json:"service"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/services", q, nil, &ss); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range ss {
			out = append(out, serviceOut(s.Service))
		}
		return sdk.JSON(out)

	case "service":
		s, err := c.service(ctx, p.Service)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(serviceOut(s))

	case "deploys":
		s, err := c.service(ctx, p.Service)
		if err != nil {
			return sdk.Result{}, err
		}
		var ds []struct {
			Deploy deploy `json:"deploy"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/services/"+s.ID+"/deploys", url.Values{"limit": {limitOf(p.Limit, 20)}}, nil, &ds); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range ds {
			out = append(out, deployOut(d.Deploy))
		}
		return sdk.JSON(out)

	case "deploy":
		sid, err := serviceID(p.Service)
		if err != nil {
			return sdk.Result{}, err
		}
		if !deployRe.MatchString(strings.TrimSpace(p.Deploy)) {
			return sdk.Result{}, errors.New("the deploy is its id, dep-…, see deploys")
		}
		s, err := c.service(ctx, sid)
		if err != nil {
			return sdk.Result{}, err
		}
		var d deploy
		if _, err := c.api.Do(ctx, http.MethodGet, "/services/"+s.ID+"/deploys/"+strings.TrimSpace(p.Deploy), nil, nil, &d); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no deploy %s on %s", p.Deploy, s.Name)
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(deployOut(d))

	case "events":
		s, err := c.service(ctx, p.Service)
		if err != nil {
			return sdk.Result{}, err
		}
		var es []struct {
			Event struct {
				ID        string          `json:"id"`
				Type      string          `json:"type"`
				Timestamp string          `json:"timestamp"`
				Details   json.RawMessage `json:"details"`
			} `json:"event"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/services/"+s.ID+"/events", url.Values{"limit": {limitOf(p.Limit, 20)}}, nil, &es); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range es {
			o := map[string]any{"type": e.Event.Type, "time": e.Event.Timestamp}
			if d := eventDetails(e.Event.Details); len(d) > 0 {
				o["details"] = d
			}
			out = append(out, o)
		}
		return sdk.JSON(out)

	case "trigger_deploy":
		return c.trigger(ctx, call, p)
	case "suspend", "resume":
		return c.suspend(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// eventDetails keeps the short, useful fields of an event's details.
func eventDetails(raw json.RawMessage) map[string]any {
	var d map[string]any
	if json.Unmarshal(raw, &d) != nil {
		return nil
	}
	out := map[string]any{}
	for _, k := range []string{"deployId", "status", "reason", "trigger", "deployStatus", "buildId", "instanceId", "exitCode", "message", "fromPlan", "toPlan"} {
		switch v := d[k].(type) {
		case string:
			out[k] = clip(v, 300)
		case float64, bool:
			out[k] = v
		case map[string]any:
			// e.g. {"newCommit": {...}} or a reason object; keep it short.
			b, _ := json.Marshal(v)
			out[k] = clip(string(b), 300)
		}
	}
	return out
}

func (c *conn) trigger(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	commit := strings.ToLower(strings.TrimSpace(p.Commit))
	if commit != "" && !commitRe.MatchString(commit) {
		return sdk.Result{}, errors.New("the commit is a SHA (7 to 40 hex characters)")
	}
	s, err := c.service(ctx, p.Service)
	if err != nil {
		return sdk.Result{}, err
	}
	if s.suspended() {
		return sdk.Result{}, fmt.Errorf("%s is suspended; resume it first", s.Name)
	}
	from := "its branch " + s.Branch
	if s.Repo == "" {
		from = "its image"
	}
	if commit != "" {
		from = "commit " + commit
	}
	if call.DryRun {
		sum := fmt.Sprintf("Deploy %s from %s", s.Name, from)
		if p.ClearCache {
			sum += " with a clear build cache"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "service " + s.Name, Op: "deploy", After: mustJSON(map[string]any{"commit": commit, "branch": s.Branch, "clearCache": p.ClearCache})}}}}, nil
	}
	body := map[string]any{"clearCache": "do_not_clear"}
	if p.ClearCache {
		body["clearCache"] = "clear"
	}
	if commit != "" {
		body["commitId"] = commit
	}
	var d deploy
	if _, err := c.api.Do(ctx, http.MethodPost, "/services/"+s.ID+"/deploys", nil, body, &d); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"service": s.Name, "from": from}
	if d.ID != "" {
		out["deploy"] = d.ID
		out["status"] = d.Status
	} else {
		out["status"] = "queued"
	}
	return sdk.JSON(out)
}

func (c *conn) suspend(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	suspending := call.Action == "suspend"
	s, err := c.service(ctx, p.Service)
	if err != nil {
		return sdk.Result{}, err
	}
	if s.suspended() == suspending {
		state := "running"
		if s.suspended() {
			state = "suspended"
		}
		return sdk.JSON(map[string]any{"service": s.Name, "note": "it is already " + state})
	}
	if call.DryRun {
		sum := fmt.Sprintf("Suspend %s (%s): it stops answering until resumed", s.Name, s.Type)
		if !suspending {
			sum = fmt.Sprintf("Resume %s (%s)", s.Name, s.Type)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "service " + s.Name, Op: call.Action, Before: mustJSON(map[string]any{"suspended": s.suspended()}), After: mustJSON(map[string]any{"suspended": suspending})}}}}, nil
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/services/"+s.ID+"/"+call.Action, nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"service": s.Name, "id": s.ID, "suspended": suspending})
	if suspending {
		res.Undo = sdk.UndoWith("resume", map[string]any{"service": s.ID}, "Resume "+s.Name)
	} else {
		res.Undo = sdk.UndoWith("suspend", map[string]any{"service": s.ID}, "Suspend "+s.Name+" again")
	}
	return res, err
}
