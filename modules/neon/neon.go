// Package neon works with Neon serverless Postgres through its API and an
// API key: projects, branches, computes (endpoints) with their state, the
// current period's compute and storage usage, creating and deleting
// branches, and suspending or starting computes.
//
// Connection strings, passwords and role details are never requested or
// returned: answers are decoded field by field, so the connection URIs
// Neon sends back when a branch is created are never read.
package neon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Neon API key.
type Config struct {
	Token        string `json:"token"`        // secret:// API key
	Organization string `json:"organization"` // optional org-… id, for a personal key that lists an organization's projects
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
	// Base replaces https://console.neon.tech/api/v2 (tests).
	Base string
}

// New returns the Neon module.
func New() *Module { return &Module{} }

const defaultBase = "https://console.neon.tech/api/v2"

var (
	projectRe  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+){0,7}$`)
	branchRe   = regexp.MustCompile(`^br-[a-z0-9]+(-[a-z0-9]+){0,7}$`)
	endpointRe = regexp.MustCompile(`^ep-[a-z0-9]+(-[a-z0-9]+){0,7}$`)
	orgRe      = regexp.MustCompile(`^org-[a-z0-9]+(-[a-z0-9]+){0,7}$`)
	nameRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	tokenRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]{20,512}$`)
)

func check(re *regexp.Regexp, s, msg string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > 64 || !re.MatchString(s) {
		return "", errors.New(msg)
	}
	return s, nil
}

const (
	projectMsg  = "the project is its id, like spring-example-302709 (see projects)"
	branchMsg   = "the branch is its id, like br-wispy-dew-591433 (see branches)"
	endpointMsg = "the compute is its endpoint id, like ep-cool-darkness-123456 (see endpoints)"
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	project := `"project":{"type":"string","description":"Project id (see projects)"}`
	branch := `"branch":{"type":"string","description":"Branch id, br-… (see branches)"}`
	endpoint := `"endpoint":{"type":"string","description":"Compute endpoint id, ep-… (see endpoints)"}`
	in := sdk.Schema(`{"type":"object","required":["project"],"properties":{` + project + `}}`)
	br := sdk.Schema(`{"type":"object","required":["project","branch"],"properties":{` + project + `,` + branch + `}}`)
	ep := sdk.Schema(`{"type":"object","required":["project","endpoint"],"properties":{` + project + `,` + endpoint + `}}`)
	return sdk.Manifest{
		ID: "neon", Name: "Neon", Version: "0.1.0", Category: "Development", Icon: "database",
		Description: "Neon serverless Postgres: projects, branches, computes and their state, usage; create and delete branches, suspend and start computes.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A Neon API key (Account settings or Organization settings, API keys)"},
			"organization":{"type":"string","description":"Organization id (org-…), to list an organization's projects with a personal API key"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Every project with its region, Postgres version, storage and when its compute was last active.", Risk: sdk.RiskRead},
			{Name: "branches", Title: "Branches", Description: "A project's branches: name, parent, default, protected, state, logical size and compute time.", Risk: sdk.RiskRead, Input: in},
			{Name: "endpoints", Title: "Computes", Description: "A project's computes (endpoints): branch, read-write or read-only, state (active or idle), autoscaling range, scale-to-zero delay and pooler.", Risk: sdk.RiskRead, Input: in},
			{Name: "usage", Title: "Usage", Description: "A project's usage in the current billing period: compute time, active time, CPU seconds, storage, written data and data transfer, with compute time per branch.", Risk: sdk.RiskRead, Input: in},
			{Name: "create_branch", Title: "Create a branch", Description: "Creates a branch from the default branch (or another parent) with a read-write compute. It counts toward the project's branch and compute quotas. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","name"],"properties":{` + project + `,
					"name":{"type":"string","description":"Name of the new branch, e.g. preview/feature-x"},
					"parent":{"type":"string","description":"Parent branch id (br-…); the default branch when left out"},
					"compute":{"type":"boolean","default":true,"description":"Add a read-write compute so the branch can be connected to"}}}`)},
			{Name: "delete_branch", Title: "Delete a branch", Description: "Deletes a branch with its data and computes, for good. The default branch and protected branches are refused.", Risk: sdk.RiskDestructive, DryRun: true, Input: br},
			{Name: "suspend_endpoint", Title: "Suspend a compute", Description: "Suspends a compute now: open connections drop and the next connection waits for it to start. Undo starts it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: ep},
			{Name: "start_endpoint", Title: "Start a compute", Description: "Starts an idle compute so the next connection doesn't wait. Undo suspends it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: ep},
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
	org := strings.TrimSpace(c.Organization)
	if org != "" && (len(org) > 64 || !orgRe.MatchString(org)) {
		return errors.New("the organization is its id, like org-morning-bread-12345678 (Organization settings)")
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
		if !tokenRe.MatchString(t) {
			return errors.New("the stored API key doesn't look like a Neon API key")
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
	m.set.Put(id, &conn{api: api, org: org})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Neon refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API key isn't allowed to do this in Neon")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

type project struct {
	ID                   string  `json:"id"`
	Name                 string  `json:"name"`
	RegionID             string  `json:"region_id"`
	PgVersion            int     `json:"pg_version"`
	OrgID                string  `json:"org_id"`
	CreatedAt            string  `json:"created_at"`
	ComputeLastActiveAt  string  `json:"compute_last_active_at"`
	SyntheticStorageSize float64 `json:"synthetic_storage_size"`
	ActiveTimeSeconds    float64 `json:"active_time_seconds"`
	ComputeTimeSeconds   float64 `json:"compute_time_seconds"`
	CPUUsedSec           float64 `json:"cpu_used_sec"`
	WrittenDataBytes     float64 `json:"written_data_bytes"`
	DataTransferBytes    float64 `json:"data_transfer_bytes"`
	DataStorageBytesHour float64 `json:"data_storage_bytes_hour"`
	PeriodStart          string  `json:"consumption_period_start"`
	PeriodEnd            string  `json:"consumption_period_end"`
}

type branch struct {
	ID                 string  `json:"id"`
	ProjectID          string  `json:"project_id"`
	ParentID           string  `json:"parent_id"`
	Name               string  `json:"name"`
	CurrentState       string  `json:"current_state"`
	PendingState       string  `json:"pending_state"`
	Default            bool    `json:"default"`
	Primary            bool    `json:"primary"`
	Protected          bool    `json:"protected"`
	LogicalSize        float64 `json:"logical_size"`
	CreatedAt          string  `json:"created_at"`
	UpdatedAt          string  `json:"updated_at"`
	ComputeTimeSeconds float64 `json:"compute_time_seconds"`
	ActiveTimeSeconds  float64 `json:"active_time_seconds"`
	CPUUsedSec         float64 `json:"cpu_used_sec"`
}

func (b branch) isDefault() bool { return b.Default || b.Primary }

type endpoint struct {
	ID                    string  `json:"id"`
	ProjectID             string  `json:"project_id"`
	BranchID              string  `json:"branch_id"`
	Host                  string  `json:"host"`
	Type                  string  `json:"type"`
	CurrentState          string  `json:"current_state"`
	PendingState          string  `json:"pending_state"`
	RegionID              string  `json:"region_id"`
	MinCU                 float64 `json:"autoscaling_limit_min_cu"`
	MaxCU                 float64 `json:"autoscaling_limit_max_cu"`
	SuspendTimeoutSeconds int     `json:"suspend_timeout_seconds"`
	Disabled              bool    `json:"disabled"`
	PoolerEnabled         bool    `json:"pooler_enabled"`
	LastActive            string  `json:"last_active"`
}

type operation struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Status string `json:"status"`
}

func ops(os []operation) []map[string]any {
	out := []map[string]any{}
	for _, o := range os {
		out = append(out, map[string]any{"id": o.ID, "action": o.Action, "status": o.Status})
	}
	return out
}

func human(b float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", b)
	}
	return fmt.Sprintf("%.1f %s", b, units[i])
}

func hours(sec float64) string { return fmt.Sprintf("%.2f h", sec/3600) }

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// projects lists every project, following Neon's cursor (bounded).
func (c *conn) projects(ctx context.Context) ([]project, error) {
	var all []project
	cursor := ""
	for page := 0; page < 10; page++ {
		q := url.Values{"limit": {"400"}}
		if c.org != "" {
			q.Set("org_id", c.org)
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var res struct {
			Projects   []project `json:"projects"`
			Pagination *struct {
				Cursor string `json:"cursor"`
			} `json:"pagination"`
		}
		if err := c.do(ctx, http.MethodGet, "/projects", q, nil, &res); err != nil {
			return nil, err
		}
		all = append(all, res.Projects...)
		if len(res.Projects) < 400 || res.Pagination == nil || res.Pagination.Cursor == "" || res.Pagination.Cursor == cursor {
			break
		}
		cursor = res.Pagination.Cursor
	}
	return all, nil
}

func notFound(err error, what string) error {
	if rest.IsStatus(err, http.StatusNotFound) {
		return fmt.Errorf("there's no %s (or the API key can't see it)", what)
	}
	return err
}

func (c *conn) project(ctx context.Context, id string) (project, error) {
	var res struct {
		Project project `json:"project"`
	}
	if err := c.do(ctx, http.MethodGet, "/projects/"+url.PathEscape(id), nil, nil, &res); err != nil {
		return project{}, notFound(err, "project "+id)
	}
	if res.Project.ID != id {
		return project{}, errors.New("unexpected project from Neon")
	}
	return res.Project, nil
}

func (c *conn) branches(ctx context.Context, pid string) ([]branch, error) {
	var res struct {
		Branches []branch `json:"branches"`
	}
	if err := c.do(ctx, http.MethodGet, "/projects/"+url.PathEscape(pid)+"/branches", nil, nil, &res); err != nil {
		return nil, notFound(err, "project "+pid)
	}
	return res.Branches, nil
}

func (c *conn) branch(ctx context.Context, pid, bid string) (branch, error) {
	var res struct {
		Branch branch `json:"branch"`
	}
	if err := c.do(ctx, http.MethodGet, "/projects/"+url.PathEscape(pid)+"/branches/"+url.PathEscape(bid), nil, nil, &res); err != nil {
		return branch{}, notFound(err, "branch "+bid+" in project "+pid)
	}
	if res.Branch.ID != bid {
		// The id goes into the delete's path.
		return branch{}, errors.New("unexpected branch from Neon")
	}
	return res.Branch, nil
}

func (c *conn) endpoints(ctx context.Context, pid string) ([]endpoint, error) {
	var res struct {
		Endpoints []endpoint `json:"endpoints"`
	}
	if err := c.do(ctx, http.MethodGet, "/projects/"+url.PathEscape(pid)+"/endpoints", nil, nil, &res); err != nil {
		return nil, notFound(err, "project "+pid)
	}
	return res.Endpoints, nil
}

func (c *conn) endpoint(ctx context.Context, pid, eid string) (endpoint, error) {
	var res struct {
		Endpoint endpoint `json:"endpoint"`
	}
	if err := c.do(ctx, http.MethodGet, "/projects/"+url.PathEscape(pid)+"/endpoints/"+url.PathEscape(eid), nil, nil, &res); err != nil {
		return endpoint{}, notFound(err, "compute "+eid+" in project "+pid)
	}
	if res.Endpoint.ID != eid {
		return endpoint{}, errors.New("unexpected compute from Neon")
	}
	return res.Endpoint, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ps, err := c.projects(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d projects", len(ps))}
}

type input struct {
	Project  string `json:"project"`
	Branch   string `json:"branch"`
	Endpoint string `json:"endpoint"`
	Name     string `json:"name"`
	Parent   string `json:"parent"`
	Compute  *bool  `json:"compute"`
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
	if call.Action == "projects" {
		ps, err := c.projects(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ps {
			row := map[string]any{"id": x.ID, "name": x.Name, "region": x.RegionID, "postgres": x.PgVersion, "created": x.CreatedAt, "storage": human(x.SyntheticStorageSize)}
			if x.OrgID != "" {
				row["organization"] = x.OrgID
			}
			if x.ComputeLastActiveAt != "" {
				row["lastActive"] = x.ComputeLastActiveAt
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	}
	switch call.Action {
	case "branches", "endpoints", "usage", "create_branch", "delete_branch", "suspend_endpoint", "start_endpoint":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	pid, err := check(projectRe, p.Project, projectMsg)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "branches":
		bs, err := c.branches(ctx, pid)
		if err != nil {
			return sdk.Result{}, err
		}
		byID := map[string]string{}
		for _, b := range bs {
			byID[b.ID] = b.Name
		}
		out := []map[string]any{}
		for _, b := range bs {
			row := map[string]any{"id": b.ID, "name": b.Name, "default": b.isDefault(), "protected": b.Protected, "state": b.CurrentState,
				"size": human(b.LogicalSize), "computeTime": hours(b.ComputeTimeSeconds), "created": b.CreatedAt}
			if b.ParentID != "" {
				row["parent"] = b.ParentID
				if n := byID[b.ParentID]; n != "" {
					row["parentName"] = n
				}
			}
			if b.PendingState != "" {
				row["pendingState"] = b.PendingState
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "endpoints":
		es, err := c.endpoints(ctx, pid)
		if err != nil {
			return sdk.Result{}, err
		}
		names := map[string]string{}
		if bs, err := c.branches(ctx, pid); err == nil {
			for _, b := range bs {
				names[b.ID] = b.Name
			}
		}
		out := []map[string]any{}
		for _, e := range es {
			out = append(out, endpointOut(e, names))
		}
		return sdk.JSON(out)

	case "usage":
		pr, err := c.project(ctx, pid)
		if err != nil {
			return sdk.Result{}, err
		}
		bs, err := c.branches(ctx, pid)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.Slice(bs, func(i, j int) bool { return bs[i].ComputeTimeSeconds > bs[j].ComputeTimeSeconds })
		per := []map[string]any{}
		for _, b := range bs {
			per = append(per, map[string]any{"branch": b.ID, "name": b.Name, "computeTime": hours(b.ComputeTimeSeconds), "activeTime": hours(b.ActiveTimeSeconds), "size": human(b.LogicalSize)})
		}
		return sdk.JSON(map[string]any{"project": pr.ID, "name": pr.Name, "periodStart": pr.PeriodStart, "periodEnd": pr.PeriodEnd,
			"computeTime": hours(pr.ComputeTimeSeconds), "computeSeconds": int64(pr.ComputeTimeSeconds), "activeTime": hours(pr.ActiveTimeSeconds),
			"cpuSeconds": int64(pr.CPUUsedSec), "storage": human(pr.SyntheticStorageSize), "storageBytes": int64(pr.SyntheticStorageSize),
			"writtenData": human(pr.WrittenDataBytes), "dataTransfer": human(pr.DataTransferBytes), "branches": per})

	case "create_branch":
		return c.createBranch(ctx, call, pid, p)

	case "delete_branch":
		bid, err := check(branchRe, p.Branch, branchMsg)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.deleteBranch(ctx, call, pid, bid)

	case "suspend_endpoint", "start_endpoint":
		eid, err := check(endpointRe, p.Endpoint, endpointMsg)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.setEndpoint(ctx, call, pid, eid)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func endpointOut(e endpoint, names map[string]string) map[string]any {
	row := map[string]any{"id": e.ID, "branch": e.BranchID, "type": e.Type, "state": e.CurrentState, "host": e.Host, "region": e.RegionID,
		"minCU": e.MinCU, "maxCU": e.MaxCU, "disabled": e.Disabled, "pooler": e.PoolerEnabled}
	if n := names[e.BranchID]; n != "" {
		row["branchName"] = n
	}
	if e.PendingState != "" {
		row["pendingState"] = e.PendingState
	}
	switch {
	case e.SuspendTimeoutSeconds < 0:
		row["scaleToZero"] = "never"
	case e.SuspendTimeoutSeconds == 0:
		row["scaleToZero"] = "default (5 minutes)"
	default:
		row["scaleToZero"] = fmt.Sprintf("after %ds", e.SuspendTimeoutSeconds)
	}
	if e.LastActive != "" {
		row["lastActive"] = e.LastActive
	}
	return row
}

func (c *conn) createBranch(ctx context.Context, call sdk.Call, pid string, p input) (sdk.Result, error) {
	name := strings.TrimSpace(p.Name)
	if !nameRe.MatchString(name) || strings.Contains(name, "..") {
		return sdk.Result{}, errors.New("the branch name is letters, digits and . _ / - (up to 128), starting with a letter or digit")
	}
	parent := ""
	if strings.TrimSpace(p.Parent) != "" {
		var err error
		if parent, err = check(branchRe, p.Parent, "the parent is a branch id, like br-wispy-dew-591433 (see branches)"); err != nil {
			return sdk.Result{}, err
		}
	}
	compute := p.Compute == nil || *p.Compute
	bs, err := c.branches(ctx, pid)
	if err != nil {
		return sdk.Result{}, err
	}
	parentName := ""
	for _, b := range bs {
		if b.Name == name {
			return sdk.JSON(map[string]any{"project": pid, "branch": b.ID, "name": b.Name, "note": "nothing to change: a branch with this name exists"})
		}
		if (parent == "" && b.isDefault()) || b.ID == parent {
			parentName = b.Name
			if parent == "" {
				parent = b.ID
			}
		}
	}
	if parentName == "" {
		if parent != "" {
			return sdk.Result{}, fmt.Errorf("there's no branch %s in project %s", parent, pid)
		}
		return sdk.Result{}, errors.New("couldn't find the project's default branch; name a parent")
	}
	if call.DryRun {
		after := map[string]any{"name": name, "parent": parentName, "compute": compute}
		sum := fmt.Sprintf("Create branch %s from %s in project %s", name, parentName, pid)
		if compute {
			sum += ", with a read-write compute (counts toward compute usage)"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "branch " + name + " in project " + pid, Op: "create", After: mustJSON(after)}}}}, nil
	}
	body := map[string]any{"branch": map[string]any{"name": name, "parent_id": parent}}
	if compute {
		body["endpoints"] = []map[string]any{{"type": "read_write"}}
	}
	// Only the branch, its computes and operations are decoded: the answer
	// also carries connection URIs with passwords, which are never read.
	var res struct {
		Branch     branch      `json:"branch"`
		Endpoints  []endpoint  `json:"endpoints"`
		Operations []operation `json:"operations"`
	}
	if err := c.do(ctx, http.MethodPost, "/projects/"+url.PathEscape(pid)+"/branches", nil, body, &res); err != nil {
		return sdk.Result{}, err
	}
	if !branchRe.MatchString(res.Branch.ID) {
		return sdk.Result{}, errors.New("unexpected answer from Neon: no branch id")
	}
	eps := []map[string]any{}
	for _, e := range res.Endpoints {
		eps = append(eps, endpointOut(e, map[string]string{res.Branch.ID: res.Branch.Name}))
	}
	out, err := sdk.JSON(map[string]any{"project": pid, "branch": res.Branch.ID, "name": res.Branch.Name, "parent": parentName, "endpoints": eps, "operations": ops(res.Operations)})
	out.Undo = sdk.UndoWith("delete_branch", map[string]string{"project": pid, "branch": res.Branch.ID}, "Delete branch "+name)
	return out, err
}

func (c *conn) deleteBranch(ctx context.Context, call sdk.Call, pid, bid string) (sdk.Result, error) {
	b, err := c.branch(ctx, pid, bid)
	if err != nil {
		return sdk.Result{}, err
	}
	if b.isDefault() {
		return sdk.Result{}, fmt.Errorf("%s is the project's default branch; it isn't deleted from here", b.Name)
	}
	if b.Protected {
		return sdk.Result{}, fmt.Errorf("%s is a protected branch; remove its protection in the Neon console first", b.Name)
	}
	label := fmt.Sprintf("branch %s (%s) in project %s", b.Name, b.ID, pid)
	if call.DryRun {
		sum := fmt.Sprintf("Delete %s with its %s of data and its computes, for good", label, human(b.LogicalSize))
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: label, Op: "delete", Before: mustJSON(map[string]any{"name": b.Name, "size": human(b.LogicalSize), "state": b.CurrentState})}}}}, nil
	}
	var res struct {
		Operations []operation `json:"operations"`
	}
	if err := c.do(ctx, http.MethodDelete, "/projects/"+url.PathEscape(pid)+"/branches/"+url.PathEscape(b.ID), nil, nil, &res); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"project": pid, "branch": b.ID, "name": b.Name, "deleted": true, "operations": ops(res.Operations)})
}

func (c *conn) setEndpoint(ctx context.Context, call sdk.Call, pid, eid string) (sdk.Result, error) {
	suspend := call.Action == "suspend_endpoint"
	e, err := c.endpoint(ctx, pid, eid)
	if err != nil {
		return sdk.Result{}, err
	}
	if suspend && e.CurrentState == "idle" {
		return sdk.JSON(map[string]any{"project": pid, "endpoint": e.ID, "state": e.CurrentState, "note": "nothing to change: it is already suspended"})
	}
	if !suspend && e.CurrentState == "active" {
		return sdk.JSON(map[string]any{"project": pid, "endpoint": e.ID, "state": e.CurrentState, "note": "nothing to change: it is already running"})
	}
	if e.Disabled {
		return sdk.Result{}, fmt.Errorf("compute %s is disabled", e.ID)
	}
	verb, op, after, back := "Start", "start", "active", "suspend_endpoint"
	if suspend {
		verb, op, after, back = "Suspend", "suspend", "idle", "start_endpoint"
	}
	label := fmt.Sprintf("compute %s (%s, branch %s, project %s)", e.ID, e.Type, e.BranchID, pid)
	if call.DryRun {
		sum := verb + " " + label
		if suspend {
			sum += ": open connections drop and the next one waits for it to start"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: label, Op: op, Before: mustJSON(map[string]string{"state": e.CurrentState}), After: mustJSON(map[string]string{"state": after})}}}}, nil
	}
	var res struct {
		Endpoint   endpoint    `json:"endpoint"`
		Operations []operation `json:"operations"`
	}
	if err := c.do(ctx, http.MethodPost, "/projects/"+url.PathEscape(pid)+"/endpoints/"+url.PathEscape(e.ID)+"/"+op, nil, nil, &res); err != nil {
		return sdk.Result{}, err
	}
	out, err := sdk.JSON(map[string]any{"project": pid, "endpoint": e.ID, "requested": op, "operations": ops(res.Operations)})
	undo := "Start " + e.ID + " again"
	if !suspend {
		undo = "Suspend " + e.ID + " again"
	}
	out.Undo = sdk.UndoWith(back, map[string]string{"project": pid, "endpoint": e.ID}, undo)
	return out, err
}
