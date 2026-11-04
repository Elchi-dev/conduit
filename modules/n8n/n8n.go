// Package n8n works with an n8n automation server through its public API
// (X-N8N-API-KEY): workflows, turning them on and off, and their executions.
//
// The public API has no call that runs a workflow, so this module doesn't
// start one; a workflow with a Webhook trigger can be called with the web
// module instead.
package n8n

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

// Config is one n8n server.
type Config struct {
	URL    string `json:"url"`    // e.g. https://n8n.example.com
	APIKey string `json:"apiKey"` // secret:// API key
}

type conn struct {
	api    *rest.Client
	origin string // for links to workflows
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the n8n module.
func New() *Module { return &Module{} }

// Workflow ids are short alphanumeric strings (numbers on old versions).
var idRe = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

var statuses = []string{"success", "error", "running", "waiting", "canceled"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	wf := `{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Workflow id (see workflows)"}}}`
	return sdk.Manifest{
		ID: "n8n", Name: "n8n", Version: "0.1.0", Category: "Automation", Icon: "workflow",
		Description: "n8n workflows and their executions: what ran, what failed, and turning workflows on or off.",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://n8n.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"API key (Settings, n8n API)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "workflows", Title: "Workflows", Description: "Workflows with whether they're active, their tags and when they changed.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"active":{"type":"boolean","description":"Only active (true) or inactive (false) ones"}}}`)},
			{Name: "activate", Title: "Activate a workflow", Description: "Turns on the workflow's triggers. Undo deactivates it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(wf)},
			{Name: "deactivate", Title: "Deactivate a workflow", Description: "Turns off the workflow's triggers. Undo activates it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(wf)},
			{Name: "executions", Title: "Executions", Description: "Recent executions, newest first, optionally of one workflow or with one status.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"workflow":{"type":"string","description":"Workflow id"},"status":{"type":"string","enum":["success","error","running","waiting","canceled"]},"limit":{"type":"integer","default":20,"maximum":100}}}`)},
			{Name: "failed_executions", Title: "Failed executions", Description: "Recent executions that ended in an error.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"workflow":{"type":"string"},"limit":{"type":"integer","default":20,"maximum":100}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is like https://n8n.example.com")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	key := c.APIKey
	root := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1")
	api := rest.New(root+"/api/v1", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, key)
		if err != nil {
			return err
		}
		r.Header.Set("X-N8N-API-KEY", strings.TrimSpace(k))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second) // through the instance's network, if any
	}
	// The key travels in X-N8N-API-KEY, which Go would forward to another host.
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api, origin: root})
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
	var r struct {
		Data []workflow `json:"data"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/workflows", url.Values{"limit": {"1"}}, nil, &r); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "n8n refused the API key"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "API reachable"}
}

type workflow struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Active    bool   `json:"active"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	Tags      []struct {
		Name string `json:"name"`
	} `json:"tags"`
	Nodes []struct {
		Type string `json:"type"`
	} `json:"nodes"`
}

func (c *conn) summary(w workflow) map[string]any {
	tags := []string{}
	for _, t := range w.Tags {
		tags = append(tags, t.Name)
	}
	return map[string]any{"id": w.ID, "name": w.Name, "active": w.Active, "tags": tags, "nodes": len(w.Nodes), "updated": w.UpdatedAt,
		"url": c.origin + "/workflow/" + w.ID}
}

// workflows lists every workflow (up to 1000), following the cursor.
func (c *conn) workflows(ctx context.Context, active *bool) ([]workflow, error) {
	var all []workflow
	cursor := ""
	for i := 0; i < 10; i++ {
		q := url.Values{"limit": {"100"}, "excludePinnedData": {"true"}}
		if active != nil {
			q.Set("active", strconv.FormatBool(*active))
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var r struct {
			Data       []workflow `json:"data"`
			NextCursor *string    `json:"nextCursor"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/workflows", q, nil, &r); err != nil {
			return nil, err
		}
		all = append(all, r.Data...)
		if r.NextCursor == nil || *r.NextCursor == "" || len(r.Data) == 0 {
			break
		}
		cursor = *r.NextCursor
	}
	return all, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		ID       string `json:"id"`
		Active   *bool  `json:"active"`
		Workflow string `json:"workflow"`
		Status   string `json:"status"`
		Limit    int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "workflows":
		list, err := c.workflows(ctx, p.Active)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, w := range list {
			out = append(out, c.summary(w))
		}
		return sdk.JSON(out)

	case "activate", "deactivate":
		if !idRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("enter the workflow id (letters and digits)")
		}
		on := call.Action == "activate"
		path := "/workflows/" + p.ID
		var w workflow
		if _, err := c.api.Do(ctx, http.MethodGet, path, url.Values{"excludePinnedData": {"true"}}, nil, &w); err != nil {
			return sdk.Result{}, err
		}
		if w.Active == on {
			return sdk.Result{}, fmt.Errorf("%s is already %s", w.Name, map[bool]string{true: "active", false: "inactive"}[on])
		}
		back := "activate"
		if on {
			back = "deactivate"
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"active": w.Active})
			after, _ := json.Marshal(map[string]any{"active": on})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s workflow %q", upper(call.Action), w.Name),
				Changes: []sdk.Change{{Target: "workflow " + w.Name, Op: call.Action, Before: before, After: after}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodPost, path+"/"+call.Action, nil, nil, &w); err != nil {
			if rest.IsStatus(err, http.StatusBadRequest) && on {
				return sdk.Result{}, fmt.Errorf("n8n won't activate %s (it needs a trigger node that can run on its own): %v", p.ID, err)
			}
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"id": p.ID, "name": w.Name, "active": on})
		res.Undo = sdk.UndoWith(back, map[string]any{"id": p.ID}, fmt.Sprintf("%s %s", upper(back), w.Name))
		return res, err

	case "executions", "failed_executions":
		status := p.Status
		if call.Action == "failed_executions" {
			status = "error"
		}
		q := url.Values{"includeData": {"false"}}
		if status != "" {
			ok := false
			for _, s := range statuses {
				ok = ok || s == status
			}
			if !ok {
				return sdk.Result{}, fmt.Errorf("the status is one of %s", strings.Join(statuses, ", "))
			}
			q.Set("status", status)
		}
		if p.Workflow != "" {
			if !idRe.MatchString(p.Workflow) {
				return sdk.Result{}, errors.New("the workflow id is letters and digits")
			}
			q.Set("workflowId", p.Workflow)
		}
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 20
		}
		q.Set("limit", strconv.Itoa(limit))
		var r struct {
			Data []struct {
				ID         flexID  `json:"id"`
				Finished   bool    `json:"finished"`
				Mode       string  `json:"mode"`
				Status     string  `json:"status"`
				StartedAt  string  `json:"startedAt"`
				StoppedAt  *string `json:"stoppedAt"`
				WorkflowID flexID  `json:"workflowId"`
				RetryOf    *string `json:"retryOf"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/executions", q, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		names := map[string]string{}
		if len(r.Data) > 0 {
			if list, err := c.workflows(ctx, nil); err == nil {
				for _, w := range list {
					names[w.ID] = w.Name
				}
			}
		}
		out := []map[string]any{}
		for _, e := range r.Data {
			row := map[string]any{"id": string(e.ID), "workflowId": string(e.WorkflowID), "workflow": names[string(e.WorkflowID)], "status": e.Status, "mode": e.Mode, "started": e.StartedAt,
				"url": c.origin + "/workflow/" + string(e.WorkflowID) + "/executions/" + string(e.ID)}
			if e.StoppedAt != nil {
				row["stopped"] = *e.StoppedAt
				if a, err1 := time.Parse(time.RFC3339, e.StartedAt); err1 == nil {
					if b, err2 := time.Parse(time.RFC3339, *e.StoppedAt); err2 == nil {
						row["seconds"] = b.Sub(a).Seconds()
					}
				}
			}
			if e.RetryOf != nil {
				row["retryOf"] = *e.RetryOf
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// flexID is an id n8n sends as a string or, on old versions, a number.
type flexID string

func (f *flexID) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*f = flexID(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexID(n.String())
	return nil
}

func upper(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
