// Package terraformcloud works with HCP Terraform (Terraform Cloud) or a
// Terraform Enterprise installation through its API and a token:
// organizations, workspaces (lock state and current run), runs with their
// plan summary, queueing plan-only runs, applying a planned run with a
// preview of what it changes and destroys, discarding and cancelling runs,
// and locking and unlocking workspaces.
package terraformcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Config is one HCP Terraform or Terraform Enterprise account.
type Config struct {
	Token        string `json:"token"`        // secret:// user or team API token
	Host         string `json:"host"`         // app.terraform.io unless Terraform Enterprise
	Organization string `json:"organization"` // default organization; optional
	Fingerprint  string `json:"fingerprint"`  // Terraform Enterprise with a self-signed certificate
}

type conn struct {
	api  *rest.Client
	org  string
	host string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://<host> (tests).
	Base string
}

// New returns the Terraform Cloud module.
func New() *Module { return &Module{} }

const defaultHost = "app.terraform.io"

var (
	hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))*(:[0-9]{1,5})?$`)
	orgRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)
	wsRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,90}$`)
	wsIDRe = regexp.MustCompile(`^ws-[A-Za-z0-9]{16}$`)
	runRe  = regexp.MustCompile(`^run-[A-Za-z0-9]{16}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	org := `"organization":{"type":"string","description":"Organization (the instance's default when empty)"}`
	ws := `"workspace":{"type":"string","description":"Workspace name or id (ws-…)"}`
	run := `"run":{"type":"string","description":"Run id (run-…, see runs)"}`
	wsIn := `{"type":"object","required":["workspace"],"properties":{` + org + `,` + ws + `}}`
	runIn := `{"type":"object","required":["run"],"properties":{` + run + `,"comment":{"type":"string","maxLength":2000}}}`
	return sdk.Manifest{
		ID: "terraformcloud", Name: "HCP Terraform", Version: "0.1.0", Category: "Infrastructure", Icon: "layers",
		Description: "HCP Terraform (Terraform Cloud) and Terraform Enterprise: workspaces, runs and plan summaries, plan-only runs, apply with a preview, lock and unlock.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"User or team API token (User settings, Tokens; or the team's API token). Its permissions decide what works"},
			"host":{"type":"string","default":"app.terraform.io","description":"Host name: app.terraform.io, app.eu.terraform.io, or your Terraform Enterprise host"},
			"organization":{"type":"string","description":"Default organization, used when an action names none"},
			"fingerprint":{"type":"string","description":"Terraform Enterprise only: SHA-256 fingerprint of a self-signed certificate"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "organizations", Title: "Organizations", Description: "The organizations the token can see.", Risk: sdk.RiskRead},
			{Name: "workspaces", Title: "Workspaces", Description: "An organization's workspaces: locked or not, the current run's status, resource count, Terraform version, VCS repository.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + org + `,"search":{"type":"string","description":"Only names containing this"}}}`)},
			{Name: "workspace", Title: "Workspace status", Description: "One workspace: lock state and who holds it, settings, and the current run with its plan summary.", Risk: sdk.RiskRead,
				Input: sdk.Schema(wsIn)},
			{Name: "runs", Title: "Runs", Description: "A workspace's recent runs with status, source, message and plan summary (adds, changes, destroys).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["workspace"],"properties":{` + org + `,` + ws + `,"limit":{"type":"integer","default":20,"maximum":100}}}`)},
			{Name: "run", Title: "Run and plan summary", Description: "One run: status, what you can do with it next, and the plan's resource additions, changes, destructions and imports.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["run"],"properties":{` + run + `}}`)},
			{Name: "queue_plan", Title: "Queue a plan-only run", Description: "Starts a speculative plan that can't be applied, to see what would change. Providers and data sources run during a plan.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["workspace"],"properties":{` + org + `,` + ws + `,"message":{"type":"string","maxLength":500}}}`)},
			{Name: "apply_run", Title: "Apply a run", Description: "Confirms a planned run so Terraform applies it to real infrastructure. The preview shows how many resources it adds, changes and destroys. No undo.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(runIn)},
			{Name: "discard_run", Title: "Discard a run", Description: "Discards a run that's waiting for confirmation; nothing is applied.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(runIn)},
			{Name: "cancel_run", Title: "Cancel a run", Description: "Interrupts a run that's planning or applying (Terraform stops gracefully; an apply may be left part done).", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(runIn)},
			{Name: "lock_workspace", Title: "Lock a workspace", Description: "Locks the workspace so no run can apply. Undo unlocks.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["workspace"],"properties":{` + org + `,` + ws + `,"reason":{"type":"string","maxLength":500}}}`)},
			{Name: "unlock_workspace", Title: "Unlock a workspace", Description: "Unlocks a workspace the token's user locked. Undo locks it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(wsIn)},
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
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	host := strings.ToLower(strings.TrimSpace(c.Host))
	host = strings.TrimSuffix(strings.TrimPrefix(host, "https://"), "/")
	if host == "" {
		host = defaultHost
	}
	if !hostRe.MatchString(host) {
		return errors.New("the host is a host name like app.terraform.io or tfe.example.com (https is always used)")
	}
	org := strings.TrimSpace(c.Organization)
	if org != "" && !orgRe.MatchString(org) {
		return errors.New("the organization is its name: letters, digits, - and _")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, false)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h)
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	base := "https://" + host
	if m.Base != "" {
		base = m.Base
	}
	tok := c.Token
	api := rest.New(base+"/api/v2", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, org: org, host: host})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Terraform refused the token")
	case rest.IsStatus(err, http.StatusNotFound):
		// The API answers 404 for things the token may not see, too.
		return fmt.Errorf("there's no %s (or the token can't see it)", what)
	}
	return err
}

// post sends a JSON:API body.
func (c *conn) post(ctx context.Context, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	res, err := c.api.Send(ctx, http.MethodPost, path, nil, rd, http.Header{"Content-Type": {"application/vnd.api+json"}, "Accept": {"application/vnd.api+json"}})
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return errors.New("unexpected answer from Terraform")
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
	var acct struct {
		Data struct {
			Attributes struct {
				Username string `json:"username"`
			} `json:"attributes"`
		} `json:"data"`
	}
	_, err = c.api.Do(ctx, http.MethodGet, "/account/details", nil, nil, &acct)
	switch {
	case err == nil:
		return sdk.Health{Status: "ok", Message: "signed in as " + acct.Data.Attributes.Username + " on " + c.host}
	case rest.IsStatus(err, http.StatusUnauthorized):
		return sdk.Health{Status: "down", Message: "Terraform refused the token"}
	case !rest.IsStatus(err, http.StatusNotFound) && !rest.IsStatus(err, http.StatusForbidden):
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	// A team token has no account; check it can list organizations.
	var orgs struct {
		Data []any `json:"data"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/organizations", nil, nil, &orgs); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "organization").Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("team token on %s · %d organizations", c.host, len(orgs.Data))}
}

type relation struct {
	Data *struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
}

func (r relation) id() string {
	if r.Data == nil {
		return ""
	}
	return r.Data.ID
}

type workspace struct {
	ID         string `json:"id"`
	Attributes struct {
		Name             string `json:"name"`
		Locked           bool   `json:"locked"`
		ExecutionMode    string `json:"execution-mode"`
		TerraformVersion string `json:"terraform-version"`
		AutoApply        bool   `json:"auto-apply"`
		ResourceCount    int    `json:"resource-count"`
		Updated          string `json:"updated-at"`
		WorkingDirectory string `json:"working-directory"`
		VCSRepo          *struct {
			Identifier string `json:"identifier"`
			Branch     string `json:"branch"`
		} `json:"vcs-repo"`
	} `json:"attributes"`
	Relationships struct {
		CurrentRun   relation `json:"current-run"`
		LockedBy     relation `json:"locked-by"`
		Organization relation `json:"organization"`
	} `json:"relationships"`
}

type run struct {
	ID         string `json:"id"`
	Attributes struct {
		Status     string `json:"status"`
		Message    string `json:"message"`
		Source     string `json:"source"`
		Created    string `json:"created-at"`
		IsDestroy  bool   `json:"is-destroy"`
		PlanOnly   bool   `json:"plan-only"`
		HasChanges bool   `json:"has-changes"`
		AutoApply  bool   `json:"auto-apply"`
		Actions    struct {
			Cancelable  bool `json:"is-cancelable"`
			Confirmable bool `json:"is-confirmable"`
			Discardable bool `json:"is-discardable"`
		} `json:"actions"`
		TargetAddrs []string `json:"target-addrs"`
		Replace     []string `json:"replace-addrs"`
	} `json:"attributes"`
	Relationships struct {
		Plan      relation `json:"plan"`
		Apply     relation `json:"apply"`
		Workspace relation `json:"workspace"`
	} `json:"relationships"`
}

type planDoc struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Status       string `json:"status"`
		HasChanges   bool   `json:"has-changes"`
		Additions    *int   `json:"resource-additions"`
		Changes      *int   `json:"resource-changes"`
		Destructions *int   `json:"resource-destructions"`
		Imports      *int   `json:"resource-imports"`
	} `json:"attributes"`
}

func n(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func (p *planDoc) counts() map[string]any {
	if p == nil {
		return nil
	}
	a := p.Attributes
	return map[string]any{"status": a.Status, "add": n(a.Additions), "change": n(a.Changes), "destroy": n(a.Destructions), "import": n(a.Imports)}
}

func clip(s string, k int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > k {
		return string(r[:k]) + "…"
	}
	return string(r)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// included finds plan and apply documents in a JSON:API "included" list.
func included(raw []json.RawMessage, id string) *planDoc {
	for _, r := range raw {
		var d planDoc
		if json.Unmarshal(r, &d) == nil && d.ID == id && id != "" {
			return &d
		}
	}
	return nil
}

func (r run) summary(plan *planDoc) map[string]any {
	a := r.Attributes
	out := map[string]any{"id": r.ID, "status": a.Status, "message": clip(a.Message, 300), "source": a.Source, "created": a.Created, "hasChanges": a.HasChanges}
	if a.IsDestroy {
		out["destroyRun"] = true
	}
	if a.PlanOnly {
		out["planOnly"] = true
	}
	if pc := plan.counts(); pc != nil {
		out["plan"] = pc
	}
	var next []string
	if a.Actions.Confirmable {
		next = append(next, "apply_run")
	}
	if a.Actions.Discardable {
		next = append(next, "discard_run")
	}
	if a.Actions.Cancelable {
		next = append(next, "cancel_run")
	}
	if next != nil {
		out["canDo"] = next
	}
	if len(a.TargetAddrs) > 0 {
		out["targets"] = a.TargetAddrs
	}
	return out
}

func (w workspace) summary() map[string]any {
	a := w.Attributes
	out := map[string]any{"id": w.ID, "name": a.Name, "locked": a.Locked, "executionMode": a.ExecutionMode, "terraformVersion": a.TerraformVersion,
		"autoApply": a.AutoApply, "resources": a.ResourceCount, "updated": a.Updated}
	if a.VCSRepo != nil {
		out["repo"], out["branch"] = a.VCSRepo.Identifier, a.VCSRepo.Branch
	}
	if id := w.Relationships.CurrentRun.id(); id != "" {
		out["currentRun"] = id
	}
	if d := w.Relationships.LockedBy.Data; a.Locked && d != nil {
		out["lockedBy"] = map[string]any{"type": strings.TrimSuffix(d.Type, "s"), "id": d.ID}
	}
	return out
}

type input struct {
	Organization string `json:"organization"`
	Workspace    string `json:"workspace"`
	Run          string `json:"run"`
	Search       string `json:"search"`
	Limit        int    `json:"limit"`
	Message      string `json:"message"`
	Comment      string `json:"comment"`
	Reason       string `json:"reason"`
}

func (c *conn) orgName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = c.org
	}
	if s == "" {
		return "", errors.New("name the organization (or set a default organization in the settings)")
	}
	if !orgRe.MatchString(s) {
		return "", fmt.Errorf("%q isn't an organization name", s)
	}
	return s, nil
}

// getWorkspace finds a workspace by id or by organization and name.
func (c *conn) getWorkspace(ctx context.Context, org, ref string) (workspace, []json.RawMessage, error) {
	var doc struct {
		Data     workspace         `json:"data"`
		Included []json.RawMessage `json:"included"`
	}
	ref = strings.TrimSpace(ref)
	q := url.Values{"include": {"current_run"}}
	switch {
	case wsIDRe.MatchString(ref):
		if _, err := c.api.Do(ctx, http.MethodGet, "/workspaces/"+ref, q, nil, &doc); err != nil {
			return doc.Data, nil, friendly(err, "workspace "+ref)
		}
	case wsRe.MatchString(ref):
		o, err := c.orgName(org)
		if err != nil {
			return doc.Data, nil, err
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/organizations/"+o+"/workspaces/"+ref, q, nil, &doc); err != nil {
			return doc.Data, nil, friendly(err, "workspace "+ref+" in "+o)
		}
	default:
		return doc.Data, nil, errors.New("the workspace is its name (letters, digits, - and _) or its id (ws-…)")
	}
	if !wsIDRe.MatchString(doc.Data.ID) {
		return doc.Data, nil, errors.New("unexpected workspace id from Terraform")
	}
	return doc.Data, doc.Included, nil
}

func (c *conn) getRun(ctx context.Context, ref string) (run, *planDoc, error) {
	var doc struct {
		Data     run               `json:"data"`
		Included []json.RawMessage `json:"included"`
	}
	ref = strings.TrimSpace(ref)
	if !runRe.MatchString(ref) {
		return doc.Data, nil, errors.New("the run is its id (run-…, see runs)")
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/runs/"+ref, url.Values{"include": {"plan"}}, nil, &doc); err != nil {
		return doc.Data, nil, friendly(err, "run "+ref)
	}
	if doc.Data.ID != ref {
		return doc.Data, nil, errors.New("unexpected run from Terraform")
	}
	return doc.Data, included(doc.Included, doc.Data.Relationships.Plan.id()), nil
}

// wsName names a run's workspace for previews (its id when it can't be read).
func (c *conn) wsName(ctx context.Context, r run) string {
	id := r.Relationships.Workspace.id()
	if !wsIDRe.MatchString(id) {
		return "its workspace"
	}
	var doc struct {
		Data workspace `json:"data"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/workspaces/"+id, nil, nil, &doc); err != nil || doc.Data.Attributes.Name == "" {
		return id
	}
	return doc.Data.Attributes.Name
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
	for _, s := range []string{p.Message, p.Comment, p.Reason} {
		if len(s) > 2000 {
			return sdk.Result{}, errors.New("the message, comment or reason is too long")
		}
	}
	switch call.Action {
	case "organizations":
		var doc struct {
			Data []struct {
				ID         string `json:"id"`
				Attributes struct {
					Name    string `json:"name"`
					Created string `json:"created-at"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/organizations", url.Values{"page[size]": {"100"}}, nil, &doc); err != nil {
			return sdk.Result{}, friendly(err, "organization")
		}
		out := []map[string]any{}
		for _, o := range doc.Data {
			out = append(out, map[string]any{"name": o.ID, "created": o.Attributes.Created})
		}
		return sdk.JSON(out)

	case "workspaces":
		org, err := c.orgName(p.Organization)
		if err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{"page[size]": {"100"}, "include": {"current_run"}}
		if s := strings.TrimSpace(p.Search); s != "" {
			if !wsRe.MatchString(s) {
				return sdk.Result{}, errors.New("search with letters, digits, - and _")
			}
			q.Set("search[name]", s)
		}
		out := []map[string]any{}
		for pg := 1; pg <= 10; pg++ {
			q.Set("page[number]", strconv.Itoa(pg))
			var doc struct {
				Data     []workspace       `json:"data"`
				Included []json.RawMessage `json:"included"`
				Meta     struct {
					Pagination struct {
						Next *int `json:"next-page"`
					} `json:"pagination"`
				} `json:"meta"`
			}
			if _, err := c.api.Do(ctx, http.MethodGet, "/organizations/"+org+"/workspaces", q, nil, &doc); err != nil {
				return sdk.Result{}, friendly(err, "organization "+org)
			}
			runs := map[string]string{}
			for _, raw := range doc.Included {
				var r run
				if json.Unmarshal(raw, &r) == nil {
					runs[r.ID] = r.Attributes.Status
				}
			}
			for _, w := range doc.Data {
				s := w.summary()
				if st, ok := runs[w.Relationships.CurrentRun.id()]; ok {
					s["currentRunStatus"] = st
				}
				out = append(out, s)
			}
			if doc.Meta.Pagination.Next == nil {
				break
			}
		}
		return sdk.JSON(out)

	case "workspace":
		w, _, err := c.getWorkspace(ctx, p.Organization, p.Workspace)
		if err != nil {
			return sdk.Result{}, err
		}
		out := w.summary()
		if w.Attributes.WorkingDirectory != "" {
			out["workingDirectory"] = w.Attributes.WorkingDirectory
		}
		if id := w.Relationships.CurrentRun.id(); runRe.MatchString(id) {
			if r, plan, err := c.getRun(ctx, id); err == nil {
				out["currentRun"] = r.summary(plan)
			}
		}
		return sdk.JSON(out)

	case "runs":
		w, _, err := c.getWorkspace(ctx, p.Organization, p.Workspace)
		if err != nil {
			return sdk.Result{}, err
		}
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 20
		}
		var doc struct {
			Data     []run             `json:"data"`
			Included []json.RawMessage `json:"included"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/workspaces/"+w.ID+"/runs", url.Values{"page[size]": {strconv.Itoa(limit)}, "include": {"plan"}}, nil, &doc); err != nil {
			return sdk.Result{}, friendly(err, "workspace")
		}
		out := []map[string]any{}
		for _, r := range doc.Data {
			out = append(out, r.summary(included(doc.Included, r.Relationships.Plan.id())))
		}
		return sdk.JSON(out)

	case "run":
		r, plan, err := c.getRun(ctx, p.Run)
		if err != nil {
			return sdk.Result{}, err
		}
		out := r.summary(plan)
		out["workspace"] = c.wsName(ctx, r)
		if len(r.Attributes.Replace) > 0 {
			out["replace"] = r.Attributes.Replace
		}
		return sdk.JSON(out)

	case "queue_plan":
		w, _, err := c.getWorkspace(ctx, p.Organization, p.Workspace)
		if err != nil {
			return sdk.Result{}, err
		}
		msg := strings.TrimSpace(p.Message)
		if msg == "" {
			msg = "Plan-only run queued from Conduit"
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Queue a plan-only run on %s (can't be applied; providers and data sources run during the plan)", w.Attributes.Name),
				Changes: []sdk.Change{{Target: "workspace " + w.Attributes.Name, Op: "plan", After: mustJSON(map[string]any{"planOnly": true, "message": msg})}}}}, nil
		}
		body := map[string]any{"data": map[string]any{"type": "runs",
			"attributes":    map[string]any{"plan-only": true, "message": msg},
			"relationships": map[string]any{"workspace": map[string]any{"data": map[string]any{"type": "workspaces", "id": w.ID}}}}}
		var doc struct {
			Data run `json:"data"`
		}
		if err := c.post(ctx, "/runs", body, &doc); err != nil {
			return sdk.Result{}, friendly(err, "workspace")
		}
		return sdk.JSON(map[string]any{"workspace": w.Attributes.Name, "run": doc.Data.ID, "status": doc.Data.Attributes.Status, "planOnly": true})

	case "apply_run", "discard_run", "cancel_run":
		return c.runAction(ctx, call, p)
	case "lock_workspace", "unlock_workspace":
		return c.lock(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) runAction(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	r, plan, err := c.getRun(ctx, p.Run)
	if err != nil {
		return sdk.Result{}, err
	}
	a := r.Attributes
	verb := strings.TrimSuffix(call.Action, "_run")
	switch call.Action {
	case "apply_run":
		if a.PlanOnly {
			return sdk.Result{}, fmt.Errorf("%s is a plan-only run and can't be applied", r.ID)
		}
		if !a.Actions.Confirmable {
			return sdk.Result{}, fmt.Errorf("%s is %s and isn't waiting for confirmation", r.ID, a.Status)
		}
	case "discard_run":
		if !a.Actions.Discardable {
			return sdk.Result{}, fmt.Errorf("%s is %s and can't be discarded", r.ID, a.Status)
		}
	case "cancel_run":
		if !a.Actions.Cancelable {
			return sdk.Result{}, fmt.Errorf("%s is %s and can't be cancelled", r.ID, a.Status)
		}
	}
	comment := strings.TrimSpace(p.Comment)
	if call.DryRun {
		ws := c.wsName(ctx, r)
		var sum string
		changes := []sdk.Change{}
		switch call.Action {
		case "apply_run":
			pc := plan.counts()
			if pc == nil {
				return sdk.Result{}, errors.New("Terraform didn't return the run's plan, so there's nothing to preview")
			}
			add, chg, del := pc["add"].(int), pc["change"].(int), pc["destroy"].(int)
			lead := ""
			switch {
			case a.IsDestroy:
				lead = fmt.Sprintf("DESTROY RUN: destroys %d resource(s). ", del)
			case del > 0:
				lead = fmt.Sprintf("DESTROYS %d resource(s). ", del)
			}
			sum = fmt.Sprintf("%sApply %s on %s: %d to add, %d to change, %d to destroy", lead, r.ID, ws, add, chg, del)
			if imp := pc["import"].(int); imp > 0 {
				sum += fmt.Sprintf(", %d to import", imp)
			}
			if len(a.TargetAddrs) > 0 {
				sum += " (targeted: " + strings.Join(a.TargetAddrs, ", ") + ")"
			}
			changes = append(changes, sdk.Change{Target: "workspace " + ws, Op: "apply", Before: mustJSON(map[string]any{"status": a.Status}), After: mustJSON(map[string]any{"add": add, "change": chg, "destroy": del, "import": pc["import"], "destroyRun": a.IsDestroy, "message": clip(a.Message, 300)})})
			if del > 0 {
				changes = append(changes, sdk.Change{Target: fmt.Sprintf("%d resource(s) in %s", del, ws), Op: "destroy"})
			}
		case "discard_run":
			sum = fmt.Sprintf("Discard %s on %s (%s); nothing is applied", r.ID, ws, a.Status)
			changes = append(changes, sdk.Change{Target: "run " + r.ID, Op: "discard", Before: mustJSON(map[string]any{"status": a.Status})})
		default:
			sum = fmt.Sprintf("Cancel %s on %s while %s", r.ID, ws, a.Status)
			if a.Status == "applying" {
				sum += "; the apply stops part way and the state keeps what was already done"
			}
			changes = append(changes, sdk.Change{Target: "run " + r.ID, Op: "cancel", Before: mustJSON(map[string]any{"status": a.Status})})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: changes}}, nil
	}
	var body any
	if comment != "" {
		body = map[string]any{"comment": comment}
	}
	if err := c.post(ctx, "/runs/"+r.ID+"/actions/"+verb, body, nil); err != nil {
		if rest.IsStatus(err, http.StatusConflict) {
			return sdk.Result{}, fmt.Errorf("Terraform refused: the run is no longer in a state to %s (%v)", verb, err)
		}
		return sdk.Result{}, friendly(err, "run")
	}
	out := map[string]any{"run": r.ID, "action": verb, "accepted": true}
	if call.Action == "apply_run" {
		out["plan"] = plan.counts()
	}
	return sdk.JSON(out)
}

func (c *conn) lock(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	locking := call.Action == "lock_workspace"
	w, _, err := c.getWorkspace(ctx, p.Organization, p.Workspace)
	if err != nil {
		return sdk.Result{}, err
	}
	name := w.Attributes.Name
	if w.Attributes.Locked == locking {
		state := "unlocked"
		if locking {
			state = "locked"
		}
		return sdk.JSON(map[string]any{"workspace": name, "note": "it's already " + state})
	}
	reason := strings.TrimSpace(p.Reason)
	if call.DryRun {
		sum := fmt.Sprintf("Lock %s so no run can apply until it's unlocked", name)
		if !locking {
			sum = fmt.Sprintf("Unlock %s; queued runs can proceed", name)
			if d := w.Relationships.LockedBy.Data; d != nil {
				sum += fmt.Sprintf(" (locked by %s %s)", strings.TrimSuffix(d.Type, "s"), d.ID)
			}
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "workspace " + name, Op: strings.TrimSuffix(call.Action, "_workspace"),
			Before: mustJSON(map[string]any{"locked": w.Attributes.Locked}), After: mustJSON(map[string]any{"locked": locking, "reason": reason})}}}}, nil
	}
	path := "/workspaces/" + w.ID + "/actions/unlock"
	var body any
	if locking {
		path = "/workspaces/" + w.ID + "/actions/lock"
		if reason == "" {
			reason = "Locked from Conduit"
		}
		body = map[string]any{"reason": reason}
	}
	if err := c.post(ctx, path, body, nil); err != nil {
		if rest.IsStatus(err, http.StatusConflict) {
			return sdk.Result{}, fmt.Errorf("Terraform refused: %v (a lock held by another user or a run needs a force unlock in the web UI)", err)
		}
		return sdk.Result{}, friendly(err, "workspace")
	}
	back, desc := "unlock_workspace", "Unlock "+name
	if !locking {
		back, desc = "lock_workspace", "Lock "+name+" again"
	}
	res, err := sdk.JSON(map[string]any{"workspace": name, "locked": locking})
	res.Undo = sdk.UndoWith(back, map[string]any{"workspace": w.ID}, desc)
	return res, err
}
