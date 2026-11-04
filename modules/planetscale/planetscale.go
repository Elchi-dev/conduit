// Package planetscale reads PlanetScale through its API and a service
// token: organizations, databases, branches (production or development,
// ready, safe migrations) and deploy requests with their state.
//
// It only reads: nothing is deployed, merged or deleted. Passwords and
// connection strings are never requested.
package planetscale

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

// Config is one PlanetScale service token.
type Config struct {
	TokenID      string `json:"tokenId"`      // service token id (plain, or a secret:// reference)
	Token        string `json:"token"`        // secret:// service token
	Organization string `json:"organization"` // optional default organization
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
	// Base replaces https://api.planetscale.com (tests).
	Base string
}

// New returns the PlanetScale module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.planetscale.com"

var (
	nameRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$`)
	idRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{4,64}$`)
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)
)

func checkName(what, s string) (string, error) {
	s = strings.TrimSpace(s)
	if !nameRe.MatchString(s) {
		return "", fmt.Errorf("the %s is its name: lowercase letters, digits, - and _ (see %ss)", what, strings.ReplaceAll(what, " ", "_"))
	}
	return s, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	org := `"organization":{"type":"string","description":"Organization name (see organizations); the configured one when left out"}`
	db := `"database":{"type":"string","description":"Database name (see databases)"}`
	return sdk.Manifest{
		ID: "planetscale", Name: "PlanetScale", Version: "0.1.0", Category: "Development", Icon: "database",
		Description: "PlanetScale organizations, databases, branches and deploy requests, read-only.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["tokenId","token"],"properties":{
			"tokenId":{"type":"string","description":"The service token's id (Organization settings, Service tokens)"},
			"token":{"type":"string","x-secret":true,"description":"The service token; give it read_database, read_branch and read_deploy_request on the databases it should see"},
			"organization":{"type":"string","description":"Organization used when an action doesn't name one"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "organizations", Title: "Organizations", Description: "The organizations the token can see, with plan and database count.", Risk: sdk.RiskRead},
			{Name: "databases", Title: "Databases", Description: "An organization's databases: engine, state, region, plan, production and development branch counts.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + org + `}}`)},
			{Name: "branches", Title: "Branches", Description: "A database's branches: production or development, ready, parent, region, safe migrations.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["database"],"properties":{` + org + `,` + db + `}}`)},
			{Name: "deploy_requests", Title: "Deploy requests", Description: "A database's deploy requests: number, branch into branch, state, deployment state, approved, author and when.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["database"],"properties":{` + org + `,` + db + `,"state":{"type":"string","enum":["open","closed"],"description":"Only open or closed ones"}}}`)},
			{Name: "deploy_request", Title: "Deploy request", Description: "One deploy request with its notes, deployment state and timestamps. Reading only: nothing is deployed.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["database","number"],"properties":{` + org + `,` + db + `,"number":{"type":"integer","minimum":1,"description":"Deploy request number"}}}`)},
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
		return errors.New("store the service token in the vault and enter its secret:// reference")
	}
	tid := strings.TrimSpace(c.TokenID)
	if !strings.HasPrefix(tid, "secret://") && !idRe.MatchString(tid) {
		return errors.New("the token id is the service token's id, shown next to it in Organization settings, Service tokens")
	}
	org := strings.TrimSpace(c.Organization)
	if org != "" && !nameRe.MatchString(org) {
		return errors.New("the organization is its name, lowercase letters, digits, - and _")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Token
	api := rest.New(base+"/v1", func(ctx context.Context, r *http.Request) error {
		i := tid
		if strings.HasPrefix(i, "secret://") {
			var err error
			if i, err = h.Secret(ctx, i); err != nil {
				return err
			}
			if i = strings.TrimSpace(i); !idRe.MatchString(i) {
				return errors.New("the stored token id doesn't look like a PlanetScale service token id")
			}
		}
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if !tokenRe.MatchString(t) {
			return errors.New("the stored token doesn't look like a PlanetScale service token")
		}
		r.Header.Set("Authorization", i+":"+t)
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
		return errors.New("PlanetScale refused the service token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the service token isn't granted this in PlanetScale")
	}
	return err
}

// list reads every page of a list (bounded).
func list[T any](ctx context.Context, c *conn, path string, q url.Values) ([]T, error) {
	var all []T
	if q == nil {
		q = url.Values{}
	}
	q.Set("per_page", "100")
	for page := 1; page <= 10; page++ {
		q.Set("page", strconv.Itoa(page))
		var res struct {
			Data     []T  `json:"data"`
			NextPage *int `json:"next_page"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &res); err != nil {
			return nil, friendly(err)
		}
		all = append(all, res.Data...)
		if res.NextPage == nil || *res.NextPage <= page || len(res.Data) == 0 {
			break
		}
	}
	return all, nil
}

type org struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Plan          string `json:"plan"`
	DatabaseCount int    `json:"database_count"`
	CreatedAt     string `json:"created_at"`
}

type region struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if c.org != "" {
		d, err := list[struct {
			State string `json:"state"`
		}](ctx, c, "/organizations/"+url.PathEscape(c.org)+"/databases", nil)
		if err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Health{Status: "down", Message: "there's no organization " + c.org + " (or the token can't see it)"}
			}
			return sdk.Health{Status: "down", Message: err.Error()}
		}
		return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d databases in %s", len(d), c.org)}
	}
	os, err := list[org](ctx, c, "/organizations", nil)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d organizations", len(os))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Organization string `json:"organization"`
		Database     string `json:"database"`
		State        string `json:"state"`
		Number       int    `json:"number"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if call.Action == "organizations" {
		os, err := list[org](ctx, c, "/organizations", nil)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, o := range os {
			out = append(out, map[string]any{"name": o.Name, "plan": o.Plan, "databases": o.DatabaseCount, "created": o.CreatedAt})
		}
		return sdk.JSON(out)
	}
	switch call.Action {
	case "databases", "branches", "deploy_requests", "deploy_request":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	o := c.org
	if strings.TrimSpace(p.Organization) != "" {
		if o, err = checkName("organization", p.Organization); err != nil {
			return sdk.Result{}, err
		}
	}
	if o == "" {
		return sdk.Result{}, errors.New("name the organization (see organizations), or set one in the settings")
	}
	op := "/organizations/" + url.PathEscape(o)
	if call.Action == "databases" {
		ds, err := list[struct {
			Name        string `json:"name"`
			Kind        string `json:"kind"`
			State       string `json:"state"`
			Plan        string `json:"plan"`
			Region      region `json:"region"`
			Production  int    `json:"production_branches_count"`
			Development int    `json:"development_branches_count"`
			CreatedAt   string `json:"created_at"`
			HTMLURL     string `json:"html_url"`
		}](ctx, c, op+"/databases", nil)
		if err != nil {
			return sdk.Result{}, notFound(err, "organization "+o)
		}
		out := []map[string]any{}
		for _, d := range ds {
			kind := d.Kind
			if kind == "" {
				kind = "mysql"
			}
			out = append(out, map[string]any{"name": d.Name, "engine": kind, "state": d.State, "plan": d.Plan, "region": d.Region.Slug,
				"productionBranches": d.Production, "developmentBranches": d.Development, "created": d.CreatedAt, "url": d.HTMLURL})
		}
		return sdk.JSON(out)
	}
	db, err := checkName("database", p.Database)
	if err != nil {
		return sdk.Result{}, err
	}
	dp := op + "/databases/" + url.PathEscape(db)
	switch call.Action {
	case "branches":
		bs, err := list[struct {
			Name           string `json:"name"`
			Production     bool   `json:"production"`
			Ready          bool   `json:"ready"`
			State          string `json:"state"`
			ParentBranch   string `json:"parent_branch"`
			Region         region `json:"region"`
			SafeMigrations bool   `json:"safe_migrations"`
			CreatedAt      string `json:"created_at"`
			UpdatedAt      string `json:"updated_at"`
			HTMLURL        string `json:"html_url"`
		}](ctx, c, dp+"/branches", nil)
		if err != nil {
			return sdk.Result{}, notFound(err, "database "+db+" in "+o)
		}
		out := []map[string]any{}
		for _, b := range bs {
			row := map[string]any{"name": b.Name, "production": b.Production, "ready": b.Ready, "region": b.Region.Slug, "safeMigrations": b.SafeMigrations,
				"created": b.CreatedAt, "updated": b.UpdatedAt, "url": b.HTMLURL}
			if b.ParentBranch != "" {
				row["parent"] = b.ParentBranch
			}
			if b.State != "" {
				row["state"] = b.State
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "deploy_requests":
		q := url.Values{}
		switch p.State {
		case "":
		case "open", "closed":
			q.Set("state", p.State)
		default:
			return sdk.Result{}, errors.New("state is open or closed")
		}
		ds, err := list[deployRequest](ctx, c, dp+"/deploy-requests", q)
		if err != nil {
			return sdk.Result{}, notFound(err, "database "+db+" in "+o)
		}
		out := []map[string]any{}
		for _, d := range ds {
			out = append(out, d.out(false))
		}
		return sdk.JSON(out)

	case "deploy_request":
		if p.Number < 1 {
			return sdk.Result{}, errors.New("the deploy request is its number (see deploy_requests)")
		}
		var d deployRequest
		if _, err := c.api.Do(ctx, http.MethodGet, dp+"/deploy-requests/"+strconv.Itoa(p.Number), nil, nil, &d); err != nil {
			return sdk.Result{}, notFound(friendly(err), fmt.Sprintf("deploy request %d on %s", p.Number, db))
		}
		if d.Number != p.Number {
			return sdk.Result{}, errors.New("unexpected deploy request from PlanetScale")
		}
		return sdk.JSON(d.out(true))
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func notFound(err error, what string) error {
	if rest.IsStatus(err, http.StatusNotFound) {
		return fmt.Errorf("there's no %s (or the token can't see it)", what)
	}
	return err
}

type deployRequest struct {
	Number          int    `json:"number"`
	Branch          string `json:"branch"`
	IntoBranch      string `json:"into_branch"`
	State           string `json:"state"`
	DeploymentState string `json:"deployment_state"`
	Approved        bool   `json:"approved"`
	Notes           string `json:"notes"`
	HTMLURL         string `json:"html_url"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	ClosedAt        string `json:"closed_at"`
	DeployedAt      string `json:"deployed_at"`
	Actor           *struct {
		DisplayName string `json:"display_name"`
	} `json:"actor"`
	Deployment *struct {
		State      string `json:"state"`
		Deployable bool   `json:"deployable"`
		QueuedAt   string `json:"queued_at"`
		StartedAt  string `json:"started_at"`
		FinishedAt string `json:"finished_at"`
	} `json:"deployment"`
}

func (d deployRequest) out(full bool) map[string]any {
	row := map[string]any{"number": d.Number, "branch": d.Branch, "into": d.IntoBranch, "state": d.State, "deploymentState": d.DeploymentState,
		"approved": d.Approved, "created": d.CreatedAt, "url": d.HTMLURL}
	if d.Actor != nil && d.Actor.DisplayName != "" {
		row["author"] = d.Actor.DisplayName
	}
	for k, v := range map[string]string{"closed": d.ClosedAt, "deployed": d.DeployedAt} {
		if v != "" {
			row[k] = v
		}
	}
	if !full {
		return row
	}
	row["updated"] = d.UpdatedAt
	if n := strings.TrimSpace(d.Notes); n != "" {
		// Free text someone wrote: redacted, then shortened.
		n = rest.Redact(n)
		if r := []rune(n); len(r) > 2000 {
			n = string(r[:2000]) + "…"
		}
		row["notes"] = n
	}
	if dep := d.Deployment; dep != nil {
		x := map[string]any{"state": dep.State, "deployable": dep.Deployable}
		for k, v := range map[string]string{"queued": dep.QueuedAt, "started": dep.StartedAt, "finished": dep.FinishedAt} {
			if v != "" {
				x[k] = v
			}
		}
		row["deployment"] = x
	}
	return row
}
