// Package vercel shows Vercel projects and deployments, redeploys, moves
// production to another deployment (with undo), and cancels builds.
package vercel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Vercel account or team.
type Config struct {
	Token  string `json:"token"`  // secret:// access token
	TeamID string `json:"teamId"` // team_… for a team; empty for a personal account
	API    string `json:"api"`    // default https://api.vercel.com (tests)
}

type conn struct {
	api  *rest.Client
	team string
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Vercel module.
func New() *Module { return &Module{} }

var (
	idRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)
	teamRe = regexp.MustCompile(`^team_[A-Za-z0-9]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	proj := `"project":{"type":"string","description":"Project id or name"}`
	dep := `"deployment":{"type":"string","description":"Deployment id (dpl_…, from Deployments)"}`
	return sdk.Manifest{
		ID: "vercel", Name: "Vercel", Version: "0.1.0", Category: "Development", Icon: "rocket",
		Description: "Projects and deployments: redeploy, move production to another deployment, cancel a build.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An access token (Account settings, Tokens), scoped to the team and with an expiry"},
			"teamId":{"type":"string","description":"team_… for a team (Team settings, General); leave empty for your personal account"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "With their production deployment.", Risk: sdk.RiskRead},
			{Name: "deployments", Title: "Deployments", Description: "Recent deployments: state, address, target, when.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + proj + `,"limit":{"type":"integer","default":20,"maximum":100}}}`)},
			{Name: "redeploy", Title: "Redeploy", Description: "Builds the same commit again. It can put an older deployment's commit in production (destructive).", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["deployment"],"properties":{` + dep + `,"production":{"type":"boolean","description":"Deploy to production"}}}`)},
			{Name: "promote", Title: "Make it production", Description: "Points the production domains at this deployment (promote or roll back). Undo points them back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","deployment"],"properties":{` + proj + `,` + dep + `}}`)},
			{Name: "cancel", Title: "Cancel a build", Risk: sdk.RiskDestructive, Input: sdk.Schema(`{"type":"object","required":["deployment"],"properties":{` + dep + `}}`)},
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
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	if c.TeamID != "" && !teamRe.MatchString(c.TeamID) {
		return errors.New("the team id looks like team_abc123")
	}
	if c.API == "" {
		c.API = "https://api.vercel.com"
	}
	tok := c.Token
	api := rest.New(c.API, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
	m.set.Put(id, &conn{api: api, team: c.TeamID})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) q(extra url.Values) url.Values {
	v := url.Values{}
	for k, x := range extra {
		v[k] = x
	}
	if c.team != "" {
		v.Set("teamId", c.team)
	}
	return v
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	if _, err := c.api.Do(ctx, "GET", "/v2/user", nil, nil, &u); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: u.User.Username}
}

type project struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Targets struct {
		Production *struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"production"`
	} `json:"targets"`
}

func (c *conn) project(ctx context.Context, p string) (project, error) {
	var out project
	if !idRe.MatchString(p) {
		return out, errors.New("the project is its id or name")
	}
	_, err := c.api.Do(ctx, "GET", "/v9/projects/"+p, c.q(nil), nil, &out)
	return out, err
}

func dpl(s string) error {
	if !idRe.MatchString(s) {
		return errors.New("which deployment? (its id, from Deployments)")
	}
	return nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Project    string `json:"project"`
		Deployment string `json:"deployment"`
		Limit      int    `json:"limit"`
		Production bool   `json:"production"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "projects":
		var r struct {
			Projects []project `json:"projects"`
		}
		if _, err := c.api.Do(ctx, "GET", "/v9/projects", c.q(url.Values{"limit": {"100"}}), nil, &r); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Production string `json:"production,omitempty"`
			URL        string `json:"url,omitempty"`
		}
		out := []row{}
		for _, x := range r.Projects {
			rw := row{ID: x.ID, Name: x.Name}
			if x.Targets.Production != nil {
				rw.Production, rw.URL = x.Targets.Production.ID, x.Targets.Production.URL
			}
			out = append(out, rw)
		}
		return sdk.JSON(out)

	case "deployments":
		lim := p.Limit
		if lim <= 0 || lim > 100 {
			lim = 20
		}
		q := url.Values{"limit": {fmt.Sprint(lim)}}
		if p.Project != "" {
			pr, err := c.project(ctx, p.Project)
			if err != nil {
				return sdk.Result{}, err
			}
			q.Set("projectId", pr.ID)
		}
		var r struct {
			Deployments []struct {
				UID     string `json:"uid"`
				Name    string `json:"name"`
				URL     string `json:"url"`
				State   string `json:"state"`
				Target  string `json:"target"`
				Created int64  `json:"created"`
				Meta    struct {
					Commit  string `json:"githubCommitMessage"`
					Branch  string `json:"githubCommitRef"`
					Creator string `json:"githubCommitAuthorName"`
				} `json:"meta"`
			} `json:"deployments"`
		}
		if _, err := c.api.Do(ctx, "GET", "/v6/deployments", c.q(q), nil, &r); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r.Deployments)

	case "redeploy":
		if err := dpl(p.Deployment); err != nil {
			return sdk.Result{}, err
		}
		var d struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if _, err := c.api.Do(ctx, "GET", "/v13/deployments/"+p.Deployment, c.q(nil), nil, &d); err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			target := "preview"
			if p.Production {
				target = "production"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: "Redeploy " + d.Name + " to " + target, Changes: []sdk.Change{{Target: d.Name, Op: "deploy"}}}}, nil
		}
		body := map[string]any{"name": d.Name, "deploymentId": d.ID}
		if p.Production {
			body["target"] = "production"
		}
		var out struct {
			ID    string `json:"id"`
			URL   string `json:"url"`
			State string `json:"readyState"`
		}
		if _, err := c.api.Do(ctx, "POST", "/v13/deployments", c.q(nil), body, &out); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(out)

	case "promote":
		if err := dpl(p.Deployment); err != nil {
			return sdk.Result{}, err
		}
		pr, err := c.project(ctx, p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		prev := ""
		if pr.Targets.Production != nil {
			prev = pr.Targets.Production.ID
		}
		if prev == p.Deployment {
			return sdk.Result{}, errors.New("that deployment is already production")
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]string{"production": prev})
			after, _ := json.Marshal(map[string]string{"production": p.Deployment})
			return sdk.Result{Plan: &sdk.Plan{Summary: "Point " + pr.Name + "'s production domains at " + p.Deployment,
				Changes: []sdk.Change{{Target: pr.Name, Op: "update", Before: before, After: after}}}}, nil
		}
		if _, err := c.api.Do(ctx, "POST", "/v10/projects/"+pr.ID+"/promote/"+p.Deployment, c.q(nil), map[string]any{}, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"project": pr.Name, "production": p.Deployment, "was": prev})
		if prev != "" {
			r.Undo = sdk.UndoWith("promote", map[string]string{"project": pr.ID, "deployment": prev}, "Point production back at "+prev)
		}
		return r, nil

	case "cancel":
		if err := dpl(p.Deployment); err != nil {
			return sdk.Result{}, err
		}
		if _, err := c.api.Do(ctx, "PATCH", "/v12/deployments/"+p.Deployment+"/cancel", c.q(nil), nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"canceled": p.Deployment})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
