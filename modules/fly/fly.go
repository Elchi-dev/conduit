// Package fly shows Fly.io apps and Machines and starts, stops and restarts
// Machines through the Fly Machines API.
package fly

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

// Config is one Fly.io organization.
type Config struct {
	Token string `json:"token"` // secret:// API token
	Org   string `json:"org"`   // organization slug, default "personal"
	API   string `json:"api"`   // default https://api.machines.dev/v1 (tests)
}

type conn struct {
	api *rest.Client
	org string
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Fly.io module.
func New() *Module { return &Module{} }

var (
	appRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	machineRe = regexp.MustCompile(`^[a-f0-9]{6,32}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	in := `"app":{"type":"string","description":"App name"},"machine":{"type":"string","description":"Machine id (from Machines)"}`
	return sdk.Manifest{
		ID: "fly", Name: "Fly.io", Version: "0.1.0", Category: "Development", Icon: "rocket",
		Description: "Your Fly.io apps and Machines: state, region, image; start, stop and restart Machines.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An org-scoped token: fly tokens create org (or deploy tokens per app)"},
			"org":{"type":"string","default":"personal","description":"Organization slug"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "apps", Title: "Apps", Risk: sdk.RiskRead},
			{Name: "machines", Title: "Machines", Description: "State, region and image of an app's Machines.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["app"],"properties":{"app":{"type":"string"}}}`)},
			{Name: "start", Title: "Start a Machine", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(`{"type":"object","required":["app","machine"],"properties":{` + in + `}}`)},
			{Name: "stop", Title: "Stop a Machine", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(`{"type":"object","required":["app","machine"],"properties":{` + in + `}}`)},
			{Name: "restart", Title: "Restart a Machine", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(`{"type":"object","required":["app","machine"],"properties":{` + in + `}}`)},
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
	if c.Org == "" {
		c.Org = "personal"
	}
	if !appRe.MatchString(c.Org) {
		return errors.New("the organization is its slug, like personal or my-team")
	}
	if c.API == "" {
		c.API = "https://api.machines.dev/v1"
	}
	tok := c.Token
	api := rest.New(c.API, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		// Macaroon tokens (FlyV1 …) carry their own scheme.
		if strings.HasPrefix(t, "FlyV1 ") {
			r.Header.Set("Authorization", t)
		} else {
			r.Header.Set("Authorization", "Bearer "+t)
		}
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
	m.set.Put(id, &conn{api: api, org: c.Org})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

type app struct {
	Name         string `json:"name"`
	MachineCount int    `json:"machine_count"`
	Network      string `json:"network"`
}

func (c *conn) apps(ctx context.Context) ([]app, error) {
	var r struct {
		Apps []app `json:"apps"`
	}
	_, err := c.api.Do(ctx, "GET", "/apps", url.Values{"org_slug": {c.org}}, nil, &r)
	return r.Apps, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	list, err := c.apps(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d apps in %s", len(list), c.org)}
}

type machine struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	State    string `json:"state"`
	Region   string `json:"region"`
	ImageRef struct {
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
	} `json:"image_ref"`
	UpdatedAt string `json:"updated_at"`
}

func state(s string) json.RawMessage { b, _ := json.Marshal(map[string]string{"state": s}); return b }

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		App     string `json:"app"`
		Machine string `json:"machine"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if call.Action == "apps" {
		list, err := c.apps(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if list == nil {
			list = []app{}
		}
		return sdk.JSON(list)
	}
	if !appRe.MatchString(p.App) {
		return sdk.Result{}, errors.New("which app? (its name)")
	}
	if call.Action == "machines" {
		var list []machine
		if _, err := c.api.Do(ctx, "GET", "/apps/"+p.App+"/machines", nil, nil, &list); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			State   string `json:"state"`
			Region  string `json:"region"`
			Image   string `json:"image"`
			Updated string `json:"updated"`
		}
		out := []row{}
		for _, x := range list {
			img := x.ImageRef.Repository
			if x.ImageRef.Tag != "" {
				img += ":" + x.ImageRef.Tag
			}
			out = append(out, row{ID: x.ID, Name: x.Name, State: x.State, Region: x.Region, Image: img, Updated: x.UpdatedAt})
		}
		return sdk.JSON(out)
	}
	switch call.Action {
	case "start", "stop", "restart":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	if !machineRe.MatchString(p.Machine) {
		return sdk.Result{}, errors.New("which Machine? (its id, from Machines)")
	}
	var mc machine
	if _, err := c.api.Do(ctx, "GET", "/apps/"+p.App+"/machines/"+p.Machine, nil, nil, &mc); err != nil {
		return sdk.Result{}, err
	}
	target := p.App + "/" + mc.ID
	if mc.Name != "" {
		target = p.App + "/" + mc.Name
	}
	if call.DryRun {
		want := map[string]string{"start": "started", "stop": "stopped", "restart": "started"}[call.Action]
		return sdk.Result{Plan: &sdk.Plan{Summary: call.Action + " " + target, Changes: []sdk.Change{{Target: target, Op: call.Action, Before: state(mc.State), After: state(want)}}}}, nil
	}
	if _, err := c.api.Do(ctx, "POST", "/apps/"+p.App+"/machines/"+p.Machine+"/"+call.Action, nil, map[string]any{}, nil); err != nil {
		return sdk.Result{}, err
	}
	r, _ := sdk.JSON(map[string]string{"machine": target, "was": mc.State, "requested": call.Action})
	in := map[string]string{"app": p.App, "machine": p.Machine}
	switch {
	case call.Action == "start" && mc.State != "started":
		r.Undo = sdk.UndoWith("stop", in, "Stop "+target+" again")
	case call.Action == "stop" && mc.State == "started":
		r.Undo = sdk.UndoWith("start", in, "Start "+target+" again")
	}
	return r, nil
}
