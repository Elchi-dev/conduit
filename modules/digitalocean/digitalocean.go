// Package digitalocean manages DigitalOcean droplets and App Platform apps,
// and reads the account balance, through the DigitalOcean API v2.
package digitalocean

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one DigitalOcean team.
type Config struct {
	Token string `json:"token"` // secret:// personal access token
	API   string `json:"api"`   // default https://api.digitalocean.com/v2 (tests)
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the DigitalOcean module.
func New() *Module { return &Module{} }

var appRe = regexp.MustCompile(`^[a-f0-9-]{8,64}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	dr := `"droplet":{"type":"integer","description":"Droplet id (from Droplets)"}`
	return sdk.Manifest{
		ID: "digitalocean", Name: "DigitalOcean", Version: "0.1.0", Category: "Infrastructure", Icon: "server",
		Description: "Droplets, App Platform apps and your balance: power droplets on and off, take snapshots, redeploy apps.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A personal access token (API, Tokens). Read scope to watch; add droplet:update, droplet:create (snapshots) and app:update to make changes"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "droplets", Title: "Droplets", Description: "Status, size, region and addresses.", Risk: sdk.RiskRead},
			{Name: "snapshots", Title: "Snapshots", Risk: sdk.RiskRead},
			{Name: "apps", Title: "Apps", Description: "App Platform apps and their latest deployment.", Risk: sdk.RiskRead},
			{Name: "balance", Title: "Balance", Description: "Month-to-date usage and balance.", Risk: sdk.RiskRead},
			{Name: "power_on", Title: "Power on a droplet", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(`{"type":"object","required":["droplet"],"properties":{` + dr + `}}`)},
			{Name: "shutdown", Title: "Shut down a droplet", Description: "Graceful shutdown. A droplet that is off is still billed.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["droplet"],"properties":{` + dr + `}}`)},
			{Name: "reboot", Title: "Reboot a droplet", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(`{"type":"object","required":["droplet"],"properties":{` + dr + `}}`)},
			{Name: "snapshot", Title: "Take a snapshot", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["droplet"],"properties":{` + dr + `,"name":{"type":"string","maxLength":120}}}`)},
			{Name: "redeploy", Title: "Redeploy an app", Description: "Builds and deploys the app's current source again.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["app"],"properties":{"app":{"type":"string","description":"App id (from Apps)"},"forceBuild":{"type":"boolean"}}}`)},
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
	if c.API == "" {
		c.API = "https://api.digitalocean.com/v2"
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
	m.set.Put(id, &conn{api: api})
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
	var a struct {
		Account struct {
			Email  string `json:"email"`
			Status string `json:"status"`
		} `json:"account"`
	}
	if _, err := c.api.Do(ctx, "GET", "/account", nil, nil, &a); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if a.Account.Status != "" && a.Account.Status != "active" {
		return sdk.Health{Status: "degraded", Message: "Account " + a.Account.Status}
	}
	return sdk.Health{Status: "ok", Message: a.Account.Email}
}

type droplet struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	SizeSlug string `json:"size_slug"`
	Region   struct {
		Slug string `json:"slug"`
	} `json:"region"`
	Networks struct {
		V4 []struct {
			IP   string `json:"ip_address"`
			Type string `json:"type"`
		} `json:"v4"`
	} `json:"networks"`
}

func (c *conn) droplet(ctx context.Context, id int) (droplet, error) {
	var r struct {
		Droplet droplet `json:"droplet"`
	}
	_, err := c.api.Do(ctx, "GET", "/droplets/"+strconv.Itoa(id), nil, nil, &r)
	return r.Droplet, err
}

func status(s string) json.RawMessage { b, _ := json.Marshal(map[string]string{"status": s}); return b }

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Droplet    int    `json:"droplet"`
		Name       string `json:"name"`
		App        string `json:"app"`
		ForceBuild bool   `json:"forceBuild"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "droplets":
		var r struct {
			Droplets []droplet `json:"droplets"`
		}
		if _, err := c.api.Do(ctx, "GET", "/droplets", url.Values{"per_page": {"200"}}, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID      int    `json:"id"`
			Name    string `json:"name"`
			Status  string `json:"status"`
			Size    string `json:"size"`
			Region  string `json:"region"`
			Public  string `json:"publicIp,omitempty"`
			Private string `json:"privateIp,omitempty"`
		}
		out := []row{}
		for _, d := range r.Droplets {
			x := row{ID: d.ID, Name: d.Name, Status: d.Status, Size: d.SizeSlug, Region: d.Region.Slug}
			for _, n := range d.Networks.V4 {
				if n.Type == "public" {
					x.Public = n.IP
				} else if n.Type == "private" {
					x.Private = n.IP
				}
			}
			out = append(out, x)
		}
		return sdk.JSON(out)

	case "snapshots":
		var r struct {
			Snapshots []struct {
				ID        string  `json:"id"`
				Name      string  `json:"name"`
				SizeGB    float64 `json:"size_gigabytes"`
				Created   string  `json:"created_at"`
				ResourceT string  `json:"resource_type"`
			} `json:"snapshots"`
		}
		if _, err := c.api.Do(ctx, "GET", "/snapshots", url.Values{"per_page": {"200"}}, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r.Snapshots)

	case "apps":
		var r struct {
			Apps []struct {
				ID   string `json:"id"`
				Spec struct {
					Name string `json:"name"`
				} `json:"spec"`
				LiveURL          string `json:"live_url"`
				ActiveDeployment *struct {
					ID    string `json:"id"`
					Phase string `json:"phase"`
				} `json:"active_deployment"`
				InProgress *struct {
					Phase string `json:"phase"`
				} `json:"in_progress_deployment"`
			} `json:"apps"`
		}
		if _, err := c.api.Do(ctx, "GET", "/apps", nil, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			URL        string `json:"url,omitempty"`
			Active     string `json:"active,omitempty"`
			InProgress string `json:"inProgress,omitempty"`
		}
		out := []row{}
		for _, a := range r.Apps {
			x := row{ID: a.ID, Name: a.Spec.Name, URL: a.LiveURL}
			if a.ActiveDeployment != nil {
				x.Active = a.ActiveDeployment.Phase
			}
			if a.InProgress != nil {
				x.InProgress = a.InProgress.Phase
			}
			out = append(out, x)
		}
		return sdk.JSON(out)

	case "balance":
		var r map[string]any
		if _, err := c.api.Do(ctx, "GET", "/customers/my/balance", nil, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r)

	case "power_on", "shutdown", "reboot", "snapshot":
		if p.Droplet <= 0 {
			return sdk.Result{}, errors.New("which droplet? (its id, from Droplets)")
		}
		d, err := c.droplet(ctx, p.Droplet)
		if err != nil {
			return sdk.Result{}, err
		}
		target := fmt.Sprintf("%s (%d)", d.Name, d.ID)
		typ := map[string]string{"power_on": "power_on", "shutdown": "shutdown", "reboot": "reboot", "snapshot": "snapshot"}[call.Action]
		body := map[string]string{"type": typ}
		if call.Action == "snapshot" {
			name := strings.TrimSpace(p.Name)
			if name == "" {
				name = d.Name + "-conduit"
			}
			body["name"] = name
		}
		if call.DryRun {
			want := map[string]string{"power_on": "active", "shutdown": "off", "reboot": "active", "snapshot": d.Status}[call.Action]
			ch := sdk.Change{Target: target, Op: call.Action, Before: status(d.Status), After: status(want)}
			if call.Action == "snapshot" {
				ch.Op, ch.Before = "create", nil
				ch.After, _ = json.Marshal(map[string]string{"snapshot": body["name"]})
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: strings.ReplaceAll(call.Action, "_", " ") + " " + target, Changes: []sdk.Change{ch}}}, nil
		}
		if _, err := c.api.Do(ctx, "POST", "/droplets/"+strconv.Itoa(p.Droplet)+"/actions", nil, body, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"droplet": target, "was": d.Status, "requested": call.Action})
		switch {
		case call.Action == "power_on" && d.Status == "off":
			r.Undo = sdk.UndoWith("shutdown", map[string]int{"droplet": p.Droplet}, "Shut "+d.Name+" down again")
		case call.Action == "shutdown" && d.Status == "active":
			r.Undo = sdk.UndoWith("power_on", map[string]int{"droplet": p.Droplet}, "Power "+d.Name+" on again")
		}
		return r, nil

	case "redeploy":
		if !appRe.MatchString(p.App) {
			return sdk.Result{}, errors.New("which app? (its id, from Apps)")
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Redeploy app " + p.App, Changes: []sdk.Change{{Target: p.App, Op: "deploy"}}}}, nil
		}
		var r struct {
			Deployment struct {
				ID    string `json:"id"`
				Phase string `json:"phase"`
			} `json:"deployment"`
		}
		if _, err := c.api.Do(ctx, "POST", "/apps/"+p.App+"/deployments", nil, map[string]bool{"force_build": p.ForceBuild}, &r); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r.Deployment)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
