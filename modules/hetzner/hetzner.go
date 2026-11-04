// Package hetzner manages Hetzner Cloud servers: status, power, snapshots
// and firewalls, through the Hetzner Cloud API.
package hetzner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Hetzner Cloud project.
type Config struct {
	Token string `json:"token"` // secret:// API token (project, Security, API tokens)
	API   string `json:"api"`   // default https://api.hetzner.cloud/v1 (tests)
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Hetzner Cloud module.
func New() *Module { return &Module{} }

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	srv := `"server":{"type":"integer","description":"Server id (from Servers)"}`
	return sdk.Manifest{
		ID: "hetzner", Name: "Hetzner Cloud", Version: "0.1.0", Category: "Infrastructure", Icon: "server",
		Description: "Your Hetzner Cloud servers: status and addresses, power on and off, snapshots and firewalls.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A project API token (Security, API tokens). Read only is enough to watch; Read & Write to power servers and take snapshots"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "servers", Title: "Servers", Description: "Status, type, addresses and location.", Risk: sdk.RiskRead},
			{Name: "images", Title: "Snapshots and backups", Risk: sdk.RiskRead},
			{Name: "firewalls", Title: "Firewalls", Risk: sdk.RiskRead},
			{Name: "power_on", Title: "Power on", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(`{"type":"object","required":["server"],"properties":{` + srv + `}}`)},
			{Name: "shutdown", Title: "Shut down", Description: "Asks the operating system to shut down (ACPI). The server's services go down until it's powered on (destructive).", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(`{"type":"object","required":["server"],"properties":{` + srv + `}}`)},
			{Name: "reboot", Title: "Reboot", Description: "Restarts the operating system.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(`{"type":"object","required":["server"],"properties":{` + srv + `}}`)},
			{Name: "snapshot", Title: "Take a snapshot", Description: "Hetzner bills snapshots by size.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["server"],"properties":{` + srv + `,"description":{"type":"string","maxLength":120}}}`)},
			{Name: "delete_image", Title: "Delete a snapshot", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(`{"type":"object","required":["image"],"properties":{"image":{"type":"integer"}}}`)},
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
	if c.API == "" {
		c.API = "https://api.hetzner.cloud/v1"
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
	list, err := c.servers(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	off := 0
	for _, s := range list {
		if s.Status != "running" {
			off++
		}
	}
	msg := fmt.Sprintf("%d servers", len(list))
	if off > 0 {
		msg += fmt.Sprintf(", %d not running", off)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type server struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	ServerType struct {
		Name   string  `json:"name"`
		Cores  int     `json:"cores"`
		Memory float64 `json:"memory"`
	} `json:"server_type"`
	PublicNet struct {
		IPv4 *struct {
			IP string `json:"ip"`
		} `json:"ipv4"`
		IPv6 *struct {
			IP string `json:"ip"`
		} `json:"ipv6"`
	} `json:"public_net"`
	Datacenter struct {
		Name string `json:"name"`
	} `json:"datacenter"`
	Created string `json:"created"`
}

func (c *conn) servers(ctx context.Context) ([]server, error) {
	var out []server
	for page := 1; page <= 20; page++ {
		var r struct {
			Servers []server `json:"servers"`
			Meta    struct {
				Pagination struct {
					NextPage *int `json:"next_page"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		if _, err := c.api.Do(ctx, "GET", "/servers", url.Values{"page": {strconv.Itoa(page)}, "per_page": {"50"}}, nil, &r); err != nil {
			return nil, err
		}
		out = append(out, r.Servers...)
		if r.Meta.Pagination.NextPage == nil {
			break
		}
	}
	return out, nil
}

func (c *conn) server(ctx context.Context, id int) (server, error) {
	var r struct {
		Server server `json:"server"`
	}
	_, err := c.api.Do(ctx, "GET", "/servers/"+strconv.Itoa(id), nil, nil, &r)
	return r.Server, err
}

func status(s string) json.RawMessage { b, _ := json.Marshal(map[string]string{"status": s}); return b }

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Server      int    `json:"server"`
		Image       int    `json:"image"`
		Description string `json:"description"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "servers":
		list, err := c.servers(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID         int    `json:"id"`
			Name       string `json:"name"`
			Status     string `json:"status"`
			Type       string `json:"type"`
			IPv4       string `json:"ipv4,omitempty"`
			IPv6       string `json:"ipv6,omitempty"`
			Datacenter string `json:"datacenter"`
		}
		out := []row{}
		for _, s := range list {
			r := row{ID: s.ID, Name: s.Name, Status: s.Status, Type: s.ServerType.Name, Datacenter: s.Datacenter.Name}
			if s.PublicNet.IPv4 != nil {
				r.IPv4 = s.PublicNet.IPv4.IP
			}
			if s.PublicNet.IPv6 != nil {
				r.IPv6 = s.PublicNet.IPv6.IP
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "images":
		var r struct {
			Images []struct {
				ID          int     `json:"id"`
				Type        string  `json:"type"`
				Description string  `json:"description"`
				ImageSize   float64 `json:"image_size"`
				Created     string  `json:"created"`
				CreatedFrom *struct {
					Name string `json:"name"`
				} `json:"created_from"`
			} `json:"images"`
		}
		if _, err := c.api.Do(ctx, "GET", "/images", url.Values{"type": {"snapshot,backup"}, "per_page": {"50"}}, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID          int     `json:"id"`
			Type        string  `json:"type"`
			Description string  `json:"description"`
			SizeGB      float64 `json:"sizeGb"`
			Server      string  `json:"server,omitempty"`
			Created     string  `json:"created"`
		}
		out := []row{}
		for _, i := range r.Images {
			x := row{ID: i.ID, Type: i.Type, Description: i.Description, SizeGB: i.ImageSize, Created: i.Created}
			if i.CreatedFrom != nil {
				x.Server = i.CreatedFrom.Name
			}
			out = append(out, x)
		}
		return sdk.JSON(out)

	case "firewalls":
		var r struct {
			Firewalls []struct {
				ID    int    `json:"id"`
				Name  string `json:"name"`
				Rules []struct {
					Direction string   `json:"direction"`
					Protocol  string   `json:"protocol"`
					Port      string   `json:"port"`
					SourceIPs []string `json:"source_ips"`
				} `json:"rules"`
				AppliedTo []any `json:"applied_to"`
			} `json:"firewalls"`
		}
		if _, err := c.api.Do(ctx, "GET", "/firewalls", nil, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r.Firewalls)

	case "power_on", "shutdown", "reboot":
		if p.Server <= 0 {
			return sdk.Result{}, errors.New("which server? (its id, from Servers)")
		}
		s, err := c.server(ctx, p.Server)
		if err != nil {
			return sdk.Result{}, err
		}
		target := fmt.Sprintf("%s (%d)", s.Name, s.ID)
		want := map[string]string{"power_on": "running", "shutdown": "off", "reboot": "running"}[call.Action]
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: strings.ReplaceAll(call.Action, "_", " ") + " " + target,
				Changes: []sdk.Change{{Target: target, Op: call.Action, Before: status(s.Status), After: status(want)}}}}, nil
		}
		path := map[string]string{"power_on": "poweron", "shutdown": "shutdown", "reboot": "reboot"}[call.Action]
		if _, err := c.api.Do(ctx, "POST", "/servers/"+strconv.Itoa(p.Server)+"/actions/"+path, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"server": target, "was": s.Status, "requested": call.Action})
		switch {
		case call.Action == "power_on" && s.Status != "running":
			r.Undo = sdk.UndoWith("shutdown", map[string]int{"server": p.Server}, "Shut "+s.Name+" down again")
		case call.Action == "shutdown" && s.Status == "running":
			r.Undo = sdk.UndoWith("power_on", map[string]int{"server": p.Server}, "Power "+s.Name+" on again")
		}
		return r, nil

	case "snapshot":
		if p.Server <= 0 {
			return sdk.Result{}, errors.New("which server? (its id, from Servers)")
		}
		s, err := c.server(ctx, p.Server)
		if err != nil {
			return sdk.Result{}, err
		}
		desc := strings.TrimSpace(p.Description)
		if desc == "" {
			desc = "Conduit snapshot of " + s.Name
		}
		if call.DryRun {
			after, _ := json.Marshal(map[string]string{"snapshot": desc})
			return sdk.Result{Plan: &sdk.Plan{Summary: "Take a snapshot of " + s.Name, Changes: []sdk.Change{{Target: s.Name, Op: "create", After: after}}}}, nil
		}
		var r struct {
			Image struct {
				ID int `json:"id"`
			} `json:"image"`
		}
		if _, err := c.api.Do(ctx, "POST", "/servers/"+strconv.Itoa(p.Server)+"/actions/create_image", nil, map[string]string{"type": "snapshot", "description": desc}, &r); err != nil {
			return sdk.Result{}, err
		}
		res, _ := sdk.JSON(map[string]any{"image": r.Image.ID, "description": desc})
		res.Undo = sdk.UndoWith("delete_image", map[string]int{"image": r.Image.ID}, "Delete the snapshot")
		return res, nil

	case "delete_image":
		if p.Image <= 0 {
			return sdk.Result{}, errors.New("which snapshot? (its id, from Snapshots)")
		}
		var r struct {
			Image struct {
				Type        string `json:"type"`
				Description string `json:"description"`
			} `json:"image"`
		}
		if _, err := c.api.Do(ctx, "GET", "/images/"+strconv.Itoa(p.Image), nil, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		if r.Image.Type != "snapshot" && r.Image.Type != "backup" {
			return sdk.Result{}, errors.New("only snapshots and backups can be deleted here")
		}
		if call.DryRun {
			before, _ := json.Marshal(r.Image)
			return sdk.Result{Plan: &sdk.Plan{Summary: "Delete snapshot " + r.Image.Description, Changes: []sdk.Change{{Target: strconv.Itoa(p.Image), Op: "delete", Before: before}}}}, nil
		}
		if _, err := c.api.Do(ctx, "DELETE", "/images/"+strconv.Itoa(p.Image), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]int{"deleted": p.Image})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
