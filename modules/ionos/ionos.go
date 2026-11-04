// Package ionos works with IONOS Cloud through the Cloud API v6 and an API
// token: data centers, servers (start, stop, reboot) and volumes.
package ionos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one IONOS Cloud token.
type Config struct {
	Token string `json:"token"` // secret:// API token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.ionos.com/cloudapi/v6 (tests).
	Base string
}

// New returns the IONOS Cloud module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.ionos.com/cloudapi/v6"

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	dc := `"datacenter":{"type":"string","description":"Data center id (from datacenters)"}`
	srv := sdk.Schema(`{"type":"object","required":["datacenter","server"],"properties":{` + dc + `,"server":{"type":"string","description":"Server id (from servers)"}}}`)
	return sdk.Manifest{
		ID: "ionos", Name: "IONOS Cloud", Version: "0.1.0", Category: "Infrastructure", Icon: "server",
		Description: "IONOS Cloud data centers, servers (state, start, stop, reboot) and volumes.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An API token (Data Center Designer, Management, Token Manager, or ionosctl token generate). Its user's privileges apply"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "datacenters", Title: "Data centers", Description: "Id, name, location and state.", Risk: sdk.RiskRead},
			{Name: "servers", Title: "Servers", Description: "Name, type, VM state, cores, memory and availability zone, in one data center or all.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + dc + `}}`)},
			{Name: "volumes", Title: "Volumes", Description: "A data center's volumes: name, type, size, licence, availability zone and state. Never user data or SSH keys.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["datacenter"],"properties":{` + dc + `}}`)},
			{Name: "start_server", Title: "Start a server", Description: "Starts a stopped server; cores and memory are billed again. Undo stops it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: srv},
			{Name: "stop_server", Title: "Stop a server", Description: "Shuts a server off and deallocates it; its services go down until it's started, and a dynamic IP may change. Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: srv},
			{Name: "reboot_server", Title: "Reboot a server", Description: "Hard-reboots a running server; its services go down while it restarts.", Risk: sdk.RiskDestructive, DryRun: true, Input: srv},
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
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("IONOS refused the API token (wrong or expired)")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token's user isn't allowed to do this in IONOS Cloud")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusUnprocessableEntity), rest.IsStatus(err, http.StatusConflict):
		return fmt.Errorf("IONOS refused: %s is busy or in the wrong state for this", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("IONOS's rate limit was hit; try again in a moment")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, out any, what string) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, url.Values{"depth": {"1"}}, nil, out)
	return friendly(err, what)
}

type meta struct {
	State string `json:"state"`
}

type datacenter struct {
	ID    string `json:"id"`
	Props struct {
		Name     string `json:"name"`
		Location string `json:"location"`
	} `json:"properties"`
	Meta meta `json:"metadata"`
}

func (c *conn) datacenters(ctx context.Context) ([]datacenter, error) {
	var r struct {
		Items []datacenter `json:"items"`
	}
	err := c.get(ctx, "/datacenters", &r, "data center list")
	return r.Items, err
}

type server struct {
	ID    string `json:"id"`
	Props struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		VMState string `json:"vmState"`
		Cores   int    `json:"cores"`
		RAM     int    `json:"ram"`
		Zone    string `json:"availabilityZone"`
		CPU     string `json:"cpuFamily"`
	} `json:"properties"`
	Meta meta `json:"metadata"`
}

func (c *conn) servers(ctx context.Context, dc string) ([]server, error) {
	var r struct {
		Items []server `json:"items"`
	}
	err := c.get(ctx, "/datacenters/"+url.PathEscape(dc)+"/servers", &r, "data center "+dc)
	return r.Items, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	dcs, err := c.datacenters(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	failed := 0
	for _, d := range dcs {
		if d.Meta.State == "FAILED" {
			failed++
		}
	}
	msg := fmt.Sprintf("%d data centers", len(dcs))
	if failed > 0 {
		return sdk.Health{Status: "degraded", Message: msg + fmt.Sprintf(", %d failed", failed)}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func state(s string) json.RawMessage { b, _ := json.Marshal(map[string]string{"vmState": s}); return b }

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Datacenter string `json:"datacenter"`
		Server     string `json:"server"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	p.Datacenter, p.Server = strings.TrimSpace(p.Datacenter), strings.TrimSpace(p.Server)
	switch call.Action {
	case "datacenters":
		dcs, err := c.datacenters(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]string{}
		for _, d := range dcs {
			out = append(out, map[string]string{"id": d.ID, "name": d.Props.Name, "location": d.Props.Location, "state": d.Meta.State})
		}
		return sdk.JSON(out)

	case "servers":
		if p.Datacenter != "" && !uuidRe.MatchString(p.Datacenter) {
			return sdk.Result{}, errors.New("a data center is its id (from datacenters)")
		}
		dcs := []datacenter{}
		if p.Datacenter != "" {
			var d datacenter
			d.ID = p.Datacenter
			dcs = append(dcs, d)
		} else if dcs, err = c.datacenters(ctx); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range dcs {
			if !uuidRe.MatchString(d.ID) {
				continue
			}
			ss, err := c.servers(ctx, d.ID)
			if err != nil {
				return sdk.Result{}, err
			}
			for _, s := range ss {
				row := map[string]any{"id": s.ID, "name": s.Props.Name, "datacenter": d.ID, "type": s.Props.Type, "vmState": s.Props.VMState,
					"cores": s.Props.Cores, "ramMb": s.Props.RAM, "zone": s.Props.Zone, "cpuFamily": s.Props.CPU, "state": s.Meta.State}
				if d.Props.Name != "" {
					row["datacenterName"] = d.Props.Name
				}
				out = append(out, row)
			}
		}
		return sdk.JSON(out)

	case "volumes":
		if !uuidRe.MatchString(p.Datacenter) {
			return sdk.Result{}, errors.New("which data center? (its id, from datacenters)")
		}
		// Decoded field by field: user data, SSH keys and the image
		// password are never read.
		var r struct {
			Items []struct {
				ID    string `json:"id"`
				Props struct {
					Name       string  `json:"name"`
					Type       string  `json:"type"`
					Size       float64 `json:"size"`
					Licence    string  `json:"licenceType"`
					Zone       string  `json:"availabilityZone"`
					BootServer string  `json:"bootServer"`
					Bus        string  `json:"bus"`
				} `json:"properties"`
				Meta meta `json:"metadata"`
			} `json:"items"`
		}
		if err := c.get(ctx, "/datacenters/"+url.PathEscape(p.Datacenter)+"/volumes", &r, "data center "+p.Datacenter); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, v := range r.Items {
			row := map[string]any{"id": v.ID, "name": v.Props.Name, "type": v.Props.Type, "sizeGb": v.Props.Size, "licence": v.Props.Licence,
				"zone": v.Props.Zone, "bus": v.Props.Bus, "state": v.Meta.State}
			if v.Props.BootServer != "" {
				row["bootServer"] = v.Props.BootServer
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "start_server", "stop_server", "reboot_server":
		if !uuidRe.MatchString(p.Datacenter) {
			return sdk.Result{}, errors.New("which data center? (its id, from datacenters)")
		}
		if !uuidRe.MatchString(p.Server) {
			return sdk.Result{}, errors.New("which server? (its id, from servers)")
		}
		return c.power(ctx, call, p.Datacenter, p.Server)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) power(ctx context.Context, call sdk.Call, dc, id string) (sdk.Result, error) {
	path := "/datacenters/" + url.PathEscape(dc) + "/servers/" + url.PathEscape(id)
	what := "server " + id
	var s server
	if err := c.get(ctx, path, &s, what); err != nil {
		return sdk.Result{}, err
	}
	if s.ID != id {
		return sdk.Result{}, fmt.Errorf("IONOS answered with another server for %s", id)
	}
	op := strings.TrimSuffix(call.Action, "_server")
	was, want := s.Props.VMState, "RUNNING"
	target := s.Props.Name + " (" + id + ")"
	switch op {
	case "start":
		if was == "RUNNING" {
			return sdk.JSON(map[string]any{"server": target, "vmState": was, "note": "nothing to change"})
		}
		if was != "SHUTOFF" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a stopped (SHUTOFF) server can be started", target, was)
		}
	case "stop":
		if was == "SHUTOFF" {
			return sdk.JSON(map[string]any{"server": target, "vmState": was, "note": "nothing to change"})
		}
		if s.Props.Type == "CUBE" {
			return sdk.Result{}, fmt.Errorf("%s is a Cube server, which IONOS suspends rather than stops; this action doesn't do that", target)
		}
		if was != "RUNNING" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a running server can be stopped", target, was)
		}
		want = "SHUTOFF"
	case "reboot":
		if was != "RUNNING" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a running server can be rebooted", target, was)
		}
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: strings.ToUpper(op[:1]) + op[1:] + " " + target,
			Changes: []sdk.Change{{Target: target, Op: op, Before: state(was), After: state(want)}}}}, nil
	}
	if _, err := c.api.Do(ctx, http.MethodPost, path+"/"+op, nil, nil, nil); err != nil {
		return sdk.Result{}, friendly(err, what)
	}
	in := map[string]string{"datacenter": dc, "server": id}
	res, err := sdk.JSON(map[string]any{"server": target, "was": was, "requested": op})
	switch op {
	case "start":
		if s.Props.Type == "CUBE" {
			break
		}
		res.Undo = sdk.UndoWith("stop_server", in, "Stop "+s.Props.Name+" again")
	case "stop":
		res.Undo = sdk.UndoWith("start_server", in, "Start "+s.Props.Name+" again")
	}
	return res, err
}
