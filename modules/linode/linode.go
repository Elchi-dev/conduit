// Package linode manages Linode (Akamai Cloud) instances through the Linode
// API v4: status, power, volumes and firewalls, plus the account's balance,
// invoices and network transfer.
package linode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Linode account.
type Config struct {
	Token string `json:"token"` // secret:// personal access token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.linode.com/v4 (tests).
	Base string
}

// New returns the Linode module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.linode.com/v4"

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	in := sdk.Schema(`{"type":"object","required":["instance"],"properties":{"instance":{"type":"integer","minimum":1,"description":"Instance id (from Instances)"}}}`)
	return sdk.Manifest{
		ID: "linode", Name: "Linode (Akamai Cloud)", Version: "0.1.0", Category: "Infrastructure", Icon: "server",
		Description: "Your Linode instances: status, region and plan, power on, shut down and reboot; volumes, firewalls, network transfer, balance and invoices.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A personal access token (Cloud Manager, your profile, API Tokens). Linodes, Volumes and Firewalls read only to watch; Linodes read/write to power instances; Account read only for balance, invoices and transfer"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "instances", Title: "Instances", Description: "Status, region, plan, size and addresses.", Risk: sdk.RiskRead},
			{Name: "volumes", Title: "Volumes", Description: "Block storage volumes with size, region and the instance they're attached to.", Risk: sdk.RiskRead},
			{Name: "firewalls", Title: "Firewalls", Description: "Cloud firewalls with their policies, rules and the devices they protect.", Risk: sdk.RiskRead},
			{Name: "network_transfer", Title: "Network transfer", Description: "This month's pooled network transfer: used, quota and billable overage, in GB.", Risk: sdk.RiskRead},
			{Name: "balance", Title: "Balance", Description: "The account balance and what's accrued but not invoiced yet (USD).", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "invoices", Title: "Invoices", Description: "Recent invoices with date, subtotal, tax and total.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":100,"default":12}}}`)},
			{Name: "power_on", Title: "Power on", Description: "Boots an instance that is offline. Undo shuts it down again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: in},
			{Name: "shutdown", Title: "Shut down", Description: "Shuts a running instance down. Its services go down until it's powered on, and it's still billed (destructive). Undo boots it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: in},
			{Name: "reboot", Title: "Reboot", Description: "Reboots an instance; its services go down while it restarts (destructive).", Risk: sdk.RiskDestructive, DryRun: true, Input: in},
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
		return errors.New("Linode refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Linode refused: the token's scopes don't allow this")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Linode's rate limit was hit; try again in a minute")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any, what string) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err, what)
}

// pages reads every page of a paginated list (up to 20 pages of 100).
func pages[T any](ctx context.Context, c *conn, path, what string) ([]T, error) {
	var out []T
	for page := 1; page <= 20; page++ {
		var r struct {
			Data  []T `json:"data"`
			Pages int `json:"pages"`
		}
		if err := c.get(ctx, path, url.Values{"page": {strconv.Itoa(page)}, "page_size": {"100"}}, &r, what); err != nil {
			return nil, err
		}
		out = append(out, r.Data...)
		if page >= r.Pages {
			break
		}
	}
	return out, nil
}

type instance struct {
	ID     int      `json:"id"`
	Label  string   `json:"label"`
	Status string   `json:"status"`
	Region string   `json:"region"`
	Type   string   `json:"type"`
	IPv4   []string `json:"ipv4"`
	IPv6   string   `json:"ipv6"`
	Specs  struct {
		VCPUs  int `json:"vcpus"`
		Memory int `json:"memory"`
		Disk   int `json:"disk"`
	} `json:"specs"`
	Created string `json:"created"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	list, err := pages[instance](ctx, c, "/linode/instances", "instance list")
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	off := 0
	for _, s := range list {
		if s.Status != "running" {
			off++
		}
	}
	msg := fmt.Sprintf("%d instances", len(list))
	if off > 0 {
		msg += fmt.Sprintf(", %d not running", off)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func status(s string) json.RawMessage { b, _ := json.Marshal(map[string]string{"status": s}); return b }

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Instance int `json:"instance"`
		Limit    int `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "instances":
		list, err := pages[instance](ctx, c, "/linode/instances", "instance list")
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID       int      `json:"id"`
			Label    string   `json:"label"`
			Status   string   `json:"status"`
			Region   string   `json:"region"`
			Type     string   `json:"type"`
			VCPUs    int      `json:"vcpus"`
			MemoryMB int      `json:"memoryMb"`
			DiskMB   int      `json:"diskMb"`
			IPv4     []string `json:"ipv4,omitempty"`
			IPv6     string   `json:"ipv6,omitempty"`
			Created  string   `json:"created"`
		}
		out := []row{}
		for _, s := range list {
			out = append(out, row{ID: s.ID, Label: s.Label, Status: s.Status, Region: s.Region, Type: s.Type,
				VCPUs: s.Specs.VCPUs, MemoryMB: s.Specs.Memory, DiskMB: s.Specs.Disk, IPv4: s.IPv4, IPv6: s.IPv6, Created: s.Created})
		}
		return sdk.JSON(out)

	case "volumes":
		type volume struct {
			ID          int    `json:"id"`
			Label       string `json:"label"`
			Status      string `json:"status"`
			SizeGB      int    `json:"size"`
			Region      string `json:"region"`
			LinodeID    *int   `json:"linode_id"`
			LinodeLabel string `json:"linode_label"`
		}
		list, err := pages[volume](ctx, c, "/volumes", "volume list")
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID         int    `json:"id"`
			Label      string `json:"label"`
			Status     string `json:"status"`
			SizeGB     int    `json:"sizeGb"`
			Region     string `json:"region"`
			AttachedTo string `json:"attachedTo,omitempty"`
		}
		out := []row{}
		for _, v := range list {
			out = append(out, row{ID: v.ID, Label: v.Label, Status: v.Status, SizeGB: v.SizeGB, Region: v.Region, AttachedTo: v.LinodeLabel})
		}
		return sdk.JSON(out)

	case "firewalls":
		type rule struct {
			Label     string `json:"label,omitempty"`
			Action    string `json:"action"`
			Protocol  string `json:"protocol"`
			Ports     string `json:"ports,omitempty"`
			Addresses struct {
				IPv4 []string `json:"ipv4,omitempty"`
				IPv6 []string `json:"ipv6,omitempty"`
			} `json:"addresses"`
		}
		type firewall struct {
			ID     int    `json:"id"`
			Label  string `json:"label"`
			Status string `json:"status"`
			Rules  struct {
				InboundPolicy  string `json:"inbound_policy"`
				OutboundPolicy string `json:"outbound_policy"`
				Inbound        []rule `json:"inbound"`
				Outbound       []rule `json:"outbound"`
			} `json:"rules"`
			Entities []struct {
				Type  string `json:"type"`
				Label string `json:"label"`
			} `json:"entities"`
		}
		list, err := pages[firewall](ctx, c, "/networking/firewalls", "firewall list")
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID             int      `json:"id"`
			Label          string   `json:"label"`
			Status         string   `json:"status"`
			InboundPolicy  string   `json:"inboundPolicy"`
			OutboundPolicy string   `json:"outboundPolicy"`
			Inbound        []rule   `json:"inbound"`
			Outbound       []rule   `json:"outbound"`
			Devices        []string `json:"devices"`
		}
		out := []row{}
		for _, f := range list {
			r := row{ID: f.ID, Label: f.Label, Status: f.Status, InboundPolicy: f.Rules.InboundPolicy, OutboundPolicy: f.Rules.OutboundPolicy,
				Inbound: f.Rules.Inbound, Outbound: f.Rules.Outbound, Devices: []string{}}
			if r.Inbound == nil {
				r.Inbound = []rule{}
			}
			if r.Outbound == nil {
				r.Outbound = []rule{}
			}
			for _, e := range f.Entities {
				r.Devices = append(r.Devices, e.Type+" "+e.Label)
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "network_transfer":
		var t struct {
			Used     float64 `json:"used"`
			Quota    float64 `json:"quota"`
			Billable float64 `json:"billable"`
		}
		if err := c.get(ctx, "/account/transfer", nil, &t, "transfer report"); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]float64{"usedGb": t.Used, "quotaGb": t.Quota, "billableGb": t.Billable})

	case "balance":
		// Only the two amounts: the account record also holds the
		// billing address, email and card details.
		var a struct {
			Balance           float64 `json:"balance"`
			BalanceUninvoiced float64 `json:"balance_uninvoiced"`
		}
		if err := c.get(ctx, "/account", nil, &a, "account"); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"balance": a.Balance, "uninvoiced": a.BalanceUninvoiced, "currency": "USD"})

	case "invoices":
		n := p.Limit
		if n == 0 {
			n = 12
		}
		if n < 1 || n > 100 {
			return sdk.Result{}, errors.New("limit is 1 to 100")
		}
		var r struct {
			Data []struct {
				ID       int     `json:"id"`
				Date     string  `json:"date"`
				Label    string  `json:"label"`
				Subtotal float64 `json:"subtotal"`
				Tax      float64 `json:"tax"`
				Total    float64 `json:"total"`
			} `json:"data"`
		}
		// Invoices come newest first.
		if err := c.get(ctx, "/account/invoices", url.Values{"page_size": {strconv.Itoa(max(n, 25))}}, &r, "invoice list"); err != nil {
			return sdk.Result{}, err
		}
		if len(r.Data) > n {
			r.Data = r.Data[:n]
		}
		return sdk.JSON(r.Data)

	case "power_on", "shutdown", "reboot":
		if p.Instance <= 0 {
			return sdk.Result{}, errors.New("which instance? (its id, from Instances)")
		}
		var s instance
		if err := c.get(ctx, "/linode/instances/"+strconv.Itoa(p.Instance), nil, &s, "such instance"); err != nil {
			return sdk.Result{}, err
		}
		target := fmt.Sprintf("%s (%d)", s.Label, s.ID)
		switch {
		case call.Action == "power_on" && s.Status == "running":
			return sdk.Result{}, fmt.Errorf("%s is already running", target)
		case call.Action == "shutdown" && s.Status == "offline":
			return sdk.Result{}, fmt.Errorf("%s is already offline", target)
		}
		want := map[string]string{"power_on": "running", "shutdown": "offline", "reboot": "running"}[call.Action]
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: strings.ReplaceAll(call.Action, "_", " ") + " " + target,
				Changes: []sdk.Change{{Target: target, Op: call.Action, Before: status(s.Status), After: status(want)}}}}, nil
		}
		path := map[string]string{"power_on": "boot", "shutdown": "shutdown", "reboot": "reboot"}[call.Action]
		if _, err := c.api.Do(ctx, http.MethodPost, "/linode/instances/"+strconv.Itoa(p.Instance)+"/"+path, nil, map[string]any{}, nil); err != nil {
			return sdk.Result{}, friendly(err, "such instance")
		}
		r, _ := sdk.JSON(map[string]any{"instance": target, "was": s.Status, "requested": call.Action})
		switch {
		case call.Action == "power_on" && s.Status == "offline":
			r.Undo = sdk.UndoWith("shutdown", map[string]int{"instance": p.Instance}, "Shut "+s.Label+" down again")
		case call.Action == "shutdown" && s.Status == "running":
			r.Undo = sdk.UndoWith("power_on", map[string]int{"instance": p.Instance}, "Power "+s.Label+" on again")
		}
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
