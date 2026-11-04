// Package vultr manages Vultr cloud instances through the Vultr API v2:
// status, power, snapshots and bandwidth, plus the account balance.
package vultr

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

// Config is one Vultr account.
type Config struct {
	APIKey string `json:"apiKey"` // secret:// API key
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.vultr.com/v2 (tests).
	Base string
}

// New returns the Vultr module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.vultr.com/v2"

// Vultr ids are UUIDs.
var idRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// descRe is a snapshot description: printable, one line.
var descRe = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,120}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	in := `"instance":{"type":"string","description":"Instance id (from Instances)"}`
	one := sdk.Schema(`{"type":"object","required":["instance"],"properties":{` + in + `}}`)
	return sdk.Manifest{
		ID: "vultr", Name: "Vultr", Version: "0.1.0", Category: "Infrastructure", Icon: "server",
		Description: "Your Vultr instances: status, region and plan, start, halt and reboot; snapshots, bandwidth and the account balance.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"The API key (Account, API). Allow Conduit's address under Access Control if you restrict it"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "instances", Title: "Instances", Description: "Status, power state, region, plan and addresses.", Risk: sdk.RiskRead},
			{Name: "snapshots", Title: "Snapshots", Description: "Snapshots with size, status and when they were taken.", Risk: sdk.RiskRead},
			{Name: "bandwidth", Title: "Bandwidth", Description: "An instance's daily incoming and outgoing traffic over the last days.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["instance"],"properties":{` + in + `,"days":{"type":"integer","minimum":1,"maximum":31,"default":7}}}`)},
			{Name: "balance", Title: "Balance", Description: "Account balance (negative means credit), pending charges and the last payment.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "start", Title: "Start an instance", Description: "Starts a stopped instance. Undo halts it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: one},
			{Name: "halt", Title: "Halt an instance", Description: "Powers a running instance off. Its services go down until it's started, and it's still billed (destructive). Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: one},
			{Name: "reboot", Title: "Reboot an instance", Description: "Reboots an instance; its services go down while it restarts (destructive).", Risk: sdk.RiskDestructive, DryRun: true, Input: one},
			{Name: "snapshot", Title: "Take a snapshot", Description: "Takes a snapshot of an instance. Vultr bills snapshots by size each month (destructive: it creates a billable resource). Undo deletes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["instance"],"properties":{` + in + `,"description":{"type":"string","maxLength":120}}}`)},
			{Name: "delete_snapshot", Title: "Delete a snapshot", Description: "Deletes a snapshot for good.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["snapshot"],"properties":{"snapshot":{"type":"string","description":"Snapshot id (from Snapshots)"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	ref := c.APIKey
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
		return errors.New("Vultr refused the API key (or Conduit's address isn't allowed under its Access Control)")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Vultr refused: the API key's user can't do this")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Vultr's rate limit was hit; try again in a moment")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any, what string) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err, what)
}

type instance struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Region      string `json:"region"`
	Plan        string `json:"plan"`
	VCPUs       int    `json:"vcpu_count"`
	RAM         int    `json:"ram"`
	Disk        int    `json:"disk"`
	MainIP      string `json:"main_ip"`
	V6MainIP    string `json:"v6_main_ip"`
	Status      string `json:"status"`
	PowerStatus string `json:"power_status"`
	Server      string `json:"server_status"`
	Created     string `json:"date_created"`
}

func (s instance) name() string {
	if s.Label != "" {
		return s.Label
	}
	return s.Hostname
}

func (c *conn) instances(ctx context.Context) ([]instance, error) {
	var out []instance
	cursor := ""
	for range 20 {
		q := url.Values{"per_page": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var r struct {
			Instances []instance `json:"instances"`
			Meta      struct {
				Links struct {
					Next string `json:"next"`
				} `json:"links"`
			} `json:"meta"`
		}
		if err := c.do(ctx, http.MethodGet, "/instances", q, nil, &r, "instance list"); err != nil {
			return nil, err
		}
		out = append(out, r.Instances...)
		if r.Meta.Links.Next == "" {
			break
		}
		cursor = r.Meta.Links.Next
	}
	return out, nil
}

func (c *conn) instance(ctx context.Context, id string) (instance, error) {
	var r struct {
		Instance instance `json:"instance"`
	}
	err := c.do(ctx, http.MethodGet, "/instances/"+id, nil, nil, &r, "such instance")
	return r.Instance, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	list, err := c.instances(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	off := 0
	for _, s := range list {
		if s.PowerStatus != "running" {
			off++
		}
	}
	msg := fmt.Sprintf("%d instances", len(list))
	if off > 0 {
		msg += fmt.Sprintf(", %d not running", off)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func power(s string) json.RawMessage { b, _ := json.Marshal(map[string]string{"power": s}); return b }

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Instance    string `json:"instance"`
		Snapshot    string `json:"snapshot"`
		Description string `json:"description"`
		Days        int    `json:"days"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	needInstance := func() error {
		if !idRe.MatchString(p.Instance) {
			return errors.New("which instance? (its id, from Instances)")
		}
		return nil
	}
	switch call.Action {
	case "instances":
		list, err := c.instances(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Status  string `json:"status"`
			Power   string `json:"power"`
			Server  string `json:"serverStatus"`
			Region  string `json:"region"`
			Plan    string `json:"plan"`
			OS      string `json:"os"`
			VCPUs   int    `json:"vcpus"`
			RAMMB   int    `json:"ramMb"`
			DiskGB  int    `json:"diskGb"`
			IPv4    string `json:"ipv4,omitempty"`
			IPv6    string `json:"ipv6,omitempty"`
			Created string `json:"created"`
		}
		out := []row{}
		for _, s := range list {
			out = append(out, row{ID: s.ID, Name: s.name(), Status: s.Status, Power: s.PowerStatus, Server: s.Server, Region: s.Region, Plan: s.Plan, OS: s.OS,
				VCPUs: s.VCPUs, RAMMB: s.RAM, DiskGB: s.Disk, IPv4: s.MainIP, IPv6: s.V6MainIP, Created: s.Created})
		}
		return sdk.JSON(out)

	case "snapshots":
		var r struct {
			Snapshots []struct {
				ID          string `json:"id"`
				Description string `json:"description"`
				Status      string `json:"status"`
				Size        int64  `json:"size"`
				Created     string `json:"date_created"`
			} `json:"snapshots"`
		}
		if err := c.do(ctx, http.MethodGet, "/snapshots", url.Values{"per_page": {"100"}}, nil, &r, "snapshot list"); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID          string  `json:"id"`
			Description string  `json:"description"`
			Status      string  `json:"status"`
			SizeGB      float64 `json:"sizeGb"`
			Created     string  `json:"created"`
		}
		out := []row{}
		for _, s := range r.Snapshots {
			out = append(out, row{ID: s.ID, Description: s.Description, Status: s.Status, SizeGB: float64(s.Size/(1<<20)) / 1024, Created: s.Created})
		}
		return sdk.JSON(out)

	case "bandwidth":
		if err := needInstance(); err != nil {
			return sdk.Result{}, err
		}
		days := p.Days
		if days == 0 {
			days = 7
		}
		if days < 1 || days > 31 {
			return sdk.Result{}, errors.New("days is 1 to 31")
		}
		var r struct {
			Bandwidth map[string]struct {
				In  int64 `json:"incoming_bytes"`
				Out int64 `json:"outgoing_bytes"`
			} `json:"bandwidth"`
		}
		if err := c.do(ctx, http.MethodGet, "/instances/"+p.Instance+"/bandwidth", nil, nil, &r, "such instance"); err != nil {
			return sdk.Result{}, err
		}
		dates := make([]string, 0, len(r.Bandwidth))
		for d := range r.Bandwidth {
			dates = append(dates, d)
		}
		sort.Strings(dates)
		if len(dates) > days {
			dates = dates[len(dates)-days:]
		}
		type row struct {
			Date     string `json:"date"`
			InBytes  int64  `json:"inBytes"`
			OutBytes int64  `json:"outBytes"`
		}
		rows := []row{}
		var in, out int64
		for _, d := range dates {
			b := r.Bandwidth[d]
			rows = append(rows, row{Date: d, InBytes: b.In, OutBytes: b.Out})
			in += b.In
			out += b.Out
		}
		return sdk.JSON(map[string]any{"days": rows, "totalInBytes": in, "totalOutBytes": out})

	case "balance":
		// Only the amounts: the account also lists name, email and ACLs.
		var r struct {
			Account struct {
				Balance           float64 `json:"balance"`
				PendingCharges    float64 `json:"pending_charges"`
				LastPaymentDate   string  `json:"last_payment_date"`
				LastPaymentAmount float64 `json:"last_payment_amount"`
			} `json:"account"`
		}
		if err := c.do(ctx, http.MethodGet, "/account", nil, nil, &r, "account"); err != nil {
			return sdk.Result{}, err
		}
		a := r.Account
		return sdk.JSON(map[string]any{"balance": a.Balance, "pendingCharges": a.PendingCharges, "lastPaymentDate": a.LastPaymentDate, "lastPaymentAmount": a.LastPaymentAmount, "currency": "USD"})

	case "start", "halt", "reboot":
		if err := needInstance(); err != nil {
			return sdk.Result{}, err
		}
		s, err := c.instance(ctx, p.Instance)
		if err != nil {
			return sdk.Result{}, err
		}
		target := s.name() + " (" + s.ID + ")"
		switch {
		case call.Action == "start" && s.PowerStatus == "running":
			return sdk.Result{}, fmt.Errorf("%s is already running", target)
		case call.Action == "halt" && s.PowerStatus == "stopped":
			return sdk.Result{}, fmt.Errorf("%s is already stopped", target)
		}
		want := map[string]string{"start": "running", "halt": "stopped", "reboot": "running"}[call.Action]
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: call.Action + " " + target,
				Changes: []sdk.Change{{Target: target, Op: call.Action, Before: power(s.PowerStatus), After: power(want)}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/instances/"+p.Instance+"/"+call.Action, nil, nil, nil, "such instance"); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"instance": target, "was": s.PowerStatus, "requested": call.Action})
		switch {
		case call.Action == "start" && s.PowerStatus == "stopped":
			r.Undo = sdk.UndoWith("halt", map[string]string{"instance": p.Instance}, "Halt "+s.name()+" again")
		case call.Action == "halt" && s.PowerStatus == "running":
			r.Undo = sdk.UndoWith("start", map[string]string{"instance": p.Instance}, "Start "+s.name()+" again")
		}
		return r, nil

	case "snapshot":
		if err := needInstance(); err != nil {
			return sdk.Result{}, err
		}
		desc := strings.TrimSpace(p.Description)
		if desc != "" && !descRe.MatchString(desc) {
			return sdk.Result{}, errors.New("the description is one line of up to 120 characters")
		}
		s, err := c.instance(ctx, p.Instance)
		if err != nil {
			return sdk.Result{}, err
		}
		if desc == "" {
			desc = "Conduit snapshot of " + s.name()
		}
		if call.DryRun {
			after, _ := json.Marshal(map[string]string{"snapshot": desc, "billing": "billed monthly by size"})
			return sdk.Result{Plan: &sdk.Plan{Summary: "Take a snapshot of " + s.name() + " (billed by size)",
				Changes: []sdk.Change{{Target: s.name(), Op: "create", After: after}}}}, nil
		}
		var r struct {
			Snapshot struct {
				ID string `json:"id"`
			} `json:"snapshot"`
		}
		if err := c.do(ctx, http.MethodPost, "/snapshots", nil, map[string]string{"instance_id": p.Instance, "description": desc}, &r, "such instance"); err != nil {
			return sdk.Result{}, err
		}
		res, _ := sdk.JSON(map[string]string{"snapshot": r.Snapshot.ID, "description": desc})
		if idRe.MatchString(r.Snapshot.ID) {
			res.Undo = sdk.UndoWith("delete_snapshot", map[string]string{"snapshot": r.Snapshot.ID}, "Delete the snapshot")
		}
		return res, nil

	case "delete_snapshot":
		if !idRe.MatchString(p.Snapshot) {
			return sdk.Result{}, errors.New("which snapshot? (its id, from Snapshots)")
		}
		var r struct {
			Snapshot struct {
				ID          string `json:"id"`
				Description string `json:"description"`
				Size        int64  `json:"size"`
				Created     string `json:"date_created"`
			} `json:"snapshot"`
		}
		if err := c.do(ctx, http.MethodGet, "/snapshots/"+p.Snapshot, nil, nil, &r, "such snapshot"); err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"description": r.Snapshot.Description, "created": r.Snapshot.Created, "sizeBytes": r.Snapshot.Size})
			return sdk.Result{Plan: &sdk.Plan{Summary: "Delete snapshot " + r.Snapshot.Description,
				Changes: []sdk.Change{{Target: p.Snapshot, Op: "delete", Before: before}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/snapshots/"+p.Snapshot, nil, nil, nil, "such snapshot"); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.Snapshot})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
