// Package xenorchestra works with Xen Orchestra (XCP-ng and XenServer
// pools) through its REST API and an authentication token: pools, hosts,
// VMs with their power state, starting, cleanly shutting down and
// rebooting VMs, and VM snapshots.
package xenorchestra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Xen Orchestra.
type Config struct {
	URL                string `json:"url"`   // https://xo.lan
	Token              string `json:"token"` // secret:// authentication token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Xen Orchestra module.
func New() *Module { return &Module{} }

var (
	pathRe  = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	uuidRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{8,512}$`)
)

// pollEvery and waitFor pace the read-back after a power action.
var (
	pollEvery = 2 * time.Second
	waitFor   = 20 * time.Second
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	vm := sdk.Schema(`{"type":"object","required":["vm"],"properties":{"vm":{"type":"string","description":"The VM's id (a UUID, from vms)"}}}`)
	return sdk.Manifest{
		ID: "xenorchestra", Name: "Xen Orchestra", Version: "0.1.0", Category: "Infrastructure", Icon: "server",
		Description: "XCP-ng and XenServer pools through Xen Orchestra: pools, hosts, VMs and their power state, start, shutdown and reboot, and snapshots.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","format":"uri","description":"Xen Orchestra's address, e.g. https://xo.lan"},
			"token":{"type":"string","x-secret":true,"description":"An authentication token (User, Authentication tokens, or xo-cli create-token); it acts with its user's permissions"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "pools", Title: "Pools", Description: "Each pool with its master host, high availability, platform version and tags.", Risk: sdk.RiskRead},
			{Name: "hosts", Title: "Hosts", Description: "Each host with pool, power state, address, product and version, CPUs, memory use, uptime and whether it needs a reboot.", Risk: sdk.RiskRead},
			{Name: "vms", Title: "VMs", Description: "Every VM with pool, host, power state, CPUs, memory, main IP address, OS, tags and snapshot count. Never its configuration data.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"state":{"type":"string","enum":["Running","Halted","Paused","Suspended"],"description":"Only VMs in this power state"}}}`)},
			{Name: "start", Title: "Start a VM", Description: "Undo shuts it down again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: vm},
			{Name: "shutdown", Title: "Shut down a VM", Description: "A clean shutdown through the guest's OS (needs the guest tools). The VM's services go down until it's started (destructive). Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: vm},
			{Name: "reboot", Title: "Reboot a VM", Description: "A clean reboot through the guest's OS; its services are down meanwhile.", Risk: sdk.RiskDestructive, DryRun: true, Input: vm},
			{Name: "snapshots", Title: "Snapshots", Description: "VM snapshots, newest first: name, description, when it was taken and the VM it belongs to.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"vm":{"type":"string","description":"Only this VM's snapshots"}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://xo.lan")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the authentication token in the vault and enter its secret:// reference")
	}
	if u.Scheme != "https" && (c.Fingerprint != "" || c.InsecureSkipVerify) {
		// Over http neither would apply, and the address would look pinned.
		return errors.New("a fingerprint or skipped certificate checks need an https address")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	ref := c.Token
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/rest/v0")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/rest/v0", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if !tokenRe.MatchString(t) {
			return errors.New("the stored token doesn't look like a Xen Orchestra authentication token")
		}
		r.Header.Set("Cookie", "authenticationToken="+t)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Xen Orchestra refused the authentication token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token's user isn't allowed to do this in Xen Orchestra")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, fields string, out any) error {
	var q url.Values
	if fields != "" {
		q = url.Values{"fields": {fields}}
	}
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var ps []struct {
		ID string `json:"id"`
	}
	if err := c.get(ctx, "/pools", "id", &ps); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Xen Orchestra REST API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var vs []struct {
		PowerState string `json:"power_state"`
	}
	msg := fmt.Sprintf("%d pools", len(ps))
	if c.get(ctx, "/vms", "power_state", &vs) == nil {
		on := 0
		for _, v := range vs {
			if v.PowerState == "Running" {
				on++
			}
		}
		msg += fmt.Sprintf(", %d VMs, %d running", len(vs), on)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type xvm struct {
	ID         string `json:"id"`
	Name       string `json:"name_label"`
	PowerState string `json:"power_state"`
	Pool       string `json:"$pool"`
	Container  string `json:"$container"`
	CPUs       struct {
		Number int `json:"number"`
		Max    int `json:"max"`
	} `json:"CPUs"`
	Memory struct {
		Size int64 `json:"size"`
	} `json:"memory"`
	MainIP    string          `json:"mainIpAddress"`
	Tags      []string        `json:"tags"`
	OS        json.RawMessage `json:"os_version"`
	Snapshots []string        `json:"snapshots"`
	StartTime *int64          `json:"startTime"`
	// Nothing else is decoded: xenStoreData, other config and boot
	// arguments can hold cloud-init data and passwords.
}

func (v xvm) label() string {
	if v.Name != "" {
		return "VM " + v.Name + " (" + v.ID + ")"
	}
	return "VM " + v.ID
}

const vmFields = "id,name_label,power_state,$pool,$container,CPUs,memory,mainIpAddress,tags,os_version,snapshots,startTime"

func osName(raw json.RawMessage) string {
	var o map[string]any
	if json.Unmarshal(raw, &o) != nil {
		return ""
	}
	for _, k := range []string{"name", "distro"} {
		if s, ok := o[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func gib(b int64) float64 { return float64(b>>20) / 1024 }

// names maps pool and host ids to their names.
func (c *conn) names(ctx context.Context) map[string]string {
	out := map[string]string{}
	for _, p := range []string{"/pools", "/hosts"} {
		var xs []struct {
			ID   string `json:"id"`
			Name string `json:"name_label"`
		}
		if c.get(ctx, p, "id,name_label", &xs) == nil {
			for _, x := range xs {
				out[x.ID] = x.Name
			}
		}
	}
	return out
}

func named(id string, by map[string]string) string {
	if n := by[id]; n != "" {
		return n
	}
	return id
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		VM    string `json:"vm"`
		State string `json:"state"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	p.VM = strings.ToLower(strings.TrimSpace(p.VM))
	switch call.Action {
	case "pools":
		var ps []struct {
			ID       string   `json:"id"`
			Name     string   `json:"name_label"`
			Desc     string   `json:"name_description"`
			Master   string   `json:"master"`
			HA       bool     `json:"HA_enabled"`
			Platform string   `json:"platform_version"`
			Tags     []string `json:"tags"`
		}
		if err := c.get(ctx, "/pools", "id,name_label,name_description,master,HA_enabled,platform_version,tags", &ps); err != nil {
			return sdk.Result{}, err
		}
		by := c.names(ctx)
		out := []map[string]any{}
		for _, x := range ps {
			out = append(out, map[string]any{"id": x.ID, "name": x.Name, "description": x.Desc, "master": named(x.Master, by), "highAvailability": x.HA,
				"platformVersion": x.Platform, "tags": x.Tags})
		}
		return sdk.JSON(out)

	case "hosts":
		var hs []struct {
			ID      string `json:"id"`
			Name    string `json:"name_label"`
			Power   string `json:"power_state"`
			Enabled *bool  `json:"enabled"`
			Address string `json:"address"`
			Brand   string `json:"productBrand"`
			Version string `json:"version"`
			Pool    string `json:"$pool"`
			CPUs    struct {
				Count json.Number `json:"cpu_count"`
			} `json:"CPUs"`
			Memory struct {
				Usage int64 `json:"usage"`
				Size  int64 `json:"size"`
			} `json:"memory"`
			RebootRequired bool  `json:"rebootRequired"`
			StartTime      int64 `json:"startTime"`
		}
		if err := c.get(ctx, "/hosts", "id,name_label,power_state,enabled,address,productBrand,version,$pool,CPUs,memory,rebootRequired,startTime", &hs); err != nil {
			return sdk.Result{}, err
		}
		by := c.names(ctx)
		sort.Slice(hs, func(i, j int) bool { return hs[i].Name < hs[j].Name })
		out := []map[string]any{}
		for _, x := range hs {
			row := map[string]any{"id": x.ID, "name": x.Name, "pool": named(x.Pool, by), "powerState": x.Power, "address": x.Address,
				"product": strings.TrimSpace(x.Brand + " " + x.Version), "memGiB": gib(x.Memory.Size), "rebootRequired": x.RebootRequired}
			if n, err := strconv.Atoi(x.CPUs.Count.String()); err == nil {
				row["cpus"] = n
			}
			if x.Memory.Size > 0 {
				row["memPercent"] = float64(int(float64(x.Memory.Usage)/float64(x.Memory.Size)*1000)) / 10
			}
			if x.Enabled != nil {
				row["enabled"] = *x.Enabled
			}
			if x.StartTime > 0 && x.Power == "Running" {
				row["uptimeHours"] = int64(time.Since(time.Unix(x.StartTime, 0)).Hours())
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "vms":
		var vs []xvm
		if err := c.get(ctx, "/vms", vmFields, &vs); err != nil {
			return sdk.Result{}, err
		}
		by := c.names(ctx)
		sort.Slice(vs, func(i, j int) bool { return vs[i].Name < vs[j].Name })
		out := []map[string]any{}
		for _, v := range vs {
			if p.State != "" && !strings.EqualFold(v.PowerState, p.State) {
				continue
			}
			row := map[string]any{"id": v.ID, "name": v.Name, "pool": named(v.Pool, by), "powerState": v.PowerState, "cpus": v.CPUs.Number,
				"memGiB": gib(v.Memory.Size), "tags": v.Tags, "snapshots": len(v.Snapshots)}
			if v.Container != "" && v.Container != v.Pool {
				row["host"] = named(v.Container, by)
			}
			if v.MainIP != "" {
				row["ip"] = v.MainIP
			}
			if os := osName(v.OS); os != "" {
				row["os"] = os
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "start", "shutdown", "reboot":
		if !uuidRe.MatchString(p.VM) {
			return sdk.Result{}, errors.New("a VM is given by its id, a UUID (see vms)")
		}
		return c.power(ctx, call, p.VM)

	case "snapshots":
		if p.VM != "" && !uuidRe.MatchString(p.VM) {
			return sdk.Result{}, errors.New("a VM is given by its id, a UUID (see vms)")
		}
		var ss []struct {
			ID   string `json:"id"`
			Name string `json:"name_label"`
			Desc string `json:"name_description"`
			Time int64  `json:"snapshot_time"`
			Of   string `json:"$snapshot_of"`
		}
		if err := c.get(ctx, "/vm-snapshots", "id,name_label,name_description,snapshot_time,$snapshot_of", &ss); err != nil {
			return sdk.Result{}, err
		}
		vmNames := map[string]string{}
		var vs []xvm
		if c.get(ctx, "/vms", "id,name_label", &vs) == nil {
			for _, v := range vs {
				vmNames[v.ID] = v.Name
			}
		}
		sort.Slice(ss, func(i, j int) bool { return ss[i].Time > ss[j].Time })
		out := []map[string]any{}
		for _, s := range ss {
			if p.VM != "" && s.Of != p.VM {
				continue
			}
			row := map[string]any{"id": s.ID, "name": s.Name, "vm": s.Of, "vmName": vmNames[s.Of]}
			if s.Desc != "" {
				row["description"] = s.Desc
			}
			if s.Time > 0 {
				row["taken"] = time.Unix(s.Time, 0).UTC().Format(time.RFC3339)
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) vm(ctx context.Context, id string) (xvm, error) {
	var v xvm
	if err := c.get(ctx, "/vms/"+url.PathEscape(id), "", &v); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return xvm{}, fmt.Errorf("there's no VM %s", id)
		}
		return xvm{}, err
	}
	if v.ID == "" {
		return xvm{}, fmt.Errorf("there's no VM %s", id)
	}
	if v.ID != id {
		// The id goes into the action's path and the undo.
		return xvm{}, fmt.Errorf("Xen Orchestra answered with another VM for %s", id)
	}
	return v, nil
}

func (c *conn) power(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	v, err := c.vm(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	want := map[string]string{"start": "Running", "shutdown": "Halted", "reboot": "Running"}[call.Action]
	op := map[string]string{"start": "start", "shutdown": "clean_shutdown", "reboot": "clean_reboot"}[call.Action]
	verb := map[string]string{"start": "Start", "shutdown": "Shut down", "reboot": "Reboot"}[call.Action]
	switch {
	case call.Action == "reboot" && v.PowerState != "Running":
		return sdk.Result{}, fmt.Errorf("%s isn't running (it's %s)", v.label(), v.PowerState)
	case call.Action == "start" && v.PowerState != "Halted" && v.PowerState != want:
		return sdk.Result{}, fmt.Errorf("%s is %s; only a halted VM is started", v.label(), v.PowerState)
	case call.Action == "shutdown" && v.PowerState != "Running" && v.PowerState != want:
		return sdk.Result{}, fmt.Errorf("%s is %s; only a running VM is shut down", v.label(), v.PowerState)
	}
	if v.PowerState == want && call.Action != "reboot" {
		return sdk.JSON(map[string]any{"vm": v.ID, "name": v.Name, "powerState": v.PowerState, "changed": false, "note": "nothing to change"})
	}
	if call.DryRun {
		before, _ := json.Marshal(map[string]string{"powerState": v.PowerState})
		after, _ := json.Marshal(map[string]string{"powerState": want})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + v.label(), Changes: []sdk.Change{{Target: v.label(), Op: call.Action, Before: before, After: after}}}}, nil
	}
	var body any
	if call.Action == "start" {
		body = map[string]any{}
	}
	var task struct {
		TaskID string `json:"taskId"`
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/vms/"+url.PathEscape(v.ID)+"/actions/"+op, nil, body, &task); err != nil {
		return sdk.Result{}, friendly(err)
	}
	out := map[string]any{"vm": v.ID, "name": v.Name, "changed": true}
	if task.TaskID != "" && len(task.TaskID) <= 64 {
		out["task"] = task.TaskID
	}
	// Read the state back until it's reached; a reboot keeps Running, so
	// it's read once.
	now := v.PowerState
	if call.Action == "reboot" {
		if x, err := c.vm(ctx, v.ID); err == nil {
			now = x.PowerState
		}
		if now != want {
			out["note"] = "Xen Orchestra accepted it; the VM is " + now + " for now, check again with vms"
		}
	} else {
		deadline := time.Now().Add(waitFor)
		for now != want && time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return sdk.Result{}, ctx.Err()
			case <-time.After(pollEvery):
			}
			if x, err := c.vm(ctx, v.ID); err == nil {
				now = x.PowerState
			}
		}
		if now != want {
			out["note"] = "Xen Orchestra accepted it; the VM is still " + now + ", check again with vms"
		}
	}
	out["powerState"] = now
	res, err := sdk.JSON(out)
	switch call.Action {
	case "start":
		res.Undo = sdk.UndoWith("shutdown", map[string]string{"vm": v.ID}, "Shut "+v.label()+" down again")
	case "shutdown":
		res.Undo = sdk.UndoWith("start", map[string]string{"vm": v.ID}, "Start "+v.label()+" again")
	}
	return res, err
}
