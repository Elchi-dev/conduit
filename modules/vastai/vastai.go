// Package vastai works with a Vast.ai account through its API and an API
// key: rented instances with GPU, status and cost per hour, starting,
// stopping and destroying instances, and the account's credit.
package vastai

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
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Vast.ai account.
type Config struct {
	APIKey string `json:"apiKey"` // secret://
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://console.vast.ai/api/v0 (tests).
	Base string
}

// New returns the Vast.ai module.
func New() *Module { return &Module{} }

var idRe = regexp.MustCompile(`^[1-9][0-9]{0,11}$`)

const instanceIn = `{"type":"object","required":["instance"],"properties":{"instance":{"type":["integer","string"],"description":"Instance id (from instances)"}}}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "vastai", Name: "Vast.ai", Version: "0.1.0", Category: "Infrastructure", Icon: "chip",
		Description: "Vast.ai: your GPU instances with status and cost per hour, start, stop and destroy them, and the account's credit.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"API key (cloud.vast.ai, Account, Keys). A restricted key needs instance read, and instance write to start, stop or destroy"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "instances", Title: "Instances", Description: "Every instance: label, status, GPU type and count, cost per hour, CPU, memory, disk, image, location, GPU use and when it started. Never its SSH or Jupyter details, environment or start script.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"running":{"type":"boolean","description":"Only running (true) or stopped (false) instances"}}}`)},
			{Name: "start_instance", Title: "Start an instance", Description: "Starts a stopped instance, billed by the hour from then on (destructive: it spends money). The preview shows the cost per hour. If its GPUs were rented out meanwhile it waits for them. Undo stops it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(instanceIn)},
			{Name: "stop_instance", Title: "Stop an instance", Description: "Stops a running instance: whatever runs on it ends, its disk is kept and still billed, and its GPUs may be rented to someone else meanwhile (destructive). Undo starts it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(instanceIn)},
			{Name: "destroy_instance", Title: "Destroy an instance", Description: "Deletes an instance and everything on its disk; it can't be undone (destructive). Billing for it ends.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(instanceIn)},
			{Name: "balance", Title: "Balance", Description: "Credit left on the account, and what running instances cost per hour together, in US dollars.", Risk: sdk.RiskRead},
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
	base := "https://console.vast.ai/api/v0"
	if m.Base != "" {
		base = m.Base
	}
	ref := c.APIKey
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
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

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Vast.ai refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Vast.ai refused: the API key isn't allowed to do this")
	}
	return err
}

// instance is decoded field by field: the SSH and Jupyter details, the
// environment, the start script and the instance's API key are never read.
type instance struct {
	ID             int64    `json:"id"`
	Label          *string  `json:"label"`
	ActualStatus   *string  `json:"actual_status"`
	IntendedStatus string   `json:"intended_status"`
	CurState       string   `json:"cur_state"`
	GPUName        string   `json:"gpu_name"`
	NumGPUs        int      `json:"num_gpus"`
	DPHTotal       *float64 `json:"dph_total"`
	StorageCost    *float64 `json:"storage_cost"`
	DiskSpace      float64  `json:"disk_space"`
	CPUCores       float64  `json:"cpu_cores_effective"`
	CPURAM         float64  `json:"cpu_ram"`
	Image          string   `json:"image_uuid"`
	Geolocation    *string  `json:"geolocation"`
	StartDate      *float64 `json:"start_date"`
	GPUUtil        *float64 `json:"gpu_util"`
	IsBid          bool     `json:"is_bid"`
	StatusMsg      *string  `json:"status_msg"`
}

func (x instance) label() string {
	if x.Label != nil && strings.TrimSpace(*x.Label) != "" {
		return strings.TrimSpace(*x.Label)
	}
	return "instance " + strconv.FormatInt(x.ID, 10)
}

func (x instance) gpu() string {
	if x.NumGPUs > 0 {
		return fmt.Sprintf("%dx %s", x.NumGPUs, x.GPUName)
	}
	return x.GPUName
}

func (x instance) cost() string {
	if x.DPHTotal == nil {
		return "an hourly rate Vast.ai didn't say"
	}
	return fmt.Sprintf("$%.3f/hr", *x.DPHTotal)
}

// running is whether it's meant to run (it may still be loading).
func (x instance) running() bool {
	if x.IntendedStatus != "" {
		return x.IntendedStatus == "running"
	}
	return x.CurState == "running"
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (x instance) summary() map[string]any {
	out := map[string]any{"id": x.ID, "label": x.label(), "status": str(x.ActualStatus), "intended": x.IntendedStatus, "gpu": x.gpu(), "gpuCount": x.NumGPUs,
		"cpuCores": x.CPUCores, "memoryGB": float64(int(x.CPURAM/1024*10)) / 10, "diskGB": x.DiskSpace, "image": x.Image, "interruptible": x.IsBid, "currency": "USD"}
	if x.DPHTotal != nil {
		out["costPerHour"] = *x.DPHTotal
	}
	if x.StorageCost != nil {
		out["storageCostPerGBMonth"] = *x.StorageCost
	}
	if g := str(x.Geolocation); g != "" {
		out["location"] = g
	}
	if x.StartDate != nil && *x.StartDate > 0 {
		out["started"] = time.Unix(int64(*x.StartDate), 0).UTC().Format(time.RFC3339)
	}
	if x.GPUUtil != nil {
		out["gpuUtilization"] = *x.GPUUtil
	}
	if s := strings.TrimSpace(str(x.StatusMsg)); s != "" {
		r := []rune(s)
		if len(r) > 300 {
			s = string(r[:300]) + "…"
		}
		out["statusMessage"] = rest.Redact(s)
	}
	return out
}

func (c *conn) instances(ctx context.Context) ([]instance, error) {
	var out struct {
		Instances []instance `json:"instances"`
	}
	_, err := c.api.Do(ctx, http.MethodGet, "/instances/", url.Values{"owner": {"me"}}, nil, &out)
	return out.Instances, friendly(err)
}

func (c *conn) instance(ctx context.Context, id string) (instance, error) {
	var out struct {
		Instances json.RawMessage `json:"instances"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/instances/"+id+"/", url.Values{"owner": {"me"}}, nil, &out); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return instance{}, fmt.Errorf("there's no instance %s", id)
		}
		return instance{}, friendly(err)
	}
	var x instance
	// One instance comes as an object; some answers wrap it in a list.
	if err := json.Unmarshal(out.Instances, &x); err != nil {
		var xs []instance
		if json.Unmarshal(out.Instances, &xs) != nil || len(xs) != 1 {
			return instance{}, fmt.Errorf("there's no instance %s", id)
		}
		x = xs[0]
	}
	if x.ID == 0 {
		return instance{}, fmt.Errorf("there's no instance %s", id)
	}
	if strconv.FormatInt(x.ID, 10) != id {
		// The id goes into the change's path and the undo.
		return instance{}, fmt.Errorf("Vast.ai answered with another instance for %s", id)
	}
	return x, nil
}

func (c *conn) credit(ctx context.Context) (float64, error) {
	var u struct {
		Credit float64 `json:"credit"`
		// The e-mail, api keys and billing details aren't decoded.
	}
	_, err := c.api.Do(ctx, http.MethodGet, "/users/current/", nil, nil, &u)
	return u.Credit, friendly(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	cr, err := c.credit(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("credit $%.2f", cr)
	if cr <= 0 {
		return sdk.Health{Status: "degraded", Message: msg + "; instances stop when credit runs out"}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// instanceID reads an id given as a number or a string.
func instanceID(raw json.RawMessage) (string, error) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if !idRe.MatchString(s) {
		return "", errors.New("an instance is its numeric id from instances")
	}
	return s, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Instance json.RawMessage `json:"instance"`
		Running  *bool           `json:"running"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "instances":
		xs, err := c.instances(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.SliceStable(xs, func(i, j int) bool { return xs[i].ID < xs[j].ID })
		list := []map[string]any{}
		var perHr float64
		for _, x := range xs {
			if p.Running != nil && x.running() != *p.Running {
				continue
			}
			if x.running() && x.DPHTotal != nil {
				perHr += *x.DPHTotal
			}
			list = append(list, x.summary())
		}
		return sdk.JSON(map[string]any{"instances": list, "runningCostPerHour": perHr, "currency": "USD"})
	case "balance":
		cr, err := c.credit(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"currency": "USD", "credit": cr}
		if xs, err := c.instances(ctx); err == nil {
			var perHr float64
			n := 0
			for _, x := range xs {
				if x.running() && x.DPHTotal != nil {
					perHr += *x.DPHTotal
					n++
				}
			}
			out["running"], out["spendPerHour"] = n, perHr
			if perHr > 0 {
				out["hoursLeftAtThisRate"] = float64(int(cr/perHr*10)) / 10
			}
		}
		return sdk.JSON(out)
	case "start_instance", "stop_instance", "destroy_instance":
		id, err := instanceID(p.Instance)
		if err != nil {
			return sdk.Result{}, err
		}
		x, err := c.instance(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.Action == "destroy_instance" {
			return c.destroy(ctx, call, id, x)
		}
		return c.power(ctx, call, id, x)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type ack struct {
	Success *bool  `json:"success"`
	Msg     string `json:"msg"`
	Error   string `json:"error"`
}

func (a ack) err() error {
	if a.Success != nil && !*a.Success {
		m := a.Msg
		if m == "" {
			m = a.Error
		}
		if m == "" {
			m = "it refused"
		}
		return errors.New("Vast.ai: " + rest.Redact(m))
	}
	return nil
}

func (c *conn) power(ctx context.Context, call sdk.Call, id string, x instance) (sdk.Result, error) {
	start := call.Action == "start_instance"
	if x.running() == start {
		return sdk.JSON(map[string]any{"instance": x.ID, "label": x.label(), "intended": x.IntendedStatus, "note": "nothing to change"})
	}
	target := fmt.Sprintf("%s (%s, %s)", x.label(), x.gpu(), x.cost())
	state, op := "stopped", "stop"
	if start {
		state, op = "running", "start"
	}
	if call.DryRun {
		sum := "Start " + x.label() + " on " + x.gpu() + ", billed " + x.cost() + " while it runs"
		if !start {
			sum = fmt.Sprintf("Stop %s (%s, %s): what runs on it ends; its %g GB disk is kept and still billed, and its GPUs may be rented out meanwhile", x.label(), x.gpu(), x.cost(), x.DiskSpace)
		}
		before, _ := json.Marshal(map[string]any{"intended": x.IntendedStatus, "status": str(x.ActualStatus)})
		after, _ := json.Marshal(map[string]any{"intended": state})
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: op, Before: before, After: after}}}}, nil
	}
	var a ack
	if _, err := c.api.Do(ctx, http.MethodPut, "/instances/"+id+"/", nil, map[string]string{"state": state}, &a); err != nil {
		return sdk.Result{}, friendly(err)
	}
	if err := a.err(); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"instance": x.ID, "label": x.label(), "intended": state, "intendedBefore": x.IntendedStatus, "gpu": x.gpu(), "costPerHour": x.DPHTotal})
	if start {
		res.Undo = sdk.UndoWith("stop_instance", map[string]string{"instance": id}, "Stop "+x.label()+" again")
	} else {
		res.Undo = sdk.UndoWith("start_instance", map[string]string{"instance": id}, "Start "+x.label()+" again")
	}
	return res, err
}

func (c *conn) destroy(ctx context.Context, call sdk.Call, id string, x instance) (sdk.Result, error) {
	if call.DryRun {
		sum := fmt.Sprintf("Destroy %s (%s, %s, %g GB disk, now %s): everything on it is deleted for good", x.label(), x.gpu(), x.cost(), x.DiskSpace, str(x.ActualStatus))
		before, _ := json.Marshal(x.summary())
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: x.label(), Op: "destroy", Before: before}}}}, nil
	}
	var a ack
	if _, err := c.api.Do(ctx, http.MethodDelete, "/instances/"+id+"/", nil, nil, &a); err != nil {
		return sdk.Result{}, friendly(err)
	}
	if err := a.err(); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"instance": x.ID, "label": x.label(), "destroyed": true})
}
