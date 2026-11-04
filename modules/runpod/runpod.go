// Package runpod works with a RunPod account through its GraphQL API and an
// API key: GPU pods with their cost per hour, starting and stopping pods,
// serverless endpoints, and the account balance and current spend.
package runpod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one RunPod account.
type Config struct {
	APIKey string `json:"apiKey"` // secret://
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.runpod.io/graphql (tests).
	Base string
}

// New returns the RunPod module.
func New() *Module { return &Module{} }

var podRe = regexp.MustCompile(`^[A-Za-z0-9]{1,40}$`)

// The queries name every field they read: a pod's environment variables,
// ports with their addresses, and registry credentials are never asked for.
const (
	podFields = `id name desiredStatus podType costPerHr gpuCount vcpuCount memoryInGb containerDiskInGb volumeInGb imageName lastStatusChange machine { gpuDisplayName location } runtime { uptimeInSeconds }`
	podsQuery = `query Pods { myself { pods { ` + podFields + ` } } }`
	podQuery  = `query Pod($input: PodFilter!) { pod(input: $input) { ` + podFields + ` } }`
	endpoints = `query Endpoints { myself { endpoints { id name gpuIds workersMin workersMax idleTimeout scalerType scalerValue locations } } }`
	balance   = `query Balance { myself { clientBalance currentSpendPerHr spendLimit } }`
	resumePod = `mutation Start($input: PodResumeInput!) { podResume(input: $input) { id desiredStatus costPerHr } }`
	stopPod   = `mutation Stop($input: PodStopInput!) { podStop(input: $input) { id desiredStatus } }`
	podIn     = `{"type":"object","required":["pod"],"properties":{"pod":{"type":"string","description":"Pod id (from pods)"}}}`
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "runpod", Name: "RunPod", Version: "0.1.0", Category: "Infrastructure", Icon: "cpu",
		Description: "RunPod: GPU pods with status and cost per hour, start and stop pods, serverless endpoints, and the balance and current spend.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"API key (runpod.io, Settings, API Keys). Read only is enough to look; starting and stopping pods needs read/write"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "pods", Title: "Pods", Description: "Every pod: status, GPU type and count, cost per hour, CPU, memory, disks, image, location and uptime. Never its environment variables or connection details.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"running":{"type":"boolean","description":"Only running (true) or stopped (false) pods"}}}`)},
			{Name: "start_pod", Title: "Start a pod", Description: "Starts a stopped pod on its GPUs, billed by the hour from then on (destructive: it spends money). The preview shows the cost per hour. Undo stops it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(podIn)},
			{Name: "stop_pod", Title: "Stop a pod", Description: "Stops a running pod: whatever runs on it ends and its container disk is cleared; the volume disk stays and is still billed for storage (destructive). Undo starts it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(podIn)},
			{Name: "endpoints", Title: "Serverless endpoints", Description: "Serverless endpoints: GPU types, minimum and maximum workers, idle timeout, scaling and locations.", Risk: sdk.RiskRead},
			{Name: "balance", Title: "Balance", Description: "Credit left, what the account spends per hour right now, and the spend limit, in US dollars.", Risk: sdk.RiskRead},
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
	base := "https://api.runpod.io/graphql"
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

var errRefused = errors.New("RunPod refused the API key")

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errRefused
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("RunPod refused: the API key isn't allowed to do this (starting and stopping pods needs a read/write key)")
	}
	return err
}

// gql sends a fixed query; every value from the caller travels in vars.
func (c *conn) gql(ctx context.Context, query string, vars map[string]any, out any) error {
	var res struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	body := map[string]any{"query": query}
	if vars != nil {
		body["variables"] = vars
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "", nil, body, &res); err != nil {
		return friendly(err)
	}
	if len(res.Errors) > 0 {
		msg := res.Errors[0].Message
		if l := strings.ToLower(msg); strings.Contains(l, "unauthorized") || strings.Contains(l, "not authorized") || strings.Contains(l, "api key") {
			return errRefused
		}
		// Redacted before it's cut, so a cut can't shorten a key below
		// what Redact recognizes.
		msg = rest.Redact(strings.TrimSpace(msg))
		if r := []rune(msg); len(r) > 300 {
			msg = string(r[:300]) + "…"
		}
		return errors.New("RunPod: " + msg)
	}
	if out != nil && len(res.Data) > 0 {
		if err := json.Unmarshal(res.Data, out); err != nil {
			return errors.New("unexpected answer from RunPod")
		}
	}
	return nil
}

type pod struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	DesiredStatus    string   `json:"desiredStatus"`
	PodType          string   `json:"podType"`
	CostPerHr        *float64 `json:"costPerHr"`
	GPUCount         int      `json:"gpuCount"`
	VCPUCount        float64  `json:"vcpuCount"`
	MemoryInGB       float64  `json:"memoryInGb"`
	ContainerDiskGB  float64  `json:"containerDiskInGb"`
	VolumeGB         float64  `json:"volumeInGb"`
	ImageName        string   `json:"imageName"`
	LastStatusChange string   `json:"lastStatusChange"`
	Machine          *struct {
		GPU      string `json:"gpuDisplayName"`
		Location string `json:"location"`
	} `json:"machine"`
	Runtime *struct {
		Uptime int64 `json:"uptimeInSeconds"`
	} `json:"runtime"`
}

func (p pod) label() string {
	if p.Name != "" {
		return p.Name
	}
	return p.ID
}

// spot is whether it's an interruptible pod, which needs a bid to start.
func (p pod) spot() bool { return strings.EqualFold(p.PodType, "INTERRUPTABLE") }

func (p pod) gpu() string {
	g := ""
	if p.Machine != nil {
		g = p.Machine.GPU
	}
	if p.GPUCount > 0 {
		if g == "" {
			g = "GPU"
		}
		return fmt.Sprintf("%dx %s", p.GPUCount, g)
	}
	return "CPU only"
}

func (p pod) cost() string {
	if p.CostPerHr == nil {
		return "an hourly rate RunPod didn't say"
	}
	return fmt.Sprintf("$%.3f/hr", *p.CostPerHr)
}

func (p pod) summary() map[string]any {
	out := map[string]any{"id": p.ID, "name": p.label(), "status": p.DesiredStatus, "gpu": p.gpu(), "gpuCount": p.GPUCount,
		"vcpus": p.VCPUCount, "memoryGB": p.MemoryInGB, "containerDiskGB": p.ContainerDiskGB, "volumeGB": p.VolumeGB, "image": p.ImageName}
	if p.CostPerHr != nil {
		out["costPerHour"] = *p.CostPerHr
		out["currency"] = "USD"
	}
	if p.PodType != "" {
		out["type"] = strings.ToLower(p.PodType)
	}
	if p.Machine != nil && p.Machine.Location != "" {
		out["location"] = p.Machine.Location
	}
	if p.Runtime != nil {
		out["uptimeSeconds"] = p.Runtime.Uptime
	}
	if p.LastStatusChange != "" {
		out["lastStatusChange"] = rest.Redact(p.LastStatusChange)
	}
	return out
}

func (c *conn) pods(ctx context.Context) ([]pod, error) {
	var d struct {
		Myself struct {
			Pods []pod `json:"pods"`
		} `json:"myself"`
	}
	err := c.gql(ctx, podsQuery, nil, &d)
	return d.Myself.Pods, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	b, err := c.balance(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("balance $%.2f, spending $%.3f/hr", b.Balance, b.SpendPerHr)
	if b.Balance <= 0 {
		return sdk.Health{Status: "degraded", Message: msg + "; the balance is used up"}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type bal struct {
	Balance    float64  `json:"clientBalance"`
	SpendPerHr float64  `json:"currentSpendPerHr"`
	SpendLimit *float64 `json:"spendLimit"`
}

func (c *conn) balance(ctx context.Context) (bal, error) {
	var d struct {
		Myself *bal `json:"myself"`
	}
	if err := c.gql(ctx, balance, nil, &d); err != nil {
		return bal{}, err
	}
	if d.Myself == nil {
		return bal{}, errRefused
	}
	return *d.Myself, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Pod     string `json:"pod"`
		Running *bool  `json:"running"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "pods":
		ps, err := c.pods(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].label() < ps[j].label() })
		list := []map[string]any{}
		var perHr float64
		for _, x := range ps {
			on := x.DesiredStatus == "RUNNING"
			if p.Running != nil && on != *p.Running {
				continue
			}
			if on && x.CostPerHr != nil {
				perHr += *x.CostPerHr
			}
			list = append(list, x.summary())
		}
		return sdk.JSON(map[string]any{"pods": list, "runningCostPerHour": perHr, "currency": "USD"})
	case "start_pod", "stop_pod":
		id := strings.TrimSpace(p.Pod)
		if !podRe.MatchString(id) {
			return sdk.Result{}, errors.New("a pod is its id from pods")
		}
		return c.power(ctx, call, id)
	case "endpoints":
		var d struct {
			Myself struct {
				Endpoints []struct {
					ID          string  `json:"id"`
					Name        string  `json:"name"`
					GPUIDs      string  `json:"gpuIds"`
					WorkersMin  int     `json:"workersMin"`
					WorkersMax  int     `json:"workersMax"`
					IdleTimeout int     `json:"idleTimeout"`
					ScalerType  string  `json:"scalerType"`
					ScalerValue int     `json:"scalerValue"`
					Locations   *string `json:"locations"`
				} `json:"endpoints"`
			} `json:"myself"`
		}
		if err := c.gql(ctx, endpoints, nil, &d); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, e := range d.Myself.Endpoints {
			row := map[string]any{"id": e.ID, "name": e.Name, "gpuTypes": splitList(e.GPUIDs), "workersMin": e.WorkersMin, "workersMax": e.WorkersMax,
				"idleTimeoutSeconds": e.IdleTimeout, "scaler": strings.ToLower(e.ScalerType), "scalerValue": e.ScalerValue}
			if e.Locations != nil && *e.Locations != "" {
				row["locations"] = splitList(*e.Locations)
			}
			list = append(list, row)
		}
		return sdk.JSON(list)
	case "balance":
		b, err := c.balance(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"currency": "USD", "balance": b.Balance, "spendPerHour": b.SpendPerHr}
		if b.SpendLimit != nil {
			out["spendLimitPerHour"] = *b.SpendLimit
		}
		if b.SpendPerHr > 0 {
			out["hoursLeftAtThisRate"] = float64(int(b.Balance/b.SpendPerHr*10)) / 10
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func splitList(s string) []string {
	out := []string{}
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func (c *conn) power(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	start := call.Action == "start_pod"
	var d struct {
		Pod *pod `json:"pod"`
	}
	if err := c.gql(ctx, podQuery, map[string]any{"input": map[string]string{"podId": id}}, &d); err != nil {
		return sdk.Result{}, err
	}
	if d.Pod == nil || d.Pod.ID == "" {
		return sdk.Result{}, fmt.Errorf("there's no pod %s", id)
	}
	x := *d.Pod
	if x.ID != id {
		// The id goes into the mutation and the undo.
		return sdk.Result{}, fmt.Errorf("RunPod answered with another pod for %s", id)
	}
	want := "EXITED"
	if start {
		want = "RUNNING"
	}
	switch {
	case x.DesiredStatus == "TERMINATED":
		return sdk.Result{}, fmt.Errorf("the pod %s was terminated; it can't be started or stopped", x.label())
	case x.DesiredStatus == want:
		return sdk.JSON(map[string]any{"pod": x.ID, "name": x.label(), "status": x.DesiredStatus, "note": "nothing to change"})
	case start && x.spot():
		return sdk.Result{}, errors.New("this is a spot (interruptible) pod: start it with a bid in the RunPod console")
	}
	target := fmt.Sprintf("pod %s (%s, %s)", x.label(), x.gpu(), x.cost())
	if call.DryRun {
		sum := "Start " + x.label() + " on " + x.gpu() + ", billed " + x.cost() + " while it runs"
		op := "start"
		if !start {
			op = "stop"
			sum = "Stop " + x.label() + " (" + x.gpu() + ", " + x.cost() + "): what runs on it ends and its container disk is cleared"
			if x.VolumeGB > 0 {
				sum += fmt.Sprintf("; the %g GB volume stays, billed for storage", x.VolumeGB)
			}
			if x.spot() {
				sum += "; it's a spot pod, so starting it again needs a bid in the RunPod console (no undo)"
			}
		}
		before, _ := json.Marshal(map[string]any{"status": x.DesiredStatus})
		after, _ := json.Marshal(map[string]any{"status": want})
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: op, Before: before, After: after}}}}, nil
	}
	var out struct {
		Resume *pod `json:"podResume"`
		Stop   *pod `json:"podStop"`
	}
	var err error
	if start {
		err = c.gql(ctx, resumePod, map[string]any{"input": map[string]any{"podId": x.ID, "gpuCount": x.GPUCount}}, &out)
	} else {
		err = c.gql(ctx, stopPod, map[string]any{"input": map[string]any{"podId": x.ID}}, &out)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	after := out.Resume
	if !start {
		after = out.Stop
	}
	if after != nil && after.DesiredStatus != "" && after.DesiredStatus != want {
		return sdk.Result{}, fmt.Errorf("RunPod left the pod %s %s", x.label(), strings.ToLower(after.DesiredStatus))
	}
	cost := x.CostPerHr
	if start && after != nil && after.CostPerHr != nil {
		// What RunPod bills from now on, which may differ from the
		// rate it showed while the pod was stopped.
		cost = after.CostPerHr
	}
	res, err := sdk.JSON(map[string]any{"pod": x.ID, "name": x.label(), "status": want, "statusBefore": x.DesiredStatus, "gpu": x.gpu(), "costPerHour": cost})
	switch {
	case start:
		res.Undo = sdk.UndoWith("stop_pod", map[string]string{"pod": x.ID}, "Stop "+x.label()+" again")
	case !x.spot():
		// A spot pod can't be started here (start_pod refuses it), so
		// stopping one has no undo.
		res.Undo = sdk.UndoWith("start_pod", map[string]string{"pod": x.ID}, "Start "+x.label()+" again (its container disk starts empty)")
	}
	return res, err
}
