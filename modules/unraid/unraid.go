// Package unraid works with an Unraid server through the Unraid API
// (GraphQL, built into Unraid 7.2 and later, or the Unraid Connect plugin)
// and an API key: the array and its disks with temperatures and errors,
// parity checks, Docker containers, virtual machines and notifications.
package unraid

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

// Config is one Unraid server.
type Config struct {
	URL                string `json:"url"`    // e.g. https://tower.local
	APIKey             string `json:"apiKey"` // secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Unraid module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// PrefixedID values look like "<server id>:<id>" (the server id is a
	// hash, container ids are hex, VM ids are UUIDs).
	idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.-]{0,255}$`)
	// Container names are Docker names; VM names are free text but short.
	refRe = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,200}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	ctr := `{"type":"object","required":["container"],"properties":{"container":{"type":"string","description":"Container name or id"}}}`
	vm := `{"type":"object","required":["vm"],"properties":{"vm":{"type":"string","description":"VM name or id"}}}`
	return sdk.Manifest{
		ID: "unraid", Name: "Unraid", Version: "0.1.0", Category: "Storage", Icon: "server",
		Description: "An Unraid server: array and disks with temperatures and errors, parity checks, Docker containers, VMs and notifications.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"The server's web UI address, e.g. https://tower.local or http://192.168.1.10"},
			"apiKey":{"type":"string","x-secret":true,"description":"An API key from Settings → Management Access → API Keys; its role decides what works (viewer for read-only)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust Unraid's self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "overview", Title: "Overview", Description: "Server name and version, array state and capacity, disks with problems, the parity check, running containers and VMs, unread notifications.", Risk: sdk.RiskRead},
			{Name: "array", Title: "Array and disks", Description: "Array state and capacity, and every parity, data, cache and boot disk with status, temperature, read/write/error counts and space, with the disks that need attention.", Risk: sdk.RiskRead},
			{Name: "parity_status", Title: "Parity check status", Description: "Whether a parity check runs, its progress, speed, errors found, and the last check's result.", Risk: sdk.RiskRead},
			{Name: "start_parity_check", Title: "Start a parity check", Description: "Starts a read-only (non-correcting) parity check. It reads every disk for hours and slows the array.", Risk: sdk.RiskWrite, DryRun: true},
			{Name: "start_correcting_parity_check", Title: "Start a correcting parity check", Description: "Starts a parity check that rewrites parity where it doesn't match the data disks.", Risk: sdk.RiskDestructive, DryRun: true},
			{Name: "pause_parity_check", Title: "Pause the parity check", Description: "Pauses the running parity check. Undo resumes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true},
			{Name: "resume_parity_check", Title: "Resume the parity check", Description: "Resumes a paused parity check. Undo pauses it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true},
			{Name: "cancel_parity_check", Title: "Cancel the parity check", Description: "Stops the running or paused parity check; its progress is lost.", Risk: sdk.RiskDestructive, DryRun: true},
			{Name: "containers", Title: "Docker containers", Description: "Containers with image, state, status, autostart and published ports.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Part of a name or image"},"state":{"type":"string","enum":["running","exited"]}}}`)},
			{Name: "start_container", Title: "Start a container", Description: "Undo stops it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(ctr)},
			{Name: "stop_container", Title: "Stop a container", Description: "Undo starts it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(ctr)},
			{Name: "restart_container", Title: "Restart a container", Description: "Stops and starts a running container.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(ctr)},
			{Name: "vms", Title: "Virtual machines", Description: "VMs with their state.", Risk: sdk.RiskRead},
			{Name: "start_vm", Title: "Start a VM", Description: "Undo shuts it down again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(vm)},
			{Name: "stop_vm", Title: "Shut down a VM", Description: "Asks the guest to shut down (ACPI). Undo starts it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(vm)},
			{Name: "notifications", Title: "Notifications", Description: "Counts of unread and archived notifications and the latest ones, newest first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"archived":{"type":"boolean","description":"Archived notifications instead of unread ones"},"importance":{"type":"string","enum":["alert","warning","info"]},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://tower.local")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	ref := c.APIKey
	root := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/graphql")
	api := rest.New(root, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-Api-Key", strings.TrimSpace(k))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errRefused = errors.New("Unraid refused the API key (or its role doesn't allow this)")

type gqlError struct {
	Message    string `json:"message"`
	Extensions struct {
		Code string `json:"code"`
	} `json:"extensions"`
}

// gql runs one query or mutation and decodes its data into out.
func (c *conn) gql(ctx context.Context, query string, vars map[string]any, out any) error {
	var res struct {
		Data   json.RawMessage `json:"data"`
		Errors []gqlError      `json:"errors"`
	}
	body := map[string]any{"query": query}
	if vars != nil {
		body["variables"] = vars
	}
	_, err := c.api.Do(ctx, http.MethodPost, "/graphql", nil, body, &res)
	if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
		return errRefused
	}
	if rest.IsStatus(err, http.StatusNotFound) {
		return errors.New("no Unraid API at this address (it's built into Unraid 7.2 and later, or comes with the Unraid Connect plugin)")
	}
	if err != nil {
		return err
	}
	if len(res.Errors) > 0 {
		e := res.Errors[0]
		low := strings.ToLower(e.Message)
		if e.Extensions.Code == "UNAUTHENTICATED" || e.Extensions.Code == "FORBIDDEN" || strings.Contains(low, "unauthorized") || strings.Contains(low, "forbidden") {
			return errRefused
		}
		return fmt.Errorf("Unraid: %s", clip(e.Message, 300))
	}
	if out != nil {
		if len(res.Data) == 0 || string(res.Data) == "null" {
			return errors.New("Unraid sent no data")
		}
		if err := json.Unmarshal(res.Data, out); err != nil {
			return fmt.Errorf("unexpected answer from Unraid: %w", err)
		}
	}
	return nil
}

// num accepts the API's Long and BigInt scalars, which arrive as numbers
// or strings.
type num float64

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil // a value we don't understand is shown as 0, not an error
	}
	*n = num(f)
	return nil
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Vars struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"vars"`
	}
	if err := c.gql(ctx, `query { vars { name version } }`, nil, &v); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := strings.TrimSpace(v.Vars.Name + " · Unraid " + v.Vars.Version)
	a, err := c.array(ctx)
	if err != nil {
		return sdk.Health{Status: "ok", Message: msg}
	}
	if a.State != "STARTED" {
		return sdk.Health{Status: "degraded", Message: msg + " · array " + strings.ToLower(a.State)}
	}
	if p := problems(a); len(p) > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s · %d disks need attention", msg, len(p))}
	}
	return sdk.Health{Status: "ok", Message: msg + " · array started"}
}

// ---- array ----

type disk struct {
	ID         string `json:"id"`
	Idx        *int   `json:"idx"`
	Name       string `json:"name"`
	Device     string `json:"device"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Temp       *int   `json:"temp"`
	NumErrors  num    `json:"numErrors"`
	NumReads   num    `json:"numReads"`
	NumWrites  num    `json:"numWrites"`
	Size       num    `json:"size"`
	FsSize     num    `json:"fsSize"`
	FsFree     num    `json:"fsFree"`
	FsUsed     num    `json:"fsUsed"`
	FsType     string `json:"fsType"`
	IsSpinning *bool  `json:"isSpinning"`
	Warning    *int   `json:"warning"`
	Critical   *int   `json:"critical"`
}

type parityCheck struct {
	Status     string `json:"status"`
	Running    *bool  `json:"running"`
	Paused     *bool  `json:"paused"`
	Correcting *bool  `json:"correcting"`
	Progress   *int   `json:"progress"`
	Errors     *int   `json:"errors"`
	Speed      string `json:"speed"`
	Duration   *int   `json:"duration"`
	Date       string `json:"date"`
}

type capacity struct {
	Free  num `json:"free"`
	Used  num `json:"used"`
	Total num `json:"total"`
}

type array struct {
	State    string `json:"state"`
	Capacity struct {
		Kilobytes capacity `json:"kilobytes"`
		Disks     capacity `json:"disks"`
	} `json:"capacity"`
	Boot              *disk       `json:"boot"`
	Parities          []disk      `json:"parities"`
	Disks             []disk      `json:"disks"`
	Caches            []disk      `json:"caches"`
	ParityCheckStatus parityCheck `json:"parityCheckStatus"`
}

const diskFields = `fragment D on ArrayDisk { id idx name device type status temp numErrors numReads numWrites size fsSize fsFree fsUsed fsType isSpinning warning critical }`
const parityFields = `parityCheckStatus { status running paused correcting progress errors speed duration date }`

func (c *conn) array(ctx context.Context) (array, error) {
	var out struct {
		Array array `json:"array"`
	}
	err := c.gql(ctx, `query { array { state capacity { kilobytes { free used total } disks { free used total } } boot { ...D } parities { ...D } disks { ...D } caches { ...D } `+parityFields+` } } `+diskFields, nil, &out)
	return out.Array, err
}

func (c *conn) parity(ctx context.Context) (parityCheck, error) {
	var out struct {
		Array struct {
			ParityCheckStatus parityCheck `json:"parityCheckStatus"`
		} `json:"array"`
	}
	err := c.gql(ctx, `query { array { `+parityFields+` } }`, nil, &out)
	return out.Array.ParityCheckStatus, err
}

// Unraid's default temperature thresholds for hard drives, used when a disk
// has none of its own.
const defWarn, defCrit = 45, 55

func (d disk) issues() []string {
	var out []string
	if d.Status != "" && d.Status != "DISK_OK" {
		out = append(out, "status "+d.Status)
	}
	if d.NumErrors > 0 {
		out = append(out, fmt.Sprintf("%d errors", int64(d.NumErrors)))
	}
	if d.Temp != nil {
		warn, crit := defWarn, defCrit
		if d.Warning != nil && *d.Warning > 0 {
			warn = *d.Warning
		}
		if d.Critical != nil && *d.Critical > 0 {
			crit = *d.Critical
		}
		switch {
		case *d.Temp >= crit:
			out = append(out, fmt.Sprintf("%d °C (critical ≥ %d)", *d.Temp, crit))
		case *d.Temp >= warn:
			out = append(out, fmt.Sprintf("%d °C (warning ≥ %d)", *d.Temp, warn))
		}
	}
	return out
}

func (a array) all() []disk {
	l := append(append(append([]disk{}, a.Parities...), a.Disks...), a.Caches...)
	if a.Boot != nil {
		l = append(l, *a.Boot)
	}
	return l
}

func problems(a array) []map[string]any {
	out := []map[string]any{}
	for _, d := range a.all() {
		if d.Status == "DISK_NP" && d.Device == "" {
			continue // an empty slot
		}
		if is := d.issues(); len(is) > 0 {
			out = append(out, map[string]any{"name": d.Name, "device": d.Device, "issues": is})
		}
	}
	return out
}

// Sizes in the API are in kilobytes.
func kb(n num) int64 { return int64(n) * 1024 }

func diskOut(d disk) map[string]any {
	e := map[string]any{"name": d.Name, "device": d.Device, "type": d.Type, "status": d.Status,
		"errors": int64(d.NumErrors), "reads": int64(d.NumReads), "writes": int64(d.NumWrites), "sizeBytes": kb(d.Size)}
	if d.Temp != nil {
		e["tempC"] = *d.Temp
	} else {
		e["tempC"] = nil // spun down or no sensor
	}
	if d.IsSpinning != nil {
		e["spinning"] = *d.IsSpinning
	}
	if d.FsSize > 0 {
		e["fs"] = map[string]any{"type": d.FsType, "sizeBytes": kb(d.FsSize), "usedBytes": kb(d.FsUsed), "freeBytes": kb(d.FsFree),
			"usedPercent": int(float64(d.FsUsed) * 100 / float64(d.FsSize))}
	}
	if is := d.issues(); len(is) > 0 {
		e["issues"] = is
	}
	return e
}

func parityOut(p parityCheck) map[string]any {
	e := map[string]any{"status": p.Status}
	if p.Running != nil {
		e["running"] = *p.Running
	}
	if p.Paused != nil {
		e["paused"] = *p.Paused
	}
	if p.Correcting != nil {
		e["correcting"] = *p.Correcting
	}
	if p.Progress != nil {
		e["progressPercent"] = *p.Progress
	}
	if p.Errors != nil {
		e["errorsFound"] = *p.Errors
	}
	if p.Speed != "" {
		e["speed"] = p.Speed
	}
	if p.Duration != nil {
		e["durationSeconds"] = *p.Duration
	}
	if p.Date != "" {
		e["date"] = p.Date
	}
	return e
}

func (p parityCheck) running() bool {
	return p.Status == "RUNNING" || (p.Running != nil && *p.Running && !p.paused())
}
func (p parityCheck) paused() bool { return p.Status == "PAUSED" || (p.Paused != nil && *p.Paused) }

func capOut(c capacity) map[string]any {
	e := map[string]any{"totalBytes": kb(c.Total), "usedBytes": kb(c.Used), "freeBytes": kb(c.Free)}
	if c.Total > 0 {
		e["usedPercent"] = int(float64(c.Used) * 100 / float64(c.Total))
	}
	return e
}

// ---- containers and VMs ----

type container struct {
	ID        string   `json:"id"`
	Names     []string `json:"names"`
	Image     string   `json:"image"`
	State     string   `json:"state"`
	Status    string   `json:"status"`
	AutoStart bool     `json:"autoStart"`
	Ports     []struct {
		IP          string `json:"ip"`
		PrivatePort *int   `json:"privatePort"`
		PublicPort  *int   `json:"publicPort"`
		Type        string `json:"type"`
	} `json:"ports"`
}

func (k container) name() string {
	if len(k.Names) > 0 {
		return strings.TrimPrefix(k.Names[0], "/")
	}
	return k.ID
}

const ctrFields = `id names image state status autoStart`

func (c *conn) containers(ctx context.Context) ([]container, error) {
	var out struct {
		Docker struct {
			Containers []container `json:"containers"`
		} `json:"docker"`
	}
	err := c.gql(ctx, `query { docker { containers(skipCache: true) { `+ctrFields+` ports { ip privatePort publicPort type } } } }`, nil, &out)
	return out.Docker.Containers, err
}

func ctrOut(k container) map[string]any {
	ports := []string{}
	for _, p := range k.Ports {
		if p.PrivatePort == nil {
			continue
		}
		s := strconv.Itoa(*p.PrivatePort) + "/" + strings.ToLower(p.Type)
		if p.PublicPort != nil && *p.PublicPort > 0 {
			s = strconv.Itoa(*p.PublicPort) + "→" + s
			if p.IP != "" && p.IP != "0.0.0.0" && p.IP != "::" {
				s = p.IP + ":" + s
			}
		}
		ports = append(ports, s)
	}
	return map[string]any{"id": k.ID, "name": k.name(), "image": k.Image, "state": strings.ToLower(k.State), "status": k.Status, "autoStart": k.AutoStart, "ports": ports}
}

// findContainer resolves a name or id, checked before it's sent.
func (c *conn) findContainer(ctx context.Context, ref string) (container, error) {
	ref = strings.TrimPrefix(strings.TrimSpace(ref), "/")
	if !refRe.MatchString(ref) {
		return container{}, errors.New("enter the container's name or id")
	}
	list, err := c.containers(ctx)
	if err != nil {
		return container{}, err
	}
	var fold *container
	for i, k := range list {
		if k.ID == ref || k.name() == ref {
			return checked(k)
		}
		if strings.EqualFold(k.name(), ref) && fold == nil {
			fold = &list[i]
		}
	}
	if fold != nil {
		return checked(*fold)
	}
	return container{}, fmt.Errorf("there's no container %s", ref)
}

func checked(k container) (container, error) {
	if !idRe.MatchString(k.ID) {
		return k, errors.New("unexpected container id from Unraid")
	}
	return k, nil
}

type vmDomain struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

func (c *conn) vms(ctx context.Context) ([]vmDomain, error) {
	var out struct {
		Vms struct {
			Domains []vmDomain `json:"domains"`
		} `json:"vms"`
	}
	err := c.gql(ctx, `query { vms { domains { id name state } } }`, nil, &out)
	return out.Vms.Domains, err
}

func (c *conn) findVM(ctx context.Context, ref string) (vmDomain, error) {
	ref = strings.TrimSpace(ref)
	if !refRe.MatchString(ref) {
		return vmDomain{}, errors.New("enter the VM's name or id")
	}
	list, err := c.vms(ctx)
	if err != nil {
		return vmDomain{}, err
	}
	var hit *vmDomain
	for i, v := range list {
		if v.ID == ref || v.Name == ref {
			hit = &list[i]
			break
		}
		if strings.EqualFold(v.Name, ref) && hit == nil {
			hit = &list[i]
		}
	}
	if hit == nil {
		return vmDomain{}, fmt.Errorf("there's no VM %s", ref)
	}
	if !idRe.MatchString(hit.ID) {
		return vmDomain{}, errors.New("unexpected VM id from Unraid")
	}
	return *hit, nil
}

func vmOut(v vmDomain) map[string]any {
	return map[string]any{"id": v.ID, "name": v.Name, "state": strings.ToLower(v.State)}
}

// ---- notifications ----

type notification struct {
	ID                 string `json:"id"`
	Title              string `json:"title"`
	Subject            string `json:"subject"`
	Description        string `json:"description"`
	Importance         string `json:"importance"`
	Link               string `json:"link"`
	Timestamp          string `json:"timestamp"`
	FormattedTimestamp string `json:"formattedTimestamp"`
}

type counts struct {
	Info    int `json:"info"`
	Warning int `json:"warning"`
	Alert   int `json:"alert"`
	Total   int `json:"total"`
}

type overviewCounts struct {
	Unread  counts `json:"unread"`
	Archive counts `json:"archive"`
}

func (c *conn) notificationCounts(ctx context.Context) (overviewCounts, error) {
	var out struct {
		Notifications struct {
			Overview overviewCounts `json:"overview"`
		} `json:"notifications"`
	}
	err := c.gql(ctx, `query { notifications { overview { unread { info warning alert total } archive { info warning alert total } } } }`, nil, &out)
	return out.Notifications.Overview, err
}

type input struct {
	Container  string `json:"container"`
	VM         string `json:"vm"`
	Search     string `json:"search"`
	State      string `json:"state"`
	Archived   bool   `json:"archived"`
	Importance string `json:"importance"`
	Limit      int    `json:"limit"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "overview":
		return c.overview(ctx)

	case "array":
		a, err := c.array(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		group := func(l []disk) []map[string]any {
			out := []map[string]any{}
			for _, d := range l {
				if d.Status == "DISK_NP" && d.Device == "" {
					continue
				}
				out = append(out, diskOut(d))
			}
			return out
		}
		res := map[string]any{"state": a.State, "capacity": capOut(a.Capacity.Kilobytes),
			"parity": group(a.Parities), "data": group(a.Disks), "cache": group(a.Caches),
			"parityCheck": parityOut(a.ParityCheckStatus), "problems": problems(a)}
		if a.Boot != nil {
			res["boot"] = diskOut(*a.Boot)
		}
		return sdk.JSON(res)

	case "parity_status":
		pc, err := c.parity(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(parityOut(pc))

	case "start_parity_check", "start_correcting_parity_check", "pause_parity_check", "resume_parity_check", "cancel_parity_check":
		return c.parityAction(ctx, call)

	case "containers":
		list, err := c.containers(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		s := strings.ToLower(strings.TrimSpace(p.Search))
		if p.State != "" && p.State != "running" && p.State != "exited" {
			return sdk.Result{}, errors.New("state is running or exited")
		}
		sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].name()) < strings.ToLower(list[j].name()) })
		out := []map[string]any{}
		for _, k := range list {
			if s != "" && !strings.Contains(strings.ToLower(k.name()), s) && !strings.Contains(strings.ToLower(k.Image), s) {
				continue
			}
			if p.State != "" && !strings.EqualFold(k.State, p.State) {
				continue
			}
			out = append(out, ctrOut(k))
		}
		return sdk.JSON(out)

	case "start_container", "stop_container", "restart_container":
		return c.containerAction(ctx, call, p.Container)

	case "vms":
		list, err := c.vms(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, v := range list {
			out = append(out, vmOut(v))
		}
		return sdk.JSON(out)

	case "start_vm", "stop_vm":
		return c.vmAction(ctx, call, p.VM)

	case "notifications":
		typ := "UNREAD"
		if p.Archived {
			typ = "ARCHIVE"
		}
		vars := map[string]any{"type": typ, "limit": 20}
		if p.Limit != 0 {
			if p.Limit < 1 || p.Limit > 100 {
				return sdk.Result{}, errors.New("limit is between 1 and 100")
			}
			vars["limit"] = p.Limit
		}
		switch p.Importance {
		case "":
			vars["importance"] = nil
		case "alert", "warning", "info":
			vars["importance"] = strings.ToUpper(p.Importance)
		default:
			return sdk.Result{}, errors.New("importance is alert, warning or info")
		}
		var out struct {
			Notifications struct {
				Overview overviewCounts `json:"overview"`
				List     []notification `json:"list"`
			} `json:"notifications"`
		}
		q := `query($type: NotificationType!, $importance: NotificationImportance, $limit: Int!) { notifications {
			overview { unread { info warning alert total } archive { info warning alert total } }
			list(filter: {type: $type, importance: $importance, offset: 0, limit: $limit}) { id title subject description importance link timestamp formattedTimestamp } } }`
		if err := c.gql(ctx, q, vars, &out); err != nil {
			return sdk.Result{}, err
		}
		list := out.Notifications.List
		sort.SliceStable(list, func(i, j int) bool { return list[i].Timestamp > list[j].Timestamp })
		items := []map[string]any{}
		for _, n := range list {
			e := map[string]any{"id": n.ID, "title": n.Title, "subject": n.Subject, "description": clip(n.Description, 1000),
				"importance": strings.ToLower(n.Importance), "time": n.Timestamp}
			if n.Link != "" {
				e["link"] = n.Link
			}
			items = append(items, e)
		}
		return sdk.JSON(map[string]any{"unread": out.Notifications.Overview.Unread, "archived": out.Notifications.Overview.Archive, "items": items})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) overview(ctx context.Context) (sdk.Result, error) {
	var v struct {
		Vars struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"vars"`
	}
	if err := c.gql(ctx, `query { vars { name version } }`, nil, &v); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"name": v.Vars.Name, "version": v.Vars.Version}
	unavailable := map[string]string{}
	if a, err := c.array(ctx); err == nil {
		out["array"] = map[string]any{"state": a.State, "capacity": capOut(a.Capacity.Kilobytes), "problems": problems(a)}
		out["parityCheck"] = parityOut(a.ParityCheckStatus)
	} else {
		unavailable["array"] = err.Error()
	}
	if list, err := c.containers(ctx); err == nil {
		run := 0
		for _, k := range list {
			if strings.EqualFold(k.State, "running") {
				run++
			}
		}
		out["containers"] = map[string]int{"running": run, "total": len(list)}
	} else {
		unavailable["containers"] = err.Error()
	}
	if list, err := c.vms(ctx); err == nil {
		run := 0
		for _, x := range list {
			if x.State == "RUNNING" {
				run++
			}
		}
		out["vms"] = map[string]int{"running": run, "total": len(list)}
	} else {
		unavailable["vms"] = err.Error()
	}
	if n, err := c.notificationCounts(ctx); err == nil {
		out["unreadNotifications"] = n.Unread
	} else {
		unavailable["notifications"] = err.Error()
	}
	if len(unavailable) > 0 {
		out["unavailable"] = unavailable
	}
	return sdk.JSON(out)
}

func (c *conn) parityAction(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	pc, err := c.parity(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	before := parityOut(pc)
	var summary, op, mutation, undo, undoDesc string
	vars := map[string]any(nil)
	switch call.Action {
	case "start_parity_check", "start_correcting_parity_check":
		if pc.running() || pc.paused() {
			return sdk.Result{}, errors.New("a parity check is already running or paused; resume or cancel it first")
		}
		correct := call.Action == "start_correcting_parity_check"
		vars = map[string]any{"correct": correct}
		mutation, op = `mutation($correct: Boolean!) { parityCheck { start(correct: $correct) } }`, "start"
		summary = "Start a read-only parity check; it reads every disk for hours and slows the array"
		if correct {
			summary = "Start a correcting parity check; parity is rewritten wherever it doesn't match the data disks"
		}
	case "pause_parity_check":
		if !pc.running() {
			return sdk.Result{}, errors.New("no parity check is running")
		}
		mutation, op, summary = `mutation { parityCheck { pause } }`, "pause", "Pause the running parity check"
		undo, undoDesc = "resume_parity_check", "Resume the parity check"
	case "resume_parity_check":
		if !pc.paused() {
			return sdk.Result{}, errors.New("no parity check is paused")
		}
		mutation, op, summary = `mutation { parityCheck { resume } }`, "resume", "Resume the paused parity check"
		undo, undoDesc = "pause_parity_check", "Pause the parity check"
	case "cancel_parity_check":
		if !pc.running() && !pc.paused() {
			return sdk.Result{}, errors.New("no parity check is running")
		}
		mutation, op = `mutation { parityCheck { cancel } }`, "cancel"
		summary = "Cancel the parity check"
		if pc.Progress != nil {
			summary += fmt.Sprintf(" at %d%%", *pc.Progress)
		}
		summary += "; its progress is lost"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "parity check", Op: op, Before: mustJSON(before)}}}}, nil
	}
	if err := c.gql(ctx, mutation, vars, nil); err != nil {
		return sdk.Result{}, err
	}
	after := map[string]any{"done": op}
	if now, err := c.parity(ctx); err == nil {
		after = parityOut(now)
	}
	res, err := sdk.JSON(after)
	if err == nil && undo != "" {
		res.Undo = sdk.UndoWith(undo, map[string]any{}, undoDesc)
	}
	return res, err
}

func (c *conn) containerAction(ctx context.Context, call sdk.Call, ref string) (sdk.Result, error) {
	k, err := c.findContainer(ctx, ref)
	if err != nil {
		return sdk.Result{}, err
	}
	name := k.name()
	running := strings.EqualFold(k.State, "running")
	verb := strings.TrimSuffix(call.Action, "_container")
	switch {
	case verb == "start" && running:
		return sdk.Result{}, fmt.Errorf("%s is already running", name)
	case verb != "start" && !running:
		return sdk.Result{}, fmt.Errorf("%s isn't running", name)
	}
	if call.DryRun {
		after := "running"
		if verb == "stop" {
			after = "exited"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s container %s (%s)", upper(verb), name, k.Image),
			Changes: []sdk.Change{{Target: "container " + name, Op: verb, Before: mustJSON(strings.ToLower(k.State)), After: mustJSON(after)}}}}, nil
	}
	run := func(m string) (container, error) {
		var out struct {
			Docker map[string]container `json:"docker"`
		}
		err := c.gql(ctx, `mutation($id: PrefixedID!) { docker { `+m+`(id: $id) { `+ctrFields+` } } }`, map[string]any{"id": k.ID}, &out)
		return out.Docker[m], err
	}
	var now container
	switch verb {
	case "restart":
		if _, err := run("stop"); err != nil {
			return sdk.Result{}, err
		}
		now, err = run("start")
	default:
		now, err = run(verb)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	if now.ID == "" {
		now = k
		now.State = map[string]string{"stop": "EXITED"}[verb]
		if now.State == "" {
			now.State = "RUNNING"
		}
	}
	res, err := sdk.JSON(map[string]any{"container": name, "state": strings.ToLower(now.State), "status": now.Status})
	undo := map[string]any{"container": k.ID}
	switch verb {
	case "start":
		res.Undo = sdk.UndoWith("stop_container", undo, "Stop "+name)
	case "stop":
		res.Undo = sdk.UndoWith("start_container", undo, "Start "+name)
	}
	return res, err
}

func (c *conn) vmAction(ctx context.Context, call sdk.Call, ref string) (sdk.Result, error) {
	v, err := c.findVM(ctx, ref)
	if err != nil {
		return sdk.Result{}, err
	}
	verb := strings.TrimSuffix(call.Action, "_vm")
	switch {
	case verb == "start" && (v.State == "RUNNING" || v.State == "PAUSED"):
		return sdk.Result{}, fmt.Errorf("%s is already %s", v.Name, strings.ToLower(v.State))
	case verb == "stop" && v.State != "RUNNING" && v.State != "PAUSED" && v.State != "IDLE":
		return sdk.Result{}, fmt.Errorf("%s isn't running (%s)", v.Name, strings.ToLower(v.State))
	}
	if call.DryRun {
		summary := "Start VM " + v.Name
		after := "running"
		if verb == "stop" {
			summary, after = "Shut down VM "+v.Name+" (the guest is asked to shut down)", "shutoff"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "VM " + v.Name, Op: verb, Before: mustJSON(strings.ToLower(v.State)), After: mustJSON(after)}}}}, nil
	}
	var out struct {
		VM map[string]bool `json:"vm"`
	}
	if err := c.gql(ctx, `mutation($id: PrefixedID!) { vm { `+verb+`(id: $id) } }`, map[string]any{"id": v.ID}, &out); err != nil {
		return sdk.Result{}, err
	}
	if !out.VM[verb] {
		return sdk.Result{}, fmt.Errorf("Unraid couldn't %s %s", verb, v.Name)
	}
	res, err := sdk.JSON(map[string]any{"vm": v.Name, "done": verb})
	if verb == "start" {
		res.Undo = sdk.UndoWith("stop_vm", map[string]any{"vm": v.ID}, "Shut down "+v.Name)
	} else {
		res.Undo = sdk.UndoWith("start_vm", map[string]any{"vm": v.ID}, "Start "+v.Name)
	}
	return res, err
}

func upper(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
