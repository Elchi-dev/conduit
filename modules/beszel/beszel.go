// Package beszel works with a Beszel hub through its PocketBase API: the
// systems it monitors with their latest CPU, memory, disk and load, recent
// stats records, alert rules, and pausing or resuming a system.
package beszel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Beszel hub.
type Config struct {
	URL                string `json:"url"`
	Email              string `json:"email"`
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api      *rest.Client
	host     sdk.Host
	email    string
	password string // secret:// reference

	mu    sync.Mutex
	token string
	until time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Beszel module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// PocketBase record ids are 15 lowercase letters and digits.
	idRe    = regexp.MustCompile(`^[a-z0-9]{15}$`)
	emailRe = regexp.MustCompile(`^[^\s@]{1,64}@[^\s@]{1,255}$`)
)

// statTypes are the stats records' resolutions Beszel keeps.
var statTypes = map[string]bool{"1m": true, "10m": true, "20m": true, "120m": true, "480m": true}

// tokenLife is how long a login is reused; PocketBase's own default is
// longer, and a refused token logs in again anyway.
const tokenLife = 30 * time.Minute

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	system := `{"type":"object","required":["system"],"properties":{"system":{"type":"string","description":"System id (from systems)"}}}`
	return sdk.Manifest{
		ID: "beszel", Name: "Beszel", Version: "0.1.0", Category: "Monitoring", Icon: "gauge",
		Description: "Beszel: monitored systems with CPU, memory, disk, load and temperature, recent stats, alert rules; pause or resume a system.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","email","password"],"properties":{
			"url":{"type":"string","description":"The hub's address, e.g. http://beszel:8090"},
			"email":{"type":"string","description":"A Beszel user's email (a read-only user is enough to read; pausing needs a regular user)"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "systems", Title: "Systems", Description: "Every system the user sees: id, name, host, status (up, down, paused, pending), CPU, memory and disk use, load, temperature, uptime and agent version. Filter by status.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["up","down","paused","pending"]}}}`)},
			{Name: "system_stats", Title: "System stats", Description: "A system's recent stats records, newest first (default 12, at most 100): CPU, memory, swap, disk, disk I/O, network, load and the hottest sensor. The resolution is 1m, 10m (default), 20m, 120m or 480m.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["system"],"properties":{"system":{"type":"string"},"type":{"type":"string","enum":["1m","10m","20m","120m","480m"],"default":"10m"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":12}}}`)},
			{Name: "alerts", Title: "Alert rules", Description: "Alert rules with their system, metric (Status, CPU, Memory, Disk, Temperature, Bandwidth, load), threshold, minutes, and whether they're triggered now.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"triggeredOnly":{"type":"boolean","default":false}}}`)},
			{Name: "pause_system", Title: "Pause a system", Description: "Stops monitoring a system: no stats and no alerts until it's resumed, so an outage would go unnoticed. Undo resumes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(system)},
			{Name: "resume_system", Title: "Resume a system", Description: "Starts monitoring a paused system again. Undo pauses it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(system)},
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
		return errors.New("the address is like http://beszel:8090")
	}
	c.Email = strings.TrimSpace(c.Email)
	if !emailRe.MatchString(c.Email) {
		return errors.New("enter the Beszel user's email")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
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
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	cn := &conn{host: h, email: c.Email, password: c.Password}
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := cn.login(ctx, false)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", t)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	cn.api = api
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errLogin = errors.New("Beszel refused the email or password")

// login returns a PocketBase auth token, reusing one for tokenLife.
func (c *conn) login(ctx context.Context, fresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !fresh && c.token != "" && time.Now().Before(c.until) {
		return c.token, nil
	}
	pw, err := c.host.Secret(ctx, c.password)
	if err != nil {
		return "", err
	}
	// The login itself goes without the Auth hook.
	plain := &rest.Client{Base: c.api.Base, HTTP: c.api.HTTP, Header: http.Header{}}
	var r struct {
		Token string `json:"token"`
	}
	if _, err := plain.Do(ctx, http.MethodPost, "/collections/users/auth-with-password", nil, map[string]string{"identity": c.email, "password": pw}, &r); err != nil {
		if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return "", errLogin
		}
		if rest.IsStatus(err, http.StatusNotFound) {
			return "", errors.New("no Beszel hub at this address")
		}
		return "", err
	}
	if r.Token == "" {
		return "", errLogin
	}
	c.token, c.until = r.Token, time.Now().Add(tokenLife)
	return c.token, nil
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		// The token expired or was revoked: log in again once.
		if _, lerr := c.login(ctx, true); lerr != nil {
			return lerr
		}
		_, err = c.api.Do(ctx, method, path, q, body, out)
	}
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errLogin
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("this Beszel user isn't allowed to do this (a read-only user can't pause or resume)")
	}
	return err
}

type info struct {
	Hostname     string             `json:"h"`
	Kernel       string             `json:"k"`
	Cores        int                `json:"c"`
	Threads      int                `json:"t"`
	CPUModel     string             `json:"m"`
	Uptime       uint64             `json:"u"`
	CPU          float64            `json:"cpu"`
	MemPct       float64            `json:"mp"`
	DiskPct      float64            `json:"dp"`
	Bandwidth    float64            `json:"b"`
	AgentVersion string             `json:"v"`
	GPUPct       float64            `json:"g"`
	Temp         float64            `json:"dt"`
	LoadAvg      []float64          `json:"la"`
	Podman       bool               `json:"p"`
	ExtraFsPct   map[string]float64 `json:"efs"`
}

type system struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Host    string `json:"host"`
	Port    string `json:"port"`
	Status  string `json:"status"`
	Info    info   `json:"info"`
	Updated string `json:"updated"`
}

func round(f float64) float64 { return math.Round(f*10) / 10 }

func (s system) row() map[string]any {
	row := map[string]any{"id": s.ID, "name": s.Name, "host": s.Host, "status": s.Status, "updated": s.Updated}
	if s.Status == "up" || s.Info.AgentVersion != "" {
		row["cpuPercent"] = round(s.Info.CPU)
		row["memoryPercent"] = round(s.Info.MemPct)
		row["diskPercent"] = round(s.Info.DiskPct)
		row["bandwidthMBps"] = round(s.Info.Bandwidth)
		row["uptimeHours"] = round(float64(s.Info.Uptime) / 3600)
		row["agentVersion"] = s.Info.AgentVersion
		row["cores"] = s.Info.Cores
		if s.Info.Hostname != "" {
			row["hostname"] = s.Info.Hostname
		}
		if s.Info.CPUModel != "" {
			row["cpuModel"] = s.Info.CPUModel
		}
		if s.Info.Kernel != "" {
			row["kernel"] = s.Info.Kernel
		}
		if len(s.Info.LoadAvg) > 0 {
			row["loadAverage"] = s.Info.LoadAvg
		}
		if s.Info.Temp != 0 {
			row["temperatureC"] = round(s.Info.Temp)
		}
		if s.Info.GPUPct != 0 {
			row["gpuPercent"] = round(s.Info.GPUPct)
		}
		if len(s.Info.ExtraFsPct) > 0 {
			row["extraDisksPercent"] = s.Info.ExtraFsPct
		}
	}
	return row
}

type list[T any] struct {
	Items      []T `json:"items"`
	TotalItems int `json:"totalItems"`
}

const systemFields = "id,name,host,port,status,info,updated"

func (c *conn) systems(ctx context.Context) ([]system, int, error) {
	var l list[system]
	q := url.Values{"perPage": {"500"}, "sort": {"name"}, "fields": {systemFields}, "skipTotal": {"false"}}
	err := c.do(ctx, http.MethodGet, "/collections/systems/records", q, nil, &l)
	return l.Items, l.TotalItems, err
}

func (c *conn) system(ctx context.Context, id string) (system, error) {
	var s system
	err := c.do(ctx, http.MethodGet, "/collections/systems/records/"+url.PathEscape(id), url.Values{"fields": {systemFields}}, nil, &s)
	if rest.IsStatus(err, http.StatusNotFound) {
		return s, fmt.Errorf("there's no system %s", id)
	}
	if err == nil && s.ID != id {
		// The id goes into the update's path and the undo.
		return s, fmt.Errorf("Beszel answered with another system for %s", id)
	}
	return s, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ss, _, err := c.systems(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	count := map[string]int{}
	for _, s := range ss {
		count[s.Status]++
	}
	msg := fmt.Sprintf("%d systems, %d up", len(ss), count["up"])
	if n := count["down"]; n > 0 {
		msg += fmt.Sprintf(", %d down", n)
		return sdk.Health{Status: "degraded", Message: msg}
	}
	if n := count["paused"]; n > 0 {
		msg += fmt.Sprintf(", %d paused", n)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	System        string `json:"system"`
	Status        string `json:"status"`
	Type          string `json:"type"`
	Limit         int    `json:"limit"`
	TriggeredOnly bool   `json:"triggeredOnly"`
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
	p.System = strings.TrimSpace(p.System)
	switch call.Action {
	case "systems":
		if p.Status != "" && p.Status != "up" && p.Status != "down" && p.Status != "paused" && p.Status != "pending" {
			return sdk.Result{}, errors.New("the status is up, down, paused or pending")
		}
		ss, total, err := c.systems(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range ss {
			if p.Status == "" || s.Status == p.Status {
				out = append(out, s.row())
			}
		}
		return sdk.JSON(map[string]any{"systems": out, "truncated": total > len(ss)})
	case "system_stats":
		return c.stats(ctx, p)
	case "alerts":
		return c.alerts(ctx, p.TriggeredOnly)
	case "pause_system", "resume_system":
		if !idRe.MatchString(p.System) {
			return sdk.Result{}, errors.New("a system is its id from systems (15 letters and digits)")
		}
		return c.setPaused(ctx, call, p.System)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) stats(ctx context.Context, p input) (sdk.Result, error) {
	if !idRe.MatchString(p.System) {
		return sdk.Result{}, errors.New("a system is its id from systems (15 letters and digits)")
	}
	typ := p.Type
	if typ == "" {
		typ = "10m"
	}
	if !statTypes[typ] {
		return sdk.Result{}, errors.New("the type is 1m, 10m, 20m, 120m or 480m")
	}
	limit := p.Limit
	if limit == 0 {
		limit = 12
	}
	if limit < 1 || limit > 100 {
		return sdk.Result{}, errors.New("the limit is 1 to 100")
	}
	s, err := c.system(ctx, p.System)
	if err != nil {
		return sdk.Result{}, err
	}
	// Both values are checked against fixed patterns, so the filter can't
	// be widened.
	q := url.Values{"filter": {fmt.Sprintf("system='%s' && type='%s'", p.System, typ)}, "sort": {"-created"}, "perPage": {strconv.Itoa(limit)}, "skipTotal": {"true"}, "fields": {"created,stats"}}
	var l list[struct {
		Created string `json:"created"`
		Stats   struct {
			CPU          float64            `json:"cpu"`
			Mem          float64            `json:"m"`
			MemUsed      float64            `json:"mu"`
			MemPct       float64            `json:"mp"`
			Swap         float64            `json:"s"`
			SwapUsed     float64            `json:"su"`
			DiskTotal    float64            `json:"d"`
			DiskUsed     float64            `json:"du"`
			DiskPct      float64            `json:"dp"`
			DiskRead     float64            `json:"dr"`
			DiskWrite    float64            `json:"dw"`
			NetSent      float64            `json:"ns"`
			NetRecv      float64            `json:"nr"`
			LoadAvg      []float64          `json:"la"`
			Temperatures map[string]float64 `json:"t"`
		} `json:"stats"`
	}]
	if err := c.do(ctx, http.MethodGet, "/collections/system_stats/records", q, nil, &l); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, r := range l.Items {
		x := r.Stats
		row := map[string]any{"time": r.Created, "cpuPercent": round(x.CPU), "memoryPercent": round(x.MemPct), "memoryUsedGB": round(x.MemUsed), "memoryGB": round(x.Mem),
			"diskPercent": round(x.DiskPct), "diskUsedGB": round(x.DiskUsed), "diskGB": round(x.DiskTotal), "diskReadMBps": round(x.DiskRead), "diskWriteMBps": round(x.DiskWrite),
			"networkSentMBps": round(x.NetSent), "networkReceivedMBps": round(x.NetRecv)}
		if x.Swap > 0 {
			row["swapUsedGB"], row["swapGB"] = round(x.SwapUsed), round(x.Swap)
		}
		if len(x.LoadAvg) > 0 {
			row["loadAverage"] = x.LoadAvg
		}
		if len(x.Temperatures) > 0 {
			hot, name := math.Inf(-1), ""
			for k, v := range x.Temperatures {
				if v > hot || (v == hot && k < name) {
					hot, name = v, k
				}
			}
			row["hottestSensor"], row["hottestC"] = name, round(hot)
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"system": s.Name, "type": typ, "records": out})
}

func (c *conn) alerts(ctx context.Context, triggeredOnly bool) (sdk.Result, error) {
	ss, _, err := c.systems(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	names := map[string]string{}
	for _, s := range ss {
		names[s.ID] = s.Name
	}
	q := url.Values{"perPage": {"500"}, "skipTotal": {"true"}, "fields": {"id,system,name,value,min,triggered"}}
	var l list[struct {
		ID        string  `json:"id"`
		System    string  `json:"system"`
		Name      string  `json:"name"`
		Value     float64 `json:"value"`
		Min       float64 `json:"min"`
		Triggered bool    `json:"triggered"`
	}]
	if err := c.do(ctx, http.MethodGet, "/collections/alerts/records", q, nil, &l); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, a := range l.Items {
		if triggeredOnly && !a.Triggered {
			continue
		}
		sys := names[a.System]
		if sys == "" {
			sys = a.System
		}
		row := map[string]any{"id": a.ID, "system": sys, "systemId": a.System, "metric": a.Name, "triggered": a.Triggered}
		if a.Name != "Status" {
			row["threshold"] = a.Value
		}
		if a.Min > 0 {
			row["minutes"] = a.Min
		}
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i]["system"] != out[j]["system"] {
			return fmt.Sprint(out[i]["system"]) < fmt.Sprint(out[j]["system"])
		}
		return fmt.Sprint(out[i]["metric"]) < fmt.Sprint(out[j]["metric"])
	})
	return sdk.JSON(out)
}

func (c *conn) setPaused(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	pause := call.Action == "pause_system"
	s, err := c.system(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	if (s.Status == "paused") == pause {
		state := "isn't paused"
		if pause {
			state = "is already paused"
		}
		return sdk.JSON(map[string]any{"system": s.ID, "name": s.Name, "status": s.Status, "note": "nothing to change: it " + state})
	}
	// Beszel moves a resumed system to pending until the agent answers.
	next, verb, back := "pending", "Resume", "pause_system"
	if pause {
		next, verb, back = "paused", "Pause", "resume_system"
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]string{"status": s.Status})
		a, _ := json.Marshal(map[string]string{"status": next})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " monitoring " + s.Name, Changes: []sdk.Change{{Target: fmt.Sprintf("system %s (%s)", s.Name, s.Host), Op: strings.ToLower(verb), Before: b, After: a}}}}, nil
	}
	var after system
	if err := c.do(ctx, http.MethodPatch, "/collections/systems/records/"+url.PathEscape(s.ID), url.Values{"fields": {"id,status"}}, map[string]string{"status": next}, &after); err != nil {
		return sdk.Result{}, err
	}
	if after.Status != "" && (after.Status == "paused") != pause {
		return sdk.Result{}, fmt.Errorf("Beszel kept the system %s", after.Status)
	}
	res, err := sdk.JSON(map[string]any{"system": s.ID, "name": s.Name, "status": next})
	undo := "Resume " + s.Name
	if !pause {
		undo = "Pause " + s.Name + " again"
	}
	res.Undo = sdk.UndoWith(back, map[string]string{"system": s.ID}, undo)
	return res, err
}
