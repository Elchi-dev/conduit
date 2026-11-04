// Package amp runs game servers on CubeCoder AMP through its API: a login
// session from a username and password, then instances, status, start, stop,
// console commands and application updates. With an ADS controller, calls
// for one instance go through the controller's proxy with their own session.
package amp

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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one AMP install (an ADS controller or a standalone instance).
type Config struct {
	URL                string `json:"url"` // e.g. https://amp.example.com
	Username           string `json:"username"`
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api      *rest.Client
	host     sdk.Host
	user     string
	password string // secret:// reference

	mu       sync.Mutex
	sessions map[string]string // API prefix ("" or "ADSModule/Servers/<id>/API/") -> session id
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the AMP module.
func New() *Module { return &Module{} }

var (
	userRe     = regexp.MustCompile(`^[A-Za-z0-9_.@\-]{1,64}$`)
	instanceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}$`)
	guidRe     = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
)

const instProp = `"instance":{"type":"string","description":"Instance name or id, from instances; leave out on a standalone AMP"}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	one := `{"type":"object","properties":{` + instProp + `}}`
	return sdk.Manifest{
		ID: "amp", Name: "AMP", Version: "0.1.0", Category: "Gaming", Icon: "gamepad",
		Description: "Game servers on CubeCoder AMP: instances, status, start, stop, console commands and updates.",
		Presets:     []string{"gamer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"AMP's address (the ADS controller, or a standalone instance), e.g. https://amp.example.com"},
			"username":{"type":"string","description":"An AMP user without two-factor sign-in; give it only the permissions Conduit needs"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "instances", Title: "Instances", Description: "Every instance on the controller with its game, state, CPU, memory and players.", Risk: sdk.RiskRead},
			{Name: "status", Title: "Status", Description: "One instance's application state, uptime, CPU, memory and players.", Risk: sdk.RiskRead, Input: sdk.Schema(one)},
			{Name: "start", Title: "Start a server", Description: "Starts the instance if it's off, then its game server. Undo stops it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(one)},
			{Name: "stop", Title: "Stop a server", Description: "Stops the game server (players are disconnected); the instance stays up. Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(one)},
			{Name: "restart", Title: "Restart a server", Description: "Players are disconnected while it restarts.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(one)},
			{Name: "command", Title: "Run a console command", Description: "Sends one line to the game server's console. Commands can carry passwords, so this is sensitive. It can't be undone.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["command"],"properties":{` + instProp + `,"command":{"type":"string","maxLength":500}}}`)},
			{Name: "update", Title: "Update the game server", Description: "Downloads and installs the game's latest version (SteamCMD or the game's updater). The server stops meanwhile, and mods may break. Can't be undone.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(one)},
			{Name: "console", Title: "Console output", Description: "Console lines since the last look. They can hold IP addresses and passwords typed into the console, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true, Input: sdk.Schema(one)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "instance", Title: "AMP instances", ListAction: "instances", GetAction: "status", ViewHint: "table"}},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is like https://amp.example.com")
	}
	if !userRe.MatchString(c.Username) {
		return errors.New("enter the AMP username")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
	if err != nil {
		return err
	}
	p := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/API")
	api := rest.New(u.Scheme+"://"+u.Host+p+"/API", nil)
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		api.HTTP = &http.Client{Timeout: 60 * time.Second, Transport: tr} // updates answer once queued, logins can be slow
	}
	// The password and session id travel in the body; a redirect elsewhere
	// (307/308 keep the body) mustn't take them along.
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api, host: h, user: c.Username, password: c.Password, sessions: map[string]string{}})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// errLogin is a refused login.
var errLogin = errors.New("AMP refused the login")

// unwrap reads an AMP answer: newer versions wrap values in {"result":…},
// errors come as {"Title":…,"Message":…} and failed tasks as
// {"Status":false,"Reason":…}.
func unwrap(raw json.RawMessage) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return raw, nil
	}
	if r, ok := obj["result"]; ok && len(obj) == 1 {
		raw = r
		obj = nil
		_ = json.Unmarshal(raw, &obj)
	}
	var e struct {
		Title   string `json:"Title"`
		Message string `json:"Message"`
		Status  *bool  `json:"Status"`
		Reason  string `json:"Reason"`
	}
	_ = json.Unmarshal(raw, &e)
	if e.Title != "" && e.Message != "" {
		if strings.Contains(e.Title, "Unauthori") {
			return nil, &rest.Error{Status: http.StatusUnauthorized, Message: rest.Redact(e.Message)}
		}
		return nil, errors.New(rest.Redact(e.Title + ": " + e.Message))
	}
	if e.Status != nil && !*e.Status {
		msg := "AMP couldn't do it"
		if e.Reason != "" {
			msg += ": " + rest.Redact(e.Reason)
		}
		return nil, errors.New(msg)
	}
	return raw, nil
}

func (c *conn) post(ctx context.Context, path string, body map[string]any) (json.RawMessage, error) {
	var raw json.RawMessage
	if _, err := c.api.Do(ctx, http.MethodPost, "/"+path, nil, body, &raw); err != nil {
		return nil, err
	}
	return unwrap(raw)
}

func (c *conn) login(ctx context.Context, prefix string) (string, error) {
	pw, err := c.host.Secret(ctx, c.password)
	if err != nil {
		return "", err
	}
	raw, err := c.post(ctx, prefix+"Core/Login", map[string]any{"username": c.user, "password": pw, "token": "", "rememberMe": false})
	if err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return "", errLogin
		}
		return "", err
	}
	var r struct {
		Success      bool   `json:"success"`
		SessionID    string `json:"sessionID"`
		ResultReason string `json:"resultReason"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || !r.Success || r.SessionID == "" {
		if r.ResultReason != "" {
			return "", fmt.Errorf("%w: %s", errLogin, rest.Redact(r.ResultReason))
		}
		return "", errLogin
	}
	c.mu.Lock()
	c.sessions[prefix] = r.SessionID
	c.mu.Unlock()
	return r.SessionID, nil
}

// call runs one API method with a session, logging in (again) when needed.
func (c *conn) call(ctx context.Context, prefix, method string, params map[string]any, out any) error {
	for try := 0; try < 2; try++ {
		c.mu.Lock()
		sid := c.sessions[prefix]
		c.mu.Unlock()
		if sid == "" {
			var err error
			if sid, err = c.login(ctx, prefix); err != nil {
				return err
			}
		}
		body := map[string]any{"SESSIONID": sid}
		for k, v := range params {
			body[k] = v
		}
		raw, err := c.post(ctx, prefix+method, body)
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			c.mu.Lock()
			delete(c.sessions, prefix)
			c.mu.Unlock()
			continue
		}
		if err != nil {
			return err
		}
		if out != nil && len(raw) > 0 && string(raw) != "null" {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("unexpected answer from AMP: %w", err)
			}
		}
		return nil
	}
	return errors.New("AMP keeps refusing the session; check the user's permissions")
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if _, err := c.login(ctx, ""); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if list, err := c.instances(ctx); err == nil {
		down := 0
		for _, i := range list {
			if !i.Running {
				down++
			}
		}
		msg := fmt.Sprintf("%d instances", len(list))
		if down > 0 {
			return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s · %d off", msg, down)}
		}
		return sdk.Health{Status: "ok", Message: msg}
	}
	var st status
	if err := c.call(ctx, "", "Core/GetStatus", nil, &st); err != nil {
		return sdk.Health{Status: "degraded", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "standalone · " + stateName(st.State)}
}

type metric struct {
	RawValue float64 `json:"RawValue"`
	MaxValue float64 `json:"MaxValue"`
	Percent  float64 `json:"Percent"`
	Units    string  `json:"Units"`
}

type instance struct {
	InstanceID   string            `json:"InstanceID"`
	InstanceName string            `json:"InstanceName"`
	FriendlyName string            `json:"FriendlyName"`
	Module       string            `json:"Module"`
	ModuleName   string            `json:"ModuleDisplayName"`
	Running      bool              `json:"Running"`
	Suspended    bool              `json:"Suspended"`
	AppState     int               `json:"AppState"`
	Metrics      map[string]metric `json:"Metrics"`
}

type status struct {
	State   int               `json:"State"`
	Uptime  string            `json:"Uptime"`
	Metrics map[string]metric `json:"Metrics"`
}

// AMP's ApplicationState values.
var states = map[int]string{-1: "undefined", 0: "stopped", 5: "pre-start", 7: "configuring", 10: "starting", 20: "running", 30: "restarting", 40: "stopping", 45: "preparing for sleep", 50: "sleeping", 60: "waiting", 70: "installing", 75: "updating", 80: "awaiting input", 100: "failed", 200: "suspended", 250: "maintenance", 999: "indeterminate"}

func stateName(s int) string {
	if n, ok := states[s]; ok {
		return n
	}
	return strconv.Itoa(s)
}

func metrics(out map[string]any, ms map[string]metric) {
	if m, ok := ms["CPU Usage"]; ok {
		out["cpu"] = m.Percent
	}
	if m, ok := ms["Memory Usage"]; ok {
		out["memoryMB"], out["memoryLimitMB"] = m.RawValue, m.MaxValue
	}
	if m, ok := ms["Active Users"]; ok {
		out["players"], out["maxPlayers"] = int(m.RawValue), int(m.MaxValue)
	}
}

func (c *conn) instances(ctx context.Context) ([]instance, error) {
	var targets []struct {
		FriendlyName string     `json:"FriendlyName"`
		Instances    []instance `json:"AvailableInstances"`
	}
	if err := c.call(ctx, "", "ADSModule/GetInstances", nil, &targets); err != nil {
		return nil, err
	}
	var out []instance
	for _, t := range targets {
		for _, i := range t.Instances {
			if i.Module == "ADS" {
				continue // the controller itself
			}
			out = append(out, i)
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].FriendlyName < out[b].FriendlyName })
	return out, nil
}

// target names where calls for one instance go: "" for the AMP at the
// configured address, or the controller's proxy for that instance.
type target struct {
	prefix  string
	label   string
	name    string // InstanceName, for ADS calls
	running bool   // the instance (not the game) is up
	ads     bool
}

func (c *conn) resolve(ctx context.Context, name string) (target, error) {
	if name == "" {
		return target{label: "the server", running: true}, nil
	}
	list, err := c.instances(ctx)
	if err != nil {
		return target{}, err
	}
	for _, i := range list {
		if strings.EqualFold(i.InstanceID, name) || strings.EqualFold(i.InstanceName, name) || strings.EqualFold(i.FriendlyName, name) {
			if !guidRe.MatchString(i.InstanceID) {
				return target{}, fmt.Errorf("AMP gave instance %s an id Conduit won't use", i.InstanceName)
			}
			label := i.FriendlyName
			if label == "" {
				label = i.InstanceName
			}
			return target{prefix: "ADSModule/Servers/" + i.InstanceID + "/API/", label: label, name: i.InstanceName, running: i.Running, ads: true}, nil
		}
	}
	return target{}, fmt.Errorf("no instance named %q", name)
}

type input struct {
	Instance string `json:"instance"`
	Command  string `json:"command"`
}

func plan(summary, tgt, op string, before, after any) *sdk.Plan {
	ch := sdk.Change{Target: tgt, Op: op}
	if before != nil {
		ch.Before, _ = json.Marshal(before)
	}
	if after != nil {
		ch.After, _ = json.Marshal(after)
	}
	return &sdk.Plan{Summary: summary, Changes: []sdk.Change{ch}}
}

func checkLine(s string) error {
	if strings.TrimSpace(s) == "" || len(s) > 500 {
		return errors.New("a command is one line of 1 to 500 characters")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return errors.New("a command is one line without control characters")
		}
	}
	return nil
}

var actions = map[string]bool{"instances": true, "status": true, "start": true, "stop": true, "restart": true, "command": true, "update": true, "console": true}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	if !actions[call.Action] {
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if call.Action == "instances" {
		list, err := c.instances(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, i := range list {
			row := map[string]any{"id": i.InstanceID, "name": i.InstanceName, "title": i.FriendlyName, "game": i.ModuleName, "running": i.Running, "state": stateName(i.AppState)}
			if row["game"] == "" {
				row["game"] = i.Module
			}
			if !i.Running {
				row["state"] = "off"
			}
			if i.Suspended {
				row["state"] = "suspended"
			}
			metrics(row, i.Metrics)
			out = append(out, row)
		}
		return sdk.JSON(out)
	}
	p.Instance = strings.TrimSpace(p.Instance)
	if p.Instance != "" && !instanceRe.MatchString(p.Instance) && !guidRe.MatchString(p.Instance) {
		return sdk.Result{}, errors.New("the instance is its name or id, from instances")
	}
	if call.Action == "command" {
		if err := checkLine(p.Command); err != nil {
			return sdk.Result{}, err
		}
	}
	t, err := c.resolve(ctx, p.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	undoIn := map[string]string{}
	if p.Instance != "" {
		undoIn["instance"] = p.Instance
	}

	// The instance itself is off: only start can do anything.
	if !t.running && call.Action != "start" {
		if call.Action == "status" {
			return sdk.JSON(map[string]any{"instance": t.label, "state": "off"})
		}
		return sdk.Result{}, fmt.Errorf("instance %s is off; start it first", t.label)
	}
	var st status
	if t.running {
		if err := c.call(ctx, t.prefix, "Core/GetStatus", nil, &st); err != nil {
			return sdk.Result{}, err
		}
	}
	state := stateName(st.State)
	if !t.running {
		state = "off"
	}

	switch call.Action {
	case "status":
		out := map[string]any{"instance": t.label, "state": state}
		if st.Uptime != "" {
			out["uptime"] = st.Uptime
		}
		metrics(out, st.Metrics)
		return sdk.JSON(out)

	case "start", "stop", "restart", "update":
		switch {
		case call.Action == "start" && t.running && (st.State == 10 || st.State == 20):
			return sdk.Result{}, fmt.Errorf("%s is already %s", t.label, state)
		case call.Action == "stop" && st.State == 0:
			return sdk.Result{}, fmt.Errorf("%s is already stopped", t.label)
		}
		if call.DryRun {
			sum := map[string]string{"start": "Start", "stop": "Stop", "restart": "Restart", "update": "Update the game on"}[call.Action] + " " + t.label
			if !t.running {
				sum = "Start instance " + t.label + " and its game server"
			}
			if m, ok := st.Metrics["Active Users"]; ok && m.RawValue > 0 && call.Action != "start" {
				sum += fmt.Sprintf("; %d players are disconnected", int(m.RawValue))
			}
			if call.Action == "update" {
				sum += "; the server stops while it updates"
			}
			after := map[string]string{"start": "running", "stop": "stopped", "restart": "running", "update": "updated"}[call.Action]
			return sdk.Result{Plan: plan(sum, t.label, call.Action, map[string]string{"state": state}, map[string]string{"state": after})}, nil
		}
		if !t.running {
			if err := c.call(ctx, "", "ADSModule/StartInstance", map[string]any{"InstanceName": t.name}, nil); err != nil {
				return sdk.Result{}, err
			}
		} else {
			method := map[string]string{"start": "Core/Start", "stop": "Core/Stop", "restart": "Core/Restart", "update": "Core/UpdateApplication"}[call.Action]
			if err := c.call(ctx, t.prefix, method, nil, nil); err != nil {
				return sdk.Result{}, err
			}
		}
		res, err := sdk.JSON(map[string]any{"instance": t.label, "done": call.Action})
		switch call.Action {
		case "start":
			res.Undo = sdk.UndoWith("stop", undoIn, "Stop "+t.label)
		case "stop":
			res.Undo = sdk.UndoWith("start", undoIn, "Start "+t.label)
		}
		return res, err

	case "command":
		if call.DryRun {
			return sdk.Result{Plan: plan(fmt.Sprintf("Run on %s's console: %s", t.label, p.Command), t.label, "command", nil, map[string]string{"command": p.Command})}, nil
		}
		if st.State != 20 {
			return sdk.Result{}, fmt.Errorf("%s is %s, so it can't take commands", t.label, state)
		}
		if err := c.call(ctx, t.prefix, "Core/SendConsoleMessage", map[string]any{"message": p.Command}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"instance": t.label, "sent": true})

	case "console":
		var u struct {
			Entries []struct {
				Timestamp string `json:"Timestamp"`
				Source    string `json:"Source"`
				Type      string `json:"Type"`
				Contents  string `json:"Contents"`
			} `json:"ConsoleEntries"`
		}
		if err := c.call(ctx, t.prefix, "Core/GetUpdates", nil, &u); err != nil {
			return sdk.Result{}, err
		}
		lines := []map[string]string{}
		for _, e := range u.Entries {
			lines = append(lines, map[string]string{"time": ampTime(e.Timestamp), "source": e.Source, "text": e.Contents})
		}
		if len(lines) > 500 {
			lines = lines[len(lines)-500:]
		}
		return sdk.JSON(map[string]any{"instance": t.label, "lines": lines})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// ampTime reads .NET's "/Date(1700000000000)/" timestamps.
func ampTime(s string) string {
	if strings.HasPrefix(s, "/Date(") {
		n := strings.TrimSuffix(strings.TrimPrefix(s, "/Date("), ")/")
		if i := strings.IndexAny(n, "+-"); i > 0 {
			n = n[:i]
		}
		if ms, err := strconv.ParseInt(n, 10, 64); err == nil {
			return time.UnixMilli(ms).UTC().Format(time.RFC3339)
		}
	}
	return s
}
