// Package tasmota works with Tasmota devices through their HTTP command API
// (/cm?cmnd=…): status, relays on/off/toggle with undo, energy metering, a
// few read-only queries and a restart. Commands are built from a fixed
// list: nothing an agent types is sent as a command, so Reset, Upgrade,
// Backlog, WifiConfig, rules, templates and passwords can't be reached.
//
// Relays wired to a garage opener, a door strike or a valve are locked:
// listed in lockedRelays, or detected from a nonzero PulseTime (the usual
// setup of an opener), and any change to them needs the destructive
// power_locked.
package tasmota

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Config is one device.
type Config struct {
	URL      string `json:"url"`      // http://tasmota-plug.local
	Username string `json:"username"` // "admin"
	Password string `json:"password"` // secret://, the web admin password
	// CriticalRelays are relay numbers (1–8) that power something that
	// mustn't go off by accident; turning them off needs power_off_critical.
	CriticalRelays []int `json:"criticalRelays"`
	// LockedRelays are relays (1–8) wired to a garage opener, a gate, a door
	// strike or a valve: any change to them needs power_locked.
	LockedRelays []int `json:"lockedRelays"`
	// NotLocked are relays with a nonzero PulseTime that aren't wired to
	// anything that opens.
	NotLocked          []int  `json:"notLocked"`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	host     sdk.Host
	base     string
	http     *http.Client
	user     string
	pass     string
	critical map[int]bool
	locked   map[int]bool
	unlocked map[int]bool // notLocked
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
}

// New returns the Tasmota module.
func New() *Module { return &Module{} }

const maxRelay = 8

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	relay := `"relay":{"type":"integer","minimum":1,"maximum":8,"default":1,"description":"Relay number (1 for single-relay devices)"}`
	return sdk.Manifest{
		ID: "tasmota", Name: "Tasmota", Version: "0.1.0", Category: "Smart home", Icon: "plug",
		Description: "Tasmota plugs, relays and meters over HTTP: status, power on/off/toggle with undo, energy, read-only queries and restart; dangerous commands are refused.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The device, e.g. http://tasmota-plug.local or http://192.168.1.50"},
			"username":{"type":"string","default":"admin"},
			"password":{"type":"string","x-secret":true,"description":"The web admin password (WebPassword), if set"},
			"criticalRelays":{"type":"array","items":{"type":"integer","minimum":1,"maximum":8},"description":"Relays that power something that mustn't go off by accident; turning them off needs power_off_critical (destructive)"},
			"lockedRelays":{"type":"array","items":{"type":"integer","minimum":1,"maximum":8},"description":"Relays wired to a garage door opener, a gate, a door strike or a valve. Any change to them, on, off or toggle, is refused by set_power and needs power_locked (destructive). A relay with a nonzero PulseTime (the usual setup of an opener) is treated as locked even when it isn't listed here."},
			"notLocked":{"type":"array","items":{"type":"integer","minimum":1,"maximum":8},"description":"Relays with a nonzero PulseTime that aren't wired to anything that opens or unlocks; set_power may change them. A relay in lockedRelays stays locked."},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the device's certificate, for https builds"},
			"insecureSkipVerify":{"type":"boolean","default":false}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Status", Description: "Name, firmware, hardware, uptime, last restart reason, Wi-Fi signal, IP address and each relay's state.", Risk: sdk.RiskRead},
			{Name: "power", Title: "Relays", Description: "Each relay's state, with its friendly name and whether it's critical.", Risk: sdk.RiskRead},
			{Name: "set_power", Title: "Switch a relay", Description: "Turns a relay on, off or toggles it. Turning off or toggling a critical relay is refused (use power_off_critical); any change to a locked relay (garage opener, door strike, valve: lockedRelays, or a nonzero PulseTime) is refused (use power_locked). Undo puts it back.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["state"],"properties":{` + relay + `,"state":{"type":"string","enum":["on","off","toggle"]}}}`)},
			{Name: "power_off_critical", Title: "Turn off a critical relay", Description: "Turns off a relay listed in criticalRelays. Undo turns it back on.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["relay"],"properties":{` + relay + `}}`)},
			{Name: "power_locked", Title: "Switch a locked relay", Description: "Turns a locked relay on or off: one wired to a garage door opener, a gate, a door strike or a valve (lockedRelays, or a nonzero PulseTime). This can open a door or a gate or shut off water. The preview names the relay.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["state"],"properties":{` + relay + `,"state":{"type":"string","enum":["on","off"]}}}`)},
			{Name: "energy", Title: "Energy", Description: "Power now, voltage, current, power factor and energy today, yesterday and in total, from the device's meter.", Risk: sdk.RiskRead},
			{Name: "command", Title: "Query", Description: "Runs one read-only query: State, Status 0–11, Power1–8, Dimmer, CT, Color, HSBColor, Timers or Timezone, without arguments. Anything else is refused.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["command"],"properties":{"command":{"type":"string","maxLength":40,"description":"e.g. Status 8 or Dimmer"}}}`)},
			{Name: "restart", Title: "Restart", Description: "Restarts the device (Restart 1); relays follow their power-on state while it boots.", Risk: sdk.RiskDestructive, DryRun: true},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("the device's address is like http://tasmota-plug.local")
	}
	user := strings.TrimSpace(c.Username)
	if user == "" {
		user = "admin"
	}
	if len(user) > 32 || strings.ContainsAny(user, ":\x00\r\n") {
		return errors.New("the username can't contain a colon or control characters")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if u.Scheme == "http" && (c.Fingerprint != "" || c.InsecureSkipVerify) {
		return errors.New("the certificate settings need an https address")
	}
	nums := func(list []int, what string) (map[int]bool, error) {
		out := map[int]bool{}
		for _, n := range list {
			if n < 1 || n > maxRelay {
				return nil, fmt.Errorf("%s are numbered 1 to %d", what, maxRelay)
			}
			out[n] = true
		}
		return out, nil
	}
	crit, err := nums(c.CriticalRelays, "critical relays")
	if err != nil {
		return err
	}
	locked, err := nums(c.LockedRelays, "locked relays")
	if err != nil {
		return err
	}
	unlocked, err := nums(c.NotLocked, "notLocked relays")
	if err != nil {
		return err
	}
	tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
	if err != nil {
		return err
	}
	tr := sdk.Transport(h)
	tr.TLSClientConfig = tc
	m.set.Put(id, &conn{host: h, base: u.Scheme + "://" + u.Host, user: user, pass: c.Password, critical: crit, locked: locked, unlocked: unlocked,
		http: rest.SameHostOnly(&http.Client{Timeout: 10 * time.Second, Transport: tr})})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// cmd is a command built by this file from fixed words and checked numbers.
type cmd string

// send runs one command. The password goes in a basic-auth header (Tasmota
// accepts that in place of user= and password= parameters), so it's never
// in a URL that could end up in an error message or a log.
func (c *conn) send(ctx context.Context, command cmd) (map[string]json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/cm?"+url.Values{"cmnd": {string(command)}}.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Conduit")
	if c.pass != "" {
		pw, err := c.host.Secret(ctx, c.pass)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(c.user, pw)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("the device refused the username or password")
	}
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("the device answered %s", res.Status)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errors.New("unexpected answer from the device (is this Tasmota?)")
	}
	if w, ok := out["WARNING"]; ok {
		if strings.Contains(string(w), "Need user") {
			if c.pass == "" {
				return nil, errors.New("the device has a web password: store it in the vault and add it to the settings")
			}
			return nil, errors.New("the device refused the username or password")
		}
		return nil, fmt.Errorf("the device: %s", rest.Redact(strings.Trim(string(w), `"`)))
	}
	if v, ok := out["Command"]; ok && strings.Contains(string(v), "Unknown") {
		return nil, fmt.Errorf("the device doesn't know %s", strings.Fields(string(command))[0])
	}
	return out, nil
}

// refused names the commands that are never sent, with why.
var refused = map[string]string{
	"reset": "erases the configuration", "upgrade": "installs firmware", "otaurl": "changes where firmware comes from",
	"backlog": "runs several commands at once", "wificonfig": "can drop the device off Wi-Fi", "restart": "use the restart action",
	"password": "changes credentials", "webpassword": "changes credentials", "mqttpassword": "changes credentials",
	"ssid": "changes Wi-Fi", "ssid1": "changes Wi-Fi", "ssid2": "changes Wi-Fi", "module": "changes the hardware setup", "template": "changes the hardware setup",
	"gpio": "changes the hardware setup", "rule": "changes automation", "rule1": "changes automation", "rule2": "changes automation", "rule3": "changes automation",
	"script": "changes automation", "setoption": "changes settings", "sleep": "changes settings", "deepsleep": "puts the device to sleep",
	"deepsleeptime": "puts the device to sleep", "savedata": "changes settings", "webserver": "can turn the web server off", "mqtthost": "changes settings",
	"fulltopic": "changes settings", "publish": "sends MQTT messages", "interlock": "changes relay safety settings", "poweronstate": "changes settings",
}

var (
	queryRe  = regexp.MustCompile(`^([A-Za-z]+)([0-9]*)$`)
	statusRe = regexp.MustCompile(`^(?i)status +([0-9]{1,2})$`)
	// queries are the commands that only report when sent without arguments.
	queries = map[string]string{"state": "State", "dimmer": "Dimmer", "ct": "CT", "color": "Color", "hsbcolor": "HSBColor", "timers": "Timers", "timezone": "Timezone"}
)

// query builds a read-only command from what was asked, or refuses it.
func query(s string) (cmd, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("say which query, e.g. Status 8")
	}
	if len(s) > 40 {
		return "", errors.New("that's not one of the queries")
	}
	words := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ';' || r == '\t' })
	if len(words) == 0 {
		return "", errors.New("say which query, e.g. Status 8")
	}
	word := strings.ToLower(words[0])
	if why, ok := refused[strings.TrimRight(word, "0123456789")]; ok {
		return "", fmt.Errorf("%s is never sent: it %s", s, why)
	}
	if why, ok := refused[word]; ok {
		return "", fmt.Errorf("%s is never sent: it %s", s, why)
	}
	if strings.HasPrefix(word, "setoption") || strings.HasPrefix(word, "rule") || strings.HasPrefix(word, "ssid") || strings.HasPrefix(word, "so") && len(word) > 2 && word[2] >= '0' && word[2] <= '9' {
		return "", fmt.Errorf("%s is never sent: it changes settings", s)
	}
	if m := statusRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		if n > 11 {
			// Status 12 is the crash dump: memory contents, not status.
			return "", errors.New("Status takes 0 to 11")
		}
		return cmd("Status " + strconv.Itoa(n)), nil
	}
	m := queryRe.FindStringSubmatch(s)
	if m == nil {
		return "", fmt.Errorf("%q isn't a query: only State, Status 0–11, Power1–8, Dimmer, CT, Color, HSBColor, Timers and Timezone, without arguments", s)
	}
	name, num := strings.ToLower(m[1]), m[2]
	switch {
	case name == "status" && num == "":
		return "Status", nil
	case name == "power":
		if num == "" {
			return "Power", nil
		}
		n, _ := strconv.Atoi(num)
		if n < 1 || n > maxRelay || strconv.Itoa(n) != num {
			return "", fmt.Errorf("relays are numbered 1 to %d", maxRelay)
		}
		return cmd("Power" + num), nil
	case queries[name] != "" && num == "":
		return cmd(queries[name]), nil
	}
	return "", fmt.Errorf("%q isn't a query: only State, Status 0–11, Power1–8, Dimmer, CT, Color, HSBColor, Timers and Timezone, without arguments", s)
}

var secretKey = regexp.MustCompile(`(?i)pass|token|secret|key|otaurl`)

// scrub drops what could be a credential from an answer: values under
// password-like keys, and user:password@ in URLs.
func scrub(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if secretKey.MatchString(k) {
				x[k] = "[redacted]"
			} else {
				x[k] = scrub(val)
			}
		}
		return x
	case []any:
		for i := range x {
			x[i] = scrub(x[i])
		}
		return x
	case string:
		if strings.Contains(x, "://") {
			return rest.StripUserinfo(x)
		}
	}
	return v
}

func relays(sts map[string]json.RawMessage) map[int]string {
	out := map[int]string{}
	for k, v := range sts {
		if !strings.HasPrefix(k, "POWER") {
			continue
		}
		n := 1
		if k != "POWER" {
			var err error
			if n, err = strconv.Atoi(k[5:]); err != nil || n < 1 || n > maxRelay {
				continue
			}
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			out[n] = s
		}
	}
	return out
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

type status0 struct {
	Status struct {
		DeviceName   string   `json:"DeviceName"`
		FriendlyName []string `json:"FriendlyName"`
		Topic        string   `json:"Topic"`
	} `json:"Status"`
	StatusPRM struct {
		Uptime        string `json:"Uptime"`
		RestartReason string `json:"RestartReason"`
		BootCount     int    `json:"BootCount"`
	} `json:"StatusPRM"`
	StatusFWR struct {
		Version  string `json:"Version"`
		Hardware string `json:"Hardware"`
	} `json:"StatusFWR"`
	StatusNET struct {
		Hostname  string `json:"Hostname"`
		IPAddress string `json:"IPAddress"`
		Mac       string `json:"Mac"`
	} `json:"StatusNET"`
	StatusSTS map[string]json.RawMessage `json:"StatusSTS"`
}

func (c *conn) status0(ctx context.Context) (status0, error) {
	var s status0
	out, err := c.send(ctx, "Status 0")
	if err != nil {
		return s, err
	}
	if json.Unmarshal(mustJSON(out), &s) != nil || s.StatusFWR.Version == "" {
		return s, errors.New("unexpected answer from the device to Status 0")
	}
	return s, nil
}

func relayName(s status0, n int) string {
	if n-1 < len(s.Status.FriendlyName) && s.Status.FriendlyName[n-1] != "" {
		return fmt.Sprintf("relay %d (%s)", n, s.Status.FriendlyName[n-1])
	}
	return fmt.Sprintf("relay %d", n)
}

// pulses reads which relays have a nonzero PulseTime: they switch off on
// their own after a moment, the setup of a garage opener or door strike.
func (c *conn) pulses(ctx context.Context) (map[int]bool, error) {
	out, err := c.send(ctx, "PulseTime")
	if err != nil {
		return nil, err
	}
	on := map[int]bool{}
	seen := false
	// Tasmota 8.x and later: {"PulseTime":{"Set":[0,…],"Remaining":[0,…]}}.
	var all struct {
		Set []float64 `json:"Set"`
	}
	if raw, ok := out["PulseTime"]; ok && json.Unmarshal(raw, &all) == nil && all.Set != nil {
		seen = true
		for i, v := range all.Set {
			if v != 0 {
				on[i+1] = true
			}
		}
	}
	// Older: {"PulseTime1":0,…} or {"PulseTime1":{"Set":0,"Remaining":0},…}.
	for k, raw := range out {
		n, err := strconv.Atoi(strings.TrimPrefix(k, "PulseTime"))
		if !strings.HasPrefix(k, "PulseTime") || err != nil {
			continue
		}
		var v float64
		var o struct {
			Set *float64 `json:"Set"`
		}
		switch {
		case json.Unmarshal(raw, &v) == nil:
		case json.Unmarshal(raw, &o) == nil && o.Set != nil:
			v = *o.Set
		default:
			continue
		}
		seen = true
		if v != 0 {
			on[n] = true
		}
	}
	if !seen {
		return nil, errors.New("unexpected answer from the device to PulseTime")
	}
	return on, nil
}

// isLocked says whether a relay is locked: listed, or pulsed and not in
// notLocked.
func (c *conn) isLocked(n int, pulse map[int]bool) bool {
	return c.locked[n] || (pulse[n] && !c.unlocked[n])
}

type input struct {
	Relay   *int   `json:"relay"`
	State   string `json:"state"`
	Command string `json:"command"`
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
	case "status":
		s, err := c.status0(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"name": s.Status.DeviceName, "firmware": s.StatusFWR.Version, "hardware": s.StatusFWR.Hardware, "uptime": s.StatusPRM.Uptime,
			"restartReason": s.StatusPRM.RestartReason, "bootCount": s.StatusPRM.BootCount, "hostname": s.StatusNET.Hostname, "ip": s.StatusNET.IPAddress, "mac": s.StatusNET.Mac}
		var w struct {
			SSID   string `json:"SSId"`
			RSSI   int    `json:"RSSI"`
			Signal int    `json:"Signal"`
		}
		if json.Unmarshal(s.StatusSTS["Wifi"], &w) == nil && w.SSID != "" {
			out["wifi"] = map[string]any{"ssid": w.SSID, "rssiPercent": w.RSSI, "signalDbm": w.Signal}
		}
		rs := map[string]string{}
		for n, st := range relays(s.StatusSTS) {
			rs[strconv.Itoa(n)] = st
		}
		out["relays"] = rs
		return sdk.JSON(out)

	case "power":
		s, err := c.status0(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		rs := relays(s.StatusSTS)
		pulse, _ := c.pulses(ctx)
		ns := make([]int, 0, len(rs))
		for n := range rs {
			ns = append(ns, n)
		}
		sort.Ints(ns)
		out := []map[string]any{}
		for _, n := range ns {
			e := map[string]any{"relay": n, "on": rs[n] == "ON"}
			if n-1 < len(s.Status.FriendlyName) && s.Status.FriendlyName[n-1] != "" {
				e["name"] = s.Status.FriendlyName[n-1]
			}
			if c.critical[n] {
				e["critical"] = true
			}
			if c.isLocked(n, pulse) {
				e["locked"] = true
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "set_power", "power_off_critical", "power_locked":
		n := 1
		if p.Relay != nil {
			n = *p.Relay
		}
		if n < 1 || n > maxRelay {
			return sdk.Result{}, fmt.Errorf("relays are numbered 1 to %d", maxRelay)
		}
		state := "off"
		switch call.Action {
		case "set_power":
			state = strings.ToLower(p.State)
			if state != "on" && state != "off" && state != "toggle" {
				return sdk.Result{}, errors.New("state is on, off or toggle")
			}
			if state != "on" && c.critical[n] {
				return sdk.Result{}, fmt.Errorf("relay %d is in criticalRelays: turning it off needs power_off_critical", n)
			}
		case "power_locked":
			state = strings.ToLower(p.State)
			if state != "on" && state != "off" {
				return sdk.Result{}, errors.New("state is on or off")
			}
		default:
			if !c.critical[n] {
				return sdk.Result{}, fmt.Errorf("relay %d isn't in criticalRelays; use set_power", n)
			}
		}
		// Whether it's locked depends on its PulseTime: when that can't be
		// read, only a relay listed in notLocked goes ahead.
		pulse, perr := c.pulses(ctx)
		locked := c.isLocked(n, pulse) || (perr != nil && !c.unlocked[n])
		if call.Action == "power_locked" {
			if !locked {
				return sdk.Result{}, fmt.Errorf("relay %d isn't locked; use set_power", n)
			}
		} else if locked {
			why := "is in lockedRelays"
			switch {
			case c.locked[n]:
			case perr != nil:
				why = "may be locked (its PulseTime couldn't be read: " + perr.Error() + ")"
			default:
				why = "has a PulseTime, the setup of a garage opener or door strike (list it in notLocked if it isn't one)"
			}
			return sdk.Result{}, fmt.Errorf("relay %d %s: any change to it needs power_locked", n, why)
		}
		s, err := c.status0(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		cur, ok := relays(s.StatusSTS)[n]
		if !ok {
			return sdk.Result{}, fmt.Errorf("the device has no relay %d (see power)", n)
		}
		was := cur == "ON"
		want := map[string]bool{"on": true, "off": false, "toggle": !was}[state]
		name := relayName(s, n)
		onOff := map[bool]string{true: "on", false: "off"}
		if call.DryRun {
			sum := "Turn " + onOff[want] + " " + name
			if call.Action == "power_locked" {
				sum = "Turn " + onOff[want] + " locked " + name + ", wired to a garage opener, gate, door strike or valve: this may open or unlock it or shut off a supply"
			}
			if want == was {
				sum = name + " is already " + onOff[was] + "; nothing would change"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: name, Op: "update",
				Before: mustJSON(map[string]bool{"on": was}), After: mustJSON(map[string]bool{"on": want})}}}}, nil
		}
		if want == was {
			return sdk.JSON(map[string]any{"relay": n, "on": was, "changed": false})
		}
		// Sent as on or off, not toggle: the outcome is what the preview said
		// even if someone pressed the button in between.
		out, err := c.send(ctx, cmd("Power"+strconv.Itoa(n)+" "+map[bool]string{true: "On", false: "Off"}[want]))
		if err != nil {
			return sdk.Result{}, err
		}
		now, ok := relays(out)[n]
		if !ok {
			return sdk.Result{}, errors.New("unexpected answer from the device")
		}
		res, err := sdk.JSON(map[string]any{"relay": n, "on": now == "ON", "changed": true})
		if call.Action == "power_locked" {
			return res, err // a pulsed relay goes back by itself; no undo
		}
		back, in := "set_power", map[string]any{"relay": n, "state": onOff[was]}
		if !was && c.critical[n] {
			back, in = "power_off_critical", map[string]any{"relay": n}
		}
		res.Undo = sdk.UndoWith(back, in, "Turn "+name+" back "+onOff[was])
		return res, err

	case "energy":
		out, err := c.send(ctx, "Status 10")
		if err != nil {
			return sdk.Result{}, err
		}
		var sns struct {
			StatusSNS struct {
				Time   string `json:"Time"`
				Energy *struct {
					Total     *float64 `json:"Total"`
					Yesterday *float64 `json:"Yesterday"`
					Today     *float64 `json:"Today"`
					Power     any      `json:"Power"`
					Apparent  any      `json:"ApparentPower"`
					Factor    any      `json:"Factor"`
					Voltage   any      `json:"Voltage"`
					Current   any      `json:"Current"`
				} `json:"ENERGY"`
			} `json:"StatusSNS"`
		}
		if json.Unmarshal(mustJSON(out), &sns) != nil {
			return sdk.Result{}, errors.New("unexpected answer from the device to Status 10")
		}
		e := sns.StatusSNS.Energy
		if e == nil {
			return sdk.Result{}, errors.New("this device has no energy meter")
		}
		res := map[string]any{"time": sns.StatusSNS.Time, "powerW": e.Power, "voltage": e.Voltage, "currentA": e.Current, "powerFactor": e.Factor, "apparentVA": e.Apparent}
		for k, v := range map[string]*float64{"todayKWh": e.Today, "yesterdayKWh": e.Yesterday, "totalKWh": e.Total} {
			if v != nil {
				res[k] = *v
			}
		}
		for k, v := range res {
			if v == nil {
				delete(res, k)
			}
		}
		return sdk.JSON(res)

	case "command":
		q, err := query(p.Command)
		if err != nil {
			return sdk.Result{}, err
		}
		out, err := c.send(ctx, q)
		if err != nil {
			return sdk.Result{}, err
		}
		var v any
		_ = json.Unmarshal(mustJSON(out), &v)
		return sdk.JSON(map[string]any{"command": string(q), "result": scrub(v)})

	case "restart":
		s, err := c.status0(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		name := s.Status.DeviceName
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Restart " + name + "; relays follow their power-on state while it boots",
				Changes: []sdk.Change{{Target: name, Op: "restart"}}}}, nil
		}
		if _, err := c.send(ctx, "Restart 1"); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"device": name, "restarting": true})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.status0(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := s.Status.DeviceName + " · Tasmota " + s.StatusFWR.Version
	if n := len(relays(s.StatusSTS)); n > 0 {
		msg += fmt.Sprintf(" · %d relay(s)", n)
	}
	if c.pass != "" && strings.HasPrefix(c.base, "http://") {
		return sdk.Health{Status: "degraded", Message: msg + " · password sent without encryption (the device is on http)"}
	}
	return sdk.Health{Status: "ok", Message: msg}
}
