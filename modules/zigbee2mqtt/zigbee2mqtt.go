// Package zigbee2mqtt works with Zigbee2MQTT through its MQTT broker: the
// bridge's info and devices (from its retained bridge topics), a device's
// state, setting a device, and permitting new devices to join. Locks,
// covers, thermostats and sirens are only set through a separate
// destructive action.
package zigbee2mqtt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/mqttx"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Zigbee2MQTT instance and its broker.
type Config struct {
	URL                string `json:"url"`
	Username           string `json:"username"`
	Password           string `json:"password"` // secret://
	ClientIDPrefix     string `json:"clientIdPrefix"`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	// BaseTopic is Zigbee2MQTT's mqtt.base_topic.
	BaseTopic string `json:"baseTopic"`
	// CriticalDevices are friendly names or IEEE addresses of devices whose
	// every change needs set_critical (a relay on a garage door, a valve, a
	// heater's plug).
	CriticalDevices []string `json:"criticalDevices"`
}

type conn struct {
	*mqttx.Broker
	base     string
	critical map[string]bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
}

// New returns the Zigbee2MQTT module.
func New() *Module { return &Module{} }

var (
	baseRe   = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)
	ieeeRe   = regexp.MustCompile(`^0x[0-9a-fA-F]{16}$`)
	keyRe    = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	critName = regexp.MustCompile(`^(warning|squawk|alarm|siren|alarm_[a-z0-9_]+|.*_alarm|system_mode|child_lock|lock|lock_state|state_lock)$`)
)

// criticalTypes are the specific exposes whose features are destructive to
// change: unlocking, opening, and turning off heating or cooling.
var criticalTypes = map[string]bool{"lock": true, "cover": true, "climate": true}

const (
	maxPayload = 4 << 10
	maxKeys    = 20
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	dev := `"device":{"type":"string","maxLength":200,"description":"The device's friendly name or IEEE address (0x…)"}`
	pay := `"payload":{"type":"object","description":"Properties to set, as the device exposes them, e.g. {\"state\":\"ON\",\"brightness\":128}"}`
	return sdk.Manifest{
		ID: "zigbee2mqtt", Name: "Zigbee2MQTT", Version: "0.1.0", Category: "Smart home", Icon: "network",
		Description: "Zigbee2MQTT over MQTT: bridge info, devices, a device's state, setting devices, permit join; locks, covers, thermostats and sirens kept apart.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The broker Zigbee2MQTT uses, e.g. mqtt://broker.local:1883 or mqtts://broker.local:8883"},
			"username":{"type":"string"},
			"password":{"type":"string","x-secret":true},
			"clientIdPrefix":{"type":"string","default":"conduit"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the broker's certificate (mqtts only)"},
			"insecureSkipVerify":{"type":"boolean","default":false},
			"baseTopic":{"type":"string","default":"zigbee2mqtt","description":"Zigbee2MQTT's mqtt.base_topic"},
			"criticalDevices":{"type":"array","items":{"type":"string"},"description":"Friendly names or IEEE addresses of devices whose changes need set_critical (garage relays, valves, heater plugs)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "bridge", Title: "Bridge", Description: "Zigbee2MQTT's version, coordinator, channel, whether joining is permitted and whether it's online.", Risk: sdk.RiskRead},
			{Name: "devices", Title: "Devices", Description: "Every device with its type, model, vendor, power source, interview state, the properties it can set, and whether it's critical.", Risk: sdk.RiskRead},
			{Name: "state", Title: "Device state", Description: "A device's last state and availability. When nothing is retained, the module asks the device for its readable properties (a /get request) and waits for the answer.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["device"],"properties":{` + dev + `,"seconds":{"type":"number","minimum":0.5,"maximum":15,"default":3}}}`)},
			{Name: "set_device", Title: "Set a device", Description: "Sets properties the device exposes as writable (lights, plugs, switches). Locks, covers, thermostats, sirens, child locks and devices in criticalDevices are refused (use set_critical). Undo puts the previous values back when the device's state was known.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["device","payload"],"properties":{` + dev + `,` + pay + `}}`)},
			{Name: "set_critical", Title: "Set a lock, cover, thermostat or alarm", Description: "Like set_device, for anything it refuses: unlocking, opening a cover or garage, changing a thermostat's mode or setpoint, sounding or silencing an alarm.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["device","payload"],"properties":{` + dev + `,` + pay + `}}`)},
			{Name: "permit_join", Title: "Permit joining", Description: "Lets new Zigbee devices join the network for up to 254 seconds (0 closes it again). Anything in radio range that's pairing can join. Undo closes it.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["seconds"],"properties":{"seconds":{"type":"integer","minimum":0,"maximum":254}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	b, err := mqttx.New(h, mqttx.Options{URL: c.URL, Username: c.Username, Password: c.Password, ClientIDPrefix: c.ClientIDPrefix,
		Fingerprint: c.Fingerprint, InsecureSkipVerify: c.InsecureSkipVerify})
	if err != nil {
		return err
	}
	base := strings.TrimSpace(c.BaseTopic)
	if base == "" {
		base = "zigbee2mqtt"
	}
	if !baseRe.MatchString(base) || len(base) > 200 {
		return errors.New("the base topic is like zigbee2mqtt (letters, digits, _, - and /, no wildcards)")
	}
	if len(c.CriticalDevices) > 500 {
		return errors.New("list at most 500 critical devices")
	}
	crit := map[string]bool{}
	for _, d := range c.CriticalDevices {
		if err := checkName(d); err != nil {
			return fmt.Errorf("criticalDevices: %w", err)
		}
		crit[strings.ToLower(d)] = true
	}
	m.set.Put(id, &conn{Broker: b, base: base, critical: crit})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// checkName applies what Zigbee2MQTT allows in a friendly name, and what
// keeps the topics built from it inside the device's own.
func checkName(n string) error {
	switch {
	case n == "" || len(n) > 200:
		return errors.New("a device name is 1 to 200 characters")
	case !utf8.ValidString(n) || mqttx.HasControl(n):
		return errors.New("a device name has no control characters")
	case strings.ContainsAny(n, "+#"):
		return errors.New("a device name has no + or #")
	case strings.HasPrefix(n, "$") || strings.HasPrefix(n, "/") || strings.HasSuffix(n, "/") || strings.Contains(n, "//"):
		return errors.New("a device name doesn't start with $ or /, end with /, or have empty levels")
	case n == "bridge" || strings.HasPrefix(n, "bridge/"):
		return errors.New("bridge is Zigbee2MQTT's own topic")
	}
	for _, l := range strings.Split(n, "/") {
		if l == "set" || l == "get" || l == "availability" {
			return fmt.Errorf("a device name has no %q level", l)
		}
	}
	return nil
}

type expose struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Property    string   `json:"property"`
	Access      int      `json:"access"`
	ValueMin    *float64 `json:"value_min"`
	ValueMax    *float64 `json:"value_max"`
	ValueOn     any      `json:"value_on"`
	ValueOff    any      `json:"value_off"`
	ValueToggle any      `json:"value_toggle"`
	Values      []any    `json:"values"`
	Features    []expose `json:"features"`
}

type device struct {
	IEEE         string `json:"ieee_address"`
	Type         string `json:"type"`
	FriendlyName string `json:"friendly_name"`
	Supported    bool   `json:"supported"`
	Disabled     bool   `json:"disabled"`
	PowerSource  string `json:"power_source"`
	Interviewed  bool   `json:"interview_completed"`
	ModelID      string `json:"model_id"`
	Manufacturer string `json:"manufacturer"`
	Definition   *struct {
		Model       string   `json:"model"`
		Vendor      string   `json:"vendor"`
		Description string   `json:"description"`
		Exposes     []expose `json:"exposes"`
	} `json:"definition"`
}

// prop is one property a device exposes.
type prop struct {
	expose
	parent   string // lock, cover, climate, light, switch, fan or ""
	critical bool
}

const (
	accessState = 1
	accessSet   = 2
	accessGet   = 4
)

func (d device) props() map[string]prop {
	out := map[string]prop{}
	var walk func(e expose, parent string)
	walk = func(e expose, parent string) {
		switch e.Type {
		case "light", "switch", "lock", "cover", "climate", "fan":
			for _, f := range e.Features {
				walk(f, e.Type)
			}
			return
		}
		if e.Property != "" {
			out[e.Property] = prop{expose: e, parent: parent, critical: criticalTypes[parent] || critName.MatchString(e.Property) || critName.MatchString(e.Name)}
			return
		}
		for _, f := range e.Features {
			walk(f, parent)
		}
	}
	if d.Definition != nil {
		for _, e := range d.Definition.Exposes {
			walk(e, "")
		}
	}
	return out
}

func (d device) critical(c *conn) bool {
	if c.critical[strings.ToLower(d.FriendlyName)] || c.critical[strings.ToLower(d.IEEE)] {
		return true
	}
	for _, p := range d.props() {
		if p.critical && p.Access&accessSet != 0 {
			return true
		}
	}
	return false
}

func (c *conn) topic(parts ...string) string { return c.base + "/" + strings.Join(parts, "/") }

// retained reads one retained bridge topic.
func (c *conn) retained(ctx context.Context, name string) ([]byte, error) {
	m, err := c.Current(ctx, c.topic("bridge", name))
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("nothing is retained on %s: is Zigbee2MQTT running, with this base topic?", c.topic("bridge", name))
	}
	return m.Payload, nil
}

func (c *conn) devices(ctx context.Context) ([]device, error) {
	raw, err := c.retained(ctx, "devices")
	if err != nil {
		return nil, err
	}
	var ds []device
	if err := json.Unmarshal(raw, &ds); err != nil {
		return nil, errors.New("Zigbee2MQTT's device list isn't what this module expects")
	}
	return ds, nil
}

// find resolves a friendly name or IEEE address among the devices.
func (c *conn) find(ctx context.Context, ref string) (device, error) {
	ref = strings.TrimSpace(ref)
	if !ieeeRe.MatchString(ref) {
		if err := checkName(ref); err != nil {
			return device{}, err
		}
	}
	ds, err := c.devices(ctx)
	if err != nil {
		return device{}, err
	}
	for _, d := range ds {
		if d.FriendlyName == ref || strings.EqualFold(d.IEEE, ref) {
			if d.Type == "Coordinator" {
				return device{}, errors.New("that's the coordinator, not a device")
			}
			if checkName(d.FriendlyName) != nil {
				return device{}, fmt.Errorf("the device's friendly name %q can't be used in a topic safely; rename it", d.FriendlyName)
			}
			return d, nil
		}
	}
	return device{}, fmt.Errorf("Zigbee2MQTT has no device %q (see devices)", ref)
}

type info struct {
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	Coordinator struct {
		Type string         `json:"type"`
		IEEE string         `json:"ieee_address"`
		Meta map[string]any `json:"meta"`
	} `json:"coordinator"`
	Network struct {
		Channel int `json:"channel"`
		PanID   any `json:"pan_id"`
	} `json:"network"`
	LogLevel        string `json:"log_level"`
	PermitJoin      bool   `json:"permit_join"`
	PermitJoinEnd   *int64 `json:"permit_join_end"`
	PermitJoinTO    *int   `json:"permit_join_timeout"`
	RestartRequired bool   `json:"restart_required"`
}

func (c *conn) info(ctx context.Context) (info, error) {
	var in info
	raw, err := c.retained(ctx, "info")
	if err != nil {
		return in, err
	}
	if json.Unmarshal(raw, &in) != nil {
		return in, errors.New("Zigbee2MQTT's bridge info isn't what this module expects")
	}
	return in, nil
}

func major(v string) int {
	n, _ := strconv.Atoi(strings.SplitN(strings.TrimPrefix(v, "v"), ".", 2)[0])
	return n
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// observed is a device's state as read from the broker.
type observed struct {
	state    map[string]any
	retained bool
	avail    string
}

// watch subscribes to a device's state and availability on a session and
// returns a channel of what arrives.
func (c *conn) watch(ctx context.Context, s *mqttx.Session, d device) (<-chan mqttx.Message, error) {
	ch := make(chan mqttx.Message, 32)
	t := c.topic(d.FriendlyName)
	err := s.Subscribe(ctx, []string{t, t + "/availability"}, 0, func(m mqttx.Message) {
		select {
		case ch <- m:
		default:
		}
	})
	return ch, err
}

// read waits for the device's state. When nothing retained arrives in the
// settle time and ask is set, it sends a /get for the readable properties.
func (c *conn) read(ctx context.Context, s *mqttx.Session, d device, ch <-chan mqttx.Message, wait time.Duration, ask bool) (observed, error) {
	var o observed
	t := c.topic(d.FriendlyName)
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	settle := time.NewTimer(c.Settle)
	defer settle.Stop()
	take := func(m mqttx.Message) bool {
		switch m.Topic {
		case t + "/availability":
			var a struct {
				State string `json:"state"`
			}
			if json.Unmarshal(m.Payload, &a) == nil && a.State != "" {
				o.avail = a.State
			} else {
				o.avail = string(m.Payload)
			}
		case t:
			var st map[string]any
			if json.Unmarshal(m.Payload, &st) == nil {
				o.state, o.retained = st, m.Retained
				return true
			}
		}
		return false
	}
	for {
		select {
		case m := <-ch:
			if take(m) {
				// Pick up an availability message that came with it.
				for {
					select {
					case m := <-ch:
						take(m)
					default:
						return o, nil
					}
				}
			}
		case <-settle.C:
			if !ask {
				return o, nil
			}
			get := map[string]string{}
			for k, p := range d.props() {
				if p.Access&accessGet != 0 && !strings.Contains(k, "/") {
					get[k] = ""
				}
			}
			if len(get) == 0 {
				continue
			}
			if err := s.Publish(ctx, t+"/get", 0, false, mustJSON(get)); err != nil {
				return o, err
			}
		case <-deadline.C:
			return o, nil
		case err := <-s.Lost():
			return o, fmt.Errorf("the broker closed the connection: %v", err)
		case <-ctx.Done():
			return o, ctx.Err()
		}
	}
}

// checkPayload validates what to set against the device's exposes.
func checkPayload(d device, payload map[string]any, allowCritical bool, deviceCritical bool) (bool, error) {
	if len(payload) == 0 {
		return false, errors.New("say what to set, e.g. {\"state\":\"ON\"}")
	}
	if len(payload) > maxKeys {
		return false, fmt.Errorf("set at most %d properties at once", maxKeys)
	}
	if len(mustJSON(payload)) > maxPayload {
		return false, errors.New("the payload is larger than 4 KB")
	}
	props := d.props()
	anyCritical := deviceCritical
	for k, v := range payload {
		if !keyRe.MatchString(k) {
			return false, fmt.Errorf("%q isn't a property name", k)
		}
		p, ok := props[k]
		if !ok || p.Access&accessSet == 0 {
			var can []string
			for n, q := range props {
				if q.Access&accessSet != 0 {
					can = append(can, n)
				}
			}
			sort.Strings(can)
			return false, fmt.Errorf("%s has no writable property %q (it has: %s)", d.FriendlyName, k, strings.Join(can, ", "))
		}
		if p.critical {
			anyCritical = true
		}
		if err := checkValue(k, p, v); err != nil {
			return false, err
		}
	}
	if anyCritical && !allowCritical {
		why := "it's in criticalDevices"
		if !deviceCritical {
			why = "it changes a lock, cover, thermostat, alarm or child lock"
		}
		return true, fmt.Errorf("%s: %s; use set_critical", d.FriendlyName, why)
	}
	return anyCritical, nil
}

func checkValue(k string, p prop, v any) error {
	switch p.Type {
	case "numeric":
		f, ok := v.(float64)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("%s is a number", k)
		}
		if p.ValueMin != nil && f < *p.ValueMin || p.ValueMax != nil && f > *p.ValueMax {
			return fmt.Errorf("%s is between %g and %g", k, deref(p.ValueMin, math.Inf(-1)), deref(p.ValueMax, math.Inf(1)))
		}
	case "binary":
		for _, ok := range []any{p.ValueOn, p.ValueOff, p.ValueToggle} {
			if ok != nil && fmt.Sprint(ok) == fmt.Sprint(v) && fmt.Sprintf("%T", ok) == fmt.Sprintf("%T", v) {
				return nil
			}
		}
		return fmt.Errorf("%s is %v or %v", k, p.ValueOn, p.ValueOff)
	case "enum":
		for _, ok := range p.Values {
			if fmt.Sprint(ok) == fmt.Sprint(v) && fmt.Sprintf("%T", ok) == fmt.Sprintf("%T", v) {
				return nil
			}
		}
		return fmt.Errorf("%s is one of %v", k, p.Values)
	case "text":
		s, ok := v.(string)
		if !ok || len(s) > 256 || mqttx.HasControl(s) {
			return fmt.Errorf("%s is a short line of text", k)
		}
	case "composite":
		o, ok := v.(map[string]any)
		if !ok || len(o) == 0 || len(o) > 8 {
			return fmt.Errorf("%s is an object, like {\"x\":0.3,\"y\":0.3} or {\"hex\":\"#ff8800\"}", k)
		}
		for ok, ov := range o {
			if !keyRe.MatchString(ok) {
				return fmt.Errorf("%s.%s isn't a property name", k, ok)
			}
			switch x := ov.(type) {
			case float64, bool:
			case string:
				if len(x) > 64 || mqttx.HasControl(x) {
					return fmt.Errorf("%s.%s is too long", k, ok)
				}
			default:
				return fmt.Errorf("%s.%s is a number, text or true/false", k, ok)
			}
		}
	default:
		return fmt.Errorf("%s (%s) isn't a kind of property this module sets", k, p.Type)
	}
	return nil
}

func deref(p *float64, d float64) float64 {
	if p == nil {
		return d
	}
	return *p
}

type input struct {
	Device  string         `json:"device"`
	Payload map[string]any `json:"payload"`
	Seconds *float64       `json:"seconds"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "bridge":
		in, err := c.info(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"version": in.Version, "permitJoin": in.PermitJoin, "logLevel": in.LogLevel, "restartRequired": in.RestartRequired,
			"coordinator": map[string]any{"type": in.Coordinator.Type, "ieee": in.Coordinator.IEEE}, "channel": in.Network.Channel}
		if in.Commit != "" {
			out["commit"] = in.Commit
		}
		if r, ok := in.Coordinator.Meta["revision"]; ok {
			out["coordinator"].(map[string]any)["revision"] = r
		}
		if in.PermitJoinEnd != nil {
			out["permitJoinUntil"] = time.UnixMilli(*in.PermitJoinEnd).UTC().Format(time.RFC3339)
		}
		if st, err := c.Current(ctx, c.topic("bridge", "state")); err == nil && st != nil {
			var s struct {
				State string `json:"state"`
			}
			if json.Unmarshal(st.Payload, &s) == nil && s.State != "" {
				out["state"] = s.State
			} else {
				out["state"] = string(st.Payload)
			}
		}
		return sdk.JSON(out)

	case "devices":
		ds, err := c.devices(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range ds {
			e := map[string]any{"name": d.FriendlyName, "ieee": d.IEEE, "type": d.Type}
			if d.Type != "Coordinator" {
				e["supported"], e["interviewed"] = d.Supported, d.Interviewed
				if d.PowerSource != "" {
					e["power"] = d.PowerSource
				}
				if d.Disabled {
					e["disabled"] = true
				}
				if d.Definition != nil {
					e["model"], e["vendor"], e["description"] = d.Definition.Model, d.Definition.Vendor, d.Definition.Description
				}
				var w []string
				for k, p := range d.props() {
					if p.Access&accessSet != 0 {
						w = append(w, k)
					}
				}
				sort.Strings(w)
				e["writable"] = w
				if d.critical(c) {
					e["critical"] = true
				}
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "state":
		var p input
		if err := sdk.Decode(call, &p); err != nil {
			return sdk.Result{}, err
		}
		secs := 3.0
		if p.Seconds != nil {
			secs = *p.Seconds
		}
		if secs < 0.5 || secs > 15 || math.IsNaN(secs) {
			return sdk.Result{}, errors.New("seconds is between 0.5 and 15")
		}
		d, err := c.find(ctx, p.Device)
		if err != nil {
			return sdk.Result{}, err
		}
		s, err := c.Connect(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		defer s.Close()
		ch, err := c.watch(ctx, s, d)
		if err != nil {
			return sdk.Result{}, err
		}
		o, err := c.read(ctx, s, d, ch, time.Duration(secs*float64(time.Second)), true)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"device": d.FriendlyName, "ieee": d.IEEE, "state": o.state}
		if o.state == nil {
			out["note"] = "the device sent no state in time (battery devices only answer when they wake up)"
		} else {
			out["retained"] = o.retained
		}
		if o.avail != "" {
			out["availability"] = o.avail
		}
		return sdk.JSON(out)

	case "set_device", "set_critical":
		var p input
		if err := sdk.Decode(call, &p); err != nil {
			return sdk.Result{}, err
		}
		d, err := c.find(ctx, p.Device)
		if err != nil {
			return sdk.Result{}, err
		}
		if d.Disabled {
			return sdk.Result{}, fmt.Errorf("%s is disabled in Zigbee2MQTT", d.FriendlyName)
		}
		critical := call.Action == "set_critical"
		devCrit := c.critical[strings.ToLower(d.FriendlyName)] || c.critical[strings.ToLower(d.IEEE)]
		if _, err := checkPayload(d, p.Payload, critical, devCrit); err != nil {
			return sdk.Result{}, err
		}
		s, err := c.Connect(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		defer s.Close()
		ch, err := c.watch(ctx, s, d)
		if err != nil {
			return sdk.Result{}, err
		}
		o, err := c.read(ctx, s, d, ch, 3*time.Second, true)
		if err != nil {
			return sdk.Result{}, err
		}
		before := map[string]any{}
		for k := range p.Payload {
			if v, ok := o.state[k]; ok {
				before[k] = v
			}
		}
		if call.DryRun {
			sum := fmt.Sprintf("Set %s: %s", d.FriendlyName, mustJSON(p.Payload))
			ch := sdk.Change{Target: "device " + d.FriendlyName, Op: "update", After: mustJSON(p.Payload)}
			if o.state != nil {
				ch.Before = mustJSON(before)
			} else {
				sum += " (its current state isn't known)"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{ch}}}, nil
		}
		// Drop what arrived before the set (a late answer to the /get), so
		// the confirmation below is the answer to this change.
	drain:
		for {
			select {
			case <-ch:
			default:
				break drain
			}
		}
		if err := s.Publish(ctx, c.topic(d.FriendlyName, "set"), 1, false, mustJSON(p.Payload)); err != nil {
			return sdk.Result{}, err
		}
		// Zigbee2MQTT answers with the new state on the device's topic.
		var now map[string]any
		wait := time.NewTimer(3 * time.Second)
		defer wait.Stop()
	confirm:
		for {
			select {
			case m := <-ch:
				var st map[string]any
				if m.Topic == c.topic(d.FriendlyName) && !m.Retained && json.Unmarshal(m.Payload, &st) == nil {
					now = st
					break confirm
				}
			case <-wait.C:
				break confirm
			case <-ctx.Done():
				return sdk.Result{}, ctx.Err()
			}
		}
		out := map[string]any{"device": d.FriendlyName, "sent": p.Payload, "confirmed": now != nil}
		if now != nil {
			after := map[string]any{}
			for k := range p.Payload {
				if v, ok := now[k]; ok {
					after[k] = v
				}
			}
			out["now"] = after
		}
		res, err := sdk.JSON(out)
		if len(before) == len(p.Payload) {
			// Every value set is known from before: undo puts them back.
			undo := map[string]any{}
			props := d.props()
			for k, v := range before {
				if checkValue(k, props[k], v) != nil {
					undo = nil
					break
				}
				undo[k] = v
			}
			if undo != nil {
				back := "set_device"
				if _, err := checkPayload(d, undo, false, devCrit); err != nil {
					back = "set_critical"
				}
				res.Undo = sdk.UndoWith(back, map[string]any{"device": d.FriendlyName, "payload": undo}, "Put "+d.FriendlyName+" back")
			}
		}
		return res, err

	case "permit_join":
		var p struct {
			Seconds *int `json:"seconds"`
		}
		if err := sdk.Decode(call, &p); err != nil {
			return sdk.Result{}, err
		}
		if p.Seconds == nil || *p.Seconds < 0 || *p.Seconds > 254 {
			return sdk.Result{}, errors.New("seconds is between 0 (close) and 254")
		}
		secs := *p.Seconds
		in, err := c.info(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			sum := fmt.Sprintf("Let new devices join for %d seconds", secs)
			if secs == 0 {
				sum = "Stop new devices from joining"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "Zigbee network", Op: "update",
				Before: mustJSON(map[string]bool{"permitJoin": in.PermitJoin}), After: mustJSON(map[string]any{"permitJoin": secs > 0, "seconds": secs})}}}}, nil
		}
		tx := mqttx.RandomHex(6)
		req := map[string]any{"time": secs, "transaction": tx}
		if major(in.Version) < 2 {
			req["value"] = secs > 0 // 1.x takes value plus an optional time
		}
		s, err := c.Connect(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		defer s.Close()
		resp := make(chan []byte, 4)
		if err := s.Subscribe(ctx, []string{c.topic("bridge", "response", "permit_join")}, 1, func(m mqttx.Message) {
			select {
			case resp <- m.Payload:
			default:
			}
		}); err != nil {
			return sdk.Result{}, err
		}
		if err := s.Publish(ctx, c.topic("bridge", "request", "permit_join"), 1, false, mustJSON(req)); err != nil {
			return sdk.Result{}, err
		}
		wait := time.NewTimer(c.Timeout)
		defer wait.Stop()
		for {
			select {
			case raw := <-resp:
				var r struct {
					Status      string `json:"status"`
					Error       string `json:"error"`
					Transaction string `json:"transaction"`
				}
				if json.Unmarshal(raw, &r) != nil || r.Transaction != tx {
					continue
				}
				if r.Status != "ok" {
					return sdk.Result{}, fmt.Errorf("Zigbee2MQTT refused: %s", r.Error)
				}
				res, err := sdk.JSON(map[string]any{"permitJoin": secs > 0, "seconds": secs})
				if secs > 0 {
					res.Undo = sdk.UndoWith("permit_join", map[string]int{"seconds": 0}, "Stop new devices from joining")
				}
				return res, err
			case <-wait.C:
				return sdk.Result{}, errors.New("Zigbee2MQTT didn't answer the request in time")
			case <-ctx.Done():
				return sdk.Result{}, ctx.Err()
			}
		}
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	in, err := c.info(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "Zigbee2MQTT " + in.Version
	st, err := c.Current(ctx, c.topic("bridge", "state"))
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if st != nil && strings.Contains(string(st.Payload), "offline") {
		return sdk.Health{Status: "down", Message: msg + " is offline"}
	}
	if in.PermitJoin {
		return sdk.Health{Status: "degraded", Message: msg + " · joining is permitted"}
	}
	return sdk.Health{Status: "ok", Message: msg}
}
