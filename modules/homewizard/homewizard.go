// Package homewizard works with one HomeWizard Energy device (P1 meter,
// Energy Socket, kWh meter, water meter) through its local API on the LAN:
// API v1 over http without a login, or API v2 over https with a token.
// Device info, the current measurements, and switching an Energy Socket on
// or off.
//
// Switching a socket off can cut power to something that matters, so it's
// destructive; a socket marked critical is never switched off by Conduit,
// and the device's own switch lock is respected.
package homewizard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one device.
type Config struct {
	URL string `json:"url"` // http://192.168.1.50 (v1) or https://192.168.1.50 (v2)
	// Token is a secret:// reference to an API v2 token; without it the
	// device is read over API v1.
	Token string `json:"token"`
	// Critical marks an Energy Socket that powers something that mustn't go
	// off by accident (a server, a router, a fridge): Conduit won't switch
	// it off.
	Critical           bool   `json:"critical"`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api      *rest.Client
	v2       bool
	critical bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the HomeWizard module.
func New() *Module { return &Module{} }

const socketType = "HWE-SKT"

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var numericLabel = regexp.MustCompile(`^([0-9]+|0x[0-9a-f]*)$`)

// localSuffixes are names that only resolve inside a network.
var localSuffixes = []string{".local", ".lan", ".home.arpa", ".internal", ".home", ".localdomain"}

// cgnat is 100.64.0.0/10, which Tailscale and NetBird give their peers.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// lanHost says whether host is on the local network: a private, loopback,
// link-local or CGNAT (Tailscale, NetBird) address, a single-label name, or
// a name under a local suffix such as .local.
func lanHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || cgnat.Contains(a)
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	// A last label that is a number isn't a host name: "134744072",
	// "0x8080808" or "8.8.8.010" are addresses to inet_aton (a proxy or a
	// libc resolver), and could be public ones.
	if numericLabel.MatchString(labels[len(labels)-1]) {
		return false
	}
	if len(labels) == 1 {
		return true
	}
	for _, s := range localSuffixes {
		if strings.HasSuffix(h, s) {
			return true
		}
	}
	return false
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "homewizard", Name: "HomeWizard Energy", Version: "0.1.0", Category: "Smart home", Icon: "plug",
		Description: "HomeWizard Energy devices on your network (P1 meter, Energy Socket, kWh and water meters): device info, live power and meter readings, and switching a socket.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The device on your network: http://192.168.1.50 for API v1, https://192.168.1.50 for API v2 (an IP address, or a .local name)"},
			"token":{"type":"string","x-secret":true,"description":"An API v2 token (needs https); leave empty for API v1, which has no login"},
			"critical":{"type":"boolean","default":false,"description":"The socket powers something that mustn't go off by accident (a server, a router, a fridge): Conduit won't switch it off"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the device's certificate, for API v2 (its certificate isn't from a public authority)"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "device", Title: "Device", Description: "Product, type, serial, firmware and API version, and for an Energy Socket whether it's critical.", Risk: sdk.RiskRead},
			{Name: "measurements", Title: "Measurements", Description: "What the device measures now: power (W, per phase), voltage, current, frequency, energy imported and exported (kWh, per tariff), the tariff, and gas or water from connected meters.", Risk: sdk.RiskRead},
			{Name: "plug", Title: "Socket state", Description: "Whether an Energy Socket is on, whether its switch lock is on, the ring's brightness, and whether it's critical.", Risk: sdk.RiskRead},
			{Name: "plug_on", Title: "Switch the socket on", Description: "Switches an Energy Socket on. Refused when its switch lock is on. Undo switches it off again (destructive).", Risk: sdk.RiskWrite, DryRun: true, Reversible: true},
			{Name: "plug_off", Title: "Switch the socket off", Description: "Switches an Energy Socket off, cutting power to what's plugged in; the preview shows what it draws now. Refused for a critical socket or when its switch lock is on. Undo switches it back on.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return errors.New("the device's address is like http://192.168.1.50 or http://energysocket-1a2b3c.local")
	}
	if !lanHost(u.Hostname()) {
		return errors.New("the device is on your network: use its local IP address or its .local name")
	}
	v2 := c.Token != ""
	if v2 && !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the token in the vault and enter its secret:// reference")
	}
	switch {
	case v2 && u.Scheme != "https":
		return errors.New("API v2 (with a token) is https: use https://")
	case !v2 && u.Scheme != "http":
		return errors.New("API v1 is plain http: use http://, or add a token for API v2 over https")
	case !v2 && (c.Fingerprint != "" || c.InsecureSkipVerify):
		return errors.New("the certificate settings need API v2 (https)")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if v2 {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	} else if c.Fingerprint != "" {
		if _, err := tlspin.Normalize(c.Fingerprint); err != nil {
			return err
		}
	}
	ref := c.Token
	api := rest.New(u.Scheme+"://"+u.Host, func(ctx context.Context, r *http.Request) error {
		if !v2 {
			return nil
		}
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		r.Header.Set("X-Api-Version", "2")
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, v2: v2, critical: c.Critical})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("the device refused the token")
	case rest.IsStatus(err, http.StatusForbidden) && !c.v2:
		return errors.New("the device's local API is off: turn it on in the HomeWizard Energy app (Settings, Meters, the device, Local API)")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the device refused the token")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("the device doesn't offer this (is it a HomeWizard Energy device, and is the API version right?)")
	}
	return err
}

// do calls one path; paths are constants from this file.
func (c *conn) do(ctx context.Context, method, path string, body, out any) error {
	_, err := c.api.Do(ctx, method, path, nil, body, out)
	return c.friendly(err)
}

type info struct {
	ProductType string `json:"product_type"`
	ProductName string `json:"product_name"`
	Serial      string `json:"serial"`
	Firmware    string `json:"firmware_version"`
	APIVersion  string `json:"api_version"`
}

func (c *conn) info(ctx context.Context) (info, error) {
	var i info
	if err := c.do(ctx, http.MethodGet, "/api", nil, &i); err != nil {
		return i, err
	}
	if i.ProductType == "" {
		return i, errors.New("no HomeWizard Energy API at this address")
	}
	return i, nil
}

func (i info) label() string {
	n := i.ProductName
	if n == "" {
		n = i.ProductType
	}
	if i.Serial != "" {
		n += " " + i.Serial
	}
	return n
}

// fields maps the measurement keys of API v1 and v2 to Conduit's names;
// anything else the device sends (meter ids, Wi-Fi name) is left out.
var fields = map[string]string{
	// v1
	"active_power_w": "powerW", "active_power_l1_w": "powerL1W", "active_power_l2_w": "powerL2W", "active_power_l3_w": "powerL3W",
	"active_voltage_v": "voltageV", "active_voltage_l1_v": "voltageL1V", "active_voltage_l2_v": "voltageL2V", "active_voltage_l3_v": "voltageL3V",
	"active_current_a": "currentA", "active_current_l1_a": "currentL1A", "active_current_l2_a": "currentL2A", "active_current_l3_a": "currentL3A",
	"active_frequency_hz": "frequencyHz", "active_reactive_power_var": "reactivePowerVar", "active_apparent_power_va": "apparentPowerVA", "active_power_factor": "powerFactor",
	"total_power_import_kwh": "importKWh", "total_power_import_t1_kwh": "importT1KWh", "total_power_import_t2_kwh": "importT2KWh", "total_power_import_t3_kwh": "importT3KWh", "total_power_import_t4_kwh": "importT4KWh",
	"total_power_export_kwh": "exportKWh", "total_power_export_t1_kwh": "exportT1KWh", "total_power_export_t2_kwh": "exportT2KWh", "total_power_export_t3_kwh": "exportT3KWh", "total_power_export_t4_kwh": "exportT4KWh",
	"active_tariff": "tariff", "total_gas_m3": "gasM3", "active_liter_lpm": "waterLpm", "total_liter_m3": "waterM3",
	"active_power_average_w": "averagePower15mW", "montly_power_peak_w": "monthlyPeakW", "monthly_power_peak_w": "monthlyPeakW",
	"any_power_fail_count": "powerFailures", "long_power_fail_count": "longPowerFailures", "wifi_strength": "wifiStrength",
	// v2
	"power_w": "powerW", "power_l1_w": "powerL1W", "power_l2_w": "powerL2W", "power_l3_w": "powerL3W",
	"voltage_v": "voltageV", "voltage_l1_v": "voltageL1V", "voltage_l2_v": "voltageL2V", "voltage_l3_v": "voltageL3V",
	"current_a": "currentA", "current_l1_a": "currentL1A", "current_l2_a": "currentL2A", "current_l3_a": "currentL3A",
	"frequency_hz": "frequencyHz", "reactive_power_var": "reactivePowerVar", "apparent_power_va": "apparentPowerVA", "power_factor": "powerFactor",
	"energy_import_kwh": "importKWh", "energy_import_t1_kwh": "importT1KWh", "energy_import_t2_kwh": "importT2KWh", "energy_import_t3_kwh": "importT3KWh", "energy_import_t4_kwh": "importT4KWh",
	"energy_export_kwh": "exportKWh", "energy_export_t1_kwh": "exportT1KWh", "energy_export_t2_kwh": "exportT2KWh", "energy_export_t3_kwh": "exportT3KWh", "energy_export_t4_kwh": "exportT4KWh",
	"tariff": "tariff", "average_power_15m_w": "averagePower15mW",
}

const maxExternal = 10

func (c *conn) measurements(ctx context.Context) (map[string]any, error) {
	path := "/api/v1/data"
	if c.v2 {
		path = "/api/measurement"
	}
	var raw map[string]json.RawMessage
	if err := c.do(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return nil, err
	}
	out := map[string]any{}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name, ok := fields[k]
		if !ok {
			continue
		}
		var v float64
		if json.Unmarshal(raw[k], &v) != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		out[name] = math.Round(v*1000) / 1000
	}
	// Gas, water and heat meters on a P1 meter; their ids are left out.
	var ext []struct {
		Type  string   `json:"type"`
		Value *float64 `json:"value"`
		Unit  string   `json:"unit"`
		Time  any      `json:"timestamp"`
	}
	if json.Unmarshal(raw["external"], &ext) == nil && len(ext) > 0 {
		list := []map[string]any{}
		for i, e := range ext {
			if i >= maxExternal || e.Value == nil {
				continue
			}
			row := map[string]any{"type": clip(e.Type, 40), "value": *e.Value, "unit": clip(e.Unit, 16)}
			switch t := e.Time.(type) {
			case float64:
				row["timestamp"] = t
			case string:
				row["timestamp"] = clip(t, 40)
			}
			list = append(list, row)
		}
		out["external"] = list
	}
	return out, nil
}

type state struct {
	PowerOn    *bool `json:"power_on"`
	SwitchLock bool  `json:"switch_lock"`
	Brightness *int  `json:"brightness"`
}

// socket checks the device is an Energy Socket on API v1 and reads its state.
func (c *conn) socket(ctx context.Context) (info, state, error) {
	var st state
	if c.v2 {
		return info{}, st, errors.New("switching a socket works over API v1: remove the token and use the http:// address")
	}
	i, err := c.info(ctx)
	if err != nil {
		return i, st, err
	}
	if i.ProductType != socketType {
		return i, st, fmt.Errorf("this is a %s, not an Energy Socket: it has no switch", i.label())
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/state", nil, &st); err != nil {
		return i, st, err
	}
	if st.PowerOn == nil {
		return i, st, errors.New("unexpected answer from the socket")
	}
	return i, st, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xc0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}

func onOff(b bool) string { return map[bool]string{true: "on", false: "off"}[b] }

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
	i, err := c.info(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	// The device info may answer without a token: read a measurement too.
	ms, err := c.measurements(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := i.label() + " · firmware " + i.Firmware
	if w, ok := ms["powerW"].(float64); ok {
		msg += fmt.Sprintf(" · %g W", w)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct{}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "device":
		i, err := c.info(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"product": i.ProductName, "type": i.ProductType, "serial": i.Serial, "firmware": i.Firmware, "apiVersion": i.APIVersion, "localApi": map[bool]string{false: "v1", true: "v2"}[c.v2]}
		if i.ProductType == socketType {
			out["critical"] = c.critical
		}
		return sdk.JSON(out)

	case "measurements":
		ms, err := c.measurements(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(ms)

	case "plug":
		_, st, err := c.socket(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"on": *st.PowerOn, "switchLock": st.SwitchLock, "critical": c.critical}
		if st.Brightness != nil {
			out["brightness"] = *st.Brightness
		}
		return sdk.JSON(out)

	case "plug_on", "plug_off":
		want := call.Action == "plug_on"
		if !want && c.critical {
			return sdk.Result{}, errors.New("this socket is marked critical: Conduit doesn't switch it off (switch it off at the socket or in the HomeWizard app, or clear critical in the settings)")
		}
		i, st, err := c.socket(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		name := "Energy Socket " + i.Serial
		if st.SwitchLock {
			return sdk.Result{}, fmt.Errorf("%s has its switch lock on, so it stays %s (turn the lock off in the HomeWizard app)", name, onOff(*st.PowerOn))
		}
		cur := *st.PowerOn
		if call.DryRun {
			sum := "Switch " + onOff(want) + " " + name
			if cur == want {
				sum = name + " is already " + onOff(want) + "; nothing would change"
			} else if !want {
				sum += ", cutting power to what's plugged in"
				if ms, err := c.measurements(ctx); err == nil {
					if w, ok := ms["powerW"].(float64); ok && w > 0 {
						sum += fmt.Sprintf(" (it draws %g W now)", math.Round(w*10)/10)
					}
				}
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: name, Op: "update",
				Before: mustJSON(map[string]bool{"on": cur}), After: mustJSON(map[string]bool{"on": want})}}}}, nil
		}
		if cur == want {
			return sdk.JSON(map[string]any{"socket": i.Serial, "on": want, "changed": false, "note": "nothing to change"})
		}
		var after state
		if err := c.do(ctx, http.MethodPut, "/api/v1/state", map[string]bool{"power_on": want}, &after); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"socket": i.Serial, "on": want, "changed": true}
		if after.PowerOn == nil {
			// The answer didn't say: read the state back.
			var now state
			if err := c.do(ctx, http.MethodGet, "/api/v1/state", nil, &now); err == nil && now.PowerOn != nil {
				after = now
			} else {
				out["note"] = "the socket accepted the switch but its state couldn't be read back; check it with plug"
			}
		}
		if after.PowerOn != nil && *after.PowerOn != want {
			return sdk.Result{}, fmt.Errorf("%s stayed %s", name, onOff(*after.PowerOn))
		}
		res, err := sdk.JSON(out)
		// Undo puts back what it was. Switching a critical socket back off
		// isn't something Conduit does, so that has no undo.
		if want && !c.critical {
			res.Undo = sdk.UndoWith("plug_off", map[string]any{}, "Switch "+name+" back off")
		} else if !want {
			res.Undo = sdk.UndoWith("plug_on", map[string]any{}, "Switch "+name+" back on")
		}
		return res, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
