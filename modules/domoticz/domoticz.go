// Package domoticz works with Domoticz through its JSON API and a user's
// name and password: devices with their status, switching a device on or
// off, and scenes and groups with activating one. Locks, garage doors,
// gates, doors, windows, alarms, security panels, cameras, valves and
// heating (by type, switch type or name), and devices listed in
// criticalDevices, are kept apart behind a destructive action.
package domoticz

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
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Domoticz server.
type Config struct {
	URL      string `json:"url"`      // e.g. http://domoticz.local:8080
	Username string `json:"username"` // a Domoticz user
	Password string `json:"password"` // secret://
	// CriticalDevices are device idx numbers or names that need
	// switch_critical_device, like a plug feeding a server or a gate
	// opener behind a plain switch.
	CriticalDevices    []string `json:"criticalDevices"`
	Fingerprint        string   `json:"fingerprint"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

type conn struct {
	api      *rest.Client
	critical map[string]bool // idx, and lowercased names
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Domoticz module.
func New() *Module { return &Module{} }

const maxDevices = 1000

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	idxRe  = regexp.MustCompile(`^[0-9]{1,9}$`)
	// criticalWord matches types, switch types and names of what opens,
	// unlocks, sounds, watches or heats something: a false match only
	// means the destructive action.
	criticalWord = regexp.MustCompile(`(?i)lock|door|gate|window|alarm|siren|secur|camera|valve|heat|hvac|radiator|boiler|thermostat|setpoint|garage|sprinkler|irrigation|smoke|water ?main|` + germanWord)
	// germanWord is the same in German, the app's other language (Tür,
	// Haustuer, Hoftor, Schloss, Fenster, Heizung …).
	germanWord = `tür|tuer|(^|[^a-zäöü])tor([^a-zäöü]|$|antrieb)|(garten|hof|einfahrt|einfahrts|zufahrt|zufahrts|haus|eingangs|garagen)tor|öffner|oeffner|schloss|riegel|fenster|heiz|sirene|ventil|kamera|rauchmelder|sicherheit|bewässerung|bewaesserung`
	// plainSwitch are the switch types a write may turn on or off.
	plainSwitch = map[string]bool{"On/Off": true, "Dimmer": true}
	// criticalSwitch are the further switch types the destructive action
	// may turn on or off (sensors, selectors and media players aren't
	// switched here).
	criticalSwitch = map[string]bool{"Door Lock": true, "Door Lock Inverted": true, "X10 Siren": true, "Blinds": true, "Blinds Inverted": true,
		"Push On Button": true, "Push Off Button": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	sw := `{"type":"object","required":["idx","switch"],"properties":{
		"idx":{"type":"string","maxLength":9,"description":"The device's idx (from devices)"},
		"switch":{"type":"string","enum":["On","Off"],"description":"On or Off"}}}`
	return sdk.Manifest{
		ID: "domoticz", Name: "Domoticz", Version: "0.1.0", Category: "Smart home", Icon: "home",
		Description: "Domoticz devices with their status, scenes and groups; switch devices on or off, with locks, garage doors, alarms and heating kept apart; activate scenes.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"Domoticz's address, e.g. https://domoticz.local:8443"},
			"username":{"type":"string","description":"A Domoticz user (Setup, More options, Users) with access to the devices"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"criticalDevices":{"type":"array","maxItems":200,"items":{"type":"string","maxLength":200},"description":"Device idx numbers or names that need switch_critical_device, like a plug feeding a server or a gate opener behind a plain switch. Door locks, sirens, security panels, thermostats and heating, and devices whose name or type contains lock, door, gate, window, alarm, siren, security, camera, valve, heat or thermostat, are critical without being listed."},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "devices", Title: "Devices", Description: "Each device in use: idx, name, type, subtype, switch type, status, data, last update, and whether it's protected or critical.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"filter":{"type":"string","enum":["all","light","weather","temp","utility"],"description":"Only switches (light), weather, temperature or utility devices"},"search":{"type":"string","maxLength":100}}}`)},
			{Name: "device", Title: "Device", Description: "One device: status, data, type, switch type, and why it's critical.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["idx"],"properties":{"idx":{"type":"string","maxLength":9,"description":"The device's idx"}}}`)},
			{Name: "switch_device", Title: "Switch a device", Description: "Turns an on/off switch or dimmer On or Off. Critical devices (locks, doors, gates, windows, alarms, cameras, valves, heating, or in criticalDevices) are refused: use switch_critical_device. Undo switches it back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(sw)},
			{Name: "switch_critical_device", Title: "Switch a critical device", Description: "Turns a critical device On or Off: this can unlock a lock, open a garage door or gate, sound or silence a siren, turn a camera off, open a valve or change the heating. The preview says which. Undo switches it back when its status was On or Off.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(sw)},
			{Name: "scenes", Title: "Scenes and groups", Description: "Each scene and group: idx, name, type, status and last update.", Risk: sdk.RiskRead},
			{Name: "activate_scene", Title: "Activate a scene", Description: "Activates a scene or switches a group on: it switches every device in it, which can include locks, doors, alarms and heating.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["idx"],"properties":{"idx":{"type":"string","maxLength":9,"description":"The scene's idx (from scenes)"}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "device", Title: "Devices", ListAction: "devices", ViewHint: "table"}},
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
		return errors.New("the address is like https://domoticz.local:8443")
	}
	user := strings.TrimSpace(c.Username)
	switch {
	case user == "" || c.Password == "":
		return errors.New("enter a Domoticz username and password")
	case !strings.HasPrefix(c.Password, "secret://"):
		return errors.New("store the password in the vault and enter its secret:// reference")
	case len(user) > 128 || strings.ContainsAny(user, "\x00\r\n:"):
		return errors.New("the username is a Domoticz user")
	}
	if u.Scheme == "http" && (c.Fingerprint != "" || c.InsecureSkipVerify) {
		return errors.New("the certificate settings need an https address")
	}
	if len(c.CriticalDevices) > 200 {
		return errors.New("list at most 200 critical devices")
	}
	crit := map[string]bool{}
	for _, a := range c.CriticalDevices {
		a = strings.TrimSpace(a)
		if a == "" || len(a) > 200 || strings.ContainsAny(a, "\x00\r\n") {
			return errors.New("a critical device is its idx or its name (up to 200 characters)")
		}
		crit[a] = true
		crit[strings.ToLower(a)] = true
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
	ref := c.Password
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/json.htm") + "/json.htm"
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, pw)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, critical: crit})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// clip redacts server text, then shortens it.
func clip(s string, n int) string {
	s = rest.Redact(strings.TrimSpace(s))
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

// call sends one JSON API command; Domoticz answers 200 with
// "status":"ERR" when it refuses one.
func (c *conn) call(ctx context.Context, q url.Values, out any) error {
	var env struct {
		Status  string          `json:"status"`
		Message string          `json:"message"`
		Result  json.RawMessage `json:"result"`
	}
	_, err := c.api.Do(ctx, http.MethodGet, "", q, nil, &env)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Domoticz refused the username or password (over http, Basic authentication must be allowed in its settings)")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the Domoticz user isn't allowed to do this")
	case err != nil:
		return err
	case env.Status != "OK":
		msg := clip(env.Message, 200)
		if msg == "" {
			msg = "no reason given"
		}
		return fmt.Errorf("Domoticz refused: %s", msg)
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return errors.New("unexpected answer from Domoticz")
		}
	}
	return nil
}

type device struct {
	Idx        string `json:"idx"`
	Name       string `json:"Name"`
	Type       string `json:"Type"`
	SubType    string `json:"SubType"`
	SwitchType string `json:"SwitchType"`
	Status     string `json:"Status"`
	Data       string `json:"Data"`
	Protected  bool   `json:"Protected"`
	LastUpdate string `json:"LastUpdate"`
	Hardware   string `json:"HardwareName"`
}

func (d device) title() string { return clip(d.Name, 100) + " (" + d.Idx + ")" }

// why says why a device is critical, or "".
func (c *conn) why(d device) string {
	switch {
	case c.critical[d.Idx] || c.critical[strings.ToLower(strings.TrimSpace(d.Name))]:
		return "listed in criticalDevices"
	case criticalWord.MatchString(d.SwitchType):
		return "a " + clip(strings.ToLower(d.SwitchType), 40) + " switch"
	case criticalWord.MatchString(d.Type) || criticalWord.MatchString(d.SubType):
		return "a " + clip(strings.ToLower(strings.TrimSpace(d.Type+" "+d.SubType)), 60) + " device"
	case criticalWord.MatchString(d.Name):
		return "its name says it opens, unlocks, sounds, watches or heats something"
	}
	return ""
}

func (c *conn) row(d device) map[string]any {
	row := map[string]any{"idx": d.Idx, "name": clip(d.Name, 100), "type": clip(d.Type, 60), "status": clip(d.Status, 100)}
	if d.SubType != "" {
		row["subtype"] = clip(d.SubType, 60)
	}
	if d.SwitchType != "" {
		row["switchType"] = clip(d.SwitchType, 60)
	}
	if d.Data != "" && d.Data != d.Status {
		row["data"] = clip(d.Data, 100)
	}
	if d.LastUpdate != "" {
		row["lastUpdate"] = clip(d.LastUpdate, 30)
	}
	if d.Hardware != "" {
		row["hardware"] = clip(d.Hardware, 60)
	}
	if d.Protected {
		row["protected"] = true
	}
	if c.why(d) != "" {
		row["critical"] = true
	}
	return row
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Version string `json:"version"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "", url.Values{"type": {"command"}, "param": {"getversion"}}, nil, &v); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Domoticz JSON API at this address"}
		}
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "Domoticz refused the username or password (over http, Basic authentication must be allowed in its settings)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	// getversion answers without signing in; the scenes need the user.
	if err := c.call(ctx, url.Values{"type": {"command"}, "param": {"getscenes"}}, nil); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "Domoticz is up"
	if v.Version != "" {
		msg = "Domoticz " + clip(v.Version, 30) + " is up"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func (c *conn) device(ctx context.Context, idx string) (device, error) {
	idx = strings.TrimSpace(idx)
	if !idxRe.MatchString(idx) {
		return device{}, errors.New("a device is its idx, a number (from devices)")
	}
	var list []device
	if err := c.call(ctx, url.Values{"type": {"command"}, "param": {"getdevices"}, "rid": {idx}}, &list); err != nil {
		return device{}, err
	}
	for _, d := range list {
		if d.Idx == idx {
			return d, nil
		}
	}
	// Domoticz answers an unknown idx with no result, or (sometimes) with
	// another device: the idx goes into the switch and the undo.
	return device{}, fmt.Errorf("there's no device %s", idx)
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Filter string `json:"filter"`
		Search string `json:"search"`
		Idx    string `json:"idx"`
		Switch string `json:"switch"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "devices":
		f := strings.TrimSpace(p.Filter)
		if f == "" {
			f = "all"
		}
		switch f {
		case "all", "light", "weather", "temp", "utility":
		default:
			return sdk.Result{}, errors.New("filter is all, light, weather, temp or utility")
		}
		var list []device
		if err := c.call(ctx, url.Values{"type": {"command"}, "param": {"getdevices"}, "filter": {f}, "used": {"true"}, "order": {"Name"}}, &list); err != nil {
			return sdk.Result{}, err
		}
		q := strings.ToLower(strings.TrimSpace(p.Search))
		out := []map[string]any{}
		for _, d := range list {
			if len(out) >= maxDevices {
				break
			}
			if q != "" && !strings.Contains(strings.ToLower(d.Name+" "+d.Type+" "+d.SwitchType), q) {
				continue
			}
			out = append(out, c.row(d))
		}
		return sdk.JSON(out)
	case "device":
		d, err := c.device(ctx, p.Idx)
		if err != nil {
			return sdk.Result{}, err
		}
		row := c.row(d)
		if why := c.why(d); why != "" {
			row["criticalBecause"] = why
		}
		return sdk.JSON(row)
	case "switch_device", "switch_critical_device":
		idx := strings.TrimSpace(p.Idx)
		if !idxRe.MatchString(idx) {
			return sdk.Result{}, errors.New("a device is its idx, a number (from devices)")
		}
		var cmd string
		switch strings.ToLower(strings.TrimSpace(p.Switch)) {
		case "on":
			cmd = "On"
		case "off":
			cmd = "Off"
		default:
			return sdk.Result{}, errors.New("switch is On or Off")
		}
		return c.switchDevice(ctx, call, idx, cmd)
	case "scenes":
		list, err := c.scenes(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range list {
			if len(out) >= maxDevices {
				break
			}
			out = append(out, s.row())
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
		return sdk.JSON(out)
	case "activate_scene":
		idx := strings.TrimSpace(p.Idx)
		if !idxRe.MatchString(idx) {
			return sdk.Result{}, errors.New("a scene is its idx, a number (from scenes)")
		}
		list, err := c.scenes(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var s *scene
		for i := range list {
			if list[i].Idx == idx {
				s = &list[i]
			}
		}
		if s == nil {
			return sdk.Result{}, fmt.Errorf("there's no scene %s", idx)
		}
		if s.Protected {
			return sdk.Result{}, fmt.Errorf("%s is protected by a passcode in Domoticz; activate it there", s.title())
		}
		kind := "scene"
		if strings.EqualFold(s.Type, "Group") {
			kind = "group"
		}
		if call.DryRun {
			b, _ := json.Marshal(s.row())
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Activate %s %s (now %s); it switches every device in it, which can include locks, doors, alarms and heating", kind, s.title(), clip(s.Status, 30)),
				Changes: []sdk.Change{{Target: kind + " " + s.title(), Op: "activate", Before: b}}}}, nil
		}
		if err := c.call(ctx, url.Values{"type": {"command"}, "param": {"switchscene"}, "idx": {idx}, "switchcmd": {"On"}}, nil); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"idx": idx, "name": clip(s.Name, 100), "activated": true}
		if after, err := c.scenes(ctx); err == nil {
			for _, a := range after {
				if a.Idx == idx {
					out["status"] = clip(a.Status, 30)
				}
			}
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type scene struct {
	Idx        string `json:"idx"`
	Name       string `json:"Name"`
	Type       string `json:"Type"`
	Status     string `json:"Status"`
	Protected  bool   `json:"Protected"`
	LastUpdate string `json:"LastUpdate"`
}

func (s scene) title() string { return clip(s.Name, 100) + " (" + s.Idx + ")" }

func (s scene) row() map[string]any {
	row := map[string]any{"idx": s.Idx, "name": clip(s.Name, 100), "type": clip(s.Type, 20), "status": clip(s.Status, 30)}
	if s.LastUpdate != "" {
		row["lastUpdate"] = clip(s.LastUpdate, 30)
	}
	if s.Protected {
		row["protected"] = true
	}
	return row
}

func (c *conn) scenes(ctx context.Context) ([]scene, error) {
	var list []scene
	err := c.call(ctx, url.Values{"type": {"command"}, "param": {"getscenes"}}, &list)
	return list, err
}

// effect says in words what switching a critical device can do.
func effect(d device, cmd string) string {
	switch {
	case strings.HasPrefix(d.SwitchType, "Door Lock"):
		return "locks or unlocks it"
	case d.SwitchType == "X10 Siren":
		if cmd == "On" {
			return "sounds the siren"
		}
		return "silences the siren"
	case strings.HasPrefix(d.SwitchType, "Blinds"):
		return "opens or closes it"
	case cmd == "On":
		return "turns it on (a gate or door opener fires, a valve opens, heating starts)"
	}
	return "turns it off (a camera, alarm or heating stops, a lock may open)"
}

func (c *conn) switchDevice(ctx context.Context, call sdk.Call, idx, cmd string) (sdk.Result, error) {
	d, err := c.device(ctx, idx)
	if err != nil {
		return sdk.Result{}, err
	}
	why := c.why(d)
	critical := call.Action == "switch_critical_device"
	if why != "" && !critical {
		return sdk.Result{}, fmt.Errorf("%s is critical (%s): use switch_critical_device", d.title(), why)
	}
	if strings.TrimSpace(d.SwitchType) == "" {
		return sdk.Result{}, fmt.Errorf("Domoticz doesn't say what kind of switch %s is, so it isn't switched", d.title())
	}
	if why == "" && critical {
		return sdk.Result{}, fmt.Errorf("%s isn't critical; use switch_device", d.title())
	}
	if !plainSwitch[d.SwitchType] && !(critical && criticalSwitch[d.SwitchType]) {
		return sdk.Result{}, fmt.Errorf("%s is a %s, which isn't switched here", d.title(), clip(d.SwitchType, 40))
	}
	if d.Protected {
		return sdk.Result{}, fmt.Errorf("%s is protected by a passcode in Domoticz; switch it there", d.title())
	}
	prev := onOff(d)
	if prev == cmd {
		return sdk.JSON(map[string]any{"idx": idx, "name": clip(d.Name, 100), "status": clip(d.Status, 100), "note": "nothing to change"})
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]string{"status": clip(d.Status, 100)})
		a, _ := json.Marshal(map[string]string{"switch": cmd})
		sum := fmt.Sprintf("Switch %s %s (a %s, now %s)", d.title(), cmd, clip(d.SwitchType, 40), clip(d.Status, 60))
		if critical {
			sum += "; this " + effect(d, cmd) + " (" + why + ")"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "device " + d.title(), Op: "switch " + cmd, Before: b, After: a}}}}, nil
	}
	if err := c.call(ctx, url.Values{"type": {"command"}, "param": {"switchlight"}, "idx": {idx}, "switchcmd": {cmd}}, nil); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"idx": idx, "name": clip(d.Name, 100), "switch": cmd, "was": clip(d.Status, 100)}
	if after, err := c.device(ctx, idx); err == nil {
		out["status"] = clip(after.Status, 100)
	}
	r, err := sdk.JSON(out)
	// Only an On or Off status is known to switch back the same way (a
	// lock's or blind's status words depend on its inversion).
	if prev != "" {
		r.Undo = sdk.UndoWith(call.Action, map[string]any{"idx": idx, "switch": prev}, fmt.Sprintf("Switch %s %s", d.title(), prev))
	}
	return r, err
}

// onOff reads an on/off switch's or dimmer's status as On or Off, or "".
func onOff(d device) string {
	if !plainSwitch[d.SwitchType] {
		return ""
	}
	switch s := strings.TrimSpace(d.Status); {
	case s == "Off":
		return "Off"
	case s == "On" || strings.HasPrefix(s, "Set Level"):
		return "On"
	}
	return ""
}
