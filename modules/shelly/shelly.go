// Package shelly works with Shelly Gen2 and Gen3 devices (Plus, Pro, Mini,
// Gen3) through their local RPC API over HTTP, with digest authentication
// when the device has a password: device info, switches with power
// metering, covers (blinds and shutters), the firmware update check, and a
// reboot.
package shelly

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // digest auth's MD5 variant, when the device asks for it
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one device.
type Config struct {
	URL      string `json:"url"`      // http://shelly-plug.local
	Password string `json:"password"` // secret://; the user is always admin
	// CriticalSwitches are switch ids whose output powers something that
	// mustn't go off by accident (a server, a fridge, a pump): turning
	// them off is only possible with switch_off_critical.
	CriticalSwitches []int `json:"criticalSwitches"`
	// GarageCovers are cover ids that drive a garage door or gate rather
	// than blinds; Conduit won't move them.
	GarageCovers       []int  `json:"garageCovers"`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	host     sdk.Host
	base     string // scheme://host
	http     *http.Client
	pass     string
	critical map[int]bool
	garage   map[int]bool
	id       atomic.Int64
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
}

// New returns the Shelly module.
func New() *Module { return &Module{} }

const maxID = 99

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	id := func(what string) string {
		return `"id":{"type":"integer","minimum":0,"maximum":99,"description":"The ` + what + ` id (0 for the first; see ` + what + `es)"}`
	}
	return sdk.Manifest{
		ID: "shelly", Name: "Shelly", Version: "0.1.0", Category: "Smart home", Icon: "plug",
		Description: "Shelly Gen2/Gen3 relays, plugs and shutters over the local RPC API: switches, power metering, covers, firmware check and reboot.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The device, e.g. http://shelly-plug.local or http://192.168.1.40"},
			"password":{"type":"string","x-secret":true,"description":"The device password, when authentication is on (the user is always admin)"},
			"criticalSwitches":{"type":"array","items":{"type":"integer","minimum":0,"maximum":99},"description":"Switch ids that power something that mustn't go off by accident; turning them off needs switch_off_critical (destructive)"},
			"garageCovers":{"type":"array","items":{"type":"integer","minimum":0,"maximum":99},"description":"Cover ids that drive a garage door or gate; Conduit won't move them"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the device's certificate, for https"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "device", Title: "Device", Description: "Model, name, firmware, uptime, Wi-Fi signal, whether a restart is pending and the updates the device knows of.", Risk: sdk.RiskRead},
			{Name: "switches", Title: "Switches", Description: "Each switch with its name, on/off, power, voltage, current, energy and temperature, and whether it's critical.", Risk: sdk.RiskRead},
			{Name: "set_switch", Title: "Turn a switch on or off", Description: "Turns a switch on or off. Turning off a critical switch is refused (use switch_off_critical). Undo puts it back.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["id","on"],"properties":{` + id("switch") + `,"on":{"type":"boolean"}}}`)},
			{Name: "switch_off_critical", Title: "Turn off a critical switch", Description: "Turns off a switch listed in criticalSwitches, cutting power to what it feeds. Undo turns it back on.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id("switch") + `}}`)},
			{Name: "power", Title: "Power", Description: "What each metering channel (switches, PM and EM meters) draws now and has used, and the total.", Risk: sdk.RiskRead},
			{Name: "covers", Title: "Covers", Description: "Each cover (blinds, shutters) with its state, position and power; garage covers are marked.", Risk: sdk.RiskRead},
			{Name: "cover", Title: "Move a cover", Description: "Opens, closes, stops or moves a cover to a position (0 closed – 100 open). Covers listed in garageCovers are refused. Undo moves it back.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["id","action"],"properties":{` + id("cover") + `,"action":{"type":"string","enum":["open","close","stop","position"]},"position":{"type":"integer","minimum":0,"maximum":100}}}`)},
			{Name: "check_update", Title: "Check for firmware", Description: "Asks the device whether a stable or beta firmware is available. Nothing is installed.", Risk: sdk.RiskRead},
			{Name: "reboot", Title: "Reboot", Description: "Restarts the device: its outputs may switch while it boots.", Risk: sdk.RiskDestructive, DryRun: true},
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
		return errors.New("the device's address is like http://shelly-plug.local or http://192.168.1.40")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if u.Scheme == "http" && (c.Fingerprint != "" || c.InsecureSkipVerify) {
		return errors.New("the certificate settings need an https address")
	}
	ids := func(list []int, what string) (map[int]bool, error) {
		out := map[int]bool{}
		for _, n := range list {
			if n < 0 || n > maxID {
				return nil, fmt.Errorf("%s ids are between 0 and %d", what, maxID)
			}
			out[n] = true
		}
		return out, nil
	}
	crit, err := ids(c.CriticalSwitches, "critical switch")
	if err != nil {
		return err
	}
	garage, err := ids(c.GarageCovers, "garage cover")
	if err != nil {
		return err
	}
	tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
	if err != nil {
		return err
	}
	tr := sdk.Transport(h)
	tr.TLSClientConfig = tc
	m.set.Put(id, &conn{host: h, base: u.Scheme + "://" + u.Host, pass: c.Password, critical: crit, garage: garage,
		http: rest.SameHostOnly(&http.Client{Timeout: 10 * time.Second, Transport: tr})})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// challenge is a parsed WWW-Authenticate: Digest header.
type challenge struct{ realm, nonce, qop, algorithm, opaque string }

var paramRe = regexp.MustCompile(`(\w+)=("([^"]*)"|[^,\s]*)`)

func parseChallenge(h string) (challenge, bool) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(h), " ")
	if !ok || !strings.EqualFold(scheme, "Digest") {
		return challenge{}, false
	}
	var c challenge
	for _, m := range paramRe.FindAllStringSubmatch(rest, -1) {
		v := m[2]
		if strings.HasPrefix(v, `"`) {
			v = m[3]
		}
		switch strings.ToLower(m[1]) {
		case "realm":
			c.realm = v
		case "nonce":
			c.nonce = v
		case "qop":
			c.qop = v
		case "algorithm":
			c.algorithm = v
		case "opaque":
			c.opaque = v
		}
	}
	return c, c.nonce != ""
}

// digest answers a challenge for POST /rpc (RFC 7616, qop=auth).
func (c challenge) answer(user, pass, method, uri string) (string, error) {
	var h func() hash.Hash
	switch strings.ToUpper(c.algorithm) {
	case "SHA-256":
		h = sha256.New
	case "", "MD5":
		h = md5.New
	default:
		return "", fmt.Errorf("the device asks for digest algorithm %q, which Conduit doesn't speak", c.algorithm)
	}
	if c.qop != "" && !strings.Contains(c.qop, "auth") {
		return "", errors.New("the device asks for a digest variant Conduit doesn't speak")
	}
	sum := func(s string) string { x := h(); io.WriteString(x, s); return hex.EncodeToString(x.Sum(nil)) }
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	cnonce := hex.EncodeToString(b)
	ha1, ha2 := sum(user+":"+c.realm+":"+pass), sum(method+":"+uri)
	alg := c.algorithm
	if alg == "" {
		alg = "MD5"
	}
	var resp string
	if c.qop == "" {
		resp = sum(ha1 + ":" + c.nonce + ":" + ha2)
		return fmt.Sprintf(`Digest username=%q, realm=%q, nonce=%q, uri=%q, algorithm=%s, response=%q`, user, c.realm, c.nonce, uri, alg, resp), nil
	}
	resp = sum(ha1 + ":" + c.nonce + ":00000001:" + cnonce + ":auth:" + ha2)
	s := fmt.Sprintf(`Digest username=%q, realm=%q, nonce=%q, uri=%q, algorithm=%s, response=%q, qop=auth, nc=00000001, cnonce=%q`, user, c.realm, c.nonce, uri, alg, resp, cnonce)
	if c.opaque != "" {
		s += fmt.Sprintf(`, opaque=%q`, c.opaque)
	}
	return s, nil
}

var errAuth = errors.New("the device refused the password (the user is admin)")

// rpc calls one method; method is always a constant from this file.
func (c *conn) rpc(ctx context.Context, method string, params, out any) error {
	frame := map[string]any{"id": c.id.Add(1), "src": "conduit", "method": method}
	if params != nil {
		frame["params"] = params
	}
	body, _ := json.Marshal(frame)
	send := func(auth string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/rpc", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Conduit")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		return c.http.Do(req)
	}
	res, err := send("")
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusUnauthorized {
		io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
		res.Body.Close()
		if c.pass == "" {
			return errors.New("the device has a password: store it in the vault and add it to the settings")
		}
		ch, ok := parseChallenge(res.Header.Get("WWW-Authenticate"))
		if !ok {
			return errors.New("the device asked for a login Conduit doesn't speak")
		}
		pw, err := c.host.Secret(ctx, c.pass)
		if err != nil {
			return err
		}
		auth, err := ch.answer("admin", pw, http.MethodPost, "/rpc")
		if err != nil {
			return err
		}
		if res, err = send(auth); err != nil {
			return err
		}
		if res.StatusCode == http.StatusUnauthorized {
			res.Body.Close()
			return errAuth
		}
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusNotFound {
		return errors.New("no Shelly RPC at this address (Gen1 devices aren't supported)")
	}
	var r struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		if res.StatusCode >= 300 {
			return fmt.Errorf("the device answered %s", res.Status)
		}
		return errors.New("unexpected answer from the device")
	}
	if r.Error != nil {
		if r.Error.Code == 401 {
			return errAuth
		}
		return fmt.Errorf("the device refused %s: %s", method, rest.Redact(r.Error.Message))
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("the device answered %s", res.Status)
	}
	if out != nil {
		if len(r.Result) == 0 || json.Unmarshal(r.Result, out) != nil {
			return fmt.Errorf("unexpected answer from the device to %s", method)
		}
	}
	return nil
}

type deviceInfo struct {
	Name   *string `json:"name"`
	ID     string  `json:"id"`
	MAC    string  `json:"mac"`
	Model  string  `json:"model"`
	Gen    int     `json:"gen"`
	Ver    string  `json:"ver"`
	App    string  `json:"app"`
	AuthEn bool    `json:"auth_en"`
}

type energy struct {
	Total *float64 `json:"total"` // Wh
}

type switchStatus struct {
	ID          int      `json:"id"`
	Output      bool     `json:"output"`
	APower      *float64 `json:"apower"`
	Voltage     *float64 `json:"voltage"`
	Current     *float64 `json:"current"`
	AEnergy     *energy  `json:"aenergy"`
	Temperature *struct {
		C *float64 `json:"tC"`
	} `json:"temperature"`
}

type coverStatus struct {
	ID         int      `json:"id"`
	State      string   `json:"state"`
	CurrentPos *int     `json:"current_pos"`
	PosControl bool     `json:"pos_control"`
	APower     *float64 `json:"apower"`
}

// status is Shelly.GetStatus split by component.
type status struct {
	switches map[int]switchStatus
	covers   map[int]coverStatus
	raw      map[string]json.RawMessage
}

func (c *conn) status(ctx context.Context) (*status, error) {
	var raw map[string]json.RawMessage
	if err := c.rpc(ctx, "Shelly.GetStatus", nil, &raw); err != nil {
		return nil, err
	}
	st := &status{switches: map[int]switchStatus{}, covers: map[int]coverStatus{}, raw: raw}
	for k, v := range raw {
		switch {
		case strings.HasPrefix(k, "switch:"):
			var s switchStatus
			if json.Unmarshal(v, &s) == nil {
				st.switches[s.ID] = s
			}
		case strings.HasPrefix(k, "cover:"):
			var s coverStatus
			if json.Unmarshal(v, &s) == nil {
				st.covers[s.ID] = s
			}
		}
	}
	return st, nil
}

// names reads the components' names from the configuration.
func (c *conn) names(ctx context.Context) map[string]string {
	var raw map[string]json.RawMessage
	out := map[string]string{}
	if c.rpc(ctx, "Shelly.GetConfig", nil, &raw) != nil {
		return out
	}
	for k, v := range raw {
		var n struct {
			Name *string `json:"name"`
		}
		if json.Unmarshal(v, &n) == nil && n.Name != nil && *n.Name != "" {
			out[k] = *n.Name
		}
	}
	return out
}

func r2(p *float64, div float64) any {
	if p == nil {
		return nil
	}
	return math.Round(*p/div*100) / 100
}

func put(e map[string]any, k string, v any) {
	if v != nil {
		e[k] = v
	}
}

func switchOut(s switchStatus, name string, critical bool) map[string]any {
	e := map[string]any{"id": s.ID, "on": s.Output}
	if name != "" {
		e["name"] = name
	}
	if critical {
		e["critical"] = true
	}
	put(e, "powerW", r2(s.APower, 1))
	put(e, "voltage", r2(s.Voltage, 1))
	put(e, "currentA", r2(s.Current, 1))
	if s.AEnergy != nil {
		put(e, "energyKWh", r2(s.AEnergy.Total, 1000))
	}
	if s.Temperature != nil {
		put(e, "temperatureC", r2(s.Temperature.C, 1))
	}
	return e
}

func coverOut(s coverStatus, name string, garage bool) map[string]any {
	e := map[string]any{"id": s.ID, "state": s.State}
	if name != "" {
		e["name"] = name
	}
	if s.CurrentPos != nil {
		e["position"] = *s.CurrentPos
	}
	if garage {
		e["garage"] = true
	}
	put(e, "powerW", r2(s.APower, 1))
	return e
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func label(kind string, id int, names map[string]string) string {
	if n := names[fmt.Sprintf("%s:%d", kind, id)]; n != "" {
		return fmt.Sprintf("%s %d (%s)", kind, id, n)
	}
	return fmt.Sprintf("%s %d", kind, id)
}

func onOff(b bool) string { return map[bool]string{true: "on", false: "off"}[b] }

type input struct {
	ID       *int   `json:"id"`
	On       *bool  `json:"on"`
	Action   string `json:"action"`
	Position *int   `json:"position"`
}

func (p input) id(what string) (int, error) {
	if p.ID == nil {
		return 0, fmt.Errorf("say which %s (its id; see %ses)", what, what)
	}
	if *p.ID < 0 || *p.ID > maxID {
		return 0, fmt.Errorf("the %s id is between 0 and %d", what, maxID)
	}
	return *p.ID, nil
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
	case "device":
		var info deviceInfo
		if err := c.rpc(ctx, "Shelly.GetDeviceInfo", nil, &info); err != nil {
			return sdk.Result{}, err
		}
		st, err := c.status(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"id": info.ID, "model": info.Model, "app": info.App, "generation": info.Gen, "firmware": info.Ver, "mac": info.MAC, "authEnabled": info.AuthEn}
		if info.Name != nil && *info.Name != "" {
			out["name"] = *info.Name
		}
		var sys struct {
			Uptime           *int `json:"uptime"`
			RestartRequired  bool `json:"restart_required"`
			AvailableUpdates map[string]struct {
				Version string `json:"version"`
			} `json:"available_updates"`
		}
		if json.Unmarshal(st.raw["sys"], &sys) == nil {
			if sys.Uptime != nil {
				out["uptimeSeconds"] = *sys.Uptime
			}
			out["restartRequired"] = sys.RestartRequired
			ups := map[string]string{}
			for k, v := range sys.AvailableUpdates {
				ups[k] = v.Version
			}
			out["updates"] = ups
		}
		var wifi struct {
			Status string `json:"status"`
			SSID   string `json:"ssid"`
			RSSI   *int   `json:"rssi"`
		}
		if json.Unmarshal(st.raw["wifi"], &wifi) == nil && wifi.Status != "" {
			w := map[string]any{"status": wifi.Status}
			if wifi.SSID != "" {
				w["ssid"] = wifi.SSID
			}
			if wifi.RSSI != nil {
				w["rssi"] = *wifi.RSSI
			}
			out["wifi"] = w
		}
		return sdk.JSON(out)

	case "switches":
		st, err := c.status(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		names := c.names(ctx)
		out := []map[string]any{}
		for _, id := range sortedKeys(st.switches) {
			out = append(out, switchOut(st.switches[id], names[fmt.Sprintf("switch:%d", id)], c.critical[id]))
		}
		return sdk.JSON(out)

	case "set_switch", "switch_off_critical":
		id, err := p.id("switch")
		if err != nil {
			return sdk.Result{}, err
		}
		want := false
		if call.Action == "set_switch" {
			if p.On == nil {
				return sdk.Result{}, errors.New("say on: true or false")
			}
			want = *p.On
			if !want && c.critical[id] {
				return sdk.Result{}, fmt.Errorf("switch %d is in criticalSwitches: turning it off needs switch_off_critical", id)
			}
		} else if !c.critical[id] {
			return sdk.Result{}, fmt.Errorf("switch %d isn't in criticalSwitches; use set_switch", id)
		}
		st, err := c.status(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		cur, ok := st.switches[id]
		if !ok {
			return sdk.Result{}, fmt.Errorf("the device has no switch %d (see switches)", id)
		}
		names := c.names(ctx)
		name := label("switch", id, names)
		if call.DryRun {
			sum := "Turn " + onOff(want) + " " + name
			if cur.Output == want {
				sum = name + " is already " + onOff(want) + "; nothing would change"
			} else if !want && cur.APower != nil && *cur.APower > 0 {
				sum += fmt.Sprintf(" (it draws %g W now)", math.Round(*cur.APower*10)/10)
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: name, Op: "update",
				Before: mustJSON(map[string]bool{"on": cur.Output}), After: mustJSON(map[string]bool{"on": want})}}}}, nil
		}
		if cur.Output == want {
			return sdk.JSON(map[string]any{"id": id, "on": want, "changed": false})
		}
		var r struct {
			WasOn bool `json:"was_on"`
		}
		if err := c.rpc(ctx, "Switch.Set", map[string]any{"id": id, "on": want}, &r); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"id": id, "on": want, "changed": r.WasOn != want})
		if r.WasOn != want {
			back := "set_switch"
			if !r.WasOn && c.critical[id] {
				back = "switch_off_critical" // turning a critical one back off is destructive
			}
			in := map[string]any{"id": id}
			if back == "set_switch" {
				in["on"] = r.WasOn
			}
			res.Undo = sdk.UndoWith(back, in, "Turn "+name+" back "+onOff(r.WasOn))
		}
		return res, err

	case "power":
		st, err := c.status(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		names := c.names(ctx)
		out := []map[string]any{}
		total := 0.0
		keys := make([]string, 0, len(st.raw))
		for k := range st.raw {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			kind, _, _ := strings.Cut(k, ":")
			var v struct {
				APower      *float64 `json:"apower"`
				ActPower    *float64 `json:"act_power"`
				TotalAct    *float64 `json:"total_act_power"`
				Voltage     *float64 `json:"voltage"`
				Current     *float64 `json:"current"`
				AEnergy     *energy  `json:"aenergy"`
				TotalEnergy *float64 `json:"total_act_energy"`
			}
			if kind != "switch" && kind != "pm1" && kind != "em1" && kind != "em" && kind != "cover" && kind != "emdata" && kind != "em1data" {
				continue
			}
			if json.Unmarshal(st.raw[k], &v) != nil {
				continue
			}
			w := v.APower
			if w == nil {
				w = v.ActPower
			}
			if w == nil {
				w = v.TotalAct
			}
			e := map[string]any{"channel": k}
			if n := names[k]; n != "" {
				e["name"] = n
			}
			put(e, "powerW", r2(w, 1))
			put(e, "voltage", r2(v.Voltage, 1))
			put(e, "currentA", r2(v.Current, 1))
			if v.AEnergy != nil {
				put(e, "energyKWh", r2(v.AEnergy.Total, 1000))
			}
			put(e, "energyKWh", r2(v.TotalEnergy, 1000))
			if len(e) == 1 || (len(e) == 2 && e["name"] != nil) {
				continue // no metering on this channel
			}
			if w != nil && kind != "emdata" && kind != "em1data" {
				total += *w
			}
			out = append(out, e)
		}
		return sdk.JSON(map[string]any{"totalW": math.Round(total*100) / 100, "channels": out})

	case "covers":
		st, err := c.status(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		names := c.names(ctx)
		out := []map[string]any{}
		for _, id := range sortedKeys(st.covers) {
			out = append(out, coverOut(st.covers[id], names[fmt.Sprintf("cover:%d", id)], c.garage[id]))
		}
		return sdk.JSON(out)

	case "cover":
		id, err := p.id("cover")
		if err != nil {
			return sdk.Result{}, err
		}
		if c.garage[id] {
			return sdk.Result{}, fmt.Errorf("cover %d is in garageCovers: Conduit doesn't open or close garage doors and gates", id)
		}
		method, params := "", map[string]any{"id": id}
		switch p.Action {
		case "open":
			method = "Cover.Open"
		case "close":
			method = "Cover.Close"
		case "stop":
			method = "Cover.Stop"
		case "position":
			if p.Position == nil || *p.Position < 0 || *p.Position > 100 {
				return sdk.Result{}, errors.New("position is between 0 (closed) and 100 (open)")
			}
			method, params["pos"] = "Cover.GoToPosition", *p.Position
		default:
			return sdk.Result{}, errors.New("action is open, close, stop or position")
		}
		if p.Action != "position" && p.Position != nil {
			return sdk.Result{}, errors.New("position goes with action: position")
		}
		st, err := c.status(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		cur, ok := st.covers[id]
		if !ok {
			return sdk.Result{}, fmt.Errorf("the device has no cover %d (see covers)", id)
		}
		if p.Action == "position" && !cur.PosControl {
			return sdk.Result{}, fmt.Errorf("cover %d isn't calibrated, so it can't go to a position (calibrate it in the Shelly app)", id)
		}
		names := c.names(ctx)
		name := label("cover", id, names)
		before := coverOut(cur, "", false)
		if call.DryRun {
			after := map[string]any{"action": p.Action}
			if p.Position != nil {
				after["position"] = *p.Position
			}
			verb := map[string]string{"open": "Open", "close": "Close", "stop": "Stop", "position": "Move"}[p.Action]
			sum := verb + " " + name
			if p.Action == "position" {
				sum += fmt.Sprintf(" to %d%%", *p.Position)
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: name, Op: p.Action, Before: mustJSON(before), After: mustJSON(after)}}}}, nil
		}
		if err := c.rpc(ctx, method, params, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"id": id, "action": p.Action, "was": before})
		switch {
		case p.Action == "stop":
		case cur.PosControl && cur.CurrentPos != nil:
			res.Undo = sdk.UndoWith("cover", map[string]any{"id": id, "action": "position", "position": *cur.CurrentPos}, fmt.Sprintf("Move %s back to %d%%", name, *cur.CurrentPos))
		case cur.State == "open" || cur.State == "closed":
			back := map[string]string{"open": "open", "closed": "close"}[cur.State]
			res.Undo = sdk.UndoWith("cover", map[string]any{"id": id, "action": back}, strings.ToUpper(back[:1])+back[1:]+" "+name+" again")
		}
		return res, err

	case "check_update":
		var info deviceInfo
		if err := c.rpc(ctx, "Shelly.GetDeviceInfo", nil, &info); err != nil {
			return sdk.Result{}, err
		}
		var ups map[string]struct {
			Version string `json:"version"`
		}
		if err := c.rpc(ctx, "Shelly.CheckForUpdate", nil, &ups); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"current": info.Ver, "updateAvailable": false}
		for _, ch := range []string{"stable", "beta"} {
			if u, ok := ups[ch]; ok && u.Version != "" {
				out[ch] = u.Version
				if ch == "stable" {
					out["updateAvailable"] = true
				}
			}
		}
		return sdk.JSON(out)

	case "reboot":
		var info deviceInfo
		if err := c.rpc(ctx, "Shelly.GetDeviceInfo", nil, &info); err != nil {
			return sdk.Result{}, err
		}
		name := info.ID
		if info.Name != nil && *info.Name != "" {
			name = *info.Name + " (" + info.ID + ")"
		}
		if call.DryRun {
			sum := "Reboot " + name + "; its outputs may switch while it starts"
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: name, Op: "restart"}}}}, nil
		}
		if err := c.rpc(ctx, "Shelly.Reboot", map[string]any{"delay_ms": 1000}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"device": name, "rebooting": true})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func sortedKeys[V any](m map[int]V) []int {
	ks := make([]int, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Ints(ks)
	return ks
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var info deviceInfo
	if err := c.rpc(ctx, "Shelly.GetDeviceInfo", nil, &info); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	// GetDeviceInfo answers without a login; check the password too.
	st, err := c.status(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := info.Model + " " + info.Ver
	if info.Name != nil && *info.Name != "" {
		msg = *info.Name + " · " + msg
	}
	if n := len(st.switches); n > 0 {
		msg += " · " + strconv.Itoa(n) + " switch(es)"
	}
	if n := len(st.covers); n > 0 {
		msg += " · " + strconv.Itoa(n) + " cover(s)"
	}
	return sdk.Health{Status: "ok", Message: msg}
}
