// Package victron reads Victron Energy installations through the VRM API
// and an access token: the installations the token's user can see, a
// summary of an installation's latest diagnostics (battery state of charge,
// PV power, grid and consumption), and its alarms. It never returns the
// user's name or e-mail or an installation's location, and changes nothing.
package victron

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one VRM account.
type Config struct {
	Token string `json:"token"` // secret:// VRM access token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://vrmapi.victronenergy.com/v2 (tests).
	Base string
}

// New returns the Victron module.
func New() *Module { return &Module{} }

const (
	defaultBase   = "https://vrmapi.victronenergy.com/v2"
	maxSite       = 999999999
	maxSites      = 100
	maxRecords    = 200
	maxAlarms     = 200
	diagnosticsN  = "1000"
	maxTextLength = 120
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	site := `"site":{"type":"integer","minimum":1,"description":"Installation id (idSite, from installations); may be left out when the account has one"}`
	return sdk.Manifest{
		ID: "victron", Name: "Victron VRM", Version: "0.1.0", Category: "Smart home", Icon: "battery",
		Description: "Victron Energy VRM: installations, battery state of charge, PV power, grid and consumption now, and alarms.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A VRM access token (VRM, Preferences, Integrations, Access tokens)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "installations", Title: "Installations", Description: "The installations the token's user can see: id, name, time zone, whether an alarm is active, mains and generator, and when it last reported. Never its location.", Risk: sdk.RiskRead},
			{Name: "summary", Title: "Latest values", Description: "An installation's latest values: battery state of charge, voltage, current, power and state, PV power, grid and consumption power, and when they were logged. all: true adds every diagnostic value (up to 200).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + site + `,"all":{"type":"boolean","default":false}}}`)},
			{Name: "alarms", Title: "Alarms", Description: "Whether an alarm is active now, and the installation's alarm rules: what they watch, low and high thresholds, delay and whether they're on. The people notified are left out.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + site + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-Authorization", "Token "+strings.TrimSpace(t))
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
		return errors.New("VRM refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token's user has no access to this installation")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("VRM doesn't know this installation")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("VRM's rate limit was hit; try again in a minute")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err)
}

type site struct {
	ID           int64  `json:"idSite"`
	Name         string `json:"name"`
	Timezone     string `json:"timezone"`
	Alarm        any    `json:"alarm"`
	HasMains     any    `json:"hasMains"`
	HasGenerator any    `json:"hasGenerator"`
	LastTS       any    `json:"last_timestamp"`
	DeviceIcon   string `json:"device_icon"`
	// Geofence, phone number, notes, owner and images aren't decoded.
}

func (c *conn) sites(ctx context.Context) ([]site, error) {
	var me struct {
		User struct {
			ID int64 `json:"id"`
		} `json:"user"`
	}
	if err := c.get(ctx, "/users/me", nil, &me); err != nil {
		return nil, err
	}
	if me.User.ID <= 0 {
		return nil, errors.New("unexpected answer from VRM")
	}
	var r struct {
		Records []site `json:"records"`
	}
	if err := c.get(ctx, "/users/"+strconv.FormatInt(me.User.ID, 10)+"/installations", nil, &r); err != nil {
		return nil, err
	}
	if len(r.Records) > maxSites {
		r.Records = r.Records[:maxSites]
	}
	return r.Records, nil
}

// siteID returns the installation asked for, or the only one.
func (c *conn) siteID(ctx context.Context, asked *int64) (int64, error) {
	if asked != nil {
		return *asked, nil
	}
	ss, err := c.sites(ctx)
	if err != nil {
		return 0, err
	}
	switch len(ss) {
	case 0:
		return 0, errors.New("the token's user has no installations")
	case 1:
		return ss[0].ID, nil
	}
	return 0, fmt.Errorf("the account has %d installations: say which (site, see installations)", len(ss))
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xc0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ss, err := c.sites(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	alarms := 0
	for _, s := range ss {
		if truthy(s.Alarm) {
			alarms++
		}
	}
	msg := fmt.Sprintf("%d installation(s)", len(ss))
	if alarms > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s, %d with an active alarm", msg, alarms)}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type diag struct {
	Timestamp   any    `json:"timestamp"`
	Device      string `json:"Device"`
	Instance    any    `json:"instance"`
	Description string `json:"description"`
	Service     string `json:"dbusServiceType"`
	Path        string `json:"dbusPath"`
	Code        string `json:"code"`
	Formatted   string `json:"formattedValue"`
	RawValue    any    `json:"rawValue"`
}

func (d *diag) number() (float64, bool) { return num(d.RawValue) }

// num reads a number VRM may send as a number or a string.
func num(v any) (float64, bool) {
	switch v := v.(type) {
	case float64:
		return v, !math.IsNaN(v) && !math.IsInf(v, 0)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	return 0, false
}

// truthy reads a flag VRM may send as a boolean, 0/1 or "0"/"1".
func truthy(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	n, ok := num(v)
	return ok && n != 0
}

func unixTime(v any) string {
	if n, ok := num(v); ok && n > 0 && n < 1e11 {
		return time.Unix(int64(n), 0).UTC().Format(time.RFC3339)
	}
	return ""
}

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

// summarize reads the system values out of the diagnostics: the Venus OS
// D-Bus paths of com.victronenergy.system, the GX device's own totals.
func summarize(ds []diag) map[string]any {
	sys := map[string]float64{}
	var latest int64
	state := ""
	for i := range ds {
		d := &ds[i]
		if n, ok := num(d.Timestamp); ok && int64(n) > latest && n < 1e11 {
			latest = int64(n)
		}
		if d.Service != "system" {
			continue
		}
		if d.Path == "/Dc/Battery/State" && d.Formatted != "" {
			state = strings.ToLower(clip(d.Formatted, 40))
		}
		if v, ok := d.number(); ok {
			sys[d.Path] = v
		}
	}
	out := map[string]any{}
	sum := func(paths ...string) (float64, bool) {
		t, found := 0.0, false
		for _, p := range paths {
			if v, ok := sys[p]; ok {
				t, found = t+v, true
			}
		}
		return t, found
	}
	phases := func(prefix string) []string {
		return []string{prefix + "/L1/Power", prefix + "/L2/Power", prefix + "/L3/Power"}
	}
	bat := map[string]any{}
	for k, p := range map[string]string{"socPercent": "/Dc/Battery/Soc", "voltage": "/Dc/Battery/Voltage", "currentA": "/Dc/Battery/Current", "powerW": "/Dc/Battery/Power"} {
		if v, ok := sys[p]; ok {
			bat[k] = round(v, 1)
		}
	}
	if state != "" {
		bat["state"] = state
	}
	if len(bat) > 0 {
		out["battery"] = bat
	}
	pv := map[string]any{}
	if v, ok := sum("/Dc/Pv/Power"); ok {
		pv["dcW"] = round(v, 0)
	}
	if v, ok := sum(append(append(phases("/Ac/PvOnGrid"), phases("/Ac/PvOnOutput")...), phases("/Ac/PvOnGenset")...)...); ok {
		pv["acW"] = round(v, 0)
	}
	if len(pv) > 0 {
		t := 0.0
		for _, v := range pv {
			t += v.(float64)
		}
		pv["totalW"] = t
		out["pv"] = pv
	}
	if v, ok := sum(phases("/Ac/Grid")...); ok {
		out["gridW"] = round(v, 0) // positive: drawing from the grid
	}
	if v, ok := sum(phases("/Ac/Genset")...); ok {
		out["generatorW"] = round(v, 0)
	}
	if v, ok := sum(append(phases("/Ac/Consumption"), "/Dc/System/Power")...); ok {
		out["consumptionW"] = round(v, 0)
	}
	if latest > 0 {
		out["loggedAt"] = time.Unix(latest, 0).UTC().Format(time.RFC3339)
	}
	return out
}

// privateWords mark a diagnostic value that locates the installation or
// identifies a device or a network: a GX device with a GPS logs its
// latitude and longitude (a boat's or a camper's position, or the house),
// and gateways log serials, MAC and IP addresses and remote support ports.
var privateWords = []string{"gps", "latitude", "longitude", "altitude", "position", "location", "satellite",
	"serial", "mac address", "ip address", "ipv4", "ipv6", "remote support", "vrm id", "portal id", "identifier", "phone", "e-mail", "email", "ssid", "password"}

// private says whether a diagnostic is left out of all: true.
func private(d diag) bool {
	if strings.EqualFold(d.Service, "gps") {
		return true
	}
	text := strings.ToLower(d.Device + " " + d.Description + " " + d.Path)
	for _, w := range privateWords {
		if strings.Contains(text, w) {
			return true
		}
	}
	return false
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Site *int64 `json:"site"`
		All  bool   `json:"all"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if p.Site != nil && (*p.Site < 1 || *p.Site > maxSite) {
		return sdk.Result{}, errors.New("site is an installation id from installations")
	}
	switch call.Action {
	case "installations":
		ss, err := c.sites(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range ss {
			e := map[string]any{"site": s.ID, "name": clip(s.Name, maxTextLength), "timezone": clip(s.Timezone, 64), "alarm": truthy(s.Alarm)}
			if s.HasMains != nil {
				e["mains"] = truthy(s.HasMains)
			}
			if s.HasGenerator != nil {
				e["generator"] = truthy(s.HasGenerator)
			}
			if t := unixTime(s.LastTS); t != "" {
				e["lastReport"] = t
			}
			if s.DeviceIcon != "" {
				e["kind"] = clip(s.DeviceIcon, 40)
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "summary":
		id, err := c.siteID(ctx, p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		var r struct {
			Records []diag `json:"records"`
		}
		if err := c.get(ctx, "/installations/"+strconv.FormatInt(id, 10)+"/diagnostics", url.Values{"count": {diagnosticsN}}, &r); err != nil {
			return sdk.Result{}, err
		}
		out := summarize(r.Records)
		out["site"] = id
		if len(out) == 1 {
			out["note"] = "no system values logged; is the GX device online and logging to VRM?"
		}
		if p.All {
			list := []map[string]any{}
			sort.SliceStable(r.Records, func(i, j int) bool {
				if r.Records[i].Device != r.Records[j].Device {
					return r.Records[i].Device < r.Records[j].Device
				}
				return r.Records[i].Description < r.Records[j].Description
			})
			for _, d := range r.Records {
				if private(d) {
					continue
				}
				if len(list) >= maxRecords {
					out["truncated"] = true
					break
				}
				e := map[string]any{"device": clip(d.Device, maxTextLength), "description": clip(d.Description, maxTextLength), "value": clip(rest.Redact(d.Formatted), maxTextLength)}
				if d.Code != "" {
					e["code"] = clip(d.Code, 20)
				}
				if n, ok := num(d.Instance); ok {
					e["instance"] = n
				}
				list = append(list, e)
			}
			out["values"] = list
		}
		return sdk.JSON(out)

	case "alarms":
		id, err := c.siteID(ctx, p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		var r struct {
			Alarms []struct {
				Attribute   int64 `json:"idDataAttribute"`
				Instance    any   `json:"instance"`
				Low         any   `json:"lowAlarm"`
				High        any   `json:"highAlarm"`
				Enabled     any   `json:"enabled"`
				NotifyAfter any   `json:"notifyAfterSeconds"`
			} `json:"alarms"`
			Attributes []struct {
				ID          int64  `json:"idDataAttribute"`
				Code        string `json:"code"`
				Description string `json:"description"`
			} `json:"attributes"`
			// users (who is notified, with e-mail addresses) isn't decoded.
		}
		if err := c.get(ctx, "/installations/"+strconv.FormatInt(id, 10)+"/alarms", nil, &r); err != nil {
			return sdk.Result{}, err
		}
		attr := map[int64]string{}
		for _, a := range r.Attributes {
			attr[a.ID] = clip(a.Description, maxTextLength)
		}
		rules := []map[string]any{}
		for i, a := range r.Alarms {
			if i >= maxAlarms {
				break
			}
			e := map[string]any{"attribute": a.Attribute, "enabled": truthy(a.Enabled)}
			if d := attr[a.Attribute]; d != "" {
				e["watches"] = d
			}
			for k, v := range map[string]any{"instance": a.Instance, "low": a.Low, "high": a.High, "notifyAfterSeconds": a.NotifyAfter} {
				if n, ok := num(v); ok {
					e[k] = n
				}
			}
			rules = append(rules, e)
		}
		out := map[string]any{"site": id, "rules": rules}
		// Whether one is active now is on the installation record.
		if ss, err := c.sites(ctx); err == nil {
			for _, s := range ss {
				if s.ID == id {
					out["active"] = truthy(s.Alarm)
				}
			}
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
