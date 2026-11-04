// Package iobroker works with ioBroker through its simple-api adapter:
// states found by an id pattern with their values, one state with its
// definition, and setting a writable state, checked against its type,
// range and allowed values. Locks, garage doors, gates, doors, windows,
// alarms, cameras, valves and heating (by role, name or id, also of the
// device or channel a state belongs to), and states listed in
// criticalStates, are kept apart behind a destructive action; system and
// admin states are never set.
package iobroker

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
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one ioBroker simple-api adapter.
type Config struct {
	URL      string `json:"url"`      // e.g. http://iobroker.local:8087
	Username string `json:"username"` // an ioBroker user, when the adapter asks for one
	Password string `json:"password"` // secret://
	// CriticalStates are state ids, or ids of the devices and channels
	// above them, that need set_critical_state, like a plug feeding a
	// server or a gate opener behind a plain switch.
	CriticalStates     []string `json:"criticalStates"`
	Fingerprint        string   `json:"fingerprint"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

type conn struct {
	api      *rest.Client
	critical []string // ids and id prefixes, lowercased
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the ioBroker module.
func New() *Module { return &Module{} }

const (
	maxStates = 500
	maxText   = 1000
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// idRe is a dotted state id of plain characters (ioBroker allows more;
	// these are what reach a request path unescaped by any server).
	idRe      = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$`)
	patternRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_*-]*(\.[A-Za-z0-9_*-]+)*$`)
	// criticalWord matches roles, names and ids of what opens, unlocks,
	// sounds, watches or heats something: a false match only means the
	// destructive action.
	criticalWord = regexp.MustCompile(`(?i)lock|door|gate|window|alarm|siren|secur|camera|valve|heat|hvac|radiator|boiler|thermostat|temperature|boost|garage|sprinkler|irrigation|smoke|water ?main`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	set := `{"type":"object","required":["id","value"],"properties":{
		"id":{"type":"string","maxLength":240,"description":"The state's id, e.g. hue.0.Desk_lamp.on"},
		"value":{"description":"The new value: true/false, a number within the state's range, or a text, as its type takes"}}}`
	return sdk.Manifest{
		ID: "iobroker", Name: "ioBroker", Version: "0.1.0", Category: "Smart home", Icon: "home",
		Description: "ioBroker states by id pattern with their values; set writable states, checked against their type and range, with locks, garage doors, alarms and heating kept apart.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The simple-api adapter's address, e.g. http://iobroker.local:8087"},
			"username":{"type":"string","description":"An ioBroker user, when the adapter has authentication on"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"criticalStates":{"type":"array","maxItems":200,"items":{"type":"string","maxLength":240},"description":"State ids, or ids of the devices and channels above them, that need set_critical_state, like a plug feeding a server or a gate opener behind a plain switch. States whose role, name or id (or their device's or channel's) contains lock, door, gate, window, alarm, siren, security, camera, valve, heat, thermostat or temperature are critical without being listed."},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "states", Title: "States", Description: "States whose id matches a pattern (* for any part), with value, acknowledged, last change, name, role, type, unit, whether it can be set, and whether it's critical.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["pattern"],"properties":{"pattern":{"type":"string","maxLength":240,"description":"An id pattern, e.g. hue.0.* or zigbee.0.*.state"}}}`)},
			{Name: "state", Title: "State", Description: "One state with its value and definition: type, role, unit, range, allowed values, whether it can be set, and why it's critical.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","maxLength":240,"description":"The state's id"}}}`)},
			{Name: "set_state", Title: "Set a state", Description: "Sets a writable state (as a command, not acknowledged), checked against its type, range and allowed values. Critical states (locks, doors, gates, windows, alarms, cameras, valves, heating, or in criticalStates) are refused: use set_critical_state. System and admin states are never set. Undo sets the previous value.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(set)},
			{Name: "set_critical_state", Title: "Set a critical state", Description: "Sets a writable state of a critical device: this can unlock a lock, open a garage door, gate, door or window, disarm an alarm, turn a camera off, open a valve or change the heating. The preview says which. Undo sets the previous value.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(set)},
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
		return errors.New("the address is like http://iobroker.local:8087")
	}
	user := strings.TrimSpace(c.Username)
	switch {
	case (user == "") != (c.Password == ""):
		return errors.New("enter both an ioBroker username and password, or neither when the adapter has no authentication")
	case c.Password != "" && !strings.HasPrefix(c.Password, "secret://"):
		return errors.New("store the password in the vault and enter its secret:// reference")
	case len(user) > 128 || strings.ContainsAny(user, "\x00\r\n:"):
		return errors.New("the username is an ioBroker user")
	}
	if u.Scheme == "http" && (c.Fingerprint != "" || c.InsecureSkipVerify) {
		return errors.New("the certificate settings need an https address")
	}
	if len(c.CriticalStates) > 200 {
		return errors.New("list at most 200 critical states")
	}
	var crit []string
	for _, a := range c.CriticalStates {
		a = strings.TrimSpace(a)
		if !idRe.MatchString(a) || len(a) > 240 {
			return errors.New("a critical state is its id, or the id of a device or channel, like zigbee.0.00158d0001")
		}
		crit = append(crit, strings.ToLower(a))
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
	var auth func(context.Context, *http.Request) error
	if user != "" {
		ref := c.Password
		// Basic authentication, never the user and pass query parameters,
		// which end up in logs.
		auth = func(ctx context.Context, r *http.Request) error {
			pw, err := h.Secret(ctx, ref)
			if err != nil {
				return err
			}
			r.SetBasicAuth(user, pw)
			return nil
		}
	}
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), auth)
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

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("ioBroker refused the username or password")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the ioBroker user isn't allowed to do this")
	}
	return err
}

type common struct {
	Name   any      `json:"name"` // a text, or one per language
	Type   string   `json:"type"`
	Role   string   `json:"role"`
	Unit   string   `json:"unit"`
	Read   *bool    `json:"read"`
	Write  *bool    `json:"write"`
	Min    *float64 `json:"min"`
	Max    *float64 `json:"max"`
	Step   *float64 `json:"step"`
	States any      `json:"states"`
}

func (cm common) name() string {
	switch n := cm.Name.(type) {
	case string:
		return clip(n, 100)
	case map[string]any:
		if s, ok := n["en"].(string); ok {
			return clip(s, 100)
		}
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if s, ok := n[k].(string); ok {
				return clip(s, 100)
			}
		}
	}
	return ""
}

func (cm common) writable() bool { return cm.Write != nil && *cm.Write }

// allowed lists the values a state's states field allows, or nil.
func (cm common) allowed() []string {
	var out []string
	switch s := cm.States.(type) {
	case map[string]any:
		for k := range s {
			out = append(out, k)
		}
	case string:
		for _, kv := range strings.Split(s, ";") {
			if k, _, ok := strings.Cut(kv, ":"); ok && k != "" {
				out = append(out, k)
			}
		}
	case []any:
		for i, v := range s {
			if cm.Type == "number" {
				out = append(out, strconv.Itoa(i))
			} else if t, ok := v.(string); ok {
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

// object is a state and its object, as simple-api's get answers.
type object struct {
	ID     string `json:"_id"`
	Type   string `json:"type"`
	Common common `json:"common"`
	Val    any    `json:"val"`
	Ack    *bool  `json:"ack"`
	TS     int64  `json:"ts"`
	LC     int64  `json:"lc"`
}

type state struct {
	Val any   `json:"val"`
	Ack *bool `json:"ack"`
	TS  int64 `json:"ts"`
	LC  int64 `json:"lc"`
}

func value(v any) any {
	switch x := v.(type) {
	case string:
		return clip(x, 200)
	case bool, float64, nil:
		return v
	}
	return "(not shown)"
}

func when(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

// protected says why a state is never set, or "".
func protected(id string) string {
	l := strings.ToLower(id)
	if strings.HasPrefix(l, "system.") || strings.HasPrefix(l, "admin.") {
		return "system and admin states aren't set here"
	}
	return ""
}

// ancestors are the ids of the devices and channels above a state, nearest
// first, down to the adapter instance (hue.0.lamp.on: hue.0.lamp).
func ancestors(id string) []string {
	parts := strings.Split(id, ".")
	var out []string
	for n := len(parts) - 1; n > 2 && len(out) < 6; n-- {
		out = append(out, strings.Join(parts[:n], "."))
	}
	return out
}

func (c *conn) listed(id string) bool {
	l := strings.ToLower(id)
	for _, e := range c.critical {
		if l == e || strings.HasPrefix(l, e+".") {
			return true
		}
	}
	return false
}

// ownWhy says why a state (or the device or channel above it) is
// critical by itself, or "".
func ownWhy(o object, id string) string {
	switch {
	case criticalWord.MatchString(o.Common.Role):
		return "its role is " + clip(o.Common.Role, 60)
	case criticalWord.MatchString(o.Common.name()):
		return "its name says it opens, unlocks, sounds, watches or heats something"
	case criticalWord.MatchString(id):
		return "its id says it opens, unlocks, sounds, watches or heats something"
	}
	return ""
}

// why says why a state is critical, counting the devices and channels
// above it: a plain switch inside a lock's or camera's device is as
// critical as the device. A device or channel that can't be read makes
// the state's safety unknown, which is an error.
func (c *conn) why(ctx context.Context, o object) (string, error) {
	if c.listed(o.ID) {
		return "listed in criticalStates", nil
	}
	if w := ownWhy(o, o.ID); w != "" {
		return w, nil
	}
	for _, a := range ancestors(o.ID) {
		var p object
		err := c.get(ctx, "/get/"+url.PathEscape(a), nil, &p)
		if rest.IsStatus(err, http.StatusNotFound) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("couldn't read %s, which %s belongs to, to tell whether it's critical: %w", a, o.ID, err)
		}
		if p.ID != "" && p.ID != a {
			return "", fmt.Errorf("ioBroker answered with another object for %s", a)
		}
		if w := ownWhy(p, ""); w != "" {
			return "part of " + a + ", " + w, nil
		}
	}
	return "", nil
}

func (c *conn) object(ctx context.Context, id string) (object, error) {
	id = strings.TrimSpace(id)
	if !idRe.MatchString(id) || len(id) > 240 {
		return object{}, errors.New("a state is its dotted id, like hue.0.Desk_lamp.on")
	}
	var o object
	if err := c.get(ctx, "/get/"+url.PathEscape(id), nil, &o); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return o, fmt.Errorf("there's no state %s", id)
		}
		return o, err
	}
	if o.ID != id {
		// The id goes into the set's path and the undo.
		return o, fmt.Errorf("ioBroker answered with another object for %s", id)
	}
	return o, nil
}

func (c *conn) row(o object) map[string]any {
	row := map[string]any{"id": o.ID, "value": value(o.Val)}
	if n := o.Common.name(); n != "" {
		row["name"] = n
	}
	if o.Ack != nil {
		row["ack"] = *o.Ack
	}
	if t := when(o.LC); t != "" {
		row["changed"] = t
	}
	if o.Common.Role != "" {
		row["role"] = clip(o.Common.Role, 60)
	}
	if o.Common.Type != "" {
		row["type"] = clip(o.Common.Type, 20)
	}
	if o.Common.Unit != "" {
		row["unit"] = clip(o.Common.Unit, 20)
	}
	row["writable"] = o.Common.writable() && protected(o.ID) == ""
	if c.listed(o.ID) || ownWhy(o, o.ID) != "" {
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
	var help any
	if err := c.get(ctx, "/help", nil, &help); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no ioBroker simple-api at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "ioBroker simple-api is up"}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Pattern string          `json:"pattern"`
		ID      string          `json:"id"`
		Value   json.RawMessage `json:"value"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "states":
		pat := strings.TrimSpace(p.Pattern)
		if !patternRe.MatchString(pat) || len(pat) > 240 {
			return sdk.Result{}, errors.New("a pattern is a dotted id with * for any part, starting with an adapter, like hue.0.* or zigbee.0.*.state")
		}
		q := url.Values{"pattern": {pat}}
		var states map[string]state
		if err := c.get(ctx, "/states", q, &states); err != nil {
			return sdk.Result{}, err
		}
		// Every object under the pattern: the states' definitions, and the
		// devices and channels they belong to.
		var objs map[string]object
		if err := c.get(ctx, "/objects", url.Values{"pattern": {pat}}, &objs); err != nil {
			return sdk.Result{}, err
		}
		ids := make([]string, 0, len(states))
		for id := range states {
			if idRe.MatchString(id) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		out := []map[string]any{}
		for _, id := range ids {
			if len(out) >= maxStates {
				break
			}
			s := states[id]
			o := objs[id]
			o.ID, o.Val, o.Ack, o.TS, o.LC = id, s.Val, s.Ack, s.TS, s.LC
			row := c.row(o)
			for _, a := range ancestors(id) {
				if p, ok := objs[a]; ok && ownWhy(p, "") != "" {
					row["critical"] = true
				}
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	case "state":
		o, err := c.object(ctx, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		row := c.row(o)
		why, err := c.why(ctx, o)
		if err != nil {
			return sdk.Result{}, err
		}
		if why != "" {
			row["critical"] = true
			row["criticalBecause"] = why
		}
		if o.Common.Min != nil {
			row["min"] = *o.Common.Min
		}
		if o.Common.Max != nil {
			row["max"] = *o.Common.Max
		}
		if o.Common.Step != nil {
			row["step"] = *o.Common.Step
		}
		if a := o.Common.allowed(); len(a) > 0 {
			if len(a) > 50 {
				a = a[:50]
			}
			for i := range a {
				a[i] = clip(a[i], 60)
			}
			row["allowed"] = a
		}
		if t := when(o.TS); t != "" {
			row["updated"] = t
		}
		return sdk.JSON(row)
	case "set_state", "set_critical_state":
		id := strings.TrimSpace(p.ID)
		if !idRe.MatchString(id) || len(id) > 240 {
			return sdk.Result{}, errors.New("a state is its dotted id, like hue.0.Desk_lamp.on")
		}
		if why := protected(id); why != "" {
			return sdk.Result{}, fmt.Errorf("%s: %s", id, why)
		}
		if len(p.Value) == 0 || string(p.Value) == "null" {
			return sdk.Result{}, errors.New("give the new value")
		}
		return c.setState(ctx, call, id, p.Value)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// coerce checks a value against a state's type, range and allowed values,
// and returns it with the type simple-api is told.
func coerce(cm common, raw json.RawMessage) (any, string, error) {
	if t := strings.TrimSpace(string(raw)); t == "" || t == "null" {
		return nil, "", errors.New("give the new value")
	}
	allowed := cm.allowed()
	switch cm.Type {
	case "boolean":
		var b bool
		if json.Unmarshal(raw, &b) != nil {
			return nil, "", errors.New("this state is true or false")
		}
		return b, "boolean", nil
	case "number":
		var n float64
		if json.Unmarshal(raw, &n) != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			var s string
			if json.Unmarshal(raw, &s) != nil {
				return nil, "", errors.New("this state is a number")
			}
			f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
			if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
				return nil, "", errors.New("this state is a number")
			}
			n = f
		}
		if cm.Min != nil && n < *cm.Min || cm.Max != nil && n > *cm.Max {
			lo, hi := math.Inf(-1), math.Inf(1)
			if cm.Min != nil {
				lo = *cm.Min
			}
			if cm.Max != nil {
				hi = *cm.Max
			}
			return nil, "", fmt.Errorf("this state is %g–%g", lo, hi)
		}
		// Without a range, states is the complete list of values.
		if cm.Min == nil && cm.Max == nil && len(allowed) > 0 && !inList(allowed, strconv.FormatFloat(n, 'f', -1, 64)) {
			return nil, "", fmt.Errorf("this state is one of %s", strings.Join(allowed, ", "))
		}
		return n, "number", nil
	case "string":
		var s string
		if json.Unmarshal(raw, &s) != nil || len([]rune(s)) > maxText || strings.IndexFunc(s, unicode.IsControl) >= 0 {
			return nil, "", fmt.Errorf("this state is a text of up to %d characters", maxText)
		}
		if len(allowed) > 0 && !inList(allowed, s) {
			return nil, "", fmt.Errorf("this state is one of %s", strings.Join(allowed, ", "))
		}
		return s, "string", nil
	case "":
		return nil, "", errors.New("ioBroker doesn't say what type this state is, so it isn't set")
	}
	return nil, "", fmt.Errorf("a state of type %s can't be set here", clip(cm.Type, 20))
}

func inList(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func same(cur, v any) bool {
	switch x := v.(type) {
	case bool:
		c, ok := cur.(bool)
		return ok && c == x
	case float64:
		c, ok := cur.(float64)
		return ok && c == x
	case string:
		c, ok := cur.(string)
		return ok && c == x
	}
	return false
}

func text(v any) string {
	switch x := v.(type) {
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case string:
		return x
	}
	return ""
}

// effect says in words what setting a critical state can do.
func effect(v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "turns it on (a gate or door opener fires, a lock may open, a valve opens, heating starts)"
		}
		return "turns it off (a lock may open, a camera or alarm stops, heating stops)"
	case float64:
		return "sets it to " + text(x) + " (a position, mode or temperature of a lock, door, alarm, valve or heating)"
	}
	return "changes a critical device (a lock, door, gate, window, alarm, camera, valve or heating)"
}

func (c *conn) setState(ctx context.Context, call sdk.Call, id string, raw json.RawMessage) (sdk.Result, error) {
	o, err := c.object(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	if o.Type != "state" {
		return sdk.Result{}, fmt.Errorf("%s is a %s, not a state", id, clip(o.Type, 20))
	}
	if !o.Common.writable() {
		return sdk.Result{}, fmt.Errorf("%s isn't writable (common.write isn't true)", id)
	}
	why, err := c.why(ctx, o)
	if err != nil {
		return sdk.Result{}, err
	}
	critical := call.Action == "set_critical_state"
	if why != "" && !critical {
		return sdk.Result{}, fmt.Errorf("%s is critical (%s): use set_critical_state", id, why)
	}
	if why == "" && critical {
		return sdk.Result{}, fmt.Errorf("%s isn't critical; use set_state", id)
	}
	v, typ, err := coerce(o.Common, raw)
	if err != nil {
		return sdk.Result{}, fmt.Errorf("%s: %w", id, err)
	}
	name := o.Common.name()
	label := id
	if name != "" {
		label = name + " (" + id + ")"
	}
	if same(o.Val, v) {
		return sdk.JSON(map[string]any{"id": id, "name": name, "value": v, "note": "nothing to change"})
	}
	prev := o.Val
	if call.DryRun {
		b, _ := json.Marshal(map[string]any{"value": value(prev)})
		a, _ := json.Marshal(map[string]any{"value": v})
		sum := fmt.Sprintf("Set %s to %s (now %v)", label, text(v), value(prev))
		if critical {
			sum += "; this " + effect(v) + " (" + why + ")"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "state " + label, Op: "set", Before: b, After: a}}}}, nil
	}
	q := url.Values{"value": {text(v)}, "type": {typ}, "ack": {"false"}}
	if err := c.get(ctx, "/set/"+url.PathEscape(id), q, nil); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"id": id, "value": v, "was": value(prev)}
	if name != "" {
		out["name"] = name
	}
	// Read back: the device's adapter acknowledges the value when it's
	// applied, which may take a moment.
	if after, err := c.object(ctx, id); err == nil {
		out["now"] = value(after.Val)
		if after.Ack != nil {
			out["ack"] = *after.Ack
		}
	}
	r, err := sdk.JSON(out)
	// The previous value goes back through the same action when it fits
	// the state's definition.
	if pr, err := json.Marshal(prev); err == nil {
		if back, _, cerr := coerce(o.Common, pr); cerr == nil {
			r.Undo = sdk.UndoWith(call.Action, map[string]any{"id": id, "value": back}, fmt.Sprintf("Set %s back to %v", label, value(prev)))
		}
	}
	return r, err
}
