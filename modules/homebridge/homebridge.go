// Package homebridge works with Homebridge through the Homebridge UI's API:
// accessories with their characteristics, setting a characteristic and
// restarting the bridge. It signs in with a UI user's name and password.
// Locks, garage doors, gates, doors, windows, security systems, valves and
// cameras (by service, characteristic or name), and accessories listed in
// criticalAccessories, are kept apart behind a destructive action.
package homebridge

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
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Homebridge UI.
type Config struct {
	URL      string `json:"url"`      // e.g. http://homebridge.local:8581
	Username string `json:"username"` // a Homebridge UI user
	Password string `json:"password"` // secret://
	// CriticalAccessories are accessory ids (uniqueId) or names that need
	// set_critical_characteristic, like a plug feeding a server or a gate
	// opener behind a plain switch.
	CriticalAccessories []string `json:"criticalAccessories"`
	Fingerprint         string   `json:"fingerprint"`
	InsecureSkipVerify  bool     `json:"insecureSkipVerify"`
}

type conn struct {
	api      *rest.Client
	login    *rest.Client
	user     string
	password string // secret:// reference
	host     sdk.Host
	now      func() time.Time
	critical map[string]bool // ids, and lowercased names

	mu      sync.Mutex
	session string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces the clock (tests).
	Now func() time.Time
}

// New returns the Homebridge module.
func New() *Module { return &Module{} }

const maxServices = 500

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	charRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
	// criticalServices open, unlock, disarm or watch something.
	criticalServices = map[string]bool{"LockMechanism": true, "LockManagement": true, "GarageDoorOpener": true, "Door": true, "Window": true,
		"SecuritySystem": true, "Valve": true, "Faucet": true, "IrrigationSystem": true, "CameraOperatingMode": true, "CameraRecordingManagement": true,
		"CameraRTPStreamManagement": true, "Doorbell": true}
	// criticalChars do the same on whatever service carries them.
	criticalChars = map[string]bool{"LockTargetState": true, "LockControlPoint": true, "LockPhysicalControls": true, "TargetDoorState": true,
		"SecuritySystemTargetState": true, "HomeKitCameraActive": true, "EventSnapshotsActive": true, "PeriodicSnapshotsActive": true,
		"CameraOperatingModeIndicator": true, "ManuallyDisabled": true, "NightVision": true}
	// criticalName matches names of what opens, unlocks, sounds or watches
	// something (Garage, Front gate, Door strike, Alarm, Camera power): a
	// false match only means the destructive action.
	criticalName = regexp.MustCompile(`(?i)garage|gate|door|lock|valve|siren|alarm|secur|camera|sprinkler|irrigation|water main`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	set := `{"type":"object","required":["accessory","characteristic","value"],"properties":{
		"accessory":{"type":"string","maxLength":128,"description":"The accessory's id (uniqueId, from accessories)"},
		"characteristic":{"type":"string","maxLength":64,"description":"The characteristic's type, e.g. On, Brightness, TargetTemperature"},
		"value":{"description":"The new value: true/false, a number within the characteristic's range, or a short text"}}}`
	return sdk.Manifest{
		ID: "homebridge", Name: "Homebridge", Version: "0.1.0", Category: "Smart home", Icon: "home",
		Description: "Homebridge accessories and their characteristics; set a characteristic, with locks, garage doors and security devices kept apart; restart the bridge.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"The Homebridge UI's address, e.g. http://homebridge.local:8581"},
			"username":{"type":"string","description":"A Homebridge UI user (an admin, to restart the bridge)"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"criticalAccessories":{"type":"array","maxItems":200,"items":{"type":"string","maxLength":200},"description":"Accessory ids or names that need set_critical_characteristic, like a plug feeding a server or a gate opener behind a plain switch. Locks, garage doors, doors, windows, security systems, valves and cameras, and accessories whose name contains garage, gate, door, lock, valve, siren, alarm, security, camera, sprinkler or irrigation, are critical without being listed."},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "accessories", Title: "Accessories", Description: "Each accessory service: id, name, type, accessory, manufacturer and model, its current values, and whether it's critical.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"type":{"type":"string","description":"Only this service type, e.g. Lightbulb"},"search":{"type":"string","maxLength":100}}}`)},
			{Name: "accessory", Title: "Accessory", Description: "One accessory service with every characteristic: value, format, range, unit and whether it can be set.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["accessory"],"properties":{"accessory":{"type":"string","maxLength":128,"description":"uniqueId from accessories"}}}`)},
			{Name: "set_characteristic", Title: "Set a characteristic", Description: "Sets one characteristic (On, Brightness, TargetTemperature …), checked against its format and range. Critical accessories (locks, garage doors, gates, doors, windows, security systems, valves, cameras, or in criticalAccessories) are refused: use set_critical_characteristic. Undo sets the previous value.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(set)},
			{Name: "set_critical_characteristic", Title: "Set a critical characteristic", Description: "Sets a characteristic of a critical accessory: this can unlock a lock, open a garage door, gate, door or window, disarm a security system, open a valve or turn a camera off. The preview says which. Undo sets the previous value.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(set)},
			{Name: "restart_bridge", Title: "Restart Homebridge", Description: "Restarts Homebridge: its accessories don't respond in HomeKit until it's back, usually within a minute.", Risk: sdk.RiskDestructive, DryRun: true},
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
		return errors.New("the address is like http://homebridge.local:8581")
	}
	user := strings.TrimSpace(c.Username)
	switch {
	case user == "" || c.Password == "":
		return errors.New("enter a Homebridge UI username and password")
	case !strings.HasPrefix(c.Password, "secret://"):
		return errors.New("store the password in the vault and enter its secret:// reference")
	case len(user) > 128 || strings.ContainsAny(user, "\x00\r\n"):
		return errors.New("the username is a Homebridge UI user")
	}
	if u.Scheme == "http" && (c.Fingerprint != "" || c.InsecureSkipVerify) {
		return errors.New("the certificate settings need an https address")
	}
	if len(c.CriticalAccessories) > 200 {
		return errors.New("list at most 200 critical accessories")
	}
	crit := map[string]bool{}
	for _, a := range c.CriticalAccessories {
		a = strings.TrimSpace(a)
		if a == "" || len(a) > 200 || strings.ContainsAny(a, "\x00\r\n") {
			return errors.New("a critical accessory is its id or its name (up to 200 characters)")
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
	client = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api") + "/api"
	cn := &conn{user: user, password: c.Password, host: h, now: now, critical: crit}
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := cn.sessionToken(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = client
	cn.login = rest.New(base, nil)
	cn.login.HTTP = client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errLogin = errors.New("Homebridge refused the username or password")

// sessionToken signs in when there's no token or it's about to end.
func (c *conn) sessionToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != "" && c.now().Add(time.Minute).Before(c.expires) {
		return c.session, nil
	}
	pw, err := c.host.Secret(ctx, c.password)
	if err != nil {
		return "", err
	}
	var res struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	_, err = c.login.Do(ctx, http.MethodPost, "/auth/login", nil, map[string]string{"username": c.user, "password": pw}, &res)
	if err != nil {
		switch {
		case rest.IsStatus(err, http.StatusPreconditionFailed):
			return "", errors.New("this Homebridge UI user has two-factor sign-in; use a user without it")
		case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusBadRequest), rest.IsStatus(err, http.StatusForbidden):
			return "", errLogin
		}
		return "", fmt.Errorf("couldn't sign in to Homebridge: %w", err)
	}
	t := strings.TrimSpace(res.AccessToken)
	if t == "" || strings.ContainsAny(t, " \r\n") {
		return "", errors.New("Homebridge's sign-in gave no access token")
	}
	c.session = t
	c.expires = c.now().Add(time.Duration(res.ExpiresIn) * time.Second)
	if res.ExpiresIn <= 0 {
		c.expires = c.now().Add(time.Hour)
	}
	return t, nil
}

func (c *conn) do(ctx context.Context, method, path string, body, out any) error {
	_, err := c.api.Do(ctx, method, path, nil, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		// The token ended early (signed out, UI restart): sign in again once.
		c.mu.Lock()
		c.session = ""
		c.mu.Unlock()
		_, err = c.api.Do(ctx, method, path, nil, body, out)
	}
	switch {
	case errors.Is(err, errLogin):
		return err
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Homebridge refused the session")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the Homebridge UI user isn't allowed to do this (it needs to be an admin)")
	}
	return err
}

// clip redacts server text, then shortens it.
func clip(s string, n int) string {
	s = rest.Redact(strings.TrimSpace(s))
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

type char struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Value       any       `json:"value"`
	Format      string    `json:"format"`
	CanWrite    bool      `json:"canWrite"`
	CanRead     *bool     `json:"canRead"`
	MinValue    *float64  `json:"minValue"`
	MaxValue    *float64  `json:"maxValue"`
	MinStep     *float64  `json:"minStep"`
	MaxLen      int       `json:"maxLen"`
	Unit        string    `json:"unit"`
	ValidValues []float64 `json:"validValues"`
}

type service struct {
	UniqueID    string `json:"uniqueId"`
	Type        string `json:"type"`
	HumanType   string `json:"humanType"`
	ServiceName string `json:"serviceName"`
	Chars       []char `json:"serviceCharacteristics"`
	Info        struct {
		Manufacturer string `json:"Manufacturer"`
		Model        string `json:"Model"`
		Name         string `json:"Name"`
		// The serial number isn't decoded.
	} `json:"accessoryInformation"`
	Instance struct {
		Name string `json:"name"`
	} `json:"instance"`
}

func (s service) name() string {
	if s.ServiceName != "" {
		return clip(s.ServiceName, 100)
	}
	return clip(s.Info.Name, 100)
}

func (s service) char(t string) *char {
	for i := range s.Chars {
		if s.Chars[i].Type == t {
			return &s.Chars[i]
		}
	}
	for i := range s.Chars {
		if strings.EqualFold(s.Chars[i].Type, t) {
			return &s.Chars[i]
		}
	}
	return nil
}

// critical says why a service is critical, or "".
func (c *conn) criticalWhy(s service) string {
	switch {
	case c.critical[s.UniqueID] || c.critical[strings.ToLower(s.ServiceName)] || (s.Info.Name != "" && c.critical[strings.ToLower(s.Info.Name)]):
		return "listed in criticalAccessories"
	case criticalServices[s.Type]:
		return "a " + strings.ToLower(human(s)) + " accessory"
	case criticalName.MatchString(s.ServiceName) || criticalName.MatchString(s.Info.Name):
		return "its name says it opens, unlocks, sounds or watches something"
	}
	for _, ch := range s.Chars {
		if ch.CanWrite && criticalChars[ch.Type] {
			return "it has " + ch.Type
		}
	}
	return ""
}

func human(s service) string {
	if s.HumanType != "" {
		return clip(s.HumanType, 60)
	}
	return clip(s.Type, 60)
}

// hidden services describe the accessory rather than do anything.
var hidden = map[string]bool{"AccessoryInformation": true, "ProtocolInformation": true}

func value(v any) any {
	if s, ok := v.(string); ok {
		return clip(s, 200)
	}
	switch v.(type) {
	case bool, float64, nil:
		return v
	}
	return "(not shown)"
}

func (c *conn) row(s service) map[string]any {
	vals := map[string]any{}
	for _, ch := range s.Chars {
		if ch.CanRead == nil || *ch.CanRead {
			vals[ch.Type] = value(ch.Value)
		}
	}
	row := map[string]any{"id": s.UniqueID, "name": s.name(), "type": human(s), "values": vals}
	if s.Info.Name != "" && s.Info.Name != s.ServiceName {
		row["accessory"] = clip(s.Info.Name, 100)
	}
	if s.Info.Manufacturer != "" {
		row["manufacturer"] = clip(s.Info.Manufacturer, 100)
	}
	if s.Info.Model != "" {
		row["model"] = clip(s.Info.Model, 100)
	}
	if s.Instance.Name != "" {
		row["bridge"] = clip(s.Instance.Name, 100)
	}
	if why := c.criticalWhy(s); why != "" {
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
	var st struct {
		Status string `json:"status"`
	}
	if err := c.do(ctx, http.MethodGet, "/status/homebridge", nil, &st); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Homebridge UI API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	switch st.Status {
	case "up":
		return sdk.Health{Status: "ok", Message: "Homebridge is up"}
	case "pending":
		return sdk.Health{Status: "degraded", Message: "Homebridge is starting"}
	}
	return sdk.Health{Status: "down", Message: "Homebridge is " + clip(st.Status, 20)}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Type           string          `json:"type"`
		Search         string          `json:"search"`
		Accessory      string          `json:"accessory"`
		Characteristic string          `json:"characteristic"`
		Value          json.RawMessage `json:"value"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "accessories":
		var ss []service
		if err := c.do(ctx, http.MethodGet, "/accessories", nil, &ss); err != nil {
			return sdk.Result{}, accErr(err)
		}
		q := strings.ToLower(strings.TrimSpace(p.Search))
		t := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p.Type), " ", ""))
		out := []map[string]any{}
		for _, s := range ss {
			if hidden[s.Type] || len(out) >= maxServices {
				continue
			}
			if t != "" && strings.ToLower(s.Type) != t && strings.ToLower(strings.ReplaceAll(s.HumanType, " ", "")) != t {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(s.ServiceName+" "+s.Info.Name+" "+s.HumanType), q) {
				continue
			}
			out = append(out, c.row(s))
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
		return sdk.JSON(out)
	case "accessory":
		s, err := c.service(ctx, p.Accessory)
		if err != nil {
			return sdk.Result{}, err
		}
		row := c.row(s)
		delete(row, "values")
		if why := c.criticalWhy(s); why != "" {
			row["criticalBecause"] = why
		}
		chars := []map[string]any{}
		for _, ch := range s.Chars {
			x := map[string]any{"type": ch.Type, "format": ch.Format, "writable": ch.CanWrite}
			if ch.CanRead == nil || *ch.CanRead {
				x["value"] = value(ch.Value)
			}
			if ch.Description != "" && ch.Description != ch.Type {
				x["description"] = clip(ch.Description, 100)
			}
			if ch.MinValue != nil {
				x["min"] = *ch.MinValue
			}
			if ch.MaxValue != nil {
				x["max"] = *ch.MaxValue
			}
			if ch.MinStep != nil {
				x["step"] = *ch.MinStep
			}
			if ch.Unit != "" {
				x["unit"] = clip(ch.Unit, 20)
			}
			if len(ch.ValidValues) > 0 {
				x["validValues"] = ch.ValidValues
			}
			chars = append(chars, x)
		}
		row["characteristics"] = chars
		return sdk.JSON(row)
	case "set_characteristic", "set_critical_characteristic":
		p.Characteristic = strings.TrimSpace(p.Characteristic)
		if !idRe.MatchString(strings.TrimSpace(p.Accessory)) {
			return sdk.Result{}, errors.New("an accessory is its id (uniqueId) from accessories")
		}
		if !charRe.MatchString(p.Characteristic) {
			return sdk.Result{}, errors.New("a characteristic is its type, like On, Brightness or TargetTemperature")
		}
		if len(p.Value) == 0 || string(p.Value) == "null" {
			return sdk.Result{}, errors.New("give the new value")
		}
		return c.set(ctx, call, strings.TrimSpace(p.Accessory), p.Characteristic, p.Value)
	case "restart_bridge":
		var st struct {
			Status string `json:"status"`
		}
		if err := c.do(ctx, http.MethodGet, "/status/homebridge", nil, &st); err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			b, _ := json.Marshal(map[string]string{"status": clip(st.Status, 20)})
			return sdk.Result{Plan: &sdk.Plan{Summary: "Restart Homebridge; its accessories don't respond until it's back, usually within a minute",
				Changes: []sdk.Change{{Target: "Homebridge", Op: "restart", Before: b}}}}, nil
		}
		var res struct {
			OK bool `json:"ok"`
		}
		if err := c.do(ctx, http.MethodPut, "/server/restart", nil, &res); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"restarting": true})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func accErr(err error) error {
	if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusNotFound) {
		return fmt.Errorf("Homebridge didn't list accessories (it needs insecure mode: Homebridge Settings, Homebridge Insecure Mode): %w", err)
	}
	return err
}

func (c *conn) service(ctx context.Context, id string) (service, error) {
	id = strings.TrimSpace(id)
	if !idRe.MatchString(id) {
		return service{}, errors.New("an accessory is its id (uniqueId) from accessories")
	}
	var s service
	if err := c.do(ctx, http.MethodGet, "/accessories/"+url.PathEscape(id), nil, &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return s, fmt.Errorf("there's no accessory %s", id)
		}
		return s, accErr(err)
	}
	if s.UniqueID != id {
		// The id goes into the update's path and the undo.
		return s, fmt.Errorf("Homebridge answered with another accessory for %s", id)
	}
	return s, nil
}

// coerce checks a value against a characteristic's format and range.
func coerce(ch char, raw json.RawMessage) (any, error) {
	switch ch.Format {
	case "bool":
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			return b, nil
		}
		var n float64
		if json.Unmarshal(raw, &n) == nil && (n == 0 || n == 1) {
			return n == 1, nil
		}
		return nil, fmt.Errorf("%s is true or false", ch.Type)
	case "int", "uint8", "uint16", "uint32", "uint64", "float":
		var n float64
		if json.Unmarshal(raw, &n) != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, fmt.Errorf("%s is a number", ch.Type)
		}
		lo, hi := -math.MaxFloat64, math.MaxFloat64
		switch ch.Format {
		case "uint8":
			lo, hi = 0, 255
		case "uint16":
			lo, hi = 0, 65535
		case "uint32":
			lo, hi = 0, 4294967295
		case "uint64":
			lo = 0
		}
		if ch.MinValue != nil {
			lo = math.Max(lo, *ch.MinValue)
		}
		if ch.MaxValue != nil {
			hi = math.Min(hi, *ch.MaxValue)
		}
		if n < lo || n > hi {
			return nil, fmt.Errorf("%s is %g–%g", ch.Type, lo, hi)
		}
		if len(ch.ValidValues) > 0 {
			ok := false
			for _, v := range ch.ValidValues {
				ok = ok || v == n
			}
			if !ok {
				return nil, fmt.Errorf("%s is one of %v", ch.Type, ch.ValidValues)
			}
		}
		if ch.Format != "float" {
			if n != math.Trunc(n) {
				return nil, fmt.Errorf("%s is a whole number", ch.Type)
			}
			return int64(n), nil
		}
		return n, nil
	case "string":
		var s string
		max := ch.MaxLen
		if max <= 0 {
			max = 64
		}
		if json.Unmarshal(raw, &s) != nil || len([]rune(s)) > max || strings.IndexFunc(s, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("%s is a text of up to %d characters", ch.Type, max)
		}
		return s, nil
	}
	return nil, fmt.Errorf("%s (%s) can't be set here", ch.Type, ch.Format)
}

// same compares a current value with a coerced one.
func same(cur, v any) bool {
	switch x := v.(type) {
	case bool:
		switch c := cur.(type) {
		case bool:
			return c == x
		case float64:
			return (c == 1) == x && (c == 0 || c == 1)
		}
	case int64:
		c, ok := cur.(float64)
		return ok && c == float64(x)
	case float64:
		c, ok := cur.(float64)
		return ok && c == x
	case string:
		c, ok := cur.(string)
		return ok && c == x
	}
	return false
}

// effect says in words what a critical change does.
func effect(t string, v any) string {
	n, _ := v.(int64)
	b, _ := v.(bool)
	switch t {
	case "LockTargetState":
		if n == 0 {
			return "unlocks it"
		}
		return "locks it"
	case "TargetDoorState":
		if n == 0 {
			return "opens it"
		}
		return "closes it"
	case "SecuritySystemTargetState":
		if n == 3 {
			return "disarms it"
		}
		return "arms it"
	case "TargetPosition":
		if n > 0 {
			return "opens it"
		}
		return "closes it"
	case "Active", "On":
		if b || n == 1 {
			return "turns it on (a valve opens, a gate opener fires)"
		}
		return "turns it off (a camera or alarm stops)"
	case "HomeKitCameraActive", "EventSnapshotsActive", "PeriodicSnapshotsActive":
		if b || n == 1 {
			return "turns the camera on"
		}
		return "turns the camera off"
	}
	return "changes a critical accessory"
}

func (c *conn) set(ctx context.Context, call sdk.Call, id, t string, raw json.RawMessage) (sdk.Result, error) {
	s, err := c.service(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	ch := s.char(t)
	if ch == nil {
		return sdk.Result{}, fmt.Errorf("%s has no characteristic %s (see accessory)", s.name(), t)
	}
	t = ch.Type
	why := c.criticalWhy(s)
	if why == "" && criticalChars[t] {
		why = "it's " + t
	}
	criticalCall := call.Action == "set_critical_characteristic"
	if why != "" && !criticalCall {
		return sdk.Result{}, fmt.Errorf("%s is critical (%s): use set_critical_characteristic", s.name(), why)
	}
	if why == "" && criticalCall {
		return sdk.Result{}, fmt.Errorf("%s isn't critical; use set_characteristic", s.name())
	}
	if !ch.CanWrite {
		return sdk.Result{}, fmt.Errorf("%s of %s can't be set", t, s.name())
	}
	v, err := coerce(*ch, raw)
	if err != nil {
		return sdk.Result{}, err
	}
	if same(ch.Value, v) {
		return sdk.JSON(map[string]any{"accessory": id, "name": s.name(), "characteristic": t, "value": v, "note": "nothing to change"})
	}
	prev := ch.Value
	if call.DryRun {
		b, _ := json.Marshal(map[string]any{t: value(prev)})
		a, _ := json.Marshal(map[string]any{t: v})
		sum := fmt.Sprintf("Set %s of %s to %v (now %v)", t, s.name(), v, value(prev))
		if criticalCall {
			sum += "; this " + effect(t, v) + " (" + why + ")"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: human(s) + " " + s.name(), Op: "set " + t, Before: b, After: a}}}}, nil
	}
	var after service
	if err := c.do(ctx, http.MethodPut, "/accessories/"+url.PathEscape(id), map[string]any{"characteristicType": t, "value": v}, &after); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"accessory": id, "name": s.name(), "characteristic": t, "value": v, "was": value(prev)}
	res, err := sdk.JSON(out)
	// The previous value goes back through the same action; a value the
	// characteristic didn't report (write-only) can't be put back.
	switch prev.(type) {
	case bool, float64, string:
		res.Undo = sdk.UndoWith(call.Action, map[string]any{"accessory": id, "characteristic": t, "value": prev}, fmt.Sprintf("Set %s of %s back to %v", t, s.name(), value(prev)))
	}
	return res, err
}
