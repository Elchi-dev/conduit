// Package librenms works with a LibreNMS network monitor through its API
// with a token: devices, ports, alerts, and acknowledging or unmuting an
// alert. Devices are decoded field by field, so SNMP communities and
// credentials never pass through.
package librenms

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
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one LibreNMS.
type Config struct {
	URL                string `json:"url"`   // e.g. https://librenms.example.com
	Token              string `json:"token"` // secret:// API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the LibreNMS module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	deviceRe = regexp.MustCompile(`^(?i)[0-9]{1,10}$|^[a-z0-9]([a-z0-9_-]{0,62})?(\.[a-z0-9_]([a-z0-9_-]{0,62})?)*$|^[0-9a-f:]{2,39}$`)
)

// Alert states.
var states = map[int]string{0: "ok", 1: "alerting", 2: "acknowledged", 3: "worse", 4: "better", 5: "changed"}

const portColumns = "port_id,device_id,ifName,ifAlias,ifDescr,ifOperStatus,ifAdminStatus,ifSpeed,ifInOctets_rate,ifOutOctets_rate,ifInErrors_delta,ifOutErrors_delta,ifLastChange,deleted,disabled,ignore"

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	alert := `{"type":"object","required":["alert"],"properties":{"alert":{"type":"integer","description":"Alert id (from alerts)"}%s}}`
	return sdk.Manifest{
		ID: "librenms", Name: "LibreNMS", Version: "0.1.0", Category: "Monitoring", Icon: "network",
		Description: "LibreNMS: monitored devices, ports and their traffic, alerts; acknowledge or unmute an alert.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"LibreNMS's address, e.g. https://librenms.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API token (Settings, API, API Settings, Create API access token); it acts with its user's rights"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "devices", Title: "Devices", Description: "Each device: id, host name, system name, OS and version, hardware, location, up or down (and why), uptime, last polled, disabled or ignored. Never SNMP communities or credentials.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"down":{"type":"boolean","description":"Only devices that are down"}}}`)},
			{Name: "ports", Title: "Ports", Description: "Ports of one device, or all: name, alias, admin and operational status, speed, traffic rates and errors. Deleted ports are left out.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"device":{"type":"string","description":"Device id or host name (default every device)"},"down":{"type":"boolean","description":"Only ports that are up by admin and down operationally"}}}`)},
			{Name: "alerts", Title: "Alerts", Description: "Alerts that are alerting (default), acknowledged, or all: id, device, rule, severity, state, since when.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"state":{"type":"string","enum":["alerting","acknowledged","all"],"default":"alerting"}}}`)},
			{Name: "ack_alert", Title: "Acknowledge an alert", Description: "Marks an alert acknowledged, which stops its notifications (until it clears, or for good). Undo unmutes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(fmt.Sprintf(alert, `,"note":{"type":"string","maxLength":500},"untilClear":{"type":"boolean","default":true,"description":"Notify again if the alert clears and comes back (false: stay acknowledged)"}`))},
			{Name: "unmute_alert", Title: "Unmute an alert", Description: "Puts an acknowledged alert back to alerting, so its notifications start again. Undo acknowledges it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(fmt.Sprintf(alert, ""))},
		},
		Resources: []sdk.ResourceSpec{
			{Kind: "device", Title: "Devices", ListAction: "devices", ViewHint: "table"},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.URL), "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is LibreNMS's, like https://librenms.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	ref := c.Token
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v0")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api/v0", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-Auth-Token", strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	var raw json.RawMessage
	_, err := c.api.Do(ctx, method, path, q, body, &raw)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("LibreNMS refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token's user isn't allowed to do this in LibreNMS")
	case err != nil:
		return err
	}
	var st struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &st)
	if st.Status == "error" {
		return fmt.Errorf("LibreNMS: %s", rest.Redact(st.Message))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("unexpected answer from LibreNMS: %w", err)
		}
	}
	return nil
}

// flex reads numbers and strings LibreNMS sends either way.
type flex string

func (f *flex) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case string:
		*f = flex(x)
	case float64:
		*f = flex(strconv.FormatFloat(x, 'f', -1, 64))
	case bool:
		if x {
			*f = "1"
		} else {
			*f = "0"
		}
	default:
		*f = ""
	}
	return nil
}

func (f flex) int() int64 { n, _ := strconv.ParseFloat(string(f), 64); return int64(n) }
func (f flex) yes() bool  { return f == "1" || f == "true" }

// device is decoded field by field: the API's device also holds the SNMP
// community and v3 auth and crypto passwords.
type device struct {
	ID           flex `json:"device_id"`
	Hostname     flex `json:"hostname"`
	SysName      flex `json:"sysName"`
	Display      flex `json:"display"`
	OS           flex `json:"os"`
	Version      flex `json:"version"`
	Hardware     flex `json:"hardware"`
	Location     flex `json:"location"`
	Status       flex `json:"status"`
	StatusReason flex `json:"status_reason"`
	Uptime       flex `json:"uptime"`
	LastPolled   flex `json:"last_polled"`
	Disabled     flex `json:"disabled"`
	Ignore       flex `json:"ignore"`
	Type         flex `json:"type"`
}

func (d device) label() string {
	for _, s := range []flex{d.Display, d.SysName, d.Hostname} {
		if s != "" {
			return string(s)
		}
	}
	return string(d.ID)
}

func (c *conn) devices(ctx context.Context) ([]device, error) {
	var r struct {
		Devices []device `json:"devices"`
	}
	if err := c.do(ctx, http.MethodGet, "/devices", nil, nil, &r); err != nil {
		return nil, err
	}
	return r.Devices, nil
}

type alert struct {
	ID        flex `json:"id"`
	DeviceID  flex `json:"device_id"`
	RuleID    flex `json:"rule_id"`
	State     flex `json:"state"`
	Severity  flex `json:"severity"`
	Timestamp flex `json:"timestamp"`
	Hostname  flex `json:"hostname"`
	Name      flex `json:"name"`
	Open      flex `json:"open"`
	Alerted   flex `json:"alerted"`
}

func (c *conn) alert(ctx context.Context, id int64) (alert, error) {
	var r struct {
		Alerts []alert `json:"alerts"`
	}
	if err := c.do(ctx, http.MethodGet, "/alerts/"+url.PathEscape(strconv.FormatInt(id, 10)), nil, nil, &r); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return alert{}, fmt.Errorf("there's no alert %d", id)
		}
		return alert{}, err
	}
	if len(r.Alerts) == 0 || r.Alerts[0].ID.int() != id {
		return alert{}, fmt.Errorf("there's no alert %d", id)
	}
	return r.Alerts[0], nil
}

// names maps rule and device ids to names, for alerts that carry ids.
func (c *conn) names(ctx context.Context) (map[string]string, map[string]string) {
	rules, devs := map[string]string{}, map[string]string{}
	var r struct {
		Rules []struct {
			ID   flex `json:"id"`
			Name flex `json:"name"`
		} `json:"rules"`
	}
	if c.do(ctx, http.MethodGet, "/rules", nil, nil, &r) == nil {
		for _, x := range r.Rules {
			rules[string(x.ID)] = string(x.Name)
		}
	}
	if ds, err := c.devices(ctx); err == nil {
		for _, d := range ds {
			devs[string(d.ID)] = d.label()
		}
	}
	return rules, devs
}

func (a alert) out(rules, devs map[string]string) map[string]any {
	st := states[int(a.State.int())]
	if st == "" {
		st = string(a.State)
	}
	o := map[string]any{"id": a.ID.int(), "state": st, "severity": string(a.Severity), "since": string(a.Timestamp)}
	o["rule"] = firstOf(string(a.Name), rules[string(a.RuleID)], string(a.RuleID))
	o["device"] = firstOf(devs[string(a.DeviceID)], string(a.Hostname), string(a.DeviceID))
	return o
}

func firstOf(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ds, err := c.devices(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no LibreNMS API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	down := 0
	for _, d := range ds {
		if !d.Status.yes() && !d.Disabled.yes() && !d.Ignore.yes() {
			down++
		}
	}
	msg := fmt.Sprintf("%d devices", len(ds))
	if down > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s, %d down", msg, down)}
	}
	return sdk.Health{Status: "ok", Message: msg + ", all up"}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Down       bool   `json:"down"`
		Device     string `json:"device"`
		State      string `json:"state"`
		Alert      int64  `json:"alert"`
		Note       string `json:"note"`
		UntilClear *bool  `json:"untilClear"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "devices":
		ds, err := c.devices(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range ds {
			if p.Down && (d.Status.yes() || d.Disabled.yes() || d.Ignore.yes()) {
				continue
			}
			row := map[string]any{"id": d.ID.int(), "name": d.label(), "hostname": string(d.Hostname), "sysName": string(d.SysName), "os": string(d.OS),
				"version": string(d.Version), "hardware": string(d.Hardware), "type": string(d.Type), "location": string(d.Location), "up": d.Status.yes(),
				"uptimeSeconds": d.Uptime.int(), "lastPolled": string(d.LastPolled), "disabled": d.Disabled.yes(), "ignored": d.Ignore.yes()}
			if !d.Status.yes() && d.StatusReason != "" {
				row["downReason"] = string(d.StatusReason)
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "ports":
		p.Device = strings.TrimSpace(p.Device)
		if p.Device != "" && !deviceRe.MatchString(p.Device) {
			return sdk.Result{}, errors.New("the device is its id or host name")
		}
		path := "/ports"
		if p.Device != "" {
			path = "/devices/" + url.PathEscape(p.Device) + "/ports"
		}
		var r struct {
			Ports []map[string]flex `json:"ports"`
		}
		if err := c.do(ctx, http.MethodGet, path, url.Values{"columns": {portColumns}}, nil, &r); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) && p.Device != "" {
				return sdk.Result{}, fmt.Errorf("there's no device %s", p.Device)
			}
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range r.Ports {
			if x["deleted"].yes() {
				continue
			}
			if p.Down && (x["ifAdminStatus"] != "up" || x["ifOperStatus"] == "up") {
				continue
			}
			row := map[string]any{"id": x["port_id"].int(), "deviceId": x["device_id"].int(), "name": firstOf(string(x["ifName"]), string(x["ifDescr"])),
				"admin": string(x["ifAdminStatus"]), "oper": string(x["ifOperStatus"]), "speedBitsPerSecond": x["ifSpeed"].int(),
				"inBytesPerSecond": x["ifInOctets_rate"].int(), "outBytesPerSecond": x["ifOutOctets_rate"].int(),
				"inErrors": x["ifInErrors_delta"].int(), "outErrors": x["ifOutErrors_delta"].int()}
			if a := string(x["ifAlias"]); a != "" && a != string(x["ifName"]) {
				row["alias"] = a
			}
			if x["disabled"].yes() || x["ignore"].yes() {
				row["ignored"] = true
			}
			out = append(out, row)
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["deviceId"].(int64) < out[j]["deviceId"].(int64) })
		return sdk.JSON(out)

	case "alerts":
		q := url.Values{}
		switch p.State {
		case "", "alerting":
			q.Set("state", "1")
		case "acknowledged":
			q.Set("state", "2")
		case "all":
		default:
			return sdk.Result{}, errors.New("the state is alerting, acknowledged or all")
		}
		var r struct {
			Alerts []alert `json:"alerts"`
		}
		if err := c.do(ctx, http.MethodGet, "/alerts", q, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		rules, devs := c.names(ctx)
		out := []map[string]any{}
		for _, a := range r.Alerts {
			out = append(out, a.out(rules, devs))
		}
		return sdk.JSON(out)

	case "ack_alert", "unmute_alert":
		if p.Alert <= 0 || p.Alert > 1<<40 {
			return sdk.Result{}, errors.New("the alert is its id from alerts")
		}
		p.Note = strings.TrimSpace(p.Note)
		if len(p.Note) > 500 || strings.ContainsFunc(p.Note, func(r rune) bool { return r < 0x20 && r != '\n' || r == 0x7f }) {
			return sdk.Result{}, errors.New("the note is text of up to 500 characters")
		}
		return c.setAck(ctx, call, p.Alert, p.Note, p.UntilClear == nil || *p.UntilClear)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) setAck(ctx context.Context, call sdk.Call, id int64, note string, untilClear bool) (sdk.Result, error) {
	ack := call.Action == "ack_alert"
	a, err := c.alert(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	state := a.State.int()
	if ack && state == 2 || !ack && state != 2 {
		st := states[int(state)]
		return sdk.JSON(map[string]any{"alert": id, "state": st, "note": "nothing to change"})
	}
	if ack && state == 0 {
		return sdk.Result{}, fmt.Errorf("alert %d has cleared; there's nothing to acknowledge", id)
	}
	rules, devs := c.names(ctx)
	o := a.out(rules, devs)
	target := fmt.Sprintf("alert %d (%v on %v, %v)", id, o["rule"], o["device"], o["severity"])
	verb, back := "Acknowledge", "unmute_alert"
	if !ack {
		verb, back = "Unmute", "ack_alert"
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]string{"state": o["state"].(string)})
		after := "acknowledged"
		if !ack {
			after = "alerting"
		}
		x, _ := json.Marshal(map[string]string{"state": after})
		sum := verb + " " + target
		if ack {
			sum += "; its notifications stop"
			if !untilClear {
				sum += " for good"
			}
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: strings.ToLower(verb), Before: b, After: x}}}}, nil
	}
	path := "/alerts/" + url.PathEscape(strconv.FormatInt(id, 10))
	var body any = map[string]any{"note": note, "until_clear": untilClear}
	if !ack {
		path = "/alerts/unmute/" + url.PathEscape(strconv.FormatInt(id, 10))
		body = map[string]any{}
	}
	if err := c.do(ctx, http.MethodPut, path, nil, body, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"alert": id, "rule": o["rule"], "device": o["device"], "acknowledged": ack})
	undo := "Unmute alert " + strconv.FormatInt(id, 10)
	if !ack {
		undo = "Acknowledge alert " + strconv.FormatInt(id, 10) + " again"
	}
	res.Undo = sdk.UndoWith(back, map[string]int64{"alert": id}, undo)
	return res, err
}
