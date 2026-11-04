// Package scrutiny reads disk health from a Scrutiny server through its web
// API: every drive with its SMART and Scrutiny status, temperature and power
// on hours; the attributes that are failing or close to it; one drive's
// latest SMART results; and temperature history over a bounded window.
// Scrutiny has no login of its own, so the module can send a username and
// password for the reverse proxy in front of it.
package scrutiny

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

// Config is one Scrutiny server.
type Config struct {
	URL                string `json:"url"`      // e.g. http://nas.local:8080
	Username           string `json:"username"` // for a reverse proxy with basic auth
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api   *rest.Client
	login bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Scrutiny module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	wwnRe  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

const (
	maxDetails   = 50   // drives whose SMART results are fetched one by one
	maxAttrs     = 200  // attributes reported for one drive
	defPoints    = 100  // temperature points per drive by default
	maxPoints    = 1000 // and at most
	maxRawPoints = 100000
)

var durations = map[string]bool{"week": true, "month": true, "year": true, "forever": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	device := `"device":{"type":"string","description":"Drive: WWN, device name (sda or /dev/sda), serial number or label"}`
	return sdk.Manifest{
		ID: "scrutiny", Name: "Scrutiny", Version: "0.1.0", Category: "Storage", Icon: "disk",
		Description: "Scrutiny disk health: drives with SMART status and temperature, failing and warning attributes, temperature history.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Scrutiny's web address, e.g. http://nas.local:8080 (with its base path, if it has one)"},
			"username":{"type":"string","description":"Only when a reverse proxy in front of Scrutiny asks for a login (basic auth)"},
			"password":{"type":"string","x-secret":true,"description":"That login's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "devices", Title: "Drives", Description: "Every drive with its status (passed, or failed by SMART or by Scrutiny's thresholds), model, serial, capacity, host, temperature, power on hours and when it was last checked.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"includeArchived":{"type":"boolean","default":false}}}`)},
			{Name: "failures", Title: "Failures and warnings", Description: "The SMART attributes that are failing or, with warnings, close to failing, on each drive (or one drive).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + device + `,"includeWarnings":{"type":"boolean","default":true}}}`)},
			{Name: "device", Title: "Drive", Description: "One drive's latest SMART results: every attribute with its value, worst, threshold, raw value and status.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["device"],"properties":{` + device + `}}`)},
			{Name: "temperatures", Title: "Temperature history", Description: "Each drive's minimum, maximum, average and latest temperature over a week, month, year or all time, with up to maxPoints evenly spread readings.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + device + `,
					"duration":{"type":"string","enum":["week","month","year","forever"],"default":"week"},
					"maxPoints":{"type":"integer","minimum":0,"maximum":1000,"default":100,"description":"Readings per drive; 0 for only the summary"}}}`)},
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
		return errors.New("the address is like http://nas.local:8080")
	}
	if strings.TrimSpace(c.Username) != c.Username || strings.Contains(c.Username, ":") || len(c.Username) > 256 || hasControl(c.Username) {
		return errors.New("the username has spaces at the ends, a colon or control characters")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if (c.Username == "") != (c.Password == "") {
		return errors.New("enter both the username and the password, or neither")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h)
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	user, ref := c.Username, c.Password
	var auth func(context.Context, *http.Request) error
	if user != "" {
		auth = func(ctx context.Context, r *http.Request) error {
			pw, err := h.Secret(ctx, ref)
			if err != nil {
				return err
			}
			r.SetBasicAuth(user, pw)
			return nil
		}
	}
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/web")
	api := rest.New(u.Scheme+"://"+u.Host+base, auth)
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, login: user != ""})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		if c.login {
			return errors.New("the login in front of Scrutiny refused the username or password")
		}
		return errors.New("Scrutiny is behind a login: enter its username and password")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no Scrutiny API at this address (check the base path)")
	}
	return err
}

type device struct {
	WWN          string `json:"wwn"`
	Name         string `json:"device_name"`
	Label        string `json:"label"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model_name"`
	Serial       string `json:"serial_number"`
	Firmware     string `json:"firmware"`
	Interface    string `json:"interface_type"`
	Rotation     int    `json:"rotational_speed"`
	Capacity     int64  `json:"capacity"`
	FormFactor   string `json:"form_factor"`
	Protocol     string `json:"device_protocol"`
	Type         string `json:"device_type"`
	HostID       string `json:"host_id"`
	Status       int    `json:"device_status"`
	Archived     bool   `json:"archived"`
	Muted        bool   `json:"muted"`
}

type tempPoint struct {
	Date string  `json:"date"`
	Temp float64 `json:"temp"`
}

type summaryEntry struct {
	Device device `json:"device"`
	Smart  *struct {
		CollectorDate string  `json:"collector_date"`
		Temp          float64 `json:"temp"`
		PowerOnHours  int64   `json:"power_on_hours"`
	} `json:"smart"`
	TempHistory []tempPoint `json:"temp_history"`
}

func (c *conn) summary(ctx context.Context) ([]summaryEntry, error) {
	var res struct {
		Success bool `json:"success"`
		Data    struct {
			Summary map[string]summaryEntry `json:"summary"`
		} `json:"data"`
	}
	if err := c.get(ctx, "/api/summary", nil, &res); err != nil {
		return nil, err
	}
	if !res.Success && res.Data.Summary == nil {
		return nil, errors.New("unexpected answer: is this Scrutiny?")
	}
	out := make([]summaryEntry, 0, len(res.Data.Summary))
	for wwn, e := range res.Data.Summary {
		if e.Device.WWN == "" {
			e.Device.WWN = wwn
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Device, out[j].Device
		if a.HostID != b.HostID {
			return a.HostID < b.HostID
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.WWN < b.WWN
	})
	return out, nil
}

func statusText(s int) string {
	switch {
	case s == 0:
		return "passed"
	case s&1 != 0 && s&2 != 0:
		return "failed (SMART and Scrutiny)"
	case s&1 != 0:
		return "failed (SMART)"
	case s&2 != 0:
		return "failed (Scrutiny)"
	}
	return "unknown"
}

func (d device) title() string {
	n := d.Name
	if d.HostID != "" {
		n = d.HostID + ":" + n
	}
	if d.Label != "" {
		n += " (" + d.Label + ")"
	}
	if n == "" {
		n = d.WWN
	}
	return n
}

func summarize(e summaryEntry) map[string]any {
	d := e.Device
	o := map[string]any{"wwn": d.WWN, "device": d.Name, "model": d.Model, "serial": d.Serial, "capacityBytes": d.Capacity,
		"protocol": d.Protocol, "status": statusText(d.Status), "failing": d.Status != 0}
	for k, v := range map[string]string{"label": d.Label, "host": d.HostID, "manufacturer": d.Manufacturer, "firmware": d.Firmware, "interface": d.Interface, "formFactor": d.FormFactor} {
		if v != "" {
			o[k] = v
		}
	}
	if d.Rotation > 0 {
		o["rpm"] = d.Rotation
	}
	if d.Archived {
		o["archived"] = true
	}
	if d.Muted {
		o["muted"] = true
	}
	if e.Smart != nil {
		o["temperature"] = e.Smart.Temp
		o["powerOnHours"] = e.Smart.PowerOnHours
		o["lastChecked"] = e.Smart.CollectorDate
	}
	return o
}

// find resolves a drive reference against Scrutiny's own list, so only a
// WWN Scrutiny reported (and that passes wwnRe) is put in a URL path.
func find(list []summaryEntry, ref string) (device, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || len(ref) > 256 || hasControl(ref) {
		return device{}, errors.New("name a drive: its WWN, device name, serial number or label")
	}
	name := strings.TrimPrefix(ref, "/dev/")
	var match []device
	for _, e := range list {
		d := e.Device
		if strings.EqualFold(d.WWN, ref) {
			match = []device{d}
			break
		}
		if d.Name == name || strings.EqualFold(d.Serial, ref) || (d.Label != "" && strings.EqualFold(d.Label, ref)) || d.title() == ref {
			match = append(match, d)
		}
	}
	switch {
	case len(match) == 0:
		have := []string{}
		for _, e := range list {
			have = append(have, e.Device.title())
		}
		return device{}, fmt.Errorf("Scrutiny has no drive %s (drives: %s)", ref, strings.Join(have, ", "))
	case len(match) > 1:
		return device{}, fmt.Errorf("more than one drive matches %s (on several hosts?); use its WWN", ref)
	}
	if !wwnRe.MatchString(match[0].WWN) {
		return device{}, fmt.Errorf("the WWN %q can't be used in a request", match[0].WWN)
	}
	return match[0], nil
}

type attr struct {
	ID          any     `json:"attribute_id"`
	Value       float64 `json:"value"`
	Worst       float64 `json:"worst"`
	Thresh      float64 `json:"thresh"`
	Raw         float64 `json:"raw_value"`
	RawString   string  `json:"raw_string"`
	WhenFailed  string  `json:"when_failed"`
	Status      int     `json:"status"`
	Reason      string  `json:"status_reason"`
	FailureRate float64 `json:"failure_rate"`
}

type meta struct {
	Name     string `json:"display_name"`
	Ideal    string `json:"ideal"`
	Critical bool   `json:"critical"`
}

type smartResult struct {
	Date            string          `json:"date"`
	Temp            float64         `json:"temp"`
	PowerOnHours    int64           `json:"power_on_hours"`
	PowerCycleCount int64           `json:"power_cycle_count"`
	Attrs           map[string]attr `json:"attrs"`
	Status          int             `json:"Status"`
}

type details struct {
	Device  device
	Latest  *smartResult
	Meta    map[string]meta
	Results int
}

func (c *conn) details(ctx context.Context, wwn string) (details, error) {
	if !wwnRe.MatchString(wwn) {
		return details{}, errors.New("invalid WWN")
	}
	var res struct {
		Data struct {
			Device       device        `json:"device"`
			SmartResults []smartResult `json:"smart_results"`
		} `json:"data"`
		Metadata map[string]meta `json:"metadata"`
	}
	if err := c.get(ctx, "/api/device/"+url.PathEscape(wwn)+"/details", url.Values{"duration_key": {"week"}}, &res); err != nil {
		return details{}, err
	}
	d := details{Device: res.Data.Device, Meta: res.Metadata, Results: len(res.Data.SmartResults)}
	for i := range res.Data.SmartResults {
		r := &res.Data.SmartResults[i]
		if d.Latest == nil || r.Date > d.Latest.Date {
			d.Latest = r
		}
	}
	return d, nil
}

func attrStatus(s int) []string {
	out := []string{}
	if s&1 != 0 {
		out = append(out, "failed (SMART)")
	}
	if s&4 != 0 {
		out = append(out, "failed (Scrutiny)")
	}
	if s&2 != 0 {
		out = append(out, "warning (Scrutiny)")
	}
	if len(out) == 0 {
		out = append(out, "passed")
	}
	return out
}

func attrOut(key string, a attr, md map[string]meta) map[string]any {
	o := map[string]any{"id": key, "value": a.Value, "worst": a.Worst, "threshold": a.Thresh, "raw": a.Raw, "status": strings.Join(attrStatus(a.Status), ", ")}
	if m, ok := md[key]; ok {
		o["name"] = m.Name
		if m.Critical {
			o["critical"] = true
		}
		if m.Ideal != "" {
			o["ideal"] = m.Ideal
		}
	}
	if a.RawString != "" && a.RawString != strconv.FormatFloat(a.Raw, 'f', -1, 64) {
		o["rawString"] = a.RawString
	}
	if a.Reason != "" {
		o["reason"] = a.Reason
	}
	if a.WhenFailed != "" {
		o["whenFailed"] = a.WhenFailed
	}
	if a.FailureRate > 0 {
		o["failureRate"] = math.Round(a.FailureRate*10000) / 10000
	}
	return o
}

// sortedKeys orders attribute keys numerically (ATA ids) then by name (NVMe
// and SCSI attributes).
func sortedKeys(m map[string]attr) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, ea := strconv.Atoi(keys[i])
		b, eb := strconv.Atoi(keys[j])
		switch {
		case ea == nil && eb == nil:
			return a < b
		case ea == nil:
			return true
		case eb == nil:
			return false
		}
		return keys[i] < keys[j]
	})
	return keys
}

type input struct {
	Device          string `json:"device"`
	IncludeArchived bool   `json:"includeArchived"`
	IncludeWarnings *bool  `json:"includeWarnings"`
	Duration        string `json:"duration"`
	MaxPoints       *int   `json:"maxPoints"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var h struct {
		Success bool `json:"success"`
	}
	if err := c.get(ctx, "/api/health", nil, &h); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if !h.Success {
		return sdk.Health{Status: "down", Message: "Scrutiny reports it isn't healthy (is its InfluxDB reachable?)"}
	}
	list, err := c.summary(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	n := 0
	var failing []string
	for _, e := range list {
		if e.Device.Archived {
			continue
		}
		n++
		if e.Device.Status != 0 && !e.Device.Muted {
			failing = append(failing, e.Device.title())
		}
	}
	msg := fmt.Sprintf("Scrutiny · %d drive(s)", n)
	if len(failing) > 0 {
		return sdk.Health{Status: "degraded", Message: msg + " · failing: " + strings.Join(failing, ", ")}
	}
	return sdk.Health{Status: "ok", Message: msg}
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
	case "devices":
		list, err := c.summary(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range list {
			if e.Device.Archived && !p.IncludeArchived {
				continue
			}
			out = append(out, summarize(e))
		}
		return sdk.JSON(out)

	case "failures":
		return c.failures(ctx, p)

	case "device":
		if strings.TrimSpace(p.Device) == "" {
			return sdk.Result{}, errors.New("name a drive: its WWN, device name, serial number or label")
		}
		list, err := c.summary(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		d, err := find(list, p.Device)
		if err != nil {
			return sdk.Result{}, err
		}
		det, err := c.details(ctx, d.WWN)
		if err != nil {
			return sdk.Result{}, err
		}
		var e summaryEntry
		for _, x := range list {
			if x.Device.WWN == d.WWN {
				e = x
			}
		}
		out := summarize(e)
		attrs := []map[string]any{}
		if r := det.Latest; r != nil {
			out["checked"], out["temperature"], out["powerOnHours"], out["powerCycles"], out["smartStatus"] = r.Date, r.Temp, r.PowerOnHours, r.PowerCycleCount, strings.Join(attrStatus(r.Status), ", ")
			for i, k := range sortedKeys(r.Attrs) {
				if i >= maxAttrs {
					break
				}
				attrs = append(attrs, attrOut(k, r.Attrs[k], det.Meta))
			}
		}
		out["attributes"] = attrs
		return sdk.JSON(out)

	case "temperatures":
		return c.temperatures(ctx, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) failures(ctx context.Context, p input) (sdk.Result, error) {
	warnings := p.IncludeWarnings == nil || *p.IncludeWarnings
	list, err := c.summary(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	var targets []summaryEntry
	if p.Device != "" {
		d, err := find(list, p.Device)
		if err != nil {
			return sdk.Result{}, err
		}
		for _, e := range list {
			if e.Device.WWN == d.WWN {
				targets = append(targets, e)
			}
		}
	} else {
		for _, e := range list {
			if !e.Device.Archived {
				targets = append(targets, e)
			}
		}
	}
	out := []map[string]any{}
	checked, skipped := 0, 0
	for _, e := range targets {
		if checked >= maxDetails || !wwnRe.MatchString(e.Device.WWN) {
			skipped++
			continue
		}
		checked++
		det, err := c.details(ctx, e.Device.WWN)
		if err != nil {
			return sdk.Result{}, err
		}
		bad := []map[string]any{}
		if r := det.Latest; r != nil {
			for _, k := range sortedKeys(r.Attrs) {
				a := r.Attrs[k]
				if a.Status&5 != 0 || (warnings && a.Status&2 != 0) {
					bad = append(bad, attrOut(k, a, det.Meta))
				}
			}
		}
		if len(bad) == 0 && e.Device.Status == 0 {
			continue
		}
		d := summarize(e)
		d["attributes"] = bad
		out = append(out, d)
	}
	res := map[string]any{"checked": checked, "drives": out}
	if skipped > 0 {
		res["notChecked"] = skipped
	}
	return sdk.JSON(res)
}

func (c *conn) temperatures(ctx context.Context, p input) (sdk.Result, error) {
	dur := p.Duration
	if dur == "" {
		dur = "week"
	}
	if !durations[dur] {
		return sdk.Result{}, errors.New(`duration is "week", "month", "year" or "forever"`)
	}
	points := defPoints
	if p.MaxPoints != nil {
		points = *p.MaxPoints
	}
	if points < 0 || points > maxPoints {
		return sdk.Result{}, fmt.Errorf("maxPoints is 0 to %d", maxPoints)
	}
	list, err := c.summary(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	only := ""
	if p.Device != "" {
		d, err := find(list, p.Device)
		if err != nil {
			return sdk.Result{}, err
		}
		only = d.WWN
	}
	var res struct {
		Data struct {
			TempHistory map[string][]tempPoint `json:"temp_history"`
		} `json:"data"`
	}
	hist := map[string][]tempPoint{}
	if err := c.get(ctx, "/api/summary/temp", url.Values{"duration_key": {dur}}, &res); err == nil {
		hist = res.Data.TempHistory
	} else if strings.HasPrefix(err.Error(), "no Scrutiny API") && dur == "week" {
		// Older Scrutiny: the summary carries the last week's readings.
		for _, e := range list {
			hist[e.Device.WWN] = e.TempHistory
		}
	} else {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, e := range list {
		d := e.Device
		if (only != "" && d.WWN != only) || (only == "" && d.Archived) {
			continue
		}
		h := hist[d.WWN]
		if len(h) > maxRawPoints {
			h = h[len(h)-maxRawPoints:]
		}
		sort.SliceStable(h, func(i, j int) bool { return h[i].Date < h[j].Date })
		o := map[string]any{"wwn": d.WWN, "device": d.Name, "readings": len(h)}
		if d.HostID != "" {
			o["host"] = d.HostID
		}
		if d.Label != "" {
			o["label"] = d.Label
		}
		if len(h) > 0 {
			lo, hi, sum := h[0].Temp, h[0].Temp, 0.0
			for _, x := range h {
				lo, hi, sum = math.Min(lo, x.Temp), math.Max(hi, x.Temp), sum+x.Temp
			}
			o["min"], o["max"], o["avg"], o["latest"], o["from"], o["to"] = lo, hi, math.Round(sum/float64(len(h))*10)/10, h[len(h)-1].Temp, h[0].Date, h[len(h)-1].Date
		}
		if points > 0 {
			o["points"] = spread(h, points)
		}
		out = append(out, o)
	}
	return sdk.JSON(map[string]any{"duration": dur, "drives": out})
}

// spread picks at most n readings evenly from h, keeping the first and last.
func spread(h []tempPoint, n int) []tempPoint {
	if len(h) <= n {
		return append([]tempPoint{}, h...)
	}
	out := make([]tempPoint, 0, n)
	if n == 1 {
		return append(out, h[len(h)-1])
	}
	for i := 0; i < n; i++ {
		out = append(out, h[i*(len(h)-1)/(n-1)])
	}
	return out
}
