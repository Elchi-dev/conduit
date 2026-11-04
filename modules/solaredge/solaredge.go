// Package solaredge reads one SolarEdge site through the monitoring API and
// an API key: the site overview (power now, energy today, this month, this
// year and lifetime), energy by meter (production, consumption,
// self-consumption, feed-in, purchased) by day or hour, and an inventory
// summary. It never returns the site's address or coordinates, and changes
// nothing.
package solaredge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one site.
type Config struct {
	APIKey string `json:"apiKey"` // secret:// site or account API key
	SiteID int64  `json:"siteId"`
}

type conn struct {
	api  *rest.Client
	site string
	now  func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://monitoringapi.solaredge.com (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the SolarEdge module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://monitoringapi.solaredge.com"
	maxSite     = 999999999999
	maxDays     = 366 // by day
	maxHourDays = 31  // by hour
	maxValues   = 744 // per meter
	maxDevices  = 100
	dateLayout  = "2006-01-02"
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "solaredge", Name: "SolarEdge", Version: "0.1.0", Category: "Smart home", Icon: "sun",
		Description: "SolarEdge monitoring: power now, energy today, this month and lifetime, energy by meter per day or hour, and the site's inverters, batteries and meters.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey","siteId"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"The API key from the monitoring portal (Admin, Site Access, API Access)"},
			"siteId":{"type":"integer","minimum":1,"description":"The site id, shown in the portal next to the site name and in its address"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "overview", Title: "Overview", Description: "Power now (W), energy today, this month, this year and lifetime (kWh), lifetime revenue, the site's name, status and peak power, and when it last reported.", Risk: sdk.RiskRead},
			{Name: "energy", Title: "Energy by day", Description: "Energy per day (up to 366 days) or per hour (up to 31 days) for each meter the site has: production, consumption, self-consumption, feed-in and purchased, with totals. Dates are the site's local dates.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"start":{"type":"string","format":"date","description":"First day, YYYY-MM-DD (default: 6 days before end)"},"end":{"type":"string","format":"date","description":"Last day, YYYY-MM-DD (default: today)"},"unit":{"type":"string","enum":["day","hour"],"default":"day"}}}`)},
			{Name: "inventory", Title: "Inventory", Description: "Inverters (model, firmware, connected optimizers), batteries (model, capacity), meters, gateways and sensors, with counts. Serial numbers are left out.", Risk: sdk.RiskRead},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	if c.SiteID < 1 || c.SiteID > maxSite {
		return errors.New("the site id is the number shown in the monitoring portal")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	ref := c.APIKey
	// The monitoring API takes the key only as a query parameter. Errors
	// never carry the URL (rest.TransportError cuts the query off).
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		q := r.URL.Query()
		q.Set("api_key", strings.TrimSpace(k))
		r.URL.RawQuery = q.Encode()
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, site: strconv.FormatInt(c.SiteID, 10), now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("SolarEdge refused the API key, or it has no access to this site")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("SolarEdge doesn't know this site id")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("SolarEdge's daily request limit (300 per site) was hit; try again later")
	}
	return err
}

// get reads /site/{id}/<what>; what is a constant from this file.
func (c *conn) get(ctx context.Context, what string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, "/site/"+url.PathEscape(c.site)+"/"+what, q, nil, out)
	return friendly(err)
}

func kwh(p *float64) any {
	if p == nil {
		return nil
	}
	return math.Round(*p/10) / 100
}

func put(e map[string]any, k string, v any) {
	if v != nil {
		e[k] = v
	}
}

type details struct {
	Details struct {
		Name      string   `json:"name"`
		Status    string   `json:"status"`
		PeakPower *float64 `json:"peakPower"`
		Type      string   `json:"type"`
		// Location, address and the account's contacts aren't decoded.
	} `json:"details"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var d details
	if err := c.get(ctx, "details", nil, &d); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := d.Details.Name
	if msg == "" {
		msg = "site " + c.site
	}
	if d.Details.PeakPower != nil {
		msg += fmt.Sprintf(" · %g kWp", *d.Details.PeakPower)
	}
	if s := strings.ToLower(d.Details.Status); s != "" && s != "active" {
		return sdk.Health{Status: "degraded", Message: msg + " · " + s}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Start string `json:"start"`
		End   string `json:"end"`
		Unit  string `json:"unit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "overview":
		return c.overview(ctx)
	case "energy":
		return c.energy(ctx, p.Start, p.End, p.Unit)
	case "inventory":
		return c.inventory(ctx)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) overview(ctx context.Context) (sdk.Result, error) {
	type data struct {
		Energy  *float64 `json:"energy"`
		Revenue *float64 `json:"revenue"`
	}
	var o struct {
		Overview struct {
			LastUpdateTime string `json:"lastUpdateTime"`
			LifeTime       data   `json:"lifeTimeData"`
			LastYear       data   `json:"lastYearData"`
			LastMonth      data   `json:"lastMonthData"`
			LastDay        data   `json:"lastDayData"`
			CurrentPower   struct {
				Power *float64 `json:"power"`
			} `json:"currentPower"`
			MeasuredBy string `json:"measuredBy"`
		} `json:"overview"`
	}
	if err := c.get(ctx, "overview", nil, &o); err != nil {
		return sdk.Result{}, err
	}
	v := o.Overview
	out := map[string]any{"site": c.site, "lastUpdate": v.LastUpdateTime}
	if v.CurrentPower.Power != nil {
		out["powerW"] = math.Round(*v.CurrentPower.Power*10) / 10
	}
	put(out, "todayKWh", kwh(v.LastDay.Energy))
	put(out, "monthKWh", kwh(v.LastMonth.Energy))
	put(out, "yearKWh", kwh(v.LastYear.Energy))
	put(out, "lifetimeKWh", kwh(v.LifeTime.Energy))
	if v.LifeTime.Revenue != nil {
		out["lifetimeRevenue"] = math.Round(*v.LifeTime.Revenue*100) / 100
	}
	if v.MeasuredBy != "" {
		out["measuredBy"] = strings.ToLower(v.MeasuredBy)
	}
	var d details
	if c.get(ctx, "details", nil, &d) == nil {
		if d.Details.Name != "" {
			out["name"] = d.Details.Name
		}
		if d.Details.Status != "" {
			out["status"] = strings.ToLower(d.Details.Status)
		}
		if d.Details.PeakPower != nil {
			out["peakPowerKWp"] = *d.Details.PeakPower
		}
	}
	return sdk.JSON(out)
}

func (c *conn) energy(ctx context.Context, start, end, unit string) (sdk.Result, error) {
	tu, limit := "DAY", maxDays
	switch unit {
	case "", "day":
	case "hour":
		tu, limit = "HOUR", maxHourDays
	default:
		return sdk.Result{}, errors.New("unit is day or hour")
	}
	today := c.now()
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	e := today
	if end != "" {
		t, err := time.Parse(dateLayout, end)
		if err != nil {
			return sdk.Result{}, errors.New("end is a date like 2026-11-04")
		}
		e = t
	}
	s := e.AddDate(0, 0, -6)
	if tu == "HOUR" {
		s = e
	}
	if start != "" {
		t, err := time.Parse(dateLayout, start)
		if err != nil {
			return sdk.Result{}, errors.New("start is a date like 2026-11-01")
		}
		s = t
	}
	if s.After(e) {
		return sdk.Result{}, errors.New("start is after end")
	}
	if days := int(e.Sub(s).Hours()/24) + 1; days > limit {
		return sdk.Result{}, fmt.Errorf("by %s, the range is at most %d days", strings.ToLower(tu), limit)
	}
	if e.After(today.AddDate(0, 0, 1)) {
		return sdk.Result{}, errors.New("end is in the future")
	}
	q := url.Values{"timeUnit": {tu}, "startTime": {s.Format(dateLayout) + " 00:00:00"}, "endTime": {e.Format(dateLayout) + " 23:59:59"}}
	var r struct {
		EnergyDetails struct {
			TimeUnit string `json:"timeUnit"`
			Unit     string `json:"unit"`
			Meters   []struct {
				Type   string `json:"type"`
				Values []struct {
					Date  string   `json:"date"`
					Value *float64 `json:"value"`
				} `json:"values"`
			} `json:"meters"`
		} `json:"energyDetails"`
	}
	if err := c.get(ctx, "energyDetails", q, &r); err != nil {
		return sdk.Result{}, err
	}
	div := 1000.0 // Wh → kWh
	switch strings.ToLower(r.EnergyDetails.Unit) {
	case "kwh":
		div = 1
	case "mwh":
		div = 0.001
	}
	meters := map[string]any{}
	totals := map[string]any{}
	for _, mt := range r.EnergyDetails.Meters {
		if mt.Type == "" || len(meters) >= 10 {
			continue
		}
		name := strings.ToLower(mt.Type[:1]) + mt.Type[1:] // selfConsumption, feedIn
		vals := mt.Values
		if len(vals) > maxValues {
			vals = vals[:maxValues]
		}
		list := []map[string]any{}
		sum := 0.0
		for _, v := range vals {
			row := map[string]any{"date": v.Date}
			if v.Value != nil {
				row["kWh"] = math.Round(*v.Value/div*1000) / 1000
				sum += *v.Value / div
			}
			list = append(list, row)
		}
		meters[name] = list
		totals[name] = math.Round(sum*1000) / 1000
	}
	return sdk.JSON(map[string]any{"site": c.site, "unit": strings.ToLower(tu), "start": s.Format(dateLayout), "end": e.Format(dateLayout), "totalsKWh": totals, "meters": meters})
}

func (c *conn) inventory(ctx context.Context) (sdk.Result, error) {
	// Decoded field by field: serial numbers aren't read.
	type dev struct {
		Name          string   `json:"name"`
		Manufacturer  string   `json:"manufacturer"`
		Model         string   `json:"model"`
		Firmware      string   `json:"firmwareVersion"`
		CPU           string   `json:"cpuVersion"`
		Optimizers    *int     `json:"connectedOptimizers"`
		Capacity      *float64 `json:"nameplateCapacity"`
		Type          string   `json:"type"`
		Form          string   `json:"form"`
		Communication string   `json:"communicationMethod"`
	}
	var r struct {
		Inventory struct {
			Inverters []dev `json:"inverters"`
			Batteries []dev `json:"batteries"`
			Meters    []dev `json:"meters"`
			Gateways  []dev `json:"gateways"`
			Sensors   []dev `json:"sensors"`
		} `json:"Inventory"`
	}
	if err := c.get(ctx, "inventory", nil, &r); err != nil {
		return sdk.Result{}, err
	}
	list := func(ds []dev, kind string) []map[string]any {
		out := []map[string]any{}
		for i, d := range ds {
			if i >= maxDevices {
				break
			}
			e := map[string]any{}
			for k, v := range map[string]string{"name": d.Name, "manufacturer": d.Manufacturer, "model": d.Model, "type": d.Type, "form": d.Form, "communication": d.Communication} {
				if v != "" {
					e[k] = v
				}
			}
			if fw := d.Firmware; fw != "" {
				e["firmware"] = fw
			} else if d.CPU != "" {
				e["firmware"] = d.CPU
			}
			if d.Optimizers != nil && kind == "inverter" {
				e["optimizers"] = *d.Optimizers
			}
			if d.Capacity != nil && kind == "battery" {
				e["capacityWh"] = *d.Capacity
			}
			out = append(out, e)
		}
		return out
	}
	inv := r.Inventory
	opt := 0
	for _, d := range inv.Inverters {
		if d.Optimizers != nil {
			opt += *d.Optimizers
		}
	}
	return sdk.JSON(map[string]any{
		"site": c.site,
		"counts": map[string]int{"inverters": len(inv.Inverters), "optimizers": opt, "batteries": len(inv.Batteries), "meters": len(inv.Meters),
			"gateways": len(inv.Gateways), "sensors": len(inv.Sensors)},
		"inverters": list(inv.Inverters, "inverter"), "batteries": list(inv.Batteries, "battery"), "meters": list(inv.Meters, "meter"),
		"gateways": list(inv.Gateways, "gateway"), "sensors": list(inv.Sensors, "sensor"),
	})
}
