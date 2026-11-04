// Package weather reads current conditions and forecasts from Open-Meteo
// (open-meteo.com, or a self-hosted copy) for the places in its settings:
// current weather, hourly precipitation, daily highs and lows and, when
// turned on, air quality. It needs no key and changes nothing.
package weather

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Place is a named location.
type Place struct {
	Name      string  `json:"name"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// Config is one set of places and where to ask about them.
type Config struct {
	URL           string  `json:"url"`           // default https://api.open-meteo.com
	AirQuality    bool    `json:"airQuality"`    // also offer air quality
	AirQualityURL string  `json:"airQualityUrl"` // default https://air-quality-api.open-meteo.com
	Units         string  `json:"units"`         // "metric" (default) or "imperial"
	Places        []Place `json:"places"`
}

type conn struct {
	http     *http.Client
	forecast string // base of /v1/forecast
	air      string // base of /v1/air-quality, "" when off
	imperial bool
	places   []Place
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the weather module.
func New() *Module { return &Module{} }

const (
	defaultURL    = "https://api.open-meteo.com"
	defaultAirURL = "https://air-quality-api.open-meteo.com"
	maxPlaces     = 10
	maxName       = 64
)

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	where := `"place":{"type":"string","description":"A place name from settings (see places)"},` +
		`"latitude":{"type":"number","minimum":-90,"maximum":90},"longitude":{"type":"number","minimum":-180,"maximum":180}`
	return sdk.Manifest{
		ID: "weather", Name: "Weather", Version: "0.1.0", Category: "Productivity", Icon: "weather",
		Description: "Current weather, rain in the next hours, the week's highs and lows and air quality for your places, from Open-Meteo.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["places"],"properties":{
			"places":{"type":"array","minItems":1,"maxItems":10,"description":"The places to report on; the first is the default","items":{"type":"object","required":["name","latitude","longitude"],"properties":{
				"name":{"type":"string","description":"e.g. Home, Office, Berlin"},
				"latitude":{"type":"number","minimum":-90,"maximum":90},
				"longitude":{"type":"number","minimum":-180,"maximum":180}}}},
			"units":{"type":"string","enum":["metric","imperial"],"default":"metric","description":"°C, km/h and mm, or °F, mph and inches"},
			"airQuality":{"type":"boolean","default":false,"description":"Also report air quality (European and US AQI, particulates, ozone)"},
			"url":{"type":"string","default":"https://api.open-meteo.com","description":"Open-Meteo's address; change it for a self-hosted copy"},
			"airQualityUrl":{"type":"string","default":"https://air-quality-api.open-meteo.com","description":"The air quality API's address"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "places", Title: "Places", Description: "The names of the places in settings, the first being the default (never their coordinates).", Risk: sdk.RiskRead},
			{Name: "today", Title: "Today", Description: "A line per place for the day: now, today's high and low, and the chance of rain in the next 12 hours.", Risk: sdk.RiskRead},
			{Name: "current", Title: "Current weather", Description: "Temperature, feels-like, conditions, humidity, wind and precipitation now, for a place (default: the first) or coordinates.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + where + `}}`)},
			{Name: "precipitation", Title: "Rain, next hours", Description: "Hour by hour for the next 12 hours (up to 48): chance of precipitation, amount, temperature and conditions.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + where + `,"hours":{"type":"integer","minimum":1,"maximum":48,"default":12}}}`)},
			{Name: "forecast", Title: "Daily forecast", Description: "Day by day for the next 7 days (up to 16): high, low, conditions, precipitation, sunrise and sunset.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + where + `,"days":{"type":"integer","minimum":1,"maximum":16,"default":7}}}`)},
			{Name: "air_quality", Title: "Air quality", Description: "European and US air quality index with particulates, ozone and nitrogen dioxide now. Only when turned on in settings.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + where + `}}`)},
		},
	}
}

func base(raw, def string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		s = def
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return "", fmt.Errorf("%q isn't an address like %s", s, def)
	}
	return u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/v1"), nil
}

func validCoord(lat, lon float64) bool {
	return !math.IsNaN(lat) && !math.IsNaN(lon) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	fc, err := base(c.URL, defaultURL)
	if err != nil {
		return err
	}
	cn := &conn{forecast: fc}
	if c.AirQuality {
		if cn.air, err = base(c.AirQualityURL, defaultAirURL); err != nil {
			return err
		}
	}
	switch c.Units {
	case "", "metric":
	case "imperial":
		cn.imperial = true
	default:
		return errors.New("units are metric or imperial")
	}
	if len(c.Places) == 0 || len(c.Places) > maxPlaces {
		return fmt.Errorf("add 1 to %d places, each with a name, latitude and longitude", maxPlaces)
	}
	seen := map[string]bool{}
	for _, p := range c.Places {
		p.Name = strings.TrimSpace(p.Name)
		if p.Name == "" || len([]rune(p.Name)) > maxName {
			return fmt.Errorf("each place has a name of 1 to %d characters", maxName)
		}
		if !validCoord(p.Latitude, p.Longitude) {
			return fmt.Errorf("%s: latitude is -90 to 90 and longitude -180 to 180", p.Name)
		}
		if k := strings.ToLower(p.Name); seen[k] {
			return fmt.Errorf("there are two places called %s", p.Name)
		} else {
			seen[k] = true
		}
		cn.places = append(cn.places, p)
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 15*time.Second)
	}
	cn.http = rest.SameHostOnly(client)
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// get asks Open-Meteo and decodes the answer, passing on its reason for a
// refusal ({"error":true,"reason":"…"}).
func (c *conn) get(ctx context.Context, baseURL, path string, q url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	res, err := c.http.Do(req)
	if err != nil {
		return rest.TransportError(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		var e struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Reason != "" {
			r := []rune(rest.Redact(e.Reason))
			if len(r) > 200 {
				r = append(r[:200], '…')
			}
			return fmt.Errorf("Open-Meteo: %s", string(r))
		}
		if res.StatusCode == http.StatusNotFound {
			return errors.New("no Open-Meteo API at this address")
		}
		return fmt.Errorf("Open-Meteo answered %s", res.Status)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("unexpected answer from Open-Meteo: %w", err)
	}
	return nil
}

type input struct {
	Place     string   `json:"place"`
	Latitude  *float64 `json:"latitude"`
	Longitude *float64 `json:"longitude"`
	Hours     int      `json:"hours"`
	Days      int      `json:"days"`
}

// where picks the place a call is about: a configured place by name,
// coordinates in range, or the first place.
func (c *conn) where(p input) (Place, error) {
	name := strings.TrimSpace(p.Place)
	if name != "" && (p.Latitude != nil || p.Longitude != nil) {
		return Place{}, errors.New("give a place or coordinates, not both")
	}
	if p.Latitude != nil || p.Longitude != nil {
		if p.Latitude == nil || p.Longitude == nil {
			return Place{}, errors.New("give both latitude and longitude")
		}
		if !validCoord(*p.Latitude, *p.Longitude) {
			return Place{}, errors.New("latitude is -90 to 90 and longitude -180 to 180")
		}
		return Place{Name: fmt.Sprintf("%.4f, %.4f", *p.Latitude, *p.Longitude), Latitude: *p.Latitude, Longitude: *p.Longitude}, nil
	}
	if name == "" {
		return c.places[0], nil
	}
	for _, pl := range c.places {
		if strings.EqualFold(pl.Name, name) {
			return pl, nil
		}
	}
	names := []string{}
	for _, pl := range c.places {
		names = append(names, pl.Name)
	}
	return Place{}, fmt.Errorf("there's no place called %q in settings (there's %s); or give latitude and longitude", name, strings.Join(names, ", "))
}

func (c *conn) query(pl Place) url.Values {
	q := url.Values{
		"latitude":  {strconv.FormatFloat(pl.Latitude, 'f', 4, 64)},
		"longitude": {strconv.FormatFloat(pl.Longitude, 'f', 4, 64)},
		"timezone":  {"auto"},
	}
	if c.imperial {
		q.Set("temperature_unit", "fahrenheit")
		q.Set("wind_speed_unit", "mph")
		q.Set("precipitation_unit", "inch")
	}
	return q
}

func (c *conn) units() map[string]string {
	if c.imperial {
		return map[string]string{"temperature": "°F", "wind": "mph", "precipitation": "inch"}
	}
	return map[string]string{"temperature": "°C", "wind": "km/h", "precipitation": "mm"}
}

// num is a value Open-Meteo may leave null.
type num = *float64

type forecast struct {
	Timezone string `json:"timezone"`
	Current  struct {
		Time        string `json:"time"`
		Temperature num    `json:"temperature_2m"`
		Humidity    num    `json:"relative_humidity_2m"`
		FeelsLike   num    `json:"apparent_temperature"`
		Precip      num    `json:"precipitation"`
		Code        num    `json:"weather_code"`
		Wind        num    `json:"wind_speed_10m"`
		WindDir     num    `json:"wind_direction_10m"`
		IsDay       num    `json:"is_day"`
	} `json:"current"`
	Hourly struct {
		Time        []string `json:"time"`
		Temperature []num    `json:"temperature_2m"`
		Chance      []num    `json:"precipitation_probability"`
		Precip      []num    `json:"precipitation"`
		Code        []num    `json:"weather_code"`
	} `json:"hourly"`
	Daily struct {
		Time    []string `json:"time"`
		Code    []num    `json:"weather_code"`
		Max     []num    `json:"temperature_2m_max"`
		Min     []num    `json:"temperature_2m_min"`
		Precip  []num    `json:"precipitation_sum"`
		Chance  []num    `json:"precipitation_probability_max"`
		Sunrise []string `json:"sunrise"`
		Sunset  []string `json:"sunset"`
	} `json:"daily"`
}

const (
	currentVars = "temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,weather_code,wind_speed_10m,wind_direction_10m,is_day"
	hourlyVars  = "temperature_2m,precipitation_probability,precipitation,weather_code"
	dailyVars   = "weather_code,temperature_2m_max,temperature_2m_min,precipitation_sum,precipitation_probability_max,sunrise,sunset"
)

func at[T any](s []T, i int) (T, bool) {
	var zero T
	if i < 0 || i >= len(s) {
		return zero, false
	}
	return s[i], true
}

func val(n num) any {
	if n == nil {
		return nil
	}
	return math.Round(*n*10) / 10
}

func cond(n num) string {
	if n == nil {
		return ""
	}
	return condition(int(*n))
}

func (c *conn) fetch(ctx context.Context, q url.Values) (forecast, error) {
	var f forecast
	err := c.get(ctx, c.forecast, "/v1/forecast", q, &f)
	return f, err
}

func (c *conn) current(ctx context.Context, pl Place) (map[string]any, error) {
	q := c.query(pl)
	q.Set("current", currentVars)
	f, err := c.fetch(ctx, q)
	if err != nil {
		return nil, err
	}
	cur := f.Current
	out := map[string]any{"place": pl.Name, "time": cur.Time, "timezone": f.Timezone, "units": c.units(),
		"temperature": val(cur.Temperature), "feelsLike": val(cur.FeelsLike), "conditions": cond(cur.Code),
		"humidity": val(cur.Humidity), "wind": val(cur.Wind), "windFrom": compass(cur.WindDir), "precipitation": val(cur.Precip)}
	if cur.IsDay != nil {
		out["daylight"] = *cur.IsDay == 1
	}
	return out, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	cur, err := c.current(ctx, c.places[0])
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := c.places[0].Name
	if t, ok := cur["temperature"].(float64); ok {
		msg += fmt.Sprintf(": %g%s", t, c.units()["temperature"])
	}
	if s, _ := cur["conditions"].(string); s != "" {
		msg += ", " + strings.ToLower(s)
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
	case "places":
		// Names only: the coordinates in settings are where people live
		// and work, and outputs go to the audit log and events.
		out := []map[string]any{}
		for i, pl := range c.places {
			out = append(out, map[string]any{"name": pl.Name, "default": i == 0})
		}
		return sdk.JSON(out)

	case "today":
		out := []map[string]any{}
		for _, pl := range c.places {
			d, err := c.today(ctx, pl)
			if err != nil {
				return sdk.Result{}, fmt.Errorf("%s: %w", pl.Name, err)
			}
			out = append(out, d)
		}
		return sdk.JSON(map[string]any{"places": out, "units": c.units()})

	case "current":
		pl, err := c.where(p)
		if err != nil {
			return sdk.Result{}, err
		}
		cur, err := c.current(ctx, pl)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(cur)

	case "precipitation":
		pl, err := c.where(p)
		if err != nil {
			return sdk.Result{}, err
		}
		hours := p.Hours
		if hours == 0 {
			hours = 12
		}
		if hours < 1 || hours > 48 {
			return sdk.Result{}, errors.New("hours is 1 to 48")
		}
		q := c.query(pl)
		q.Set("hourly", hourlyVars)
		q.Set("forecast_hours", strconv.Itoa(hours))
		f, err := c.fetch(ctx, q)
		if err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for i, t := range f.Hourly.Time {
			if i == hours {
				break
			}
			chance, _ := at(f.Hourly.Chance, i)
			amount, _ := at(f.Hourly.Precip, i)
			temp, _ := at(f.Hourly.Temperature, i)
			code, _ := at(f.Hourly.Code, i)
			rows = append(rows, map[string]any{"time": t, "chance": val(chance), "amount": val(amount), "temperature": val(temp), "conditions": cond(code)})
		}
		return sdk.JSON(map[string]any{"place": pl.Name, "timezone": f.Timezone, "units": c.units(), "hours": rows})

	case "forecast":
		pl, err := c.where(p)
		if err != nil {
			return sdk.Result{}, err
		}
		days := p.Days
		if days == 0 {
			days = 7
		}
		if days < 1 || days > 16 {
			return sdk.Result{}, errors.New("days is 1 to 16")
		}
		q := c.query(pl)
		q.Set("daily", dailyVars)
		q.Set("forecast_days", strconv.Itoa(days))
		f, err := c.fetch(ctx, q)
		if err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for i, d := range f.Daily.Time {
			if i == days {
				break
			}
			hi, _ := at(f.Daily.Max, i)
			lo, _ := at(f.Daily.Min, i)
			code, _ := at(f.Daily.Code, i)
			amount, _ := at(f.Daily.Precip, i)
			chance, _ := at(f.Daily.Chance, i)
			rise, _ := at(f.Daily.Sunrise, i)
			set, _ := at(f.Daily.Sunset, i)
			rows = append(rows, map[string]any{"date": d, "high": val(hi), "low": val(lo), "conditions": cond(code),
				"precipitation": val(amount), "chance": val(chance), "sunrise": rise, "sunset": set})
		}
		return sdk.JSON(map[string]any{"place": pl.Name, "timezone": f.Timezone, "units": c.units(), "days": rows})

	case "air_quality":
		if c.air == "" {
			return sdk.Result{}, errors.New("air quality is off; turn it on in this instance's settings")
		}
		pl, err := c.where(p)
		if err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{"latitude": {strconv.FormatFloat(pl.Latitude, 'f', 4, 64)}, "longitude": {strconv.FormatFloat(pl.Longitude, 'f', 4, 64)},
			"timezone": {"auto"}, "current": {"european_aqi,us_aqi,pm10,pm2_5,ozone,nitrogen_dioxide"}}
		var a struct {
			Current struct {
				Time string `json:"time"`
				EU   num    `json:"european_aqi"`
				US   num    `json:"us_aqi"`
				PM10 num    `json:"pm10"`
				PM25 num    `json:"pm2_5"`
				O3   num    `json:"ozone"`
				NO2  num    `json:"nitrogen_dioxide"`
			} `json:"current"`
		}
		if err := c.get(ctx, c.air, "/v1/air-quality", q, &a); err != nil {
			return sdk.Result{}, err
		}
		cur := a.Current
		return sdk.JSON(map[string]any{"place": pl.Name, "time": cur.Time, "europeanAqi": val(cur.EU), "rating": euRating(cur.EU), "usAqi": val(cur.US),
			"pm10": val(cur.PM10), "pm2_5": val(cur.PM25), "ozone": val(cur.O3), "no2": val(cur.NO2), "unit": "μg/m³"})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// today is one place's line for the day.
func (c *conn) today(ctx context.Context, pl Place) (map[string]any, error) {
	q := c.query(pl)
	q.Set("current", "temperature_2m,weather_code")
	q.Set("daily", "temperature_2m_max,temperature_2m_min,weather_code")
	q.Set("hourly", "precipitation_probability,precipitation")
	q.Set("forecast_days", "1")
	q.Set("forecast_hours", "12")
	f, err := c.fetch(ctx, q)
	if err != nil {
		return nil, err
	}
	hi, _ := at(f.Daily.Max, 0)
	lo, _ := at(f.Daily.Min, 0)
	code, _ := at(f.Daily.Code, 0)
	var chance, amount float64
	rainFrom := ""
	for i := range f.Hourly.Time {
		if i == 12 {
			break
		}
		ch, _ := at(f.Hourly.Chance, i)
		am, _ := at(f.Hourly.Precip, i)
		if ch != nil && *ch > chance {
			chance = *ch
		}
		if am != nil {
			amount += *am
			if *am > 0 && rainFrom == "" {
				rainFrom = f.Hourly.Time[i]
			}
		}
	}
	out := map[string]any{"place": pl.Name, "now": val(f.Current.Temperature), "nowConditions": cond(f.Current.Code),
		"high": val(hi), "low": val(lo), "conditions": cond(code), "rainChance12h": chance, "rain12h": math.Round(amount*10) / 10}
	if rainFrom != "" {
		out["rainFrom"] = rainFrom
	}
	out["summary"] = summary(out, c.units()["temperature"])
	return out, nil
}

// summary is a short line like "8°C, overcast; 5–11°C today, 70% chance of rain".
func summary(d map[string]any, unit string) string {
	var parts []string
	if t, ok := d["now"].(float64); ok {
		s := fmt.Sprintf("%g%s", t, unit)
		if c, _ := d["nowConditions"].(string); c != "" {
			s += ", " + strings.ToLower(c)
		}
		parts = append(parts, s)
	}
	hi, okH := d["high"].(float64)
	lo, okL := d["low"].(float64)
	day := ""
	if okH && okL {
		day = fmt.Sprintf("%g–%g%s today", lo, hi, unit)
	}
	if ch, _ := d["rainChance12h"].(float64); ch >= 20 {
		if day != "" {
			day += ", "
		}
		day += fmt.Sprintf("%g%% chance of rain", ch)
	}
	if day != "" {
		parts = append(parts, day)
	}
	return strings.Join(parts, "; ")
}

// condition names a WMO weather interpretation code.
func condition(code int) string {
	switch code {
	case 0:
		return "Clear sky"
	case 1:
		return "Mainly clear"
	case 2:
		return "Partly cloudy"
	case 3:
		return "Overcast"
	case 45:
		return "Fog"
	case 48:
		return "Rime fog"
	case 51:
		return "Light drizzle"
	case 53:
		return "Drizzle"
	case 55:
		return "Dense drizzle"
	case 56, 57:
		return "Freezing drizzle"
	case 61:
		return "Light rain"
	case 63:
		return "Rain"
	case 65:
		return "Heavy rain"
	case 66, 67:
		return "Freezing rain"
	case 71:
		return "Light snow"
	case 73:
		return "Snow"
	case 75:
		return "Heavy snow"
	case 77:
		return "Snow grains"
	case 80:
		return "Light showers"
	case 81:
		return "Showers"
	case 82:
		return "Violent showers"
	case 85:
		return "Light snow showers"
	case 86:
		return "Heavy snow showers"
	case 95:
		return "Thunderstorm"
	case 96, 99:
		return "Thunderstorm with hail"
	}
	return "Code " + strconv.Itoa(code)
}

func compass(deg num) string {
	if deg == nil {
		return ""
	}
	dirs := []string{"N", "NE", "E", "SE", "S", "SW", "W", "NW"}
	i := int(math.Mod(math.Round(*deg/45), 8))
	if i < 0 {
		i += 8
	}
	return dirs[i]
}

// euRating is the European AQI band.
func euRating(v num) string {
	if v == nil {
		return ""
	}
	switch x := *v; {
	case x <= 20:
		return "good"
	case x <= 40:
		return "fair"
	case x <= 60:
		return "moderate"
	case x <= 80:
		return "poor"
	case x <= 100:
		return "very poor"
	}
	return "extremely poor"
}
