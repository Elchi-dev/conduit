package weather

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeMeteo struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeMeteo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.Path+"?"+r.URL.RawQuery)
	f.mu.Unlock()
	q := r.URL.Query()
	if q.Get("latitude") == "" || q.Get("longitude") == "" || q.Get("timezone") != "auto" {
		w.WriteHeader(400)
		io.WriteString(w, `{"error":true,"reason":"Parameter 'latitude' and 'longitude' must have the same number of elements"}`)
		return
	}
	if q.Get("latitude") == "89.0000" {
		w.WriteHeader(400)
		io.WriteString(w, `{"error":true,"reason":"Cannot initialize WeatherVariable from invalid String value"}`)
		return
	}
	switch r.URL.Path {
	case "/v1/forecast":
		var parts []string
		if q.Get("current") != "" {
			parts = append(parts, `"current":{"time":"2026-11-04T09:00","interval":900,"temperature_2m":8.14,"relative_humidity_2m":81,"apparent_temperature":5.9,"precipitation":0,"weather_code":3,"wind_speed_10m":12.3,"wind_direction_10m":250,"is_day":1}`)
		}
		if q.Get("hourly") != "" {
			parts = append(parts, `"hourly":{"time":["2026-11-04T09:00","2026-11-04T10:00","2026-11-04T11:00"],"temperature_2m":[8.1,9,null],"precipitation_probability":[10,70,40],"precipitation":[0,0.4,0.2],"weather_code":[3,61,80]}`)
		}
		if q.Get("daily") != "" {
			parts = append(parts, `"daily":{"time":["2026-11-04","2026-11-05"],"weather_code":[61,0],"temperature_2m_max":[11.2,13],"temperature_2m_min":[5.04,4],"precipitation_sum":[1.2,0],"precipitation_probability_max":[70,5],"sunrise":["2026-11-04T07:12","2026-11-05T07:14"],"sunset":["2026-11-04T16:30","2026-11-05T16:28"]}`)
		}
		io.WriteString(w, `{"latitude":52.52,"longitude":13.41,"timezone":"Europe/Berlin",`+strings.Join(parts, ",")+`}`)
	case "/v1/air-quality":
		io.WriteString(w, `{"current":{"time":"2026-11-04T09:00","european_aqi":32,"us_aqi":45,"pm10":14.2,"pm2_5":8.1,"ozone":40,"nitrogen_dioxide":18}}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, mod func(*Config)) (*Module, *fakeMeteo) {
	f := &fakeMeteo{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	c := Config{URL: srv.URL, AirQualityURL: srv.URL + "/v1", AirQuality: true, Places: []Place{{Name: "Home", Latitude: 52.52, Longitude: 13.405}, {Name: "Office", Latitude: 48.137, Longitude: 11.575}}}
	if mod != nil {
		mod(&c)
	}
	raw, _ := json.Marshal(c)
	if err := m.Configure(context.Background(), fakehost.New(nil), "w", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "w", Action: action, Input: json.RawMessage(in)})
}

func TestWeather(t *testing.T) {
	m, f := setup(t, nil)
	if h := m.Health(context.Background(), "w"); h.Status != "ok" || h.Message != "Home: 8.1°C, overcast" {
		t.Fatalf("%+v", h)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s isn't read-only", a.Name)
		}
	}
	for _, c := range []struct{ action, in, want string }{
		{"places", `{}`, `"name":"Office"`},
		{"current", `{}`, `"windFrom":"W"`},
		{"current", `{"place":"office"}`, `"place":"Office"`},
		{"current", `{"latitude":-33.86,"longitude":151.2}`, `"place":"-33.8600, 151.2000"`},
		{"precipitation", `{}`, `{"amount":0.4,"chance":70,"conditions":"Light rain","temperature":9,"time":"2026-11-04T10:00"}`},
		{"precipitation", `{"hours":2}`, `"time":"2026-11-04T10:00"`},
		{"forecast", `{"place":"Home"}`, `"high":11.2,"low":5`},
		{"forecast", `{"days":1}`, `"sunset":"2026-11-04T16:30"`},
		{"air_quality", `{}`, `"rating":"fair"`},
		{"today", `{}`, `"summary":"8.1°C, overcast; 5–11.2°C today, 70% chance of rain"`},
	} {
		r, err := invoke(m, c.action, c.in)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if r, _ := invoke(m, "precipitation", `{"hours":2}`); strings.Contains(string(r.Output), "11:00") {
		t.Fatalf("more hours than asked: %s", r.Output)
	}
	joined := strings.Join(f.seen, "\n")
	for _, want := range []string{"latitude=48.1370&longitude=11.5750", "forecast_hours=12", "forecast_days=7", "forecast_days=1", "latitude=-33.8600"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("no %s in %s", want, joined)
		}
	}
	if strings.Contains(joined, "fahrenheit") {
		t.Fatal("metric asked in fahrenheit")
	}

	imp, fi := setup(t, func(c *Config) { c.Units = "imperial"; c.AirQuality = false })
	if r, err := invoke(imp, "current", `{}`); err != nil || !strings.Contains(string(r.Output), `"temperature":"°F"`) || !strings.Contains(fi.seen[0], "temperature_unit=fahrenheit") {
		t.Fatalf("%s %v %v", r.Output, err, fi.seen)
	}
	if _, err := invoke(imp, "air_quality", `{}`); err == nil || !strings.Contains(err.Error(), "off") {
		t.Fatal(err)
	}

	// The server's reason is passed on.
	if _, err := invoke(m, "current", `{"latitude":89,"longitude":0}`); err == nil || !strings.Contains(err.Error(), "Open-Meteo: Cannot initialize") {
		t.Fatal(err)
	}
}

func TestWeatherValidation(t *testing.T) {
	m, f := setup(t, nil)
	for _, c := range []struct{ action, in string }{
		{"current", `{"place":"Paris"}`},
		{"current", `{"place":"Home","latitude":1,"longitude":2}`},
		{"current", `{"latitude":1}`},
		{"current", `{"longitude":1}`},
		{"current", `{"latitude":91,"longitude":0}`},
		{"current", `{"latitude":0,"longitude":-180.5}`},
		{"current", `{"latitude":"52&current=x","longitude":1}`},
		{"precipitation", `{"hours":49}`},
		{"precipitation", `{"hours":-1}`},
		{"forecast", `{"days":17}`},
		{"air_quality", `{"place":"../v1"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{},
		{Places: []Place{{Name: "", Latitude: 1, Longitude: 1}}},
		{Places: []Place{{Name: "A", Latitude: 100, Longitude: 1}}},
		{Places: []Place{{Name: "A", Latitude: 1, Longitude: 200}}},
		{Places: []Place{{Name: "A", Latitude: 1, Longitude: 1}, {Name: "a", Latitude: 2, Longitude: 2}}},
		{Places: []Place{{Name: "A", Latitude: 1, Longitude: 1}}, Units: "kelvin"},
		{Places: []Place{{Name: "A", Latitude: 1, Longitude: 1}}, URL: "api.open-meteo.com"},
		{Places: []Place{{Name: "A", Latitude: 1, Longitude: 1}}, URL: "https://api.open-meteo.com/?apikey=x"},
		{Places: []Place{{Name: "A", Latitude: 1, Longitude: 1}}, AirQuality: true, AirQualityURL: "ftp://x"},
		{Places: make([]Place, 11)},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	// No URL means the public API; no credentials are needed.
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(`{"places":[{"name":"Home","latitude":1,"longitude":2}]}`)); err != nil {
		t.Fatal(err)
	}
	if h := New().Health(context.Background(), "w"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestWeatherRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Places: []Place{{Name: "Home", Latitude: 1, Longitude: 2}}})
	if err := m.Configure(context.Background(), fakehost.New(nil), "w", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "w"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
