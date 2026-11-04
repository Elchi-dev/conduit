package solaredge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const key = "L4QLVQ1LOKCQX2193VSEICXW61NP6B1O"

type fakeSE struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeSE) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("api_key") != key {
		w.WriteHeader(403)
		io.WriteString(w, `{"String":"Invalid token"}`)
		return
	}
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.Path+" "+r.URL.Query().Get("timeUnit")+" "+r.URL.Query().Get("startTime")+" "+r.URL.Query().Get("endTime"))
	f.mu.Unlock()
	switch r.URL.Path {
	case "/site/123456/details":
		io.WriteString(w, `{"details":{"id":123456,"name":"Roof","status":"Active","peakPower":9.8,"type":"Optimizers & Inverters","location":{"address":"LEAKME 1","city":"LEAKME","latitude":52.1},"primaryModule":{"manufacturerName":"X"}}}`)
	case "/site/123456/overview":
		io.WriteString(w, `{"overview":{"lastUpdateTime":"2026-11-04 12:00:00","lifeTimeData":{"energy":7619857.5,"revenue":946.134},"lastYearData":{"energy":3000000},"lastMonthData":{"energy":120500},"lastDayData":{"energy":8250},"currentPower":{"power":2431.27},"measuredBy":"INVERTER"}}`)
	case "/site/123456/energyDetails":
		io.WriteString(w, `{"energyDetails":{"timeUnit":"DAY","unit":"Wh","meters":[{"type":"Production","values":[{"date":"2026-11-03 00:00:00","value":8000},{"date":"2026-11-04 00:00:00","value":8250}]},{"type":"FeedIn","values":[{"date":"2026-11-03 00:00:00","value":3000},{"date":"2026-11-04 00:00:00"}]},{"type":"LEAKME-x","values":[{"date":"LEAKME"}]}]}}`)
	case "/site/123456/inventory":
		io.WriteString(w, `{"Inventory":{"meters":[{"name":"Production Meter","manufacturer":"WattNode","model":"WNC-3Y","firmwareVersion":"3.3","SN":"LEAKME-SN","type":"Production"}],"sensors":[],"gateways":[],"batteries":[{"name":"Battery 1","manufacturer":"LG","model":"RESU10H","nameplateCapacity":9800,"SN":"LEAKME-SN"}],"inverters":[{"name":"Inverter 1","manufacturer":"SolarEdge","model":"SE7K","communicationMethod":"ETHERNET","cpuVersion":"4.14.110","SN":"LEAKME-SN","connectedOptimizers":24}]}}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeSE) {
	f := &fakeSE{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 15, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{APIKey: ref, SiteID: 123456})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://se": key, "secret://bad": "WRONGKEY0000000000000000000000"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
}

func TestSolarEdge(t *testing.T) {
	m, f := setup(t, "secret://se")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "Roof · 9.8 kWp" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"overview", `{}`, `{"lastUpdate":"2026-11-04 12:00:00","lifetimeKWh":7619.86,"lifetimeRevenue":946.13,"measuredBy":"inverter","monthKWh":120.5,"name":"Roof","peakPowerKWp":9.8,"powerW":2431.3,"site":"123456","status":"active","todayKWh":8.25,"yearKWh":3000}`},
		{"energy", `{}`, `"totalsKWh":{"feedIn":3,"production":16.25}`},
		{"energy", `{}`, `"start":"2026-10-29"`},
		{"inventory", `{}`, `"counts":{"batteries":1,"gateways":0,"inverters":1,"meters":1,"optimizers":24,"sensors":0}`},
		{"inventory", `{}`, `"capacityWh":9800`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, key) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	n := len(f.seen)
	if _, err := invoke(m, "energy", `{"unit":"hour","start":"2026-10-05","end":"2026-11-04"}`); err != nil {
		t.Fatal(err)
	}
	if got := f.seen[n]; got != "/site/123456/energyDetails HOUR 2026-10-05 00:00:00 2026-11-04 23:59:59" {
		t.Fatal(got)
	}
}

func TestSolarEdgeValidation(t *testing.T) {
	m, f := setup(t, "secret://se")
	for _, in := range []string{
		`{"start":"2025-11-01","end":"2026-11-04"}`,               // 369 days
		`{"unit":"hour","start":"2026-10-01","end":"2026-11-04"}`, // 35 days by hour
		`{"start":"2026-11-04","end":"2026-11-01"}`,
		`{"start":"yesterday"}`,
		`{"end":"2026-11-04&api_key=x"}`,
		`{"end":"2027-01-01"}`,
		`{"unit":"quarter"}`,
	} {
		if _, err := invoke(m, "energy", in); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{APIKey: key, SiteID: 1}, {APIKey: "secret://se"}, {APIKey: "secret://se", SiteID: -4}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil || strings.Contains(err.Error(), key) {
			t.Fatalf("accepted %+v: %v", c, err)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || h.Message != "SolarEdge refused the API key, or it has no access to this site" {
		t.Fatalf("%+v", h)
	}
}

// The key travels in the query: a failed connection mustn't show it.
func TestSolarEdgeKeyNotInErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, _ := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Close()
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: "secret://se", SiteID: 1})
	m.Configure(context.Background(), fakehost.New(map[string]string{"secret://se": key}), "s", raw)
	_, err := invoke(m, "overview", `{}`)
	if err == nil || strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "api_key") {
		t.Fatal(err)
	}
}

func TestSolarEdgeRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.URL.RawQuery }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: "secret://se", SiteID: 1})
	m.Configure(context.Background(), fakehost.New(map[string]string{"secret://se": key}), "s", raw)
	h := m.Health(context.Background(), "s")
	if h.Status != "down" || leaked != "" || strings.Contains(h.Message, key) {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
	if _, err := invoke(m, "overview", `{}`); err == nil || strings.Contains(err.Error(), key) {
		t.Fatal(err)
	}
}
