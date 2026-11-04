package scrutiny

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeScrutiny struct {
	mu    sync.Mutex
	paths []string
	login bool
}

const summaryJSON = `{"success":true,"data":{"summary":{
 "0x5000cca264eb01d7":{"device":{"wwn":"0x5000cca264eb01d7","device_name":"sda","manufacturer":"ATA","model_name":"WDC WD140EDFZ","serial_number":"9RK1XXYC","firmware":"81.00A81","rotational_speed":5400,"capacity":14000519643136,"device_protocol":"ATA","host_id":"nas","device_status":2,"archived":false,"muted":false},
   "smart":{"collector_date":"2026-11-04T06:00:00Z","temp":41,"power_on_hours":20101},"temp_history":[{"date":"2026-11-03T06:00:00Z","temp":39},{"date":"2026-11-04T06:00:00Z","temp":41}]},
 "eui.0025385b71b0e3f2":{"device":{"wwn":"eui.0025385b71b0e3f2","device_name":"nvme0","model_name":"Samsung SSD 980","serial_number":"S64DNX0R","capacity":1000204886016,"device_protocol":"NVMe","host_id":"nas","label":"boot","device_status":0},
   "smart":{"collector_date":"2026-11-04T06:00:00Z","temp":35,"power_on_hours":800}},
 "0xold":{"device":{"wwn":"0xold","device_name":"sdz","model_name":"Old","device_status":1,"archived":true}},
 "bad/../wwn":{"device":{"wwn":"bad/../wwn","device_name":"sdx","model_name":"Weird","device_status":0}}
}}}`

func (f *fakeScrutiny) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.login {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "pw" {
			w.WriteHeader(401)
			return
		}
	}
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.EscapedPath()+"?"+r.URL.RawQuery)
	f.mu.Unlock()
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	switch r.URL.EscapedPath() {
	case "/api/health":
		io.WriteString(w, `{"success":true}`)
	case "/api/summary":
		io.WriteString(w, summaryJSON)
	case "/api/summary/temp":
		var pts []string
		for i := 0; i < 500; i++ {
			pts = append(pts, fmt.Sprintf(`{"date":"2026-10-%02dT%02d:00:00Z","temp":%d}`, 1+i/24, i%24, 30+i%15))
		}
		io.WriteString(w, `{"success":true,"data":{"temp_history":{"0x5000cca264eb01d7":[`+strings.Join(pts, ",")+`],"eui.0025385b71b0e3f2":[{"date":"2026-11-04T06:00:00Z","temp":35}]}}}`)
	case "/api/device/0x5000cca264eb01d7/details":
		io.WriteString(w, `{"success":true,"data":{"device":{"wwn":"0x5000cca264eb01d7"},"smart_results":[
			{"date":"2026-11-03T06:00:00Z","temp":39,"attrs":{"5":{"attribute_id":5,"value":100,"status":0}},"Status":0},
			{"date":"2026-11-04T06:00:00Z","temp":41,"power_on_hours":20101,"power_cycle_count":77,"Status":2,"attrs":{
				"5":{"attribute_id":5,"value":100,"worst":100,"thresh":5,"raw_value":16,"raw_string":"16","status":4,"status_reason":"Scrutiny observed reallocated sectors","failure_rate":0.0251},
				"197":{"attribute_id":197,"value":200,"worst":200,"thresh":0,"raw_value":2,"status":2,"status_reason":"pending sectors"},
				"9":{"attribute_id":9,"value":73,"worst":73,"thresh":0,"raw_value":20101,"status":0}}}]},
			"metadata":{"5":{"display_name":"Reallocated Sectors Count","ideal":"low","critical":true},"197":{"display_name":"Current Pending Sector Count","ideal":"low","critical":true},"9":{"display_name":"Power-On Hours"}}}`)
	case "/api/device/eui.0025385b71b0e3f2/details":
		io.WriteString(w, `{"success":true,"data":{"device":{},"smart_results":[{"date":"2026-11-04T06:00:00Z","temp":35,"Status":0,"attrs":{
			"media_errors":{"attribute_id":"media_errors","value":0,"thresh":0,"status":0},"critical_warning":{"attribute_id":"critical_warning","value":0,"status":0}}}]},
			"metadata":{"media_errors":{"display_name":"Media and Data Integrity Errors","critical":true}}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"success":false,"errors":["not found"]}`)
	}
}

func setup(t *testing.T, f *fakeScrutiny, c Config) *Module {
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	c.URL = srv.URL + "/web/"
	raw, _ := json.Marshal(c)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "nope"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
}

func TestScrutinyRead(t *testing.T) {
	f := &fakeScrutiny{}
	m := setup(t, f, Config{})
	if h := m.Health(context.Background(), "s"); h.Status != "degraded" || h.Message != "Scrutiny · 3 drive(s) · failing: nas:sda" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"devices", `{}`, `{"capacityBytes":14000519643136,"device":"sda","failing":true,"firmware":"81.00A81","host":"nas","lastChecked":"2026-11-04T06:00:00Z","manufacturer":"ATA","model":"WDC WD140EDFZ","powerOnHours":20101,"protocol":"ATA","rpm":5400,"serial":"9RK1XXYC","status":"failed (Scrutiny)","temperature":41,"wwn":"0x5000cca264eb01d7"}`},
		{"devices", `{"includeArchived":true}`, `"status":"failed (SMART)"`},
		{"failures", `{}`, `"attributes":[{"critical":true,"failureRate":0.0251,"id":"5","ideal":"low","name":"Reallocated Sectors Count","raw":16,"reason":"Scrutiny observed reallocated sectors","status":"failed (Scrutiny)","threshold":5,"value":100,"worst":100},{"critical":true,"id":"197","ideal":"low","name":"Current Pending Sector Count","raw":2,"reason":"pending sectors","status":"warning (Scrutiny)","threshold":0,"value":200,"worst":200}]`},
		{"failures", `{}`, `"checked":2`},
		{"failures", `{"includeWarnings":false}`, `"status":"failed (Scrutiny)","threshold":5,"value":100,"worst":100}]`},
		{"device", `{"device":"/dev/sda"}`, `"powerCycles":77`},
		{"device", `{"device":"9rk1xxyc"}`, `{"id":"9","name":"Power-On Hours","raw":20101,"status":"passed","threshold":0,"value":73,"worst":73}`},
		{"device", `{"device":"boot"}`, `{"critical":true,"id":"media_errors","name":"Media and Data Integrity Errors","raw":0,"status":"passed","threshold":0,"value":0,"worst":0}`},
		{"temperatures", `{"duration":"month","maxPoints":10}`, `{"avg":37,"device":"sda","from":"2026-10-01T00:00:00Z","host":"nas","latest":34,"max":44,"min":30,"points":[{"date":"2026-10-01T00:00:00Z","temp":30},{"date":"2026-10-03T07:00:00Z","temp":40}`},
		{"temperatures", `{"device":"nvme0","maxPoints":0}`, `"drives":[{"avg":35,"device":"nvme0","from":"2026-11-04T06:00:00Z","host":"nas","label":"boot","latest":35,"max":35,"min":35,"readings":1,"to":"2026-11-04T06:00:00Z","wwn":"eui.0025385b71b0e3f2"}]`},
	} {
		r, err := invoke(m, c.action, c.in)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	r, _ := invoke(m, "failures", `{"includeWarnings":false}`)
	if strings.Contains(string(r.Output), "pending sectors") || strings.Contains(string(r.Output), "nvme0") {
		t.Fatal(string(r.Output))
	}
	r, _ = invoke(m, "temperatures", `{"duration":"month","maxPoints":10}`)
	var tr struct {
		Drives []struct {
			Readings int         `json:"readings"`
			Points   []tempPoint `json:"points"`
		} `json:"drives"`
	}
	json.Unmarshal(r.Output, &tr)
	if len(tr.Drives) != 3 || tr.Drives[2].Readings != 500 || len(tr.Drives[2].Points) != 10 || tr.Drives[2].Points[9].Date != "2026-10-21T19:00:00Z" {
		t.Fatalf("%+v", tr)
	}
	for _, p := range f.paths {
		if strings.Contains(p, "bad") || strings.Contains(p, "0xold") {
			t.Fatalf("requested %s", p)
		}
	}
}

func TestScrutinyRefusals(t *testing.T) {
	f := &fakeScrutiny{login: true}
	if h := setup(t, f, Config{}).Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "behind a login") {
		t.Fatalf("%+v", h)
	}
	if h := setup(t, f, Config{Username: "admin", Password: "secret://bad"}).Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "refused the username or password") {
		t.Fatalf("%+v", h)
	}
	m := setup(t, f, Config{Username: "admin", Password: "secret://pw"})
	if h := m.Health(context.Background(), "s"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	f.paths = nil
	for _, c := range []struct{ action, in string }{
		{"device", `{}`},
		{"device", `{"device":"sdq"}`},
		{"device", `{"device":"bad/../wwn"}`},
		{"device", `{"device":"sdx"}`},
		{"device", `{"device":"../../api/health"}`},
		{"failures", `{"device":"sda\u0000"}`},
		{"temperatures", `{"duration":"decade"}`},
		{"temperatures", `{"maxPoints":5000}`},
		{"temperatures", `{"maxPoints":-1}`},
		{"delete", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	for _, p := range f.paths {
		if p != "/api/summary?" {
			t.Fatalf("refused input reached Scrutiny: %v", f.paths)
		}
	}
	for _, c := range []Config{{URL: "http://nas:8080", Username: "a", Password: "plain"}, {URL: "http://nas:8080", Username: "a"}, {URL: "nas:8080"},
		{URL: "http://u:p@nas:8080"}, {URL: "http://nas:8080/?x=1"}, {URL: "http://nas:8080", Username: "a:b", Password: "secret://pw"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://pw"})
	rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "s", raw)
	if h := rm.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "another host") || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
