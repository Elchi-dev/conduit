package speedtest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeST struct {
	mu     sync.Mutex
	writes []string
	reads  []string
	n      int // results, one per hour back from now
	canRun bool
}

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func result(i int) map[string]any {
	st, healthy := "completed", any(true)
	if i%10 == 3 {
		st = "failed"
	}
	if i%10 == 5 {
		healthy = false
	}
	return map[string]any{"id": 1000 - i, "service": "ookla", "ping": 10.5 + float64(i%4), "download": 12_500_000 + i*1000, "upload": 2_500_000, "healthy": healthy, "status": st, "scheduled": true,
		"created_at": now.Add(-time.Duration(i) * time.Hour).Format(time.RFC3339),
		"data": map[string]any{"isp": "Example ISP", "ping": map[string]any{"jitter": 1.234}, "packetLoss": 0, "message": "no servers",
			"server":    map[string]any{"id": 12345, "name": "Example Net", "location": "Amsterdam", "country": "Netherlands", "ip": "203.0.113.1"},
			"interface": map[string]any{"externalIp": "198.51.100.77", "internalIp": "192.168.1.50", "macAddr": "AA:BB:CC:DD:EE:FF"},
			"result":    map[string]any{"url": "https://www.speedtest.net/result/c/abc"}}}
}

func (f *fakeST) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("Authorization")
	if tok != "Bearer read" && tok != "Bearer run" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthenticated."}`)
		return
	}
	if r.Header.Get("Accept") != "application/json" {
		w.WriteHeader(406)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != "GET" {
		f.writes = append(f.writes, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	} else {
		f.reads = append(f.reads, r.URL.Path+"?"+r.URL.RawQuery)
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/results/latest":
		if f.n == 0 {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"No result found."}`)
			return
		}
		b, _ := json.Marshal(result(0))
		w.Write(b)
	case "GET /api/v1/results":
		per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		if r.URL.Query().Get("sort") != "-created_at" && per != 1 {
			w.WriteHeader(400)
			return
		}
		data := []map[string]any{}
		for i := (page - 1) * per; i < page*per && i < f.n; i++ {
			data = append(data, result(i))
		}
		b, _ := json.Marshal(map[string]any{"data": data, "meta": map[string]any{"current_page": page, "last_page": (f.n + per - 1) / per}})
		w.Write(b)
	case "POST /api/v1/speedtests/run":
		if tok != "Bearer run" {
			w.WriteHeader(403)
			io.WriteString(w, `{"message":"This action is unauthorized."}`)
			return
		}
		if s := r.URL.Query().Get("server_id"); s == "999999" {
			w.WriteHeader(422)
			io.WriteString(w, `{"message":"The selected server id is invalid."}`)
			return
		}
		w.WriteHeader(201)
		io.WriteString(w, `{"data":{"id":1001,"service":"ookla","status":"waiting","scheduled":false,"created_at":"2026-11-04T12:00:01Z"},"message":"Speedtest added to the queue."}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

func setup(t *testing.T, f *fakeST, tok string) *Module {
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return now }
	raw, _ := json.Marshal(Config{URL: srv.URL + "/admin", APIToken: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://read": "read", "secret://run": "run", "secret://bad": "nope"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestSpeedtestRead(t *testing.T) {
	f := &fakeST{n: 1200}
	m := setup(t, f, "secret://read")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "Speedtest Tracker · 100↓ / 20↑ Mbit/s" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "latest", `{}`, false)
	want := `{"at":"2026-11-04T12:00:00Z","downloadMbps":100,"healthy":true,"id":1000,"isp":"Example ISP","jitterMs":1.23,"packetLossPercent":0,"pingMs":10.5,"resultUrl":"https://www.speedtest.net/result/c/abc","scheduled":true,"server":{"country":"Netherlands","id":12345,"location":"Amsterdam","name":"Example Net"},"service":"ookla","status":"completed","uploadMbps":20}`
	if err != nil || string(r.Output) != want {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "history", `{"days":1,"limit":5}`, false)
	if err != nil || strings.Count(string(r.Output), `"id":`) != 10 || !strings.Contains(string(r.Output), `"more":true`) || !strings.Contains(string(r.Output), `"error":"no servers"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "history", `{"days":1,"limit":500}`, false)
	if err != nil || strings.Count(string(r.Output), `"isp"`) != 25 || !strings.Contains(string(r.Output), `"more":false`) {
		t.Fatalf("%d %v", strings.Count(string(r.Output), `"isp"`), err)
	}
	r, err = invoke(m, "stats", `{"days":30}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"completed":649,"days":30`) || !strings.Contains(string(r.Output), `"failed":72`) || !strings.Contains(string(r.Output), `"unhealthy":72`) ||
		!strings.Contains(string(r.Output), `"tests":721`) || !strings.Contains(string(r.Output), `"pingMs":{"avg":11.94,"max":13.5,"min":10.5,"p90":13.5}`) || !strings.Contains(string(r.Output), `"uploadMbps":{"avg":20,"max":20,"min":20,"p10":20}`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "stats", `{"days":365}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"tests":1200`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, x := range []string{"198.51.100.77", "192.168.1.50", "AA:BB", "203.0.113.1"} {
		if strings.Contains(string(r.Output), x) {
			t.Fatal("leaked", x)
		}
	}
	empty := setup(t, &fakeST{}, "secret://read")
	if h := empty.Health(context.Background(), "s"); h.Status != "ok" || !strings.Contains(h.Message, "no results yet") {
		t.Fatalf("%+v", h)
	}
	if r, err := invoke(empty, "latest", `{}`, false); err != nil || !strings.Contains(string(r.Output), "no speedtests yet") {
		t.Fatal(err)
	}
}

func TestSpeedtestRun(t *testing.T) {
	f := &fakeST{n: 3}
	m := setup(t, f, "secret://run")
	p, err := invoke(m, "run", `{"serverId":12345}`, true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, "Ookla server 12345") || len(f.writes) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := invoke(m, "run", `{"serverId":12345}`, false)
	if err != nil || r.Undo != nil || string(r.Output) != `{"id":1001,"message":"Speedtest added to the queue.","queued":true,"server":"Ookla server 12345","status":"waiting"}` ||
		f.writes[0] != "POST /api/v1/speedtests/run?server_id=12345" {
		t.Fatalf("%s %v %v", r.Output, err, f.writes)
	}
	if _, err := invoke(m, "run", `{}`, false); err != nil || f.writes[1] != "POST /api/v1/speedtests/run?" {
		t.Fatal(err, f.writes)
	}
	if _, err := invoke(m, "run", `{"serverId":999999}`, false); err == nil || err.Error() != "The selected server id is invalid." {
		t.Fatal(err)
	}
	ro := setup(t, f, "secret://read")
	if _, err := invoke(ro, "run", `{}`, false); err == nil || !strings.Contains(err.Error(), `"Run speedtest" ability`) {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "run") != (a.Risk == sdk.RiskWrite) || a.Reversible {
			t.Fatal(a.Name)
		}
	}
}

func TestSpeedtestRefusals(t *testing.T) {
	f := &fakeST{n: 3}
	if h := setup(t, f, "secret://bad").Health(context.Background(), "s"); h.Status != "down" || h.Message != "Speedtest Tracker refused the API token" {
		t.Fatalf("%+v", h)
	}
	m := setup(t, f, "secret://run")
	for _, c := range []struct{ action, in string }{
		{"run", `{"serverId":0}`},
		{"run", `{"serverId":-4}`},
		{"run", `{"serverId":99999999999}`},
		{"run", `{"serverId":"1&x=y"}`},
		{"history", `{"days":0}`},
		{"history", `{"days":4000}`},
		{"history", `{"limit":501}`},
		{"stats", `{"days":-1}`},
		{"delete", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.writes) != 0 || len(f.reads) != 0 {
		t.Fatalf("refused input reached the server: %v %v", f.writes, f.reads)
	}
	for _, c := range []Config{{URL: "http://st:8080", APIToken: "plaintoken"}, {URL: "st:8080", APIToken: "secret://k"}, {URL: "http://a:b@st", APIToken: "secret://k"}, {URL: "ftp://st", APIToken: "secret://k"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIToken: "secret://k"})
	rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "read"}), "s", raw)
	if h := rm.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "another host") || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}

}
