package uptimekuma

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestUptimeKuma(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/status-page/home":
			io.WriteString(w, `{"publicGroupList":[{"name":"Services","monitorList":[{"id":1,"name":"Website","type":"http"},{"id":2,"name":"NAS","type":"ping"}]}]}`)
		case "/api/status-page/heartbeat/home":
			io.WriteString(w, `{"heartbeatList":{"1":[{"status":1,"msg":"200 OK","ping":120}],"2":[{"status":1,"ping":3},{"status":0,"msg":"timeout","ping":null}]},"uptimeList":{"1_24":0.999,"2_24":0.5}}`)
		case "/metrics":
			if _, pw, _ := r.BasicAuth(); pw != "uk_key" {
				w.WriteHeader(401)
				return
			}
			io.WriteString(w, "# HELP monitor_status x\nmonitor_status{monitor_name=\"Website\",monitor_type=\"http\",monitor_url=\"https://example.com\",monitor_hostname=\"null\",monitor_port=\"null\"} 1\n"+
				"monitor_status{monitor_name=\"DNS\",monitor_type=\"dns\",monitor_url=\"https://\",monitor_hostname=\"1.1.1.1\",monitor_port=\"53\"} 3\n"+
				"monitor_response_time{monitor_name=\"Website\",monitor_type=\"http\",monitor_url=\"https://example.com\",monitor_hostname=\"null\",monitor_port=\"null\"} 98\n")
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	h := fakehost.New(map[string]string{"secret://uk": "uk_key", "secret://bad": "nope"})
	if bad, _ := json.Marshal(Config{URL: srv.URL, StatusPages: []string{"../admin"}}); m.Configure(ctx, h, "x", bad) == nil {
		t.Fatal("bad slug accepted")
	}
	cfg, _ := json.Marshal(Config{URL: srv.URL, StatusPages: []string{"home"}, APIKey: "secret://uk"})
	if err := m.Configure(ctx, h, "k", cfg); err != nil {
		t.Fatal(err)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "k", Action: "monitors"})
	if err != nil {
		t.Fatal(err)
	}
	var ms []Monitor
	_ = json.Unmarshal(r.Output, &ms)
	if len(ms) != 3 || ms[0].Name != "NAS" || ms[0].Status != "down" || ms[0].Message != "timeout" {
		t.Fatalf("%+v", ms)
	}
	byName := map[string]Monitor{}
	for _, x := range ms {
		byName[x.Name] = x
	}
	if w := byName["Website"]; w.Status != "up" || *w.ResponseMS != 98 || *w.Uptime24h < 99.8 || w.Target != "https://example.com" {
		t.Fatalf("website %+v", w)
	}
	if d := byName["DNS"]; d.Status != "maintenance" || d.Target != "1.1.1.1" {
		t.Fatalf("dns %+v", d)
	}
	if hl := m.Health(ctx, "k"); hl.Status != "degraded" {
		t.Fatalf("health %+v", hl)
	}
	cfg, _ = json.Marshal(Config{URL: srv.URL, APIKey: "secret://bad"})
	_ = m.Configure(ctx, h, "b", cfg)
	if hl := m.Health(ctx, "b"); hl.Status != "down" {
		t.Fatalf("bad key health %+v", hl)
	}
}
