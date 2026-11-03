package adguard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestAdGuard(t *testing.T) {
	protection := true
	var duration float64
	rules := []string{"||existing.example^"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "pw" {
			w.WriteHeader(401)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /control/status":
			b, _ := json.Marshal(map[string]any{"protection_enabled": protection, "running": true, "version": "v0.107.55"})
			w.Write(b)
		case "GET /control/stats":
			io.WriteString(w, `{"num_dns_queries":200,"num_blocked_filtering":50,"avg_processing_time":0.004,"top_blocked_domains":[{"ads.example":30}]}`)
		case "GET /control/querylog":
			io.WriteString(w, `{"data":[{"time":"2026-11-03T22:00:00Z","client":"192.168.1.20","reason":"FilteredBlackList","question":{"name":"ads.example","type":"A"}}]}`)
		case "POST /control/protection":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			protection = b["enabled"] == true
			duration, _ = b["duration"].(float64)
		case "GET /control/filtering/status":
			b, _ := json.Marshal(map[string]any{"user_rules": rules})
			w.Write(b)
		case "POST /control/filtering/set_rules":
			var b struct{ Rules []string }
			_ = json.NewDecoder(r.Body).Decode(&b)
			rules = b.Rules
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	h := fakehost.New(map[string]string{"secret://ag": "pw"})
	cfg, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://ag"})
	if err := m.Configure(ctx, h, "a", cfg); err != nil {
		t.Fatal(err)
	}
	call := func(a, in string) (sdk.Result, error) {
		return m.Invoke(ctx, sdk.Call{Instance: "a", Action: a, Input: json.RawMessage(in)})
	}
	r, err := call("status", `{}`)
	if err != nil || !strings.Contains(string(r.Output), `"percentBlocked":25`) || !strings.Contains(string(r.Output), `"ads.example"`) {
		t.Fatalf("status %s %v", r.Output, err)
	}
	r, err = call("protection_off", `{"minutes":5}`)
	if err != nil || protection || duration != 300000 {
		t.Fatalf("off %v %v %v", err, protection, duration)
	}
	if hl := m.Health(ctx, "a"); hl.Status != "degraded" {
		t.Fatalf("health while paused %+v", hl)
	}
	if _, err := call(r.Undo.Action, string(r.Undo.Input)); err != nil || !protection {
		t.Fatalf("undo off %v", err)
	}
	r, err = call("rule_add", `{"rule":"||tracker.example^"}`)
	if err != nil || len(rules) != 2 || r.Undo == nil {
		t.Fatalf("add %v %v", err, rules)
	}
	if _, err := call(r.Undo.Action, string(r.Undo.Input)); err != nil || len(rules) != 1 || rules[0] != "||existing.example^" {
		t.Fatalf("undo add %v %v", err, rules)
	}
	if _, err := call("rule_add", `{"rule":"a\nb"}`); err == nil {
		t.Fatal("multi-line rule accepted")
	}
	if _, err := call("rule_remove", `{"rule":"||nope^"}`); err == nil {
		t.Fatal("removing a missing rule succeeded")
	}
	r, err = call("query_log", `{"limit":10}`)
	if err != nil || !strings.Contains(string(r.Output), `"domain":"ads.example"`) {
		t.Fatalf("log %s %v", r.Output, err)
	}
	if err := m.Configure(ctx, h, "x", json.RawMessage(`{"url":"http://x","username":"a","password":"plain"}`)); err == nil {
		t.Fatal("plaintext password accepted")
	}
}
