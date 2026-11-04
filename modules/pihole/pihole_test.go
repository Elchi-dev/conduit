package pihole

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

func TestPihole(t *testing.T) {
	var mu sync.Mutex
	logins := 0
	sid := "s1"
	blockingOn := true
	deny := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/api/auth" {
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["password"] != "app-pw" {
				io.WriteString(w, `{"session":{"valid":false,"message":"password incorrect"}}`)
				return
			}
			logins++
			io.WriteString(w, `{"session":{"valid":true,"sid":"`+sid+`","validity":1800}}`)
			return
		}
		if r.Header.Get("X-FTL-SID") != sid {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"message":"Unauthorized"}}`)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/stats/summary":
			io.WriteString(w, `{"queries":{"total":1000,"blocked":250,"percent_blocked":25.0},"clients":{"active":7},"gravity":{"domains_being_blocked":150000}}`)
		case r.Method == "GET" && r.URL.Path == "/api/stats/top_domains":
			io.WriteString(w, `{"domains":[{"domain":"ads.example.com","count":99}]}`)
		case r.URL.Path == "/api/dns/blocking":
			if r.Method == "POST" {
				var b map[string]any
				_ = json.NewDecoder(r.Body).Decode(&b)
				blockingOn = b["blocking"] == true
			}
			state := "disabled"
			if blockingOn {
				state = "enabled"
			}
			io.WriteString(w, `{"blocking":"`+state+`","timer":null}`)
		case r.Method == "POST" && r.URL.Path == "/api/domains/deny/exact":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			deny[b["domain"].(string)] = true
			w.WriteHeader(201)
		case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/api/domains/deny/exact/"):
			delete(deny, strings.TrimPrefix(r.URL.Path, "/api/domains/deny/exact/"))
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	h := fakehost.New(map[string]string{"secret://ph": "app-pw", "secret://bad": "x"})
	cfg, _ := json.Marshal(Config{URL: srv.URL, Password: "secret://ph"})
	if err := m.Configure(ctx, h, "p", cfg); err != nil {
		t.Fatal(err)
	}
	call := func(a, in string) (sdk.Result, error) {
		return m.Invoke(ctx, sdk.Call{Instance: "p", Action: a, Input: json.RawMessage(in)})
	}
	r, err := call("summary", `{}`)
	if err != nil || !strings.Contains(string(r.Output), `"blocked":250`) || !strings.Contains(string(r.Output), `"blocking":"enabled"`) {
		t.Fatalf("summary %s %v", r.Output, err)
	}
	r, err = call("disable", `{"seconds":60}`)
	if err != nil || blockingOn || r.Undo == nil {
		t.Fatalf("disable %v", err)
	}
	if _, err := call(r.Undo.Action, string(r.Undo.Input)); err != nil || !blockingOn {
		t.Fatalf("undo disable %v", err)
	}
	r, err = call("domain_add", `{"domain":"Tracker.Example.com"}`)
	if err != nil || !deny["tracker.example.com"] {
		t.Fatalf("add %v %v", err, deny)
	}
	if _, err := call(r.Undo.Action, string(r.Undo.Input)); err != nil || deny["tracker.example.com"] {
		t.Fatalf("undo add %v %v", err, deny)
	}
	for _, bad := range []string{`{"domain":"../../auth"}`, `{"domain":"x.com","list":"gravity"}`, `{"domain":"no_dots"}`} {
		if _, err := call("domain_add", bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	// The session expires on the Pi-hole side: the module signs in again.
	mu.Lock()
	sid = "s2"
	mu.Unlock()
	if _, err := call("top_blocked", `{}`); err != nil {
		t.Fatal(err)
	}
	if logins != 2 {
		t.Fatalf("logins %d, want 2", logins)
	}
	if hl := m.Health(ctx, "p"); hl.Status != "ok" {
		t.Fatalf("health %+v", hl)
	}
	cfg, _ = json.Marshal(Config{URL: srv.URL, Password: "secret://bad"})
	_ = m.Configure(ctx, h, "b", cfg)
	if hl := m.Health(ctx, "b"); hl.Status != "down" || !strings.Contains(hl.Message, "refused") {
		t.Fatalf("bad password health %+v", hl)
	}
}

// What these do reaches past what an agent approved for write may do
// (going public, paging or silencing people, filtering every client,
// network access, stopping a service), so they're destructive.
func TestRiskOfReachingActions(t *testing.T) {
	want := map[string]bool{}
	for _, n := range []string{"domain_add"} {
		want[n] = true
	}
	for _, a := range New().Manifest().Actions {
		if want[a.Name] {
			delete(want, a.Name)
			if a.Risk != sdk.RiskDestructive {
				t.Errorf("%s must be destructive, is %s", a.Name, a.Risk)
			}
		}
	}
	for n := range want {
		t.Errorf("no action %s", n)
	}
}
