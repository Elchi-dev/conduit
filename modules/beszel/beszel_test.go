package beszel

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

const (
	web = "abc123def456ghi"
	nas = "zzz999yyy888xxx"
)

type fakeBeszel struct {
	mu     sync.Mutex
	seen   []string
	logins int
	status map[string]string
	token  string
}

func (f *fakeBeszel) sys(id string) string {
	return fmt.Sprintf(`{"id":%q,"name":"name-%s","host":"10.0.0.%d","port":"45876","status":%q,"users":["LEAKME"],"updated":"2026-11-04 10:00:00.000Z",
		"info":{"h":"host-%s","k":"6.8.0","c":4,"t":8,"m":"Ryzen","u":7200,"cpu":12.34,"mp":55.55,"dp":70.01,"b":1.2,"v":"0.12.0","dt":48.4,"la":[0.5,0.4,0.3]}}`,
		id, id[:3], len(f.seen)%250, f.status[id], id[:3])
}

func (f *fakeBeszel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/api/collections/users/auth-with-password" {
		var b map[string]string
		json.Unmarshal(body, &b)
		if b["identity"] != "me@example.com" || b["password"] != "bz-good" {
			w.WriteHeader(400)
			io.WriteString(w, `{"code":400,"message":"Failed to authenticate.","data":{}}`)
			return
		}
		f.logins++
		f.token = fmt.Sprintf("jwt-%d", f.logins)
		fmt.Fprintf(w, `{"token":%q,"record":{"id":"u1","email":"me@example.com"}}`, f.token)
		return
	}
	if r.Header.Get("Authorization") != f.token || f.token == "" {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":401,"message":"The request requires valid record authorization token.","data":{}}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/collections/systems/records":
		fmt.Fprintf(w, `{"page":1,"perPage":500,"totalItems":2,"items":[%s,%s]}`, f.sys(web), f.sys(nas))
	case r.Method == "GET" && (r.URL.Path == "/api/collections/systems/records/"+web || r.URL.Path == "/api/collections/systems/records/"+nas):
		io.WriteString(w, f.sys(strings.TrimPrefix(r.URL.Path, "/api/collections/systems/records/")))
	case r.Method == "GET" && r.URL.Path == "/api/collections/systems/records/aaaaaaaaaaaaaaa":
		io.WriteString(w, f.sys(web)) // another system
	case r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, "/api/collections/systems/records/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/collections/systems/records/")
		var b map[string]string
		json.Unmarshal(body, &b)
		f.status[id] = b["status"]
		fmt.Fprintf(w, `{"id":%q,"status":%q}`, id, b["status"])
	case r.Method == "GET" && r.URL.Path == "/api/collections/system_stats/records":
		io.WriteString(w, `{"items":[{"created":"2026-11-04 10:00:00.000Z","stats":{"cpu":20.04,"m":15.5,"mu":8.21,"mp":53,"d":500,"du":350,"dp":70,"dr":1.5,"dw":2.5,"ns":0.3,"nr":1.1,"la":[1,2,3],"t":{"cpu":61.2,"nvme":44}}}]}`)
	case r.Method == "GET" && r.URL.Path == "/api/collections/alerts/records":
		fmt.Fprintf(w, `{"items":[{"id":"a1","user":"LEAKME","system":%q,"name":"CPU","value":80,"min":10,"triggered":true},{"id":"a2","system":%q,"name":"Status","value":0,"min":0,"triggered":false}]}`, web, nas)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":404,"message":"The requested resource wasn't found.","data":{}}`)
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeBeszel) {
	f := &fakeBeszel{status: map[string]string{web: "up", nas: "paused"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Email: "me@example.com", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bz": "bz-good", "secret://bad": "bz-bad"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestBeszel(t *testing.T) {
	m, f := setup(t, "secret://bz")
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || h.Message != "2 systems, 1 up, 1 paused" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"systems", `{}`, `"cpuPercent":12.3`},
		{"systems", `{"status":"paused"}`, `"name":"name-zzz"`},
		{"system_stats", `{"system":"` + web + `"}`, `"hottestSensor":"cpu"`},
		{"system_stats", `{"system":"` + web + `","type":"1m","limit":5}`, `"memoryUsedGB":8.2`},
		{"alerts", `{}`, `"system":"name-abc"`},
		{"alerts", `{"triggeredOnly":true}`, `"threshold":80`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "jwt-") || strings.Contains(out, "bz-good") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if r, _ := invoke(m, "systems", `{"status":"paused"}`, false); strings.Contains(string(r.Output), web) {
		t.Fatal(string(r.Output))
	}
	if !strings.Contains(strings.Join(f.seen, "\n"), "filter=system%3D%27"+web+"%27+%26%26+type%3D%271m%27") {
		t.Fatal(f.seen)
	}
	if f.logins != 1 {
		t.Fatalf("logged in %d times", f.logins)
	}

	// Pause: preview, real, undo, nothing to change.
	r, err := invoke(m, "pause_system", `{"system":"`+web+`"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Pause monitoring name-abc" || f.status[web] != "up" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "pause_system", `{"system":"`+web+`"}`, false)
	if err != nil || f.status[web] != "paused" || r.Undo == nil || r.Undo.Action != "resume_system" || string(r.Undo.Input) != `{"system":"`+web+`"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if again, err := invoke(m, "pause_system", `{"system":"`+web+`"}`, false); err != nil || again.Undo != nil || !strings.Contains(string(again.Output), "nothing to change") {
		t.Fatalf("%s %v", again.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status[web] != "pending" {
		t.Fatal(err, f.status)
	}

	// An expired token logs in again once.
	f.token = "revoked"
	if _, err := invoke(m, "systems", `{}`, false); err != nil || f.logins != 2 {
		t.Fatal(err, f.logins)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "pause_system" && a.Risk != sdk.RiskDestructive {
			t.Fatal("pause_system must be destructive")
		}
	}
}

func TestBeszelValidation(t *testing.T) {
	m, f := setup(t, "secret://bz")
	for _, c := range []struct{ action, in string }{
		{"pause_system", `{}`},
		{"pause_system", `{"system":"../users/records"}`},
		{"resume_system", `{"system":"abc' || id!='x"}`},
		{"system_stats", `{"system":"abc' || 1=1 || '"}`},
		{"system_stats", `{"system":"` + web + `","type":"5m"}`},
		{"system_stats", `{"system":"` + web + `","limit":1000}`},
		{"systems", `{"status":"gone"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.logins != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// The system changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "pause_system", `{"system":"aaaaaaaaaaaaaaa"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("changed another system: %v %v", err, f.seen)
	}
	for _, c := range []Config{
		{URL: "http://beszel:8090", Email: "me@example.com", Password: "plain"},
		{URL: "http://beszel:8090", Password: "secret://bz"},
		{URL: "beszel:8090", Email: "me@example.com", Password: "secret://bz"},
		{URL: "http://u:p@beszel:8090", Email: "me@example.com", Password: "secret://bz"},
		{URL: "http://beszel:8090/?x", Email: "me@example.com", Password: "secret://bz"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "b"); h.Status != "down" || h.Message != "Beszel refused the email or password" {
		t.Fatalf("%+v", h)
	}
}

func TestBeszelRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = r.Header.Get("Authorization") + string(b)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Email: "me@example.com", Password: "secret://bz"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bz": "bz-good"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "b"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
