package authentik

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

type fakeAuthentik struct {
	mu     sync.Mutex
	seen   []string
	active map[int]bool
}

var names = map[int]string{1: "akadmin", 7: "alice", 8: "bob"}

func (f *fakeAuthentik) user(pk int) string {
	return fmt.Sprintf(`{"pk":%d,"username":%q,"name":"Name %d","email":"%s@example.com","is_active":%t,"is_superuser":%t,"type":"internal","last_login":"2026-11-03T08:00:00Z","groups_obj":[{"name":"staff"}]}`,
		pk, names[pk], pk, names[pk], f.active[pk], pk == 1)
}

func (f *fakeAuthentik) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer atok" {
		w.WriteHeader(403) // authentik answers 403 for a bad token
		io.WriteString(w, `{"detail":"Token invalid/expired"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	q := r.URL.Query()
	pageOf := func(count int, items ...string) {
		fmt.Fprintf(w, `{"pagination":{"next":0,"previous":0,"count":%d,"current":1},"results":[%s]}`, count, strings.Join(items, ","))
	}
	switch r.Method + " " + strings.TrimPrefix(r.URL.Path, "/api/v3") {
	case "GET /core/users/me/":
		io.WriteString(w, `{"user":{"pk":1,"username":"akadmin"}}`)
	case "GET /admin/version/":
		io.WriteString(w, `{"version_current":"2026.8.1","version_latest":"2026.10.0","outdated":true,"build_hash":"abc"}`)
	case "GET /admin/system/":
		io.WriteString(w, `{"http_headers":{"Authorization":"Bearer atok-LEAKME"},"runtime":{"python_version":"3.12","environment":"docker","uname":"x"},"server_time":"2026-11-04T12:00:00Z"}`)
	case "GET /admin/workers/":
		io.WriteString(w, `[{"worker_id":"a"},{"worker_id":"b"}]`)
	case "GET /outposts/instances/":
		pageOf(1, `{"name":"authentik Embedded Outpost","type":"proxy","config":{"secret":"LEAKME"}}`)
	case "GET /core/users/":
		if q.Get("page_size") == "1" {
			n := 3
			switch {
			case q.Get("is_active") == "false":
				n = 1
			case q.Get("is_active") == "true":
				n = 2
			case q.Get("is_superuser") == "true":
				n = 1
			}
			pageOf(n)
			return
		}
		if u := q.Get("username"); u != "" {
			for pk, n := range names {
				if n == u {
					pageOf(1, f.user(pk))
					return
				}
			}
			pageOf(0)
			return
		}
		pageOf(3, f.user(1), f.user(7), f.user(8))
	case "GET /core/users/7/", "GET /core/users/8/", "GET /core/users/1/":
		var pk int
		fmt.Sscanf(r.URL.Path, "/api/v3/core/users/%d/", &pk)
		io.WriteString(w, f.user(pk))
	case "PATCH /core/users/7/", "PATCH /core/users/8/":
		var pk int
		fmt.Sscanf(r.URL.Path, "/api/v3/core/users/%d/", &pk)
		var b struct {
			IsActive bool `json:"is_active"`
		}
		json.Unmarshal(body, &b)
		f.active[pk] = b.IsActive
		io.WriteString(w, f.user(pk))
	case "GET /core/groups/":
		pageOf(2, `{"pk":"g1","name":"admins","is_superuser":true,"users":[1]}`, `{"pk":"g2","name":"family","is_superuser":false,"users":[7,8],"parent_name":"people"}`)
	case "GET /core/applications/":
		if q.Get("superuser_full_list") != "true" {
			pageOf(0)
			return
		}
		pageOf(1, `{"pk":"a1","name":"Grafana","slug":"grafana","provider_obj":{"name":"grafana-oidc","verbose_name":"OAuth2/OpenID Provider","client_secret":"LEAKME"},"launch_url":"https://grafana.example.com","group":"monitoring"}`)
	case "GET /events/events/":
		if q.Get("ordering") != "-created" {
			w.WriteHeader(400)
			return
		}
		pageOf(1, `{"pk":"e1","user":{"pk":7,"username":"alice","email":"alice@example.com"},"action":"login_failed","app":"authentik.events.signals","context":{"username":"alice","password":"********","http_request":{"path":"/api/v3/flows/executor/default-authentication-flow/"},"geo":{"country":"DE"}},"client_ip":"203.0.113.9","created":"2026-11-04T11:00:00Z"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not found."}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeAuthentik) {
	f := &fakeAuthentik{active: map[int]bool{1: true, 7: true, 8: false}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/if/admin/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://a": "atok", "secret://bad": "x"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestAuthentik(t *testing.T) {
	m, f := setup(t, "secret://a")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "signed in as akadmin · authentik 2026.8.1 (2026.10.0 is out)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"status", `{}`, `"workers":2`},
		{"status", `{}`, `"python_version":"3.12"`},
		{"users", `{}`, `"counts":{"active":2,"inactive":1,"superusers":1,"total":3}`},
		{"users", `{}`, `"groups":["staff"]`},
		{"users", `{"includeEmail":true}`, `"email":"alice@example.com"`},
		{"groups", `{}`, `"members":2`},
		{"applications", `{}`, `"provider":"grafana-oidc (OAuth2/OpenID Provider)"`},
		{"events", `{"action":"login_failed"}`, `"clientIp":"203.0.113.9"`},
		{"events", `{}`, `"country":"DE"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "LEAKME") || strings.Contains(string(r.Output), "********") {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	if r, _ := invoke(m, "users", `{}`, false); strings.Contains(string(r.Output), "@example.com") {
		t.Fatal("emails without being asked")
	}
	if r, _ := invoke(m, "users", `{"limit":0}`, false); strings.Contains(string(r.Output), `"users"`) {
		t.Fatal(string(r.Output))
	}
	if r, _ := invoke(m, "events", `{}`, false); strings.Contains(string(r.Output), "@example.com") {
		t.Fatal("events carry emails")
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "users" || a.Name == "events") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
		if strings.HasSuffix(a.Name, "_user") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}

	// Deactivate alice by username: preview, then for real, then undo.
	r, err := invoke(m, "deactivate_user", `{"username":"alice"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Deactivate alice" || !f.active[7] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "deactivate_user", `{"username":"alice"}`, false)
	if err != nil || f.active[7] || r.Undo == nil || r.Undo.Action != "activate_user" || string(r.Undo.Input) != `{"id":7}` {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], `PATCH /api/v3/core/users/7/ {"is_active":false}`) {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || !f.active[7] || r.Undo.Action != "deactivate_user" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "activate_user", `{"id":7}`, false); err != nil || r.Undo != nil {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, "deactivate_user", `{"id":1}`, false); err == nil || !strings.Contains(err.Error(), "own user") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "deactivate_user", `{"username":"mallory"}`, false); err == nil || !strings.Contains(err.Error(), "no user") {
		t.Fatal(err)
	}
}

func TestAuthentikValidation(t *testing.T) {
	m, f := setup(t, "secret://a")
	for _, c := range []struct{ action, in string }{
		{"deactivate_user", `{}`},
		{"deactivate_user", `{"id":"7/../../admin"}`},
		{"deactivate_user", `{"id":0}`},
		{"activate_user", `{"id":2.5}`},
		{"users", `{"type":"robot"}`},
		{"users", `{"limit":1000}`},
		{"events", `{"action":"login&ordering=x"}`},
		{"groups", `{"search":"a\nb"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://auth", Token: "plain"}, {URL: "auth.local", Token: "secret://a"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || h.Message != "authentik refused the token" {
		t.Fatalf("%+v", h)
	}
}

func TestAuthentikRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://a"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://a": "atok"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
