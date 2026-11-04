package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeNPM struct {
	mu     sync.Mutex
	seen   []string
	logins int
	hosts  map[int]map[string]any
	nextID int
}

func (f *fakeNPM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	path := strings.TrimPrefix(r.URL.Path, "/api")
	if r.Method == "GET" && path == "/" {
		io.WriteString(w, `{"status":"OK","version":{"major":2,"minor":12,"revision":3}}`)
		return
	}
	if r.Method == "POST" && path == "/tokens" {
		var b struct{ Identity, Secret string }
		json.Unmarshal(body, &b)
		if b.Identity != "admin@example.com" || b.Secret != "pw" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"code":401,"message":"Invalid email or password"}}`)
			return
		}
		f.logins++
		fmt.Fprintf(w, `{"token":"tok%d","expires":"2099-01-01T00:00:00.000Z"}`, f.logins)
		return
	}
	if r.Header.Get("Authorization") != fmt.Sprintf("Bearer tok%d", f.logins) {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":401,"message":"Token has expired"}}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var id int
	switch {
	case r.Method == "GET" && path == "/users/me":
		io.WriteString(w, `{"id":1,"email":"admin@example.com"}`)
	case r.Method == "GET" && path == "/nginx/proxy-hosts":
		var ids []int
		for id := range f.hosts {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		var out []map[string]any
		for _, id := range ids {
			out = append(out, f.hosts[id])
		}
		json.NewEncoder(w).Encode(out)
	case r.Method == "GET" && path == "/nginx/certificates":
		io.WriteString(w, `[{"id":3,"provider":"letsencrypt","nice_name":"example.com","domain_names":["example.com","*.example.com"],"expires_on":"2026-11-14 12:00:00","meta":{"dns_challenge":true,"dns_provider_credentials":"dns_cloudflare_api_token = LEAKME"}},
			{"id":4,"provider":"other","nice_name":"old","domain_names":["old.lan"],"expires_on":"2026-10-01 00:00:00","meta":{}},
			{"id":5,"provider":"letsencrypt","nice_name":"far","domain_names":["far.example.com"],"expires_on":"2027-06-01 00:00:00","meta":{}}]`)
	case r.Method == "POST" && path == "/nginx/proxy-hosts":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.nextID++
		b["id"] = f.nextID
		b["enabled"] = true
		f.hosts[f.nextID] = b
		json.NewEncoder(w).Encode(b)
	case sscan(path, "/nginx/proxy-hosts/%d/enable", &id) && r.Method == "POST":
		f.hosts[id]["enabled"] = 1
		io.WriteString(w, `true`)
	case sscan(path, "/nginx/proxy-hosts/%d/disable", &id) && r.Method == "POST":
		f.hosts[id]["enabled"] = 0
		io.WriteString(w, `true`)
	case sscan(path, "/nginx/proxy-hosts/%d", &id):
		h, ok := f.hosts[id]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":{"code":404,"message":"Not Found"}}`)
			return
		}
		if r.Method == "DELETE" {
			delete(f.hosts, id)
			io.WriteString(w, `true`)
			return
		}
		json.NewEncoder(w).Encode(h)
	default:
		w.WriteHeader(404)
	}
}

func sscan(path, format string, id *int) bool {
	var rest string
	n, _ := fmt.Sscanf(path+" end", format+" %s", id, &rest)
	return n == 2 && rest == "end"
}

func setup(t *testing.T, secret string) (*Module, *fakeNPM) {
	f := &fakeNPM{nextID: 10, hosts: map[int]map[string]any{
		1: {"id": 1, "domain_names": []string{"app.example.com"}, "forward_scheme": "http", "forward_host": "10.0.0.5", "forward_port": 8080,
			"certificate_id": 3, "ssl_forced": 1, "block_exploits": 1, "allow_websocket_upgrade": 0, "enabled": 1, "advanced_config": "client_max_body_size 0;",
			"locations": []any{map[string]any{"path": "/api", "forward_host": "10.0.0.6", "forward_port": 9000}},
			"meta":      map[string]any{"nginx_online": true}, "certificate": map[string]any{"nice_name": "example.com"}},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Email: "admin@example.com", Password: secret})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "nope"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestNPM(t *testing.T) {
	m, f := setup(t, "secret://pw")
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || h.Message != "Nginx Proxy Manager 2.12.3" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "proxy_hosts", `{"query":"app"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"forward":"http://10.0.0.5:8080"`) || !strings.Contains(string(r.Output), `"certificate":"example.com"`) || !strings.Contains(string(r.Output), `"enabled":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "certificates", `{"withinDays":30}`, false)
	if err != nil || strings.Contains(string(r.Output), "LEAKME") || strings.Contains(string(r.Output), "far") {
		t.Fatalf("%s %v", r.Output, err)
	}
	var certs []map[string]any
	json.Unmarshal(r.Output, &certs)
	if len(certs) != 2 || certs[0]["name"] != "old" || certs[0]["expired"] != true || certs[1]["daysLeft"] != float64(10) || certs[1]["proxyHosts"] != float64(1) {
		t.Fatalf("%s", r.Output)
	}

	// Disable with preview and undo.
	r, err = invoke(m, "disable", `{"id":1}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Disable the proxy host for app.example.com" || f.hosts[1]["enabled"] != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "disable", `{"id":1}`, false)
	if err != nil || f.hosts[1]["enabled"] != 0 || r.Undo == nil || r.Undo.Action != "enable" || string(r.Undo.Input) != `{"id":1}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.hosts[1]["enabled"] != 1 {
		t.Fatal(err)
	}
	if r, _ := invoke(m, "enable", `{"id":1}`, false); r.Undo != nil {
		t.Fatal("no-op enable has an undo")
	}

	// Create, with a duplicate check, preview and undo.
	if _, err := invoke(m, "create_proxy_host", `{"domains":["APP.example.com"],"forwardHost":"x","forwardPort":80}`, false); err == nil || !strings.Contains(err.Error(), "already served by proxy host 1") {
		t.Fatal(err)
	}
	in := `{"domains":["new.example.com"],"forwardHost":"jellyfin","forwardPort":8096,"websockets":true,"certificateId":3,"sslForced":true}`
	r, err = invoke(m, "create_proxy_host", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(string(r.Plan.Changes[0].After), `"forward":"http://jellyfin:8096"`) || len(f.hosts) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_proxy_host", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_proxy_host" || string(r.Undo.Input) != `{"id":11}` {
		t.Fatalf("%+v %v", r, err)
	}
	if h := f.hosts[11]; h["allow_websocket_upgrade"] != true || h["ssl_forced"] != true || h["block_exploits"] != true || h["forward_host"] != "jellyfin" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.hosts[11] != nil {
		t.Fatal(err)
	}

	// Delete host 1 and undo: it comes back with its settings under a new id.
	r, err = invoke(m, "delete_proxy_host", `{"id":1}`, true)
	if err != nil || r.Plan == nil || r.Plan.Changes[0].Op != "delete" || f.hosts[1] == nil {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "delete_proxy_host", `{"id":1}`, false)
	if err != nil || f.hosts[1] != nil || r.Undo == nil || r.Undo.Action != "create_proxy_host" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	h := f.hosts[12]
	if h == nil || h["advanced_config"] != "client_max_body_size 0;" || h["certificate_id"] != float64(3) || h["ssl_forced"] != true || len(h["locations"].([]any)) != 1 {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "delete_proxy_host", `{"id":99}`, false); err == nil || !strings.Contains(err.Error(), "no proxy host 99") {
		t.Fatal(err)
	}

	// A revoked token: sign in again once.
	f.logins++
	if _, err := invoke(m, "proxy_hosts", `{}`, false); err != nil || f.logins != 3 {
		t.Fatalf("%v logins=%d", err, f.logins)
	}
}

func TestNPMValidation(t *testing.T) {
	m, f := setup(t, "secret://pw")
	for _, c := range []struct{ action, in string }{
		{"enable", `{}`},
		{"enable", `{"id":"1/../../users"}`},
		{"disable", `{"id":0}`},
		{"delete_proxy_host", `{"id":1.5}`},
		{"create_proxy_host", `{"domains":[],"forwardHost":"x","forwardPort":80}`},
		{"create_proxy_host", `{"domains":["bad domain"],"forwardHost":"x","forwardPort":80}`},
		{"create_proxy_host", `{"domains":["a.example.com"],"forwardHost":"x; return 200 hi","forwardPort":80}`},
		{"create_proxy_host", `{"domains":["a.example.com"],"forwardHost":"x","forwardPort":0}`},
		{"create_proxy_host", `{"domains":["a.example.com"],"forwardHost":"x","forwardPort":80,"forwardScheme":"ftp"}`},
		{"create_proxy_host", `{"domains":["a.example.com"],"forwardHost":"x","forwardPort":80,"sslForced":true}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "http://npm:81", Email: "a@b", Password: "plain"}, {URL: "npm:81", Email: "a@b", Password: "secret://pw"}, {URL: "http://npm:81", Email: "admin", Password: "secret://pw"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" || h.Message != errLogin.Error() {
		t.Fatalf("%+v", h)
	}
}

func TestNPMRefusesCrossHostRedirect(t *testing.T) {
	var leaked bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = strings.Contains(string(b), "pw") || r.Header.Get("Authorization") != ""
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/" {
			io.WriteString(w, `{"status":"OK","version":{"major":2}}`)
			return
		}
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Email: "admin@example.com", Password: "secret://pw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "down" || leaked {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
