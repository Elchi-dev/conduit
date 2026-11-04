package upstash

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
	email = "ops@example.com"
	key   = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	db1   = "4f8a1c2e-1111-4a2b-9c3d-0123456789ab"
)

type fakeUpstash struct {
	mu   sync.Mutex
	seen []string
}

// Upstash returns the password and REST tokens with every database.
var dbJSON = fmt.Sprintf(`{"database_id":%q,"database_name":"cache","database_type":"Pay as You Go","type":"payg","region":"global","primary_region":"eu-central-1","read_regions":["us-east-1"],
	"port":6379,"creation_time":1700000000,"state":"active","password":"LEAKPASS","user_email":"ops@example.com","endpoint":"cache-1234.upstash.io","tls":true,
	"rest_token":"AXLEAKRESTTOKEN","read_only_rest_token":"AXLEAKROTOKEN","eviction":true,"budget":20,
	"connection_string":"rediss://default:LEAKPASS@cache-1234.upstash.io:6379"}`, db1)

func (f *fakeUpstash) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if !ok || u != email || p != key {
		w.WriteHeader(401)
		io.WriteString(w, `"Unauthorized"`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	switch r.Method + " " + r.URL.Path {
	case "GET /v2/redis/databases":
		io.WriteString(w, "["+dbJSON+"]")
	case "GET /v2/redis/database/" + db1:
		io.WriteString(w, dbJSON)
	case "GET /v2/redis/stats/" + db1:
		io.WriteString(w, `{"keyspace":1200,"current_storage":2097152,"total_monthly_requests":50000,"total_monthly_read_requests":40000,"total_monthly_write_requests":10000,
			"total_monthly_billing":1.25,"total_monthly_bandwidth":1048576,"connection_count":[{"x":"2026-11-04 10:00","y":3},{"x":"2026-11-04 11:00","y":5}],
			"dailyrequests":[{"x":"2026-11-03","y":900},{"x":"2026-11-04","y":1100}],"throughput":"odd shape"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `"not found"`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeUpstash) {
	f := &fakeUpstash{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Email: email, Key: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://up": key, "secret://bad": "00000000-0000-0000-0000-000000000000"}), "u", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "u", Action: action, Input: json.RawMessage(in)})
}

func TestUpstash(t *testing.T) {
	m, _ := setup(t, "secret://up")
	if h := m.Health(context.Background(), "u"); h.Status != "ok" || h.Message != "1 Redis databases" {
		t.Fatalf("%+v", h)
	}
	in := `{"database":"` + strings.ToUpper(db1) + `"}`
	for _, c := range []struct{ action, in, want string }{
		{"redis_databases", `{}`, `"host":"cache-1234.upstash.io"`},
		{"redis_databases", `{}`, `"readRegions":["us-east-1"]`},
		{"redis_databases", `{}`, `"plan":"payg"`},
		{"redis_stats", in, `"keys":1200`},
		{"redis_stats", in, `"storage":"2.0 MB"`},
		{"redis_stats", in, `"connections":5`},
		{"redis_stats", in, `{"day":"2026-11-04","requests":1100}`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
		if strings.Contains(out, "LEAK") || strings.Contains(out, "rediss://") || strings.Contains(out, "password") || strings.Contains(out, "token") {
			t.Fatalf("leaked: %s", out)
		}
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestUpstashValidation(t *testing.T) {
	m, f := setup(t, "secret://up")
	for _, in := range []string{`{}`, `{"database":"../databases"}`, `{"database":"cache"}`, `{"database":"` + db1 + `/x"}`} {
		if _, err := invoke(m, "redis_stats", in); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Email: email, Key: key}, {Email: "not an email", Key: "secret://up"}, {Key: "secret://up"}, {Email: "a:b@example.com", Key: "secret://up"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "u"); h.Status != "down" || h.Message != "Upstash refused the email and API key" {
		t.Fatalf("%+v", h)
	}
}

func TestUpstashRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.URL.Path + r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Email: email, Key: "secret://up"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://up": key}), "u", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "u"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
