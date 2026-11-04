package planetscale

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

const (
	tid = "a1b2c3d4e5f6"
	tok = "fakepscale_0123456789abcdefghijklmnopqrstuv"
)

type fakePS struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakePS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != tid+":"+tok {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":"unauthorized","message":"The access token is invalid"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	dp := "/v1/organizations/acme/databases/shop"
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/organizations":
		if r.URL.Query().Get("page") == "1" {
			io.WriteString(w, `{"data":[{"id":"o1","name":"acme","plan":"scaler_pro","database_count":2}],"next_page":2}`)
		} else {
			io.WriteString(w, `{"data":[{"id":"o2","name":"beta","plan":"hobby","database_count":0}],"next_page":null}`)
		}
	case "GET /v1/organizations/acme/databases":
		io.WriteString(w, `{"data":[{"id":"d1","name":"shop","kind":"mysql","state":"ready","plan":"scaler_pro","region":{"slug":"aws-eu-west-1","display_name":"AWS eu-west-1"},
			"production_branches_count":1,"development_branches_count":2,"html_url":"https://app.planetscale.com/acme/shop","url":"mysql://user:LEAKPASS@aws.connect.psdb.cloud/shop"}],"next_page":null}`)
	case "GET " + dp + "/branches":
		io.WriteString(w, `{"data":[{"name":"main","production":true,"ready":true,"region":{"slug":"aws-eu-west-1"},"safe_migrations":true,"mysql_address":"aws.connect.psdb.cloud","password":"pscale_pw_LEAKPASS"},
			{"name":"dev","production":false,"ready":true,"parent_branch":"main","region":{"slug":"aws-eu-west-1"}}],"next_page":null}`)
	case "GET " + dp + "/deploy-requests":
		state := r.URL.Query().Get("state")
		if state != "" && state != "open" {
			io.WriteString(w, `{"data":[],"next_page":null}`)
			return
		}
		io.WriteString(w, `{"data":[{"id":"dr1","number":7,"branch":"dev","into_branch":"main","state":"open","deployment_state":"ready","approved":true,"notes":"adds index","actor":{"display_name":"Ada","id":"LEAKID"},"created_at":"2026-11-04T10:00:00Z"}],"next_page":null}`)
	case "GET " + dp + "/deploy-requests/7":
		io.WriteString(w, `{"id":"dr1","number":7,"branch":"dev","into_branch":"main","state":"open","deployment_state":"ready","approved":true,
			"notes":"adds index; temp creds password=LEAKPASS99","actor":{"display_name":"Ada"},"deployment":{"state":"ready","deployable":true}}`)
	case "GET " + dp + "/deploy-requests/8":
		io.WriteString(w, `{"number":7}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":"not_found","message":"Not Found"}`)
	}
}

func setup(t *testing.T, ref, org string) (*Module, *fakePS) {
	f := &fakePS{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{TokenID: tid, Token: ref, Organization: org})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ps": tok, "secret://bad": "fakepscale_00000000000000000000"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in)})
}

func TestPlanetScale(t *testing.T) {
	m, _ := setup(t, "secret://ps", "")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "2 organizations" {
		t.Fatalf("%+v", h)
	}
	in := `{"organization":"acme","database":"shop"}`
	for _, c := range []struct{ action, in, want string }{
		{"organizations", `{}`, `"name":"beta"`},
		{"databases", `{"organization":"acme"}`, `"productionBranches":1`},
		{"databases", `{"organization":"acme"}`, `"region":"aws-eu-west-1"`},
		{"branches", in, `"parent":"main"`},
		{"branches", in, `"production":true`},
		{"deploy_requests", in, `"author":"Ada"`},
		{"deploy_requests", `{"organization":"acme","database":"shop","state":"open"}`, `"number":7`},
		{"deploy_request", `{"organization":"acme","database":"shop","number":7}`, `"deployable":true`},
		{"deploy_request", `{"organization":"acme","database":"shop","number":7}`, `"notes":"adds index; temp creds [redacted]"`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
		if strings.Contains(out, "LEAK") || strings.Contains(out, "mysql://") {
			t.Fatalf("leaked: %s", out)
		}
	}
	if r, _ := invoke(m, "deploy_requests", `{"organization":"acme","database":"shop","state":"closed"}`); string(r.Output) != "[]" {
		t.Fatal(string(r.Output))
	}
	if _, err := invoke(m, "deploy_request", `{"organization":"acme","database":"shop","number":8}`); err == nil {
		t.Fatal("accepted another deploy request")
	}
	if _, err := invoke(m, "branches", `{"organization":"acme","database":"nope"}`); err == nil || !strings.Contains(err.Error(), "no database nope") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "databases", `{}`); err == nil || !strings.Contains(err.Error(), "name the organization") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
	// A configured organization is the default, and the health check uses it.
	d, _ := setup(t, "secret://ps", "acme")
	if h := d.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "1 databases in acme" {
		t.Fatalf("%+v", h)
	}
	if r, err := invoke(d, "branches", `{"database":"shop"}`); err != nil || !strings.Contains(string(r.Output), `"name":"dev"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestPlanetScaleValidation(t *testing.T) {
	m, f := setup(t, "secret://ps", "acme")
	for _, c := range []struct{ action, in string }{
		{"branches", `{}`},
		{"branches", `{"database":"../../organizations"}`},
		{"branches", `{"database":"Shop DB"}`},
		{"databases", `{"organization":"acme/x"}`},
		{"deploy_requests", `{"database":"shop","state":"all"}`},
		{"deploy_request", `{"database":"shop"}`},
		{"deploy_request", `{"database":"shop","number":-1}`},
		{"deploy", `{"database":"shop","number":7}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{TokenID: tid, Token: tok}, {TokenID: "a b", Token: "secret://ps"}, {Token: "secret://ps"}, {TokenID: tid, Token: "secret://ps", Organization: "Acme Inc"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", "")
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || h.Message != "PlanetScale refused the service token" {
		t.Fatalf("%+v", h)
	}
}

func TestPlanetScaleRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.URL.Path + r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{TokenID: tid, Token: "secret://ps"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ps": tok}), "p", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
