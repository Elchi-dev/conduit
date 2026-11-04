package turso

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

const tok = "eyJhbGciOiJFZERTQSJ9.platformtoken0123456789"

type fakeTurso struct {
	mu   sync.Mutex
	seen []string
	dbs  map[string]bool // name -> delete protection
}

func (f *fakeTurso) db(name string) string {
	// The token fields are planted: Turso never sends them here, and they
	// mustn't come out if it did.
	return fmt.Sprintf(`{"Name":%q,"DbId":"id-%s","Hostname":"%s-acme.turso.io","group":"default","primaryRegion":"fra","regions":["fra","iad"],"version":"0.24.1",
		"block_reads":false,"block_writes":%t,"delete_protection":%t,"token":"LEAKTOKEN","jwt":"LEAKTOKEN"}`, name, name, name, name == "logs", f.dbs[name])
}

func (f *fakeTurso) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+tok {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"invalid token"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	o := "/v1/organizations/acme"
	path := r.Method + " " + r.URL.Path
	switch {
	case path == "GET "+o+"/databases":
		rows := []string{}
		for _, n := range []string{"app", "logs", "kept", "fresh"} {
			if _, ok := f.dbs[n]; ok {
				rows = append(rows, f.db(n))
			}
		}
		fmt.Fprintf(w, `{"databases":[%s]}`, strings.Join(rows, ","))
	case path == "POST "+o+"/databases":
		var b map[string]string
		json.Unmarshal(body, &b)
		f.dbs[b["name"]] = false
		fmt.Fprintf(w, `{"database":{"DbId":"id-%s","Hostname":"%s-acme.turso.io","Name":%q}}`, b["name"], b["name"], b["name"])
	case strings.HasPrefix(path, "GET "+o+"/databases/") && strings.HasSuffix(path, "/usage"):
		io.WriteString(w, `{"database":{"uuid":"id-app","usage":{"rows_read":10,"rows_written":5,"storage_bytes":2048,"bytes_synced":0}}}`)
	case strings.HasPrefix(path, "GET "+o+"/databases/"):
		n := strings.TrimPrefix(r.URL.Path, o+"/databases/")
		if _, ok := f.dbs[n]; !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"database not found"}`)
			return
		}
		fmt.Fprintf(w, `{"database":%s}`, f.db(n))
	case strings.HasPrefix(path, "DELETE "+o+"/databases/"):
		delete(f.dbs, strings.TrimPrefix(r.URL.Path, o+"/databases/"))
		io.WriteString(w, `{"database":"x"}`)
	case path == "GET "+o+"/groups":
		io.WriteString(w, `{"groups":[{"name":"default","uuid":"g1","version":"0.24.1","primary":"fra","locations":["fra","iad"],"archived":false}]}`)
	case path == "GET "+o+"/groups/default":
		io.WriteString(w, `{"group":{"name":"default","primary":"fra","locations":["fra","iad"]}}`)
	case path == "GET "+o+"/usage":
		io.WriteString(w, `{"organization":{"uuid":"o1","usage":{"rows_read":100,"rows_written":50,"databases":2,"locations":2,"storage_bytes":1048576,"groups":1,"bytes_synced":0},
			"databases":[{"uuid":"id-app","usage":{"rows_read":90,"rows_written":40,"storage_bytes":1000000}}]}}`)
	case path == "GET /v1/locations":
		io.WriteString(w, `{"locations":{"iad":"Ashburn, Virginia (US)","fra":"Frankfurt, Germany"}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"not found"}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeTurso) {
	f := &fakeTurso{dbs: map[string]bool{"app": false, "logs": false, "kept": true}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: ref, Organization: "Acme"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://turso": tok, "secret://bad": "eyJbad0000000000000000000000"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestTursoReads(t *testing.T) {
	m, _ := setup(t, "secret://turso")
	if h := m.Health(context.Background(), "t"); h.Status != "degraded" || h.Message != "3 databases, 1 with reads or writes blocked" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"databases", `{}`, `"locations":["fra","iad"]`},
		{"databases", `{"group":"default"}`, `"deleteProtection":true`},
		{"groups", `{}`, `"databases":3`},
		{"locations", `{}`, `{"code":"fra","name":"Frankfurt, Germany"}`},
		{"usage", `{}`, `"database":"app"`},
		{"usage", `{}`, `"storage":"1.0 MB"`},
		{"usage", `{"database":"app"}`, `"rowsWritten":5`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "LEAKTOKEN") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
}

func TestTursoCreateDelete(t *testing.T) {
	m, f := setup(t, "secret://turso")
	r, err := invoke(m, "create_database", `{"name":"fresh"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "group default (fra, iad)") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, ok := f.dbs["fresh"]; ok {
		t.Fatal("created on a dry run")
	}
	r, err = invoke(m, "create_database", `{"name":"fresh"}`, false)
	if _, ok := f.dbs["fresh"]; err != nil || !ok || r.Undo == nil || r.Undo.Action != "delete_database" || string(r.Undo.Input) != `{"database":"fresh","id":"id-fresh"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "create_database", `{"name":"fresh"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	d, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true)
	if err != nil || d.Plan == nil || !strings.Contains(d.Plan.Summary, "for good") {
		t.Fatalf("%+v %v", d.Plan, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.dbs["fresh"]; ok {
		t.Fatal("not deleted")
	}
	// An undo naming another id (the database was replaced) deletes nothing.
	if _, err := invoke(m, "delete_database", `{"database":"app","id":"id-older"}`, false); err == nil || !strings.Contains(err.Error(), "nothing deleted") {
		t.Fatal(err)
	}
	if _, ok := f.dbs["app"]; !ok {
		t.Fatal("deleted a database with another id")
	}
	if _, err := invoke(m, "delete_database", `{"database":"kept"}`, false); err == nil || !strings.Contains(err.Error(), "delete protection") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_database", `{"database":"gone"}`, false); err == nil || !strings.Contains(err.Error(), "no database") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "create_database", `{"name":"x","group":"nope"}`, false); err == nil || !strings.Contains(err.Error(), "no group") {
		t.Fatal(err)
	}
	for _, s := range f.seen {
		if strings.Contains(s, "/auth/tokens") || strings.Contains(s, "/tokens") {
			t.Fatalf("asked for a token: %s", s)
		}
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "delete_database" && a.Risk != sdk.RiskDestructive) || (a.Name == "create_database" && (a.Risk != sdk.RiskWrite || !a.Reversible)) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestTursoValidation(t *testing.T) {
	m, f := setup(t, "secret://turso")
	for _, c := range []struct{ action, in string }{
		{"delete_database", `{}`},
		{"delete_database", `{"database":"../groups"}`},
		{"delete_database", `{"database":"App"}`},
		{"usage", `{"database":"a/b"}`},
		{"create_database", `{"name":"-x"}`},
		{"create_database", `{"name":"ok","group":"a b"}`},
		{"databases", `{"group":"x?y"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Token: "plain-token", Organization: "acme"}, {Token: "secret://turso"}, {Token: "secret://turso", Organization: "acme/../x"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "t"); h.Status != "down" || h.Message != "Turso refused the platform API token" {
		t.Fatalf("%+v", h)
	}
}

func TestTursoRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.URL.Path + r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://turso": tok}), "t", json.RawMessage(`{"token":"secret://turso","organization":"acme"}`)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "t"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
