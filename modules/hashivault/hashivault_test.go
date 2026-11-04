package hashivault

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

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fake struct {
	mu       sync.Mutex
	seen     []string
	versions map[int]map[string]string
	current  int
	deleted  map[int]bool
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/sys/health" {
		io.WriteString(w, `{"initialized":true,"sealed":false,"standby":false,"version":"1.17.2","cluster_name":"prod"}`)
		return
	}
	if r.Header.Get("X-Vault-Token") != "hvs.good" {
		w.WriteHeader(403)
		io.WriteString(w, `{"errors":["permission denied"]}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	q := r.URL.Query()
	switch r.Method + " " + r.URL.EscapedPath() {
	case "GET /v1/sys/seal-status":
		io.WriteString(w, `{"type":"shamir","t":3,"n":5,"progress":0,"storage_type":"raft"}`)
	case "GET /v1/auth/token/lookup-self":
		io.WriteString(w, `{"data":{"id":"hvs.good","accessor":"acc-123","display_name":"token-ops","policies":["default","ops"],"type":"service","ttl":3600,"renewable":true,"expire_time":"2026-11-05T00:00:00Z"}}`)
	case "GET /v1/sys/mounts":
		io.WriteString(w, `{"secret/":{"type":"kv","options":{"version":"2"},"description":"key/value"},"sys/":{"type":"system"},"request_id":"x","data":{"secret/":{"type":"kv","options":{"version":"2"},"description":"key/value"},"sys/":{"type":"system"}}}`)
	case "GET /v1/sys/internal/ui/mounts/secret":
		io.WriteString(w, `{"data":{"type":"kv","options":{"version":"2"},"path":"secret/"}}`)
	case "GET /v1/sys/internal/ui/mounts/old":
		io.WriteString(w, `{"data":{"type":"kv","options":{"version":"1"},"path":"old/"}}`)
	case "GET /v1/secret/metadata/":
		io.WriteString(w, `{"data":{"keys":["app/","top"]}}`)
	case "GET /v1/secret/metadata/app/":
		io.WriteString(w, `{"data":{"keys":["db","web/"]}}`)
	case "GET /v1/secret/metadata/app/db":
		if f.current == 0 {
			w.WriteHeader(404)
			io.WriteString(w, `{"errors":[]}`)
			return
		}
		vs := map[string]any{}
		for v := range f.versions {
			e := map[string]any{"created_time": "2026-01-0" + strconv.Itoa(v) + "T00:00:00Z", "deletion_time": "", "destroyed": false}
			if f.deleted[v] {
				e["deletion_time"] = "2026-02-01T00:00:00Z"
			}
			vs[strconv.Itoa(v)] = e
		}
		enc.Encode(map[string]any{"data": map[string]any{"current_version": f.current, "oldest_version": 1, "max_versions": 0, "versions": vs, "custom_metadata": map[string]string{"owner": "ops"}}})
	case "GET /v1/secret/data/app/db":
		v := f.current
		if s := q.Get("version"); s != "" {
			v, _ = strconv.Atoi(s)
		}
		d, ok := f.versions[v]
		if !ok || f.deleted[v] {
			w.WriteHeader(404)
			io.WriteString(w, `{"errors":[]}`)
			return
		}
		enc.Encode(map[string]any{"data": map[string]any{"data": d, "metadata": map[string]any{"version": v, "created_time": "2026-01-01T00:00:00Z"}}})
	case "POST /v1/secret/data/app/db":
		var b struct {
			Options struct{ CAS int }
			Data    map[string]string
		}
		json.Unmarshal(body, &b)
		if b.Options.CAS != f.current {
			w.WriteHeader(400)
			io.WriteString(w, `{"errors":["check-and-set parameter did not match the current version"]}`)
			return
		}
		f.current++
		f.versions[f.current] = b.Data
		enc.Encode(map[string]any{"data": map[string]any{"version": f.current}})
	case "GET /v1/sys/metrics":
		io.WriteString(w, `{"Gauges":[{"Name":"vault.expire.num_leases","Value":42},{"Name":"vault.expire.num_irrevocable_leases","Value":1}]}`)
	case "GET /v1/sys/leases/lookup/database/creds/":
		io.WriteString(w, `{"data":{"keys":["app/","ro/"]}}`)
	case "GET /v1/sys/leases/lookup/database/creds/app/":
		io.WriteString(w, `{"data":{"keys":["l1","l2","l3"]}}`)
	case "GET /v1/sys/leases/lookup/database/creds/ro/":
		io.WriteString(w, `{"data":{"keys":["l4"]}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[]}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	f := &fake{versions: map[int]map[string]string{1: {"user": "app", "password": "old-pass"}, 2: {"user": "app", "password": "hunter2"}}, current: 2, deleted: map[int]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Address: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://v": "hvs.good", "secret://bad": "nope"}), "v", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "v", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestVaultReads(t *testing.T) {
	m, _ := setup(t, "secret://v")
	if h := m.Health(context.Background(), "v"); h.Status != "ok" || !strings.Contains(h.Message, "token token-ops") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"status", `{}`, `"threshold":3`},
		{"mounts", `{}`, `"kvVersion":"2"`},
		{"list_keys", `{}`, `"folders":["app/"]`},
		{"list_keys", `{"path":"app"}`, `"secrets":["db"]`},
		{"metadata", `{"path":"app/db"}`, `"currentVersion":2`},
		{"read_secret", `{"path":"app/db"}`, `"names":["password","user"]`},
		{"token", `{}`, `"policies":["default","ops"]`},
		{"leases", `{}`, `"leases":42`},
		{"leases", `{"prefix":"database/creds"}`, `"leases":4`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "hunter2") || strings.Contains(out, "hvs.good") || strings.Contains(out, "acc-123") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	// A value only when asked for by key.
	r, err := invoke(m, "read_secret", `{"path":"app/db","reveal":["password","nope"]}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"values":{"password":"hunter2"}`) || strings.Contains(string(r.Output), `"user":"app"`) || !strings.Contains(string(r.Output), `"missing":["nope"]`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, _ = invoke(m, "read_secret", `{"path":"app/db","version":1,"reveal":["password"]}`, false)
	if !strings.Contains(string(r.Output), "old-pass") {
		t.Fatal(string(r.Output))
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "read_secret" && (!a.Sensitive || a.Risk != sdk.RiskRead) {
			t.Fatal("read_secret must be a sensitive read")
		}
	}
}

func TestVaultWriteAndRestore(t *testing.T) {
	m, f := setup(t, "secret://v")
	r, err := invoke(m, "write_secret", `{"path":"app/db","data":{"password":"n3w-pass","host":"db1"}}`, true)
	if err != nil || r.Plan == nil || f.current != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	plan, _ := json.Marshal(r.Plan)
	for _, want := range []string{`"added":["host"]`, `"changed":["password"]`, `"removed":["user"]`, "undo restores version 2"} {
		if !strings.Contains(string(plan), want) {
			t.Fatalf("plan missing %s: %s", want, plan)
		}
	}
	if strings.Contains(string(plan), "n3w-pass") || strings.Contains(string(plan), "hunter2") || strings.Contains(string(plan), "db1") {
		t.Fatalf("plan shows values: %s", plan)
	}
	r, err = invoke(m, "write_secret", `{"path":"app/db","data":{"password":"n3w-pass"},"merge":true}`, false)
	if err != nil || f.current != 3 || f.versions[3]["user"] != "app" || f.versions[3]["password"] != "n3w-pass" || r.Undo == nil || r.Undo.Action != "restore_version" {
		t.Fatalf("%+v %v %v", r, err, f.versions[3])
	}
	if strings.Contains(string(r.Output), "n3w-pass") || !strings.Contains(string(f.seen[len(f.seen)-1]), `"cas":2`) {
		t.Fatalf("%s %s", r.Output, f.seen[len(f.seen)-1])
	}
	undo := string(r.Undo.Input)
	if p, err := invoke(m, "restore_version", undo, true); err != nil || p.Plan == nil || f.current != 3 || !strings.Contains(p.Plan.Summary, "copy of version 2") {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, "restore_version", undo, false); err != nil || f.current != 4 || f.versions[4]["password"] != "hunter2" {
		t.Fatalf("%v %v", err, f.versions[4])
	}
	// The same undo again is refused: the secret moved on.
	if _, err := invoke(m, "restore_version", undo, false); err == nil || !strings.Contains(err.Error(), "changed since") {
		t.Fatal(err)
	}
	f.deleted[1] = true
	if _, err := invoke(m, "restore_version", `{"path":"app/db","version":1}`, false); err == nil || !strings.Contains(err.Error(), "gone") {
		t.Fatal(err)
	}
	// Writes go only to KV version 2 mounts.
	if _, err := invoke(m, "write_secret", `{"mount":"old","path":"x","data":{"a":"b"}}`, false); err == nil || !strings.Contains(err.Error(), "isn't a KV version 2 mount") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		switch a.Name {
		case "write_secret":
			if a.Risk != sdk.RiskDestructive || !a.DryRun || !a.Reversible || !a.Sensitive {
				t.Fatal(a.Name)
			}
		case "restore_version":
			if a.Risk != sdk.RiskDestructive || !a.DryRun || !a.Reversible {
				t.Fatal(a.Name)
			}
		}
		if strings.Contains(a.Name, "seal") || strings.Contains(a.Name, "polic") {
			t.Fatalf("%s must not exist", a.Name)
		}
	}
}

func TestVaultValidation(t *testing.T) {
	m, f := setup(t, "secret://v")
	for _, c := range []struct{ action, in string }{
		{"metadata", `{"path":"../sys/policy/root"}`},
		{"metadata", `{"path":"app/../../sys"}`},
		{"metadata", `{"path":"app?list=true"}`},
		{"metadata", `{"path":"app#x"}`},
		{"metadata", `{"path":"a%2fb"}`},
		{"metadata", `{"path":""}`},
		{"metadata", `{"path":"x","mount":"sys"}`},
		{"metadata", `{"path":"x","mount":"auth/token"}`},
		{"list_keys", `{"mount":"../sys"}`},
		{"list_keys", `{"path":"a//b"}`},
		{"read_secret", `{"path":"app/db","reveal":["bad\nkey"]}`},
		{"read_secret", `{"path":"app/db","version":-1}`},
		{"write_secret", `{"path":"app/db"}`},
		{"write_secret", `{"path":"app/db","data":{"":"x"}}`},
		{"write_secret", `{"path":"app/db","data":{"k":"` + strings.Repeat("x", maxValue+1) + `"}}`},
		{"write_secret", `{"path":"../../sys/seal","data":{"k":"v"}}`},
		{"restore_version", `{"path":"app/db"}`},
		{"leases", `{"prefix":"../../sys"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Address: "http://x:8200", Token: "plain"}, {Address: "http://x:8200"}, {Address: "ftp://x", Token: "secret://v"}, {Address: "http://u:p@x:8200", Token: "secret://v"},
		{Address: "http://x:8200/v1", Token: "secret://v"}, {Address: "http://x", Token: "secret://v", Namespace: "a b"}, {Address: "http://x", Token: "secret://v", KVMount: "sys"}, {Address: "https://x", Token: "secret://v", Fingerprint: "zz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "v"); h.Status != "down" || !strings.Contains(h.Message, "refused the token") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "list_keys", `{}`, false); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatal(err)
	}
}

func TestVaultRedirectAndNamespace(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Vault-Token") + "!" }))
	defer evil.Close()
	var ns string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ns = r.Header.Get("X-Vault-Namespace")
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{Address: srv.URL, Token: "secret://v", Namespace: "team-a"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://v": "hvs.good"}), "v", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "token", `{}`, false); err == nil || leaked != "" || ns != "team-a" {
		t.Fatalf("followed the redirect: %v %q %q", err, leaked, ns)
	}
}
