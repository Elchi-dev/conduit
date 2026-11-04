package harbor

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

var digest = "sha256:" + strings.Repeat("ab", 32)

type fake struct {
	mu      sync.Mutex
	seen    []string
	tags    []string
	deleted bool
	scanned bool
}

func (f *fake) artifact() map[string]any {
	var tags []any
	for _, t := range f.tags {
		tags = append(tags, map[string]any{"name": t})
	}
	return map[string]any{"digest": digest, "type": "IMAGE", "size": 50 << 20, "push_time": "2026-10-01T00:00:00Z", "tags": tags,
		"scan_overview": map[string]any{"application/vnd.security.vulnerability.report; version=1.1": map[string]any{"scan_status": "Success", "severity": "High", "end_time": "2026-10-02T00:00:00Z",
			"summary": map[string]any{"total": 12, "fixable": 7, "summary": map[string]int{"High": 2, "Medium": 10}}, "scanner": map[string]any{"name": "Trivy", "version": "v0.50"}}}}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v2.0/health" {
		io.WriteString(w, `{"status":"healthy","components":[{"name":"core","status":"healthy"}]}`)
		return
	}
	if u, p, ok := r.BasicAuth(); !ok || u != "robot$conduit" || p != "hbsecret" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"code":"UNAUTHORIZED","message":"unauthorized"}]}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	repo := "/api/v2.0/projects/lib/repositories/web%252Fapi"
	if r.Header.Get("X-Is-Resource-Name") != "true" {
		w.WriteHeader(400)
		return
	}
	switch r.Method + " " + r.URL.EscapedPath() {
	case "GET /api/v2.0/projects":
		w.Header().Set("X-Total-Count", "3")
		io.WriteString(w, `[{"name":"lib","project_id":4,"repo_count":2,"owner_name":"admin","metadata":{"public":"true","auto_scan":"true"}},{"name":"cache","project_id":5,"registry_id":1,"metadata":{}}]`)
	case "GET /api/v2.0/projects/lib":
		io.WriteString(w, `{"project_id":4,"name":"lib"}`)
	case "GET /api/v2.0/projects/lib/repositories":
		io.WriteString(w, `[{"name":"lib/web/api","artifact_count":3,"pull_count":99}]`)
	case "GET " + repo + "/artifacts":
		if r.Header.Get("X-Accept-Vulnerabilities") == "" {
			w.WriteHeader(400)
			return
		}
		if f.deleted {
			io.WriteString(w, `[]`)
			return
		}
		enc.Encode([]any{f.artifact()})
	case "GET " + repo + "/artifacts/" + digest:
		enc.Encode(f.artifact())
	case "GET " + repo + "/artifacts/v1", "GET " + repo + "/artifacts/latest":
		tag := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		for _, t := range f.tags {
			if t == tag {
				enc.Encode(f.artifact())
				return
			}
		}
		w.WriteHeader(404)
	case "POST " + repo + "/artifacts/" + digest + "/scan":
		f.scanned = true
		w.WriteHeader(202)
	case "DELETE " + repo + "/artifacts/" + digest:
		f.deleted = true
	case "DELETE " + repo + "/artifacts/" + digest + "/tags/latest":
		f.tags = []string{"v1"}
	case "POST " + repo + "/artifacts/" + digest + "/tags":
		var b struct{ Name string }
		json.Unmarshal(body, &b)
		f.tags = append(f.tags, b.Name)
		w.WriteHeader(201)
	case "GET /api/v2.0/robots":
		if r.URL.Query().Get("q") != "Level=project,ProjectID=4" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"id":1,"name":"robot$lib+ci","level":"project","secret":"robot-secret-xyz","expires_at":-1,"permissions":[{"kind":"project","namespace":"lib","access":[{"resource":"repository","action":"push"}]}]}]`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[{"code":"NOT_FOUND","message":"not found"}]}`)
	}
}

func setup(t *testing.T, pw string) (*Module, *fake) {
	f := &fake{tags: []string{"v1", "latest"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Address: srv.URL, Username: "robot$conduit", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hb": "hbsecret", "secret://bad": "nope"}), "h", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "h", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestHarborReads(t *testing.T) {
	m, _ := setup(t, "secret://hb")
	if h := m.Health(context.Background(), "h"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"total":3`},
		{"projects", `{"name":"li"}`, `"proxyCache":true`},
		{"repositories", `{"project":"lib"}`, `"name":"web/api"`},
		{"artifacts", `{"project":"lib","repository":"web/api"}`, `"bySeverity":{"High":2,"Medium":10},"completed":"2026-10-02T00:00:00Z","fixable":7,"scanner":"Trivy v0.50","severity":"High","status":"Success","total":12`},
		{"artifacts", `{"project":"lib","repository":"lib/web/api"}`, `"tags":["v1","latest"]`},
		{"robots", `{"project":"lib"}`, `"access":["repository:push"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "robot-secret") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
}

func TestHarborChanges(t *testing.T) {
	m, f := setup(t, "secret://hb")
	r, err := invoke(m, "scan", `{"project":"lib","repository":"web/api","reference":"v1"}`, true)
	if err != nil || r.Plan == nil || f.scanned || !strings.Contains(r.Plan.Summary, "last scan: Success") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "scan", `{"project":"lib","repository":"web/api","reference":"v1"}`, false); err != nil || !f.scanned {
		t.Fatal(err)
	}

	r, err = invoke(m, "delete_tag", `{"project":"lib","repository":"web/api","tag":"latest"}`, true)
	if err != nil || r.Plan == nil || len(f.tags) != 2 || !strings.Contains(r.Plan.Summary, "with tags v1") {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "delete_tag", `{"project":"lib","repository":"web/api","tag":"latest"}`, false)
	if err != nil || len(f.tags) != 1 || r.Undo == nil || r.Undo.Action != "add_tag" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || len(f.tags) != 2 || f.tags[1] != "latest" || r.Undo == nil || r.Undo.Action != "delete_tag" {
		t.Fatalf("%+v %v %v", r, err, f.tags)
	}

	r, err = invoke(m, "delete_artifact", `{"project":"lib","repository":"web/api","reference":"v1"}`, true)
	if err != nil || r.Plan == nil || f.deleted || !strings.Contains(r.Plan.Summary, "2 tag(s): v1, latest") || !strings.Contains(r.Plan.Summary, "can't be undone") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "delete_artifact", `{"project":"lib","repository":"web/api","reference":"v1"}`, false); err != nil || !f.deleted {
		t.Fatal(err)
	}
	// The delete went by digest, not by the tag.
	if !strings.Contains(f.seen[len(f.seen)-1], "DELETE /api/v2.0/projects/lib/repositories/web%252Fapi/artifacts/"+digest) {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	for _, a := range m.Manifest().Actions {
		switch a.Name {
		case "delete_artifact", "delete_tag", "add_tag":
			if a.Risk != sdk.RiskDestructive || !a.DryRun {
				t.Fatal(a.Name)
			}
		case "scan":
			if a.Risk != sdk.RiskWrite || !a.DryRun {
				t.Fatal(a.Name)
			}
		}
	}
}

func TestHarborValidation(t *testing.T) {
	m, f := setup(t, "secret://hb")
	for _, c := range []struct{ action, in string }{
		{"repositories", `{"project":"../users"}`},
		{"repositories", `{"project":"Lib"}`},
		{"repositories", `{}`},
		{"projects", `{"name":"a&b"}`},
		{"artifacts", `{"project":"lib","repository":"../../users"}`},
		{"artifacts", `{"project":"lib","repository":"web/../x"}`},
		{"artifacts", `{"project":"lib","repository":"web?x"}`},
		{"scan", `{"project":"lib","repository":"web/api","reference":"../x"}`},
		{"scan", `{"project":"lib","repository":"web/api","reference":"sha256:zz"}`},
		{"delete_artifact", `{"project":"lib","repository":"web/api","reference":""}`},
		{"delete_tag", `{"project":"lib","repository":"web/api","tag":"a/b"}`},
		{"add_tag", `{"project":"lib","repository":"web/api","reference":"v1","tag":".x"}`},
		{"robots", `{"project":"a/b"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Address: "http://x", Username: "u", Password: "plain"}, {Address: "http://x", Username: "u"}, {Address: "http://x", Password: "secret://hb"}, {Address: "ftp://x", Username: "u", Password: "secret://hb"},
		{Address: "http://u:p@x", Username: "u", Password: "secret://hb"}, {Address: "http://x/api", Username: "u", Password: "secret://hb"}, {Address: "https://x", Username: "u", Password: "secret://hb", Fingerprint: "zz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "h"); h.Status != "down" || !strings.Contains(h.Message, "refused the username or password") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "projects", `{}`, false); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
}

func TestHarborRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "!" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{Address: srv.URL, Username: "u", Password: "secret://hb"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hb": "hbsecret"}), "h", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "projects", `{}`, false); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}
