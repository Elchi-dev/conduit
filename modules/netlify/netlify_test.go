package netlify

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
	siteUUID = "5a1b2c3d-0000-4000-8000-000000000001"
	d1       = "aaaaaaaaaaaaaaaaaaaaaaa1" // live
	d2       = "aaaaaaaaaaaaaaaaaaaaaaa2" // older, ready
	d3       = "aaaaaaaaaaaaaaaaaaaaaaa3" // failed
	dOther   = "bbbbbbbbbbbbbbbbbbbbbbb1" // other site
)

type fakeNetlify struct {
	mu     sync.Mutex
	seen   []string
	live   string
	locked bool
	builds int
}

func (f *fakeNetlify) deploy(id string) map[string]any {
	d := map[string]any{"id": id, "site_id": siteUUID, "state": "ready", "context": "production", "branch": "main", "commit_ref": "c0ffee" + id[23:], "created_at": "2026-11-0" + id[23:] + "T10:00:00Z", "deploy_ssl_url": "https://" + id + "--blog.netlify.app"}
	switch id {
	case d1:
		d["locked"] = f.locked
	case d3:
		d["state"], d["error_message"] = "error", "Build script returned non-zero exit code: 2"
		d["summary"] = map[string]any{"status": "error", "messages": []any{map[string]any{"type": "error", "title": "Build failed", "description": "npm run build exited 2", "details": "TypeError at app.js:10"}}}
	case dOther:
		d["site_id"] = "5a1b2c3d-0000-4000-8000-000000000099"
	}
	return d
}

func (f *fakeNetlify) site() map[string]any {
	live := f.deploy(f.live)
	live["locked"] = f.locked
	return map[string]any{"id": siteUUID, "name": "blog", "ssl_url": "https://blog.netlify.app", "account_slug": "elchi", "published_deploy": live,
		"build_settings": map[string]any{"repo_url": "https://github.com/elchi/blog", "repo_branch": "main"}}
}

func (f *fakeNetlify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer nftok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":401,"message":"Access Denied"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	switch r.Method + " " + r.URL.Path {
	case "GET /user":
		io.WriteString(w, `{"full_name":"Elchi","email":"private@example.com"}`)
	case "GET /sites", "GET /elchi/sites":
		enc.Encode([]any{f.site()})
	case "GET /sites/" + siteUUID, "GET /sites/blog.netlify.app":
		enc.Encode(f.site())
	case "GET /sites/" + siteUUID + "/deploys":
		enc.Encode([]any{f.deploy(d3), f.deploy(d1), f.deploy(d2)})
	case "GET /deploys/" + d1, "GET /deploys/" + d2, "GET /deploys/" + d3, "GET /deploys/" + dOther:
		enc.Encode(f.deploy(strings.TrimPrefix(r.URL.Path, "/deploys/")))
	case "POST /sites/" + siteUUID + "/builds":
		f.builds++
		io.WriteString(w, `{"id":"build1","deploy_id":"aaaaaaaaaaaaaaaaaaaaaaa4"}`)
	case "POST /sites/" + siteUUID + "/deploys/" + d1 + "/restore", "POST /sites/" + siteUUID + "/deploys/" + d2 + "/restore":
		f.live = strings.Split(r.URL.Path, "/")[4]
		enc.Encode(f.deploy(f.live))
	case "POST /deploys/" + d1 + "/lock", "POST /deploys/" + d2 + "/lock":
		f.locked = true
		io.WriteString(w, `{}`)
	case "POST /deploys/" + d1 + "/unlock", "POST /deploys/" + d2 + "/unlock":
		f.locked = false
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":404,"message":"Not Found"}`)
	}
}

func setup(t *testing.T, tok, account string) (*Module, *fakeNetlify) {
	f := &fakeNetlify{live: d1}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok, Account: account})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nf": "nftok", "secret://bad": "nope"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestNetlifyReads(t *testing.T) {
	m, f := setup(t, "secret://nf", "elchi")
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || h.Message != "signed in as Elchi" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"sites", `{}`, `"repo":"https://github.com/elchi/blog"`},
		{"site", `{"site":"Blog.Netlify.app"}`, `"autoPublishLocked":false`},
		{"deploys", `{"site":"blog.netlify.app"}`, `"error":"Build script returned non-zero exit code: 2"`},
		{"deploys", `{"site":"blog.netlify.app"}`, `"live":true`},
		{"deploy", `{"deploy":"` + d3 + `"}`, `"details":"TypeError at app.js:10"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "private@") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if !strings.HasPrefix(f.seen[1], "GET /elchi/sites?") {
		t.Fatalf("team scope not used: %v", f.seen[1])
	}
}

func TestNetlifyWrites(t *testing.T) {
	m, f := setup(t, "secret://nf", "")

	if r, err := invoke(m, "trigger_build", `{"site":"blog.netlify.app","clearCache":true}`, true); err != nil || r.Plan == nil || r.Plan.Summary != "Build blog from main with a clear cache" || f.builds != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "trigger_build", `{"site":"blog.netlify.app"}`, false); err != nil || f.builds != 1 || !strings.Contains(string(r.Output), `"build":"build1"`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Rollback with no deploy picks the newest ready production deploy older than the live one.
	r, err := invoke(m, "rollback", `{"site":"blog.netlify.app"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Publish deploy "+d2) || !strings.Contains(r.Plan.Summary, "auto-publishing is on") || f.live != d1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if !strings.Contains(string(r.Plan.Changes[0].Before), d1) || !strings.Contains(string(r.Plan.Changes[0].After), d2) {
		t.Fatalf("%+v", r.Plan.Changes)
	}
	r, err = invoke(m, "rollback", `{"site":"blog.netlify.app"}`, false)
	if err != nil || f.live != d2 || r.Undo == nil || string(r.Undo.Input) != `{"deploy":"`+d1+`","site":"`+siteUUID+`"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.live != d1 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "rollback", `{"site":"blog.netlify.app","deploy":"`+d3+`"}`, false); err == nil || !strings.Contains(err.Error(), "is error") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "rollback", `{"site":"blog.netlify.app","deploy":"`+dOther+`"}`, false); err == nil || !strings.Contains(err.Error(), "another site") {
		t.Fatal(err)
	}

	// Lock and unlock auto-publishing.
	if r, err := invoke(m, "lock_publishing", `{"site":"blog.netlify.app"}`, true); err != nil || r.Plan == nil || f.locked {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "lock_publishing", `{"site":"blog.netlify.app"}`, false)
	if err != nil || !f.locked || r.Undo == nil || r.Undo.Action != "unlock_publishing" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "lock_publishing", `{"site":"blog.netlify.app"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "already locked") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.locked {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "rollback" && (a.Risk != sdk.RiskDestructive || !a.DryRun) {
			t.Fatal("rollback must be destructive with a preview")
		}
	}
}

func TestNetlifyValidation(t *testing.T) {
	m, f := setup(t, "secret://nf", "")
	for _, c := range []struct{ action, in string }{
		{"site", `{"site":"../user"}`},
		{"site", `{"site":"a/b"}`},
		{"site", `{"site":""}`},
		{"deploys", `{"site":"blog..netlify.app"}`},
		{"deploy", `{"deploy":"abc"}`},
		{"deploy", `{"deploy":"` + d1 + `/../x"}`},
		{"rollback", `{"site":"blog.netlify.app","deploy":"nope"}`},
		{"lock_publishing", `{"site":"blog netlify"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Token: "plain"}, {Token: "secret://nf", Account: "../x"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", "")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestNetlifyRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://nf"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nf": "nftok"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
