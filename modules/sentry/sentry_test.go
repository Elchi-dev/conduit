package sentry

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

type fake struct {
	mu     sync.Mutex
	status string
	query  string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer sntrys_x" {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":"Invalid token"}`)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/0/organizations/acme/":
		io.WriteString(w, `{"name":"Acme"}`)
	case "GET /api/0/organizations/acme/projects/":
		io.WriteString(w, `[{"slug":"web","name":"Web","platform":"javascript"}]`)
	case "GET /api/0/organizations/acme/issues/":
		f.query = r.URL.Query().Get("query")
		io.WriteString(w, `[{"id":"123","shortId":"WEB-1","title":"TypeError: x is undefined","culprit":"app.js","level":"error","count":"40","userCount":12,"project":{"slug":"web"}}]`)
	case "GET /api/0/organizations/acme/issues/123/":
		io.WriteString(w, `{"shortId":"WEB-1","title":"TypeError","status":"`+f.status+`","count":"40","userCount":12}`)
	case "GET /api/0/organizations/acme/issues/123/events/latest/":
		io.WriteString(w, `{"eventID":"abc","dateCreated":"2026-11-03T22:00:00Z","platform":"javascript","tags":[{"key":"release","value":"1.4.0"},{"key":"user","value":"secret@x"}]}`)
	case "PUT /api/0/organizations/acme/issues/123/":
		var b struct{ Status string }
		json.NewDecoder(r.Body).Decode(&b)
		f.status = b.Status
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"not found"}`)
	}
}

func TestSentry(t *testing.T) {
	f := &fake{status: "unresolved"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ctx := context.Background()
	host := fakehost.New(map[string]string{"secret://s": "sntrys_x"})
	m := New()
	cfg, _ := json.Marshal(Config{URL: srv.URL, Organization: "acme", Token: "secret://s"})
	if err := m.Configure(ctx, host, "s", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "s"); h.Status != "ok" || h.Message != "Acme" {
		t.Fatalf("health %+v", h)
	}
	call := func(action, in string) sdk.Result {
		t.Helper()
		r, err := m.Invoke(ctx, sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return r
	}
	call("projects", "")
	if out := string(call("issues", `{"project":"web"}`).Output); !strings.Contains(out, "WEB-1") || f.query != "is:unresolved project:web" {
		t.Fatalf("%s %q", out, f.query)
	}
	out := string(call("issue", `{"id":"123"}`).Output)
	if !strings.Contains(out, "1.4.0") || strings.Contains(out, "secret@x") {
		t.Fatalf("issue %s", out)
	}
	r := call("resolve", `{"id":"123"}`)
	if f.status != "resolved" {
		t.Fatal("resolve")
	}
	call(r.Undo.Action, string(r.Undo.Input))
	if f.status != "unresolved" {
		t.Fatal("undo")
	}
	call("ignore", `{"id":"123"}`)
	for _, bad := range []string{`{"id":"../../x"}`, `{"id":"12a"}`} {
		if _, err := m.Invoke(ctx, sdk.Call{Instance: "s", Action: "resolve", Input: json.RawMessage(bad)}); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "s", Action: "issues", Input: json.RawMessage(`{"project":"Web/../x"}`)}); err == nil {
		t.Fatal("bad project accepted")
	}
	for _, c := range []Config{{URL: "http://sentry.example.com", Organization: "acme", Token: "secret://s"}, {Organization: "Acme Inc", Token: "secret://s"}, {Organization: "acme"}} {
		b, _ := json.Marshal(c)
		if err := New().Configure(ctx, host, "x", b); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}
