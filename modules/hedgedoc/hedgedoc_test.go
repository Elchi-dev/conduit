package hedgedoc

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

const token = "hd2tokenAbCdEfGhIjKlMnOpQrStUvWxYz0123"

type fakeHedgeDoc struct {
	mu    sync.Mutex
	seen  []string
	notes map[string]string
}

func (f *fakeHedgeDoc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.EscapedPath()+" "+string(body))
	p := strings.TrimPrefix(r.URL.EscapedPath(), "/md")
	if strings.HasPrefix(p, "/api/v2/") {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(403) // HedgeDoc 2's guard refuses with 403
			io.WriteString(w, `{"message":"Forbidden resource","error":"Forbidden","statusCode":403}`)
			return
		}
		meta := func(id string) map[string]any {
			return map[string]any{"id": id, "aliases": []any{map[string]any{"name": id, "primaryAlias": true}}, "primaryAddress": id, "title": "Runbook", "description": "", "tags": []string{"ops"}, "updatedAt": "2026-11-04T10:00:00Z"}
		}
		switch {
		case r.Method == "GET" && p == "/api/v2/me":
			io.WriteString(w, `{"username":"elchi","displayName":"Elchi","email":"e@example.com"}`)
		case r.Method == "GET" && p == "/api/v2/me/notes":
			json.NewEncoder(w).Encode([]any{meta("runbook")})
		case r.Method == "POST" && p == "/api/v2/notes":
			if r.Header.Get("Content-Type") != "text/markdown" {
				w.WriteHeader(400)
				return
			}
			f.notes["new1"] = string(body)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"content": string(body), "metadata": meta("new1")})
		case r.Method == "GET" && strings.HasSuffix(p, "/metadata"):
			id := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v2/notes/"), "/metadata")
			if _, ok := f.notes[id]; !ok {
				w.WriteHeader(404)
				return
			}
			json.NewEncoder(w).Encode(meta(id))
		case r.Method == "GET" && strings.HasSuffix(p, "/content"):
			id := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v2/notes/"), "/content")
			w.Header().Set("Content-Type", "text/markdown")
			io.WriteString(w, f.notes[id])
		default:
			w.WriteHeader(404)
		}
		return
	}
	// HedgeDoc 1's public routes.
	switch {
	case r.Method == "GET" && p == "/status":
		io.WriteString(w, `{"onlineNotes":1,"onlineUsers":2,"notesCount":5}`)
	case r.Method == "POST" && p == "/new":
		if r.Header.Get("Content-Type") != "text/markdown" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(400)
			return
		}
		f.notes["AbCdEf_12-x"] = string(body)
		http.Redirect(w, r, "https://md.example.com/AbCdEf_12-x", http.StatusFound)
	case r.Method == "GET" && strings.HasSuffix(p, "/info"):
		if _, ok := f.notes[strings.Trim(strings.TrimSuffix(p, "/info"), "/")]; !ok {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"title":"Runbook","description":"Steps","viewcount":3,"createtime":"2026-11-01","updatetime":"2026-11-02"}`)
	case r.Method == "GET" && strings.HasSuffix(p, "/download"):
		io.WriteString(w, f.notes[strings.Trim(strings.TrimSuffix(p, "/download"), "/")])
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeHedgeDoc, string) {
	f := &fakeHedgeDoc{notes: map[string]string{"runbook": "# Runbook\nsecret steps"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	cfg.URL = srv.URL + "/md/"
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hd": token, "secret://bad": "nopenopenope"}), "h", raw); err != nil {
		t.Fatal(err)
	}
	return m, f, srv.URL
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "h", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestHedgeDoc2(t *testing.T) {
	m, f, base := setup(t, Config{Token: "secret://hd"})
	if h := m.Health(context.Background(), "h"); h.Status != "ok" || h.Message != "signed in as Elchi (elchi)" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "notes", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"note":"runbook"`) || strings.Contains(string(r.Output), "secret steps") {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, id := range []string{"runbook", base + "/md/n/runbook"} {
		r, err = invoke(m, "read_note", `{"note":"`+id+`"}`, false)
		if err != nil || !strings.Contains(string(r.Output), `"content":"# Runbook\nsecret steps"`) {
			t.Fatalf("%s %v", r.Output, err)
		}
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "read_note") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
	}
	r, err = invoke(m, "create_note", `{"content":"# New\nhello"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(string(r.Plan.Changes[0].After), `"added":2`) || len(f.notes) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_note", `{"content":"# New\nhello"}`, false)
	if err != nil || f.notes["new1"] != "# New\nhello" || !strings.Contains(string(r.Output), `"note":"new1"`) || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "read_note", `{"note":"missing"}`, false); err == nil || !strings.Contains(err.Error(), "no note") {
		t.Fatal(err)
	}
}

func TestHedgeDoc1(t *testing.T) {
	m, f, _ := setup(t, Config{Version: 1})
	if h := m.Health(context.Background(), "h"); h.Status != "ok" || h.Message != "HedgeDoc 1 · 5 notes · 2 online" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "notes", `{}`, false); err == nil || !strings.Contains(err.Error(), "HedgeDoc 2") {
		t.Fatal(err)
	}
	r, err := invoke(m, "read_note", `{"note":"runbook"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"content":"# Runbook\nsecret steps"`) || !strings.Contains(string(r.Output), `"title":"Runbook"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	// The redirect points at the new note; it isn't followed.
	r, err = invoke(m, "create_note", `{"content":"hello"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"note":"AbCdEf_12-x"`) || f.notes["AbCdEf_12-x"] != "hello" {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, s := range f.seen {
		if strings.Contains(s, "AbCdEf_12-x ") && strings.HasPrefix(s, "GET") {
			t.Fatalf("followed the redirect: %s", s)
		}
	}
}

func TestHedgeDocValidation(t *testing.T) {
	m, f, _ := setup(t, Config{Token: "secret://hd"})
	for _, c := range []struct{ action, in string }{
		{"read_note", `{}`},
		{"read_note", `{"note":"../api/v2/me"}`},
		{"read_note", `{"note":"a/b"}`},
		{"read_note", `{"note":".."}`},
		{"read_note", `{"note":"a?b"}`},
		{"read_note", `{"note":"https://evil.example.com/runbook"}`},
		{"create_note", `{}`},
		{"create_note", `{"content":"` + strings.Repeat("x", 1<<20+1) + `"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %.80s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://md.example.com", Token: token},
		{URL: "https://md.example.com"},
		{URL: "https://md.example.com", Version: 1, Token: "secret://hd"},
		{URL: "https://md.example.com", Version: 3, Token: "secret://hd"},
		{URL: "md.example.com", Token: "secret://hd"},
		{URL: "https://u:p@md.example.com", Token: "secret://hd"},
		{URL: "https://md.example.com?x", Token: "secret://hd"},
		{URL: "https://md.example.com#x", Token: "secret://hd"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _, _ := setup(t, Config{Token: "secret://bad"})
	if h := bad.Health(context.Background(), "h"); h.Status != "down" || !strings.Contains(h.Message, "refused the API token") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "read_note", `{"note":"runbook"}`, false); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
}

func TestHedgeDocNoSecretInOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]any{"message": "token " + r.Header.Get("Authorization") + " broke"})
	}))
	defer srv.Close()
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://hd"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hd": token}), "h", raw); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "h")
	_, err := invoke(m, "read_note", `{"note":"x"}`, false)
	if h.Status != "down" || strings.Contains(h.Message, token) || err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("%+v %v", h, err)
	}
}

func TestHedgeDocRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://hd"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hd": token}), "h", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "h"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
