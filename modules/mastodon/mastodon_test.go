package mastodon

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

type fakeMasto struct {
	mu    sync.Mutex
	posts map[string]map[string]any
	seen  []string
}

func (f *fakeMasto) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer mtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"The access token is invalid"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	switch {
	case r.URL.Path == "/api/v1/accounts/verify_credentials":
		io.WriteString(w, `{"id":"109","acct":"elchi"}`)
	case r.Method == "POST" && r.URL.Path == "/api/v1/statuses":
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		f.posts["200"] = b
		json.NewEncoder(w).Encode(map[string]any{"id": "200", "url": "https://m/@elchi/200", "visibility": b["visibility"]})
	case strings.HasPrefix(r.URL.Path, "/api/v1/statuses/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/statuses/")
		b, ok := f.posts[id]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"Record not found"}`)
			return
		}
		if r.Method == "DELETE" {
			delete(f.posts, id)
		}
		json.NewEncoder(w).Encode(map[string]any{"id": id, "url": "https://m/@elchi/" + id, "content": "<p>" + b["status"].(string) + "</p>"})
	case r.URL.Path == "/api/v1/notifications":
		io.WriteString(w, `[{"id":"1","type":"mention","account":{"acct":"sam@other.social"},"status":{"id":"5","content":"<p>hey &amp; hi<br>there</p>"}}]`)
	case r.URL.Path == "/api/v1/accounts/109/statuses":
		io.WriteString(w, `[{"id":"9","content":"<p>old</p>","visibility":"public","favourites_count":3}]`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeMasto) {
	f := &fakeMasto{posts: map[string]map[string]any{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{Instance: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://m": "mtok", "secret://bad": "no"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "m", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMastodon(t *testing.T) {
	m, f := setup(t, "secret://m")
	if h := m.Health(context.Background(), "m"); h.Status != "ok" || h.Message != "@elchi" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "post", `{"text":"hello fediverse"}`, false)
	if err != nil || r.Undo == nil || f.posts["200"]["visibility"] != "public" {
		t.Fatalf("%+v %v %v", r, err, f.posts)
	}
	p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || p.Plan.Summary != `Delete the post "hello fediverse"` || f.posts["200"] == nil {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.posts["200"] != nil {
		t.Fatal("not deleted", err)
	}
	if _, err := invoke(m, "post", `{"text":"quiet","visibility":"unlisted","warning":"cw"}`, false); err != nil || f.posts["200"]["spoiler_text"] != "cw" || f.posts["200"]["visibility"] != "unlisted" {
		t.Fatal(err, f.posts)
	}
	r, err = invoke(m, "notifications", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"text":"hey \u0026 hi\nthere"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "mine", `{"limit":5}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"text":"old"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestMastodonValidation(t *testing.T) {
	m, f := setup(t, "secret://m")
	for _, c := range [][2]string{
		{"post", `{"text":""}`},
		{"post", `{"text":"x","visibility":"everyone"}`},
		{"post", `{"text":"x","replyTo":"../1"}`},
		{"delete", `{"id":"../accounts/1"}`},
		{"delete", `{"id":"1?x=2"}`},
	} {
		if _, err := invoke(m, c[0], c[1], false); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
	if len(f.seen) != 0 {
		t.Fatal(f.seen)
	}
	for _, c := range []Config{{Instance: "https://m.social", Token: "plain"}, {Instance: "https://m.social/web", Token: "secret://m"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	raw, _ := json.Marshal(Config{Instance: "mastodon.social", Token: "secret://m"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
		t.Fatal("bare host refused", err)
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "m"); h.Status != "down" {
		t.Fatalf("%+v", h)
	}
}

// Posting can be public and notifies everyone mentioned, so it's
// destructive; the preview names who it reaches and creates nothing.
func TestMastodonPostIsDestructiveWithPreview(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		if a.Name == "post" && (a.Risk != sdk.RiskDestructive || !a.DryRun) {
			t.Fatalf("post is %s (dry run %v)", a.Risk, a.DryRun)
		}
	}
	m, f := setup(t, "secret://m")
	f.posts["7"] = map[string]any{"status": "original"}
	p, err := invoke(m, "post", `{"text":"thanks @sam@other.social and @kim","visibility":"direct","replyTo":"7"}`, true)
	if err != nil || p.Plan == nil {
		t.Fatal(err)
	}
	if len(f.posts) != 1 {
		t.Fatal("the preview posted", f.posts)
	}
	after := string(p.Plan.Changes[0].After)
	for _, want := range []string{`"visibility":"direct"`, `"mentions":["@sam@other.social","@kim"]`, `"replyTo":{"author":"@`, `"id":"7"`} {
		if !strings.Contains(after, want) {
			t.Fatalf("missing %s in %s", want, after)
		}
	}
	if !strings.Contains(p.Plan.Summary, "notifies @sam@other.social, @kim") || !strings.Contains(p.Plan.Summary, "Reply (direct)") {
		t.Fatal(p.Plan.Summary)
	}
}
