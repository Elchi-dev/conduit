package discourse

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

type fakeForum struct {
	mu    sync.Mutex
	seen  []string
	posts []map[string]any
}

func (f *fakeForum) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Api-Key") != "dkey" || r.Header.Get("Api-Username") != "conduit" {
		w.WriteHeader(403)
		io.WriteString(w, `{"errors":["You are not permitted to view the requested resource. The API username or key is invalid."],"error_type":"invalid_access"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	topic := func(id, cat string, closed bool) string {
		c := "false"
		if closed {
			c = "true"
		}
		return `{"id":` + id + `,"title":"Upgrade plans","category_id":` + cat + `,"posts_count":2,"closed":` + c + `,"archetype":"regular","post_stream":{"posts":[` +
			`{"id":100,"username":"sam","created_at":"2026-11-04T10:00:00Z","post_number":1,"cooked":"<p>We should <strong>upgrade</strong> &amp; test.</p>"},` +
			`{"id":101,"username":"kim","created_at":"2026-11-04T10:05:00Z","post_number":2,"reply_to_post_number":1,"cooked":"<p>Agreed</p>"}]}}`
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /session/current.json":
		io.WriteString(w, `{"current_user":{"id":5,"username":"conduit"}}`)
	case "GET /site.json":
		io.WriteString(w, `{"categories":[{"id":1,"name":"General","slug":"general"},{"id":2,"name":"Staff","slug":"staff","read_restricted":true},{"id":3,"name":"Ops","slug":"ops","parent_category_id":1}]}`)
	case "GET /latest.json":
		io.WriteString(w, `{"topic_list":{"topics":[{"id":7,"title":"Upgrade plans","category_id":1,"posts_count":2,"last_posted_at":"2026-11-04T10:05:00Z","unread_posts":1},{"id":8,"title":"Salaries","category_id":2,"posts_count":1,"pinned":true}]}}`)
	case "GET /unread.json":
		io.WriteString(w, `{"topic_list":{"topics":[{"id":7,"title":"Upgrade plans","category_id":1,"unread_posts":1}]}}`)
	case "GET /new.json":
		io.WriteString(w, `{"topic_list":{"topics":[]}}`)
	case "GET /t/7.json", "GET /t/7/1.json":
		io.WriteString(w, topic("7", "1", false))
	case "GET /t/8.json":
		io.WriteString(w, topic("8", "2", false))
	case "GET /t/9.json":
		io.WriteString(w, topic("9", "1", true))
	case "POST /posts.json":
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		f.posts = append(f.posts, in)
		io.WriteString(w, `{"id":102,"topic_id":7,"post_number":3,"username":"conduit"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":["The requested URL or resource could not be found."],"error_type":"not_found"}`)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeForum) {
	t.Helper()
	f := &fakeForum{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	cfg.URL = srv.URL + "/"
	if cfg.Username == "" {
		cfg.Username = "conduit"
	}
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://d": "dkey", "secret://bad": "nope"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestDiscourse(t *testing.T) {
	m, f := setup(t, Config{APIKey: "secret://d", AllowedCategories: []string{"General", "3"}})
	if h := m.Health(context.Background(), "d"); h.Status != "ok" || h.Message != "signed in as conduit, 2 allowed categories" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "categories", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `{"allowed":false,"id":2,"name":"Staff","private":true,"slug":"staff"}`) ||
		!strings.Contains(string(r.Output), `{"allowed":true,"id":3,"name":"Ops","parent":"general","private":false,"slug":"ops"}`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "latest", `{"limit":1}`, false)
	if err != nil || string(r.Output) != `[{"allowed":true,"category":"general","id":7,"lastPost":"2026-11-04T10:05:00Z","posts":2,"title":"Upgrade plans","unread":1}]` {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err = invoke(m, "unread", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"id":7`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "read_topic", `{"topic":7}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"text":"We should upgrade \u0026 test."`) || !strings.Contains(string(r.Output), `"title":"Upgrade plans"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "read_topic", `{"topic":8}`, false); err == nil || !strings.Contains(err.Error(), "allowed category") {
		t.Fatal("read a topic outside the allowed categories", err)
	}

	r, err = invoke(m, "reply", `{"topic":7,"text":"Sounds good to me, let's go.","replyTo":1}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "(public category general), to sam's post #1 (notifies them)") || len(f.posts) != 0 {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "reply", `{"topic":7,"text":"Sounds good to me, let's go.","replyTo":1}`, false)
	if err != nil || r.Undo != nil || len(f.posts) != 1 || f.posts[0]["reply_to_post_number"] != float64(1) || !strings.HasSuffix(string(r.Output), `/t/7/3"}`) {
		t.Fatalf("%s %+v %v", r.Output, f.posts, err)
	}
	for _, in := range []string{`{"topic":8,"text":"x"}`, `{"topic":9,"text":"x"}`, `{"topic":7,"text":"x","replyTo":5}`} {
		if _, err := invoke(m, "reply", in, false); err == nil || len(f.posts) != 1 {
			t.Fatalf("replied: %s %v", in, err)
		}
	}
	if spec := m.Manifest().Actions[4]; spec.Name != "reply" || spec.Risk != sdk.RiskDestructive || !spec.Sensitive {
		t.Fatalf("%+v", spec)
	}
}

func TestDiscourseValidation(t *testing.T) {
	m, f := setup(t, Config{APIKey: "secret://d", AllowedCategories: []string{"general"}})
	for _, in := range []string{
		`{"topic":0,"text":"x"}`,
		`{"topic":"../admin","text":"x"}`,
		`{"topic":7,"text":"  "}`,
		`{"topic":7,"text":"x","replyTo":-1}`,
		`{"topic":7,"text":"` + strings.Repeat("a", maxRaw+1) + `"}`,
	} {
		if _, err := invoke(m, "reply", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := invoke(m, "read_topic", `{"topic":-3}`, false); err == nil {
		t.Fatal("accepted topic")
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	none, nf := setup(t, Config{APIKey: "secret://d"})
	if _, err := invoke(none, "read_topic", `{"topic":7}`, false); err == nil || len(nf.seen) != 0 {
		t.Fatal("read with no allowed categories", err)
	}
	if h := none.Health(context.Background(), "d"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []Config{
		{URL: "https://forum", Username: "conduit", APIKey: "plain"},
		{URL: "forum.example.com", Username: "conduit", APIKey: "secret://d"},
		{URL: "https://forum", Username: "a b", APIKey: "secret://d"},
		{URL: "https://forum", Username: "conduit", APIKey: "secret://d", AllowedCategories: []string{"../x"}},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, Config{APIKey: "secret://bad"})
	if h := bad.Health(context.Background(), "d"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestDiscourseRefusesRedirect(t *testing.T) {
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Api-Key") }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "conduit", APIKey: "secret://d"})
	_ = m.Configure(context.Background(), fakehost.New(map[string]string{"secret://d": "dkey"}), "d", raw)
	if h := m.Health(context.Background(), "d"); h.Status != "down" || leaked != "" {
		t.Fatalf("%+v %q", h, leaked)
	}
}
