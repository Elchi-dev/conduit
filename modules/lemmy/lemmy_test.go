package lemmy

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

type fakeLemmy struct {
	mu     sync.Mutex
	seen   []string
	logins int
	jwt    string // the session currently accepted
	made   []map[string]any
}

func (f *fakeLemmy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+r.URL.RawQuery)
	if r.URL.Path == "/api/v3/user/login" {
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		if in["username_or_email"] != "kim" || in["password"] != "pw" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"incorrect_login"}`)
			return
		}
		f.logins++
		io.WriteString(w, `{"jwt":"`+f.jwt+`"}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+f.jwt {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"not_logged_in"}`)
		return
	}
	q := r.URL.Query()
	host := "http://" + r.Host
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v3/site":
		io.WriteString(w, `{"site_view":{},"my_user":{"local_user_view":{"person":{"name":"kim"}},"follows":[`+
			`{"community":{"id":1,"name":"selfhosted","title":"Self-hosted","actor_id":"`+host+`/c/selfhosted"}},`+
			`{"community":{"id":2,"name":"linux","title":"Linux","actor_id":"https://lemmy.ml/c/linux"}}]}}`)
	case "GET /api/v3/post/list":
		if q.Get("limit") != "20" || q.Get("sort") != "Hot" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"posts":[{"post":{"id":10,"name":"My homelab","url":"https://example.com/a?b=1","published":"2026-11-04T10:00:00Z"},`+
			`"creator":{"name":"sam","actor_id":"https://lemmy.ml/u/sam"},"community":{"name":"selfhosted","actor_id":"`+host+`/c/selfhosted"},"counts":{"score":5,"comments":2}}]}`)
	case "GET /api/v3/comment/list":
		io.WriteString(w, `{"comments":[{"comment":{"id":20,"post_id":10,"content":"Nice rack","path":"0.20"},"creator":{"name":"lee","actor_id":"`+host+`/u/lee"},"counts":{"score":3}},`+
			`{"comment":{"id":21,"post_id":10,"content":"x","path":"0.20.21","removed":true},"creator":{"name":"bob","actor_id":"`+host+`/u/bob"},"counts":{}}]}`)
	case "GET /api/v3/community":
		switch q.Get("name") {
		case "selfhosted":
			io.WriteString(w, `{"community_view":{"community":{"id":1,"name":"selfhosted","actor_id":"`+host+`/c/selfhosted"}}}`)
		case "linux@lemmy.ml":
			io.WriteString(w, `{"community_view":{"community":{"id":2,"name":"linux","actor_id":"https://lemmy.ml/c/linux"}}}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"couldnt_find_community"}`)
		}
	case "GET /api/v3/post":
		locked := "false"
		if q.Get("id") == "11" {
			locked = "true"
		}
		io.WriteString(w, `{"post_view":{"post":{"id":`+q.Get("id")+`,"name":"My homelab","locked":`+locked+`,"ap_id":"`+host+`/post/`+q.Get("id")+`"},`+
			`"creator":{"name":"sam","actor_id":"https://lemmy.ml/u/sam"},"community":{"name":"selfhosted","actor_id":"`+host+`/c/selfhosted"}}}`)
	case "GET /api/v3/comment":
		io.WriteString(w, `{"comment_view":{"comment":{"id":20,"post_id":10},"creator":{"name":"lee","actor_id":"`+host+`/u/lee"}}}`)
	case "POST /api/v3/post":
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		f.made = append(f.made, in)
		io.WriteString(w, `{"post_view":{"post":{"id":12,"ap_id":"`+host+`/post/12"}}}`)
	case "POST /api/v3/comment":
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		f.made = append(f.made, in)
		io.WriteString(w, `{"comment_view":{"comment":{"id":22,"ap_id":"`+host+`/comment/22"}}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"unknown"}`)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeLemmy) {
	t.Helper()
	f := &fakeLemmy{jwt: "jwt1"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	cfg.URL = srv.URL + "/"
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://jwt": "jwt1", "secret://bad": "nope"}), "l", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "l", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestLemmy(t *testing.T) {
	m, f := setup(t, Config{Username: "kim", Password: "secret://pw"})
	if h := m.Health(context.Background(), "l"); h.Status != "ok" || h.Message != "signed in as kim" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "communities", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"community":"linux@lemmy.ml"`) || !strings.Contains(string(r.Output), `"community":"selfhosted@127.0.0.1"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "posts", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"from":"sam@lemmy.ml"`) || !strings.Contains(string(r.Output), `"url":"https://example.com/a?b=1"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "comments", `{"post":10}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"text":"Nice rack"`) || !strings.Contains(string(r.Output), `"parent":20,"removed":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if f.logins != 1 {
		t.Fatalf("signed in %d times", f.logins)
	}
	// An expired session signs in again once.
	f.jwt = "jwt2"
	if _, err := invoke(m, "communities", `{}`, false); err != nil || f.logins != 2 {
		t.Fatal(err, f.logins)
	}

	r, err = invoke(m, "create_post", `{"community":"!linux@lemmy.ml","title":"Hello","body":"First post","url":"https://93.184.216.34/x"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Post publicly to !linux@lemmy.ml (hosted on another instance); it's copied to every instance that follows it" || len(f.made) != 0 {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_post", `{"community":"selfhosted","title":"Hello"}`, false)
	if err != nil || r.Undo != nil || len(f.made) != 1 || f.made[0]["community_id"] != float64(1) || f.made[0]["name"] != "Hello" {
		t.Fatalf("%s %+v %v", r.Output, f.made, err)
	}
	r, err = invoke(m, "create_comment", `{"post":10,"parent":20,"text":"Thanks"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "replying to lee@127.0.0.1's comment (notifies them)") {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "create_comment", `{"post":10,"text":"Thanks"}`, false); err != nil || len(f.made) != 2 || f.made[1]["post_id"] != float64(10) {
		t.Fatal(err, f.made)
	}
	if _, err := invoke(m, "create_comment", `{"post":11,"text":"x"}`, false); err == nil || len(f.made) != 2 {
		t.Fatal("commented on a locked post")
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasPrefix(a.Name, "create_") && (a.Risk != sdk.RiskDestructive || a.Reversible || !a.Sensitive) {
			t.Fatalf("%+v", a)
		}
	}
}

func TestLemmyToken(t *testing.T) {
	m, f := setup(t, Config{Token: "secret://jwt", AllowedCommunities: []string{"selfhosted"}})
	if h := m.Health(context.Background(), "l"); h.Status != "ok" || f.logins != 0 {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "create_post", `{"community":"linux@lemmy.ml","title":"x"}`, false); err == nil || !strings.Contains(err.Error(), "allowedCommunities") {
		t.Fatal("posted outside the allowed communities", err)
	}
	if _, err := invoke(m, "create_comment", `{"post":10,"text":"x"}`, false); err != nil {
		t.Fatal(err)
	}
	f.jwt = "other"
	if h := m.Health(context.Background(), "l"); h.Status != "down" || !strings.Contains(h.Message, "refused") || f.logins != 0 {
		t.Fatalf("%+v", h)
	}
}

func TestLemmyValidation(t *testing.T) {
	m, f := setup(t, Config{Username: "kim", Password: "secret://pw"})
	for _, in := range []string{
		`{"community":"../admin","title":"x"}`,
		`{"community":"li nux","title":"x"}`,
		`{"community":"linux","title":"  "}`,
		`{"community":"linux","title":"a\nb"}`,
		`{"community":"linux","title":"` + strings.Repeat("a", maxTitle+1) + `"}`,
		`{"community":"linux","title":"x","url":"http://127.0.0.1:8080/admin"}`,
		`{"community":"linux","title":"x","url":"http://user:pw@93.184.216.34/"}`,
		`{"community":"linux","title":"x","url":"file:///etc/passwd"}`,
	} {
		if _, err := invoke(m, "create_post", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	for _, in := range []string{`{"post":0,"text":"x"}`, `{"post":10,"text":" "}`, `{"post":10,"parent":-1,"text":"x"}`} {
		if _, err := invoke(m, "create_comment", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	for _, in := range []string{`{"feed":"mod"}`, `{"sort":"old"}`, `{"community":"a/b"}`} {
		if _, err := invoke(m, "posts", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := invoke(m, "comments", `{"post":-1}`, false); err == nil {
		t.Fatal("accepted post id")
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://lemmy.example", Username: "kim", Password: "plain"},
		{URL: "https://lemmy.example", Token: "jwt"},
		{URL: "https://lemmy.example"},
		{URL: "https://lemmy.example", Username: "a/b", Password: "secret://pw"},
		{URL: "lemmy.example", Username: "kim", Password: "secret://pw"},
		{URL: "https://lemmy.example/api/v3", Username: "kim", Password: "secret://pw"},
		{URL: "https://lemmy.example", Token: "secret://jwt", AllowedCommunities: []string{"a b"}},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, Config{Username: "kim", Password: "secret://bad"})
	if h := bad.Health(context.Background(), "l"); h.Status != "down" || !strings.Contains(h.Message, "refused the user name and password") {
		t.Fatalf("%+v", h)
	}
}

func TestLemmyRefusesRedirect(t *testing.T) {
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = r.Header.Get("Authorization") + string(b)
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "kim", Password: "secret://pw"})
	_ = m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "l", raw)
	if h := m.Health(context.Background(), "l"); h.Status != "down" || leaked != "" {
		t.Fatalf("%+v %q", h, leaked)
	}
}
