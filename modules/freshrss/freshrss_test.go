package freshrss

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	id1 = "tag:google.com,2005:reader/item/0000000000000001"
	id2 = "tag:google.com,2005:reader/item/0000000000000002"
)

type fakeFresh struct {
	mu      sync.Mutex
	seen    []string
	logins  int
	session string
	read    map[string]bool
}

func (f *fakeFresh) item(id string) string {
	cats := `"user/-/state/com.google/reading-list"`
	if f.read[id] {
		cats += `,"user/-/state/com.google/read"`
	}
	n := id[len(id)-1:]
	return fmt.Sprintf(`{"id":%q,"title":"Story %s","published":1793000000,"categories":[%s],"canonical":[{"href":"https://news.example.com/%s"}],"origin":{"streamId":"feed/3","title":"Example news"}}`, id, n, cats, n)
}

func (f *fakeFresh) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/greader.php")
	form, _ := url.ParseQuery(string(body))
	if path == "/accounts/ClientLogin" {
		f.seen = append(f.seen, "login")
		if r.Method != "POST" || form.Get("Email") != "elchi" || form.Get("Passwd") != "api-pass" || r.URL.RawQuery != "" {
			w.WriteHeader(401)
			io.WriteString(w, "Unauthorized!")
			return
		}
		f.logins++
		f.session = fmt.Sprintf("elchi/sess%d", f.logins)
		fmt.Fprintf(w, "SID=%s\nLSID=null\nAuth=%s\n", f.session, f.session)
		return
	}
	if r.Header.Get("Authorization") != "GoogleLogin auth="+f.session || f.session == "" {
		w.WriteHeader(401)
		io.WriteString(w, "Unauthorized!")
		return
	}
	f.seen = append(f.seen, r.Method+" "+path+"?"+r.URL.RawQuery+" "+string(body))
	q := r.URL.Query()
	switch {
	case path == "/reader/api/0/user-info":
		io.WriteString(w, `{"userId":"1","userName":"elchi","userProfileId":"1","userEmail":""}`)
	case path == "/reader/api/0/unread-count":
		io.WriteString(w, `{"max":2,"unreadcounts":[{"id":"feed/3","count":1,"newestItemTimestampUsec":"1"},{"id":"feed/4","count":0},{"id":"user/-/state/com.google/reading-list","count":1}]}`)
	case path == "/reader/api/0/subscription/list":
		io.WriteString(w, `{"subscriptions":[{"id":"feed/3","title":"Example news","categories":[{"id":"user/-/label/News","label":"News"}],"url":"https://news.example.com/feed","htmlUrl":"https://news.example.com/"}]}`)
	case strings.HasPrefix(path, "/reader/api/0/stream/contents/") && q.Get("xt") == "user/-/state/com.google/read":
		var items []string
		for _, id := range []string{id1, id2} {
			if !f.read[id] {
				items = append(items, f.item(id))
			}
		}
		fmt.Fprintf(w, `{"id":"x","items":[%s]}`, strings.Join(items, ","))
	case path == "/reader/api/0/stream/items/contents" && r.Method == "POST":
		var items []string
		for _, id := range form["i"] {
			if _, ok := f.read[id]; ok {
				items = append(items, f.item(id))
			}
		}
		fmt.Fprintf(w, `{"items":[%s]}`, strings.Join(items, ","))
	case path == "/reader/api/0/token":
		io.WriteString(w, "writetoken123\n")
	case path == "/reader/api/0/edit-tag" && r.Method == "POST":
		if form.Get("T") != "writetoken123" {
			w.WriteHeader(401)
			return
		}
		for _, id := range form["i"] {
			f.read[id] = form.Get("a") == "user/-/state/com.google/read"
		}
		io.WriteString(w, "OK")
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, pass string) (*Module, *fakeFresh) {
	f := &fakeFresh{read: map[string]bool{id1: false, id2: true}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api/greader.php", User: "elchi", Password: pass})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://p": "api-pass", "secret://bad": "nope"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "f", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestFreshRSS(t *testing.T) {
	m, f := setup(t, "secret://p")
	if h := m.Health(context.Background(), "f"); h.Status != "ok" || h.Message != "signed in as elchi" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"unread_count", `{}`, `{"feeds":[{"feedId":"feed/3","title":"Example news","unread":1}],"unread":1}`},
		{"unread", `{}`, `"url":"https://news.example.com/1"`},
		{"unread", `{"feed":"3","limit":5}`, `"feed":"Example news"`},
		{"subscriptions", `{}`, `"categories":["News"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if r, _ := invoke(m, "unread", `{}`, false); strings.Contains(string(r.Output), "Story 2") {
		t.Fatalf("read item listed: %s", r.Output)
	}

	// mark_read changes only the unread item, undo only that one.
	r, err := invoke(m, "mark_read", `{"items":["`+id1+`","`+id2+`"]}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 1 || !strings.Contains(r.Plan.Changes[0].Target, "Story 1") || f.read[id1] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "mark_read", `{"items":["`+id1+`","`+id2+`"]}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "mark_unread" || string(r.Undo.Input) != `{"items":["`+id1+`"]}` || !f.read[id1] {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.read[id1] || !f.read[id2] {
		t.Fatal(err, f.read)
	}
	n := len(f.seen)
	if r, err := invoke(m, "mark_unread", `{"items":["`+id1+`"]}`, false); err != nil || r.Undo != nil || strings.Contains(strings.Join(f.seen[n:], "\n"), "edit-tag") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, "mark_read", `{"items":["tag:google.com,2005:reader/item/00000000000000ff"]}`, false); err == nil {
		t.Fatal("marked an item FreshRSS doesn't have")
	}

	// An expired session is renewed once.
	f.mu.Lock()
	f.session = "elchi/expired"
	logins := f.logins
	f.mu.Unlock()
	if _, err := invoke(m, "unread_count", `{}`, false); err != nil || f.logins != logins+1 {
		t.Fatalf("%v %d", err, f.logins)
	}
	for _, s := range f.seen {
		if strings.Contains(s, "api-pass") {
			t.Fatalf("password outside the login request: %s", s)
		}
	}
}

func TestFreshRSSValidation(t *testing.T) {
	m, f := setup(t, "secret://p")
	many := make([]string, 51)
	for i := range many {
		many[i] = fmt.Sprintf(`"%d"`, i+1)
	}
	for _, c := range []struct{ action, in string }{
		{"unread", `{"feed":"../../user-info"}`},
		{"unread", `{"feed":"feed/3?x=1"}`},
		{"unread", `{"feed":"user/-/label/x"}`},
		{"mark_read", `{}`},
		{"mark_read", `{"items":[]}`},
		{"mark_read", `{"items":["abc"]}`},
		{"mark_read", `{"items":["tag:google.com,2005:reader/item/xyz"]}`},
		{"mark_unread", `{"items":["1&a=x"]}`},
		{"mark_read", `{"items":[` + strings.Join(many, ",") + `]}`},
		{"mark_read", `{"items":[1]}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://rss.example.com", User: "elchi", Password: "plain"},
		{URL: "https://rss.example.com", User: "", Password: "secret://p"},
		{URL: "https://rss.example.com", User: "a b", Password: "secret://p"},
		{URL: "rss.example.com", User: "elchi", Password: "secret://p"},
		{URL: "https://rss.example.com/?x=1", User: "elchi", Password: "secret://p"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, bf := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "f"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "unread", `{}`, false); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
	seen := append([]string(nil), bf.seen...)
	sort.Strings(seen)
	if strings.Join(seen, ",") != "login,login" {
		t.Fatalf("went past a failed login: %v", bf.seen)
	}
}

func TestFreshRSSRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect) // 307 replays the password
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, User: "elchi", Password: "secret://p"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://p": "api-pass"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "f"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
