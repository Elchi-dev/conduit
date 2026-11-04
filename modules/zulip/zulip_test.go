package zulip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type stored struct{ stream, topic, content string }

type fakeZulip struct {
	mu   sync.Mutex
	seen []string
	msgs map[string]stored
}

func (f *fakeZulip) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, pw, ok := r.BasicAuth(); !ok || u != "bot@example.com" || pw != "zkey" {
		w.WriteHeader(401)
		io.WriteString(w, `{"result":"error","msg":"Invalid API key","code":"INVALID_API_KEY"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+r.URL.RawQuery+" "+string(body))
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/users/me":
		io.WriteString(w, `{"result":"success","msg":"","full_name":"Conduit bot","email":"bot@example.com"}`)
	case "GET /api/v1/users/me/subscriptions":
		io.WriteString(w, `{"result":"success","subscriptions":[{"stream_id":2,"name":"ops","invite_only":true},{"stream_id":1,"name":"general","is_muted":true},{"stream_id":3,"name":"random"}]}`)
	case "GET /api/v1/messages":
		switch q.Get("narrow") {
		case `[{"operator":"is","operand":"unread"}]`:
			io.WriteString(w, `{"result":"success","found_oldest":true,"messages":[`+
				`{"id":1,"type":"stream","display_recipient":"general","subject":"deploys","content":"x"},`+
				`{"id":2,"type":"stream","display_recipient":"general","subject":"lunch","content":"x"},`+
				`{"id":3,"type":"stream","display_recipient":"random","subject":"private matter","content":"x"},`+
				`{"id":4,"type":"private","display_recipient":[{"email":"kim@example.com"}],"content":"x"}]}`)
		case `[{"operator":"stream","operand":"general"}]`, `[{"operator":"stream","operand":"ops"},{"operator":"topic","operand":"deploys"}]`:
			if q.Get("num_before") != "30" || q.Get("anchor") != "newest" {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"result":"success","messages":[`+
				`{"id":10,"type":"stream","display_recipient":"general","subject":"deploys","sender_full_name":"Sam","content":"deploy done","timestamp":1793786400},`+
				`{"id":11,"type":"stream","display_recipient":"general","subject":"deploys","sender_full_name":"Kim","content":"thanks","timestamp":1793786460}]}`)
		default:
			w.WriteHeader(400)
			io.WriteString(w, `{"result":"error","msg":"bad narrow"}`)
		}
	case "POST /api/v1/messages":
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(400)
			return
		}
		form, _ := url.ParseQuery(string(body))
		if form.Get("type") != "stream" {
			w.WriteHeader(400)
			return
		}
		f.msgs["42"] = stored{form.Get("to"), form.Get("topic"), form.Get("content")}
		io.WriteString(w, `{"result":"success","msg":"","id":42}`)
	case "GET /api/v1/messages/42", "GET /api/v1/messages/43":
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/messages/")
		s, ok := f.msgs[id]
		if !ok {
			w.WriteHeader(400)
			io.WriteString(w, `{"result":"error","msg":"Invalid message(s)","code":"BAD_REQUEST"}`)
			return
		}
		fmt.Fprintf(w, `{"result":"success","message":{"id":%s,"type":"stream","display_recipient":%q,"subject":%q,"sender_full_name":"Conduit bot","content":%q,"timestamp":1793786400}}`, id, s.stream, s.topic, s.content)
	case "DELETE /api/v1/messages/42", "DELETE /api/v1/messages/43":
		delete(f.msgs, strings.TrimPrefix(r.URL.Path, "/api/v1/messages/"))
		io.WriteString(w, `{"result":"success","msg":""}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"result":"error","msg":"Not found"}`)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeZulip) {
	t.Helper()
	f := &fakeZulip{msgs: map[string]stored{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	cfg.URL = srv.URL + "/"
	if cfg.Email == "" {
		cfg.Email = "bot@example.com"
	}
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://z": "zkey", "secret://bad": "nope"}), "z", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "z", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestZulip(t *testing.T) {
	m, f := setup(t, Config{APIKey: "secret://z", Allowed: []string{"#general", "ops > Deploys"}})
	if h := m.Health(context.Background(), "z"); h.Status != "ok" || h.Message != "signed in as Conduit bot, 1 allowed streams and 1 topics" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "streams", `{}`, false)
	if err != nil || string(r.Output) != `[{"allowed":true,"id":1,"muted":true,"private":false,"stream":"general"},{"allowed":"some topics","id":2,"private":true,"stream":"ops"},{"allowed":false,"id":3,"private":false,"stream":"random"}]` {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "unread", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"direct":1`) || !strings.Contains(string(r.Output), `"total":4`) ||
		!strings.Contains(string(r.Output), `{"stream":"general","topics":[`) || strings.Contains(string(r.Output), "private matter") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "messages", `{"stream":"general"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `{"from":"Sam","id":10,"text":"deploy done","topic":"deploys","when":"2026-11-04T10:00:00Z"}`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "messages", `{"stream":"ops","topic":"deploys"}`, false); err != nil {
		t.Fatal(err)
	}

	r, err = invoke(m, "send_message", `{"stream":"ops","topic":"deploys","content":"shipped"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Send a message to #ops > deploys" || len(f.msgs) != 0 {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "send_message", `{"stream":"ops","topic":"deploys","content":"shipped"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_message" || string(r.Undo.Input) != `{"id":42}` || f.msgs["42"] != (stored{"ops", "deploys", "shipped"}) {
		t.Fatalf("%+v %v %v", r, err, f.msgs)
	}
	p, err := invoke(m, "delete_message", string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Delete Conduit bot's message from 2026-11-04T10:00:00Z in #ops" || len(f.msgs) != 1 ||
		strings.Contains(string(p.Plan.Changes[0].Before), "shipped") {
		t.Fatalf("dry %+v %v", p.Plan, err)
	}
	f.msgs["43"] = stored{"ops", "other topic", "x"}
	if _, err := invoke(m, "delete_message", `{"id":43}`, false); err == nil || len(f.msgs) != 2 {
		t.Fatal("deleted a message outside the allowed topics", err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.msgs["42"] != (stored{}) {
		t.Fatal("not deleted", err)
	}
}

func TestZulipValidation(t *testing.T) {
	m, f := setup(t, Config{APIKey: "secret://z", Allowed: []string{"general", "ops > deploys"}})
	for _, in := range []string{
		`{"stream":"random","topic":"x","content":"x"}`,  // not allowed
		`{"stream":"ops","topic":"other","content":"x"}`, // topic not allowed
		`{"stream":"general","content":"x"}`,             // no topic
		`{"stream":"general","topic":"t","content":"  "}`,
		`{"stream":"general","topic":"` + strings.Repeat("t", 61) + `","content":"x"}`,
		`{"stream":"general","topic":"a\nb","content":"x"}`,
		`{"stream":"general","topic":"t","content":"` + strings.Repeat("a", maxContent+1) + `"}`,
	} {
		if _, err := invoke(m, "send_message", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	for _, in := range []string{`{"stream":"random"}`, `{"stream":"ops"}`, `{"stream":""}`} {
		if _, err := invoke(m, "messages", in, false); err == nil {
			t.Fatalf("read %s", in)
		}
	}
	if _, err := invoke(m, "delete_message", `{"id":0}`, false); err == nil {
		t.Fatal("accepted message id")
	}
	if _, err := invoke(m, "delete_message", `{"id":"../x"}`, false); err == nil {
		t.Fatal("accepted message id")
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://z", Email: "bot@example.com", APIKey: "plain"},
		{URL: "z.example.com", Email: "bot@example.com", APIKey: "secret://z"},
		{URL: "https://z", Email: "bot", APIKey: "secret://z"},
		{URL: "https://z", Email: "bot@example.com", APIKey: "secret://z", Allowed: []string{"general > "}},
		{URL: "https://z", Email: "bot@example.com", APIKey: "secret://z", Allowed: []string{strings.Repeat("s", 61)}},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	none, _ := setup(t, Config{APIKey: "secret://z"})
	if h := none.Health(context.Background(), "z"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	bad, _ := setup(t, Config{APIKey: "secret://bad"})
	if h := bad.Health(context.Background(), "z"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestZulipRefusesRedirect(t *testing.T) {
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Email: "bot@example.com", APIKey: "secret://z"})
	_ = m.Configure(context.Background(), fakehost.New(map[string]string{"secret://z": "zkey"}), "z", raw)
	if h := m.Health(context.Background(), "z"); h.Status != "down" || leaked != "" {
		t.Fatalf("%+v %q", h, leaked)
	}
}
