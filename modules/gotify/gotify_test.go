package gotify

import (
	"context"
	"encoding/json"
	"fmt"
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

type fakeGotify struct {
	mu       sync.Mutex
	seen     []string
	messages map[int]bool
	lastBody map[string]any
	next     int
	sendApp  int // the application the application token belongs to; 1 when 0
}

func (f *fakeGotify) msg(id int) string {
	return fmt.Sprintf(`{"id":%d,"appid":1,"title":"Backup","message":"backup %d done","priority":5,"date":"2026-11-04T10:00:00Z","extras":{"client::notification":{"click":{"url":"https://x/?token=LEAKME"}}}}`, id, id)
}

func (f *fakeGotify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("X-Gotify-Key")
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/health":
		io.WriteString(w, `{"health":"green","database":"green"}`)
		return
	case "/version":
		io.WriteString(w, `{"version":"2.6.1","commit":"x","buildDate":"y"}`)
		return
	}
	client, app := key == "Cgood", key == "Agood"
	if r.URL.Path == "/message" && r.Method == http.MethodPost {
		if !app {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"Unauthorized","errorCode":401,"errorDescription":"you need to provide a valid access token"}`)
			return
		}
	} else if !client {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Unauthorized","errorCode":401,"errorDescription":"you need to provide a valid access token"}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch {
	case r.Method == "GET" && r.URL.Path == "/application":
		io.WriteString(w, `[{"id":1,"token":"ALEAKME","name":"backups","description":"restic","internal":false,"defaultPriority":5,"lastUsed":"2026-11-04T10:00:00Z","image":"image/x.png"}]`)
	case r.Method == "GET" && (r.URL.Path == "/message" || r.URL.Path == "/application/1/message"):
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		since, _ := strconv.Atoi(r.URL.Query().Get("since"))
		if since == 0 {
			since = 1 << 30
		}
		ms := []string{}
		last := 0
		for id := 100; id > 0 && len(ms) < limit; id-- {
			if f.messages[id] && id < since {
				ms = append(ms, f.msg(id))
				last = id
			}
		}
		fmt.Fprintf(w, `{"messages":[%s],"paging":{"size":%d,"since":%d,"limit":%d}}`, strings.Join(ms, ","), len(ms), last, limit)
	case r.Method == "GET" && r.URL.Path == "/application/9/message":
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Not Found","errorCode":404,"errorDescription":"app does not exist"}`)
	case r.Method == "POST" && r.URL.Path == "/message":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.lastBody = b
		f.next++
		f.messages[f.next] = true
		app := f.sendApp
		if app == 0 {
			app = 1
		}
		fmt.Fprintf(w, `{"id":%d,"appid":%d,"message":%q,"priority":5}`, f.next, app, b["message"])
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/message/"):
		id, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/message/"))
		if !f.messages[id] {
			w.WriteHeader(404)
			return
		}
		delete(f.messages, id)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeGotify) {
	f := &fakeGotify{messages: map[int]bool{3: true, 7: true}, next: 10}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	cfg.URL = srv.URL
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "Cgood", "secret://a": "Agood", "secret://bad": "Cbad"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestGotify(t *testing.T) {
	m, f := setup(t, Config{ClientToken: "secret://c", AppToken: "secret://a"})
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || h.Message != "Gotify 2.6.1 · 1 applications" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"applications", `{}`, `"name":"backups"`},
		{"messages", `{}`, `"application":"backups"`},
		{"messages", `{"application":1,"limit":1}`, `"before":7`},
		{"messages", `{"before":7}`, `"message":"backup 3 done"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if _, err := invoke(m, "messages", `{"application":9}`, false); err == nil || !strings.Contains(err.Error(), "no application 9") {
		t.Fatal(err)
	}

	// Send: preview, real, undo deletes it.
	r, err := invoke(m, "send_message", `{"title":"Deploy","message":"**done**","priority":8,"markdown":true}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(string(r.Plan.Changes[0].After), `"priority":8`) || f.next != 10 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "send_message", `{"title":"Deploy","message":"**done**","priority":8,"markdown":true}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_message" || string(r.Undo.Input) != `{"id":11}` || !f.messages[11] {
		t.Fatalf("%+v %v", r, err)
	}
	if strings.Contains(string(r.Output), "done**") || f.lastBody["priority"] != float64(8) || f.lastBody["extras"] == nil {
		t.Fatal(string(r.Output), f.lastBody)
	}
	if r, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || r.Plan == nil || !strings.Contains(string(r.Plan.Changes[0].Before), `"title":"Backup"`) || !f.messages[11] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.messages[11] {
		t.Fatal(err)
	}
	if r, err := invoke(m, "delete_message", `{"id":11}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "delete_message" && a.Risk != sdk.RiskDestructive {
			t.Fatal(a.Risk)
		}
	}

	// An application token of another user than the client token's: the
	// client token couldn't delete the message, so there's no undo.
	f.sendApp = 2
	if r, err := invoke(m, "send_message", `{"message":"hi"}`, false); err != nil || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}

	// With only an application token: send works, reading and undo don't.
	ao, _ := setup(t, Config{AppToken: "secret://a"})
	if h := ao.Health(context.Background(), "g"); h.Status != "ok" || !strings.Contains(h.Message, "application token only") {
		t.Fatalf("%+v", h)
	}
	if r, err := invoke(ao, "send_message", `{"message":"hi"}`, false); err != nil || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(ao, "messages", `{}`, false); err == nil || !strings.Contains(err.Error(), "client token") {
		t.Fatal(err)
	}
}

func TestGotifyValidation(t *testing.T) {
	m, f := setup(t, Config{ClientToken: "secret://c", AppToken: "secret://a"})
	for _, c := range []struct{ action, in string }{
		{"send_message", `{}`}, {"send_message", `{"message":"  "}`}, {"send_message", `{"message":"x","priority":11}`},
		{"send_message", `{"message":"` + strings.Repeat("x", maxMessage+1) + `"}`}, {"send_message", `{"message":"x","title":"` + strings.Repeat("t", maxTitle+1) + `"}`},
		{"delete_message", `{}`}, {"delete_message", `{"id":-1}`}, {"messages", `{"limit":500}`}, {"messages", `{"application":-2}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://g.example.com"}, {URL: "https://g.example.com", ClientToken: "Cplain"}, {URL: "https://g.example.com", ClientToken: "secret://c", AppToken: "Aplain"},
		{URL: "g.example.com", ClientToken: "secret://c"}, {URL: "https://u:p@g.example.com", ClientToken: "secret://c"}, {URL: "https://g.example.com/?a=1", ClientToken: "secret://c"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, Config{ClientToken: "secret://bad"})
	if h := bad.Health(context.Background(), "g"); h.Status != "down" || h.Message != "Gotify refused the client token" {
		t.Fatalf("%+v", h)
	}
	wrong, _ := setup(t, Config{AppToken: "secret://bad"})
	if _, err := invoke(wrong, "send_message", `{"message":"x"}`, false); err == nil || err.Error() != "Gotify refused the application token" {
		t.Fatal(err)
	}
}

func TestGotifyRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Gotify-Key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, ClientToken: "secret://c"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "Cgood"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "g"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
