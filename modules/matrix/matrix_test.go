package matrix

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
	ops   = "!ops:example.org"
	other = "!dm:example.org"
)

type fake struct {
	mu       sync.Mutex
	seen     []string
	sent     []map[string]any
	txns     map[string]bool
	redacted map[string]string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer mxtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errcode":"M_UNKNOWN_TOKEN","error":"Invalid access token passed."}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/_matrix/client/v3")
	f.seen = append(f.seen, r.Method+" "+path)
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	enc := json.NewEncoder(w)
	switch {
	case path == "/account/whoami":
		io.WriteString(w, `{"user_id":"@bot:example.org"}`)
	case path == "/joined_rooms":
		enc.Encode(map[string]any{"joined_rooms": []string{ops, other}})
	case path == "/rooms/"+ops+"/state/m.room.name/":
		io.WriteString(w, `{"name":"Ops"}`)
	case strings.HasSuffix(path, "/state/m.room.name/"):
		w.WriteHeader(404)
		io.WriteString(w, `{"errcode":"M_NOT_FOUND","error":"no name"}`)
	case path == "/rooms/"+ops+"/messages":
		q := r.URL.Query()
		if q.Get("dir") != "b" || q.Get("limit") != "2" || !strings.Contains(q.Get("filter"), "m.room.message") {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"chunk":[
			{"event_id":"$3","type":"m.room.encrypted","sender":"@a:example.org","origin_server_ts":1793000002000,"content":{"ciphertext":"x"}},
			{"event_id":"$2","type":"m.room.message","sender":"@ana:example.org","origin_server_ts":1793000001000,"content":{"msgtype":"m.text","body":"deploy done"}},
			{"event_id":"$1","type":"m.room.message","sender":"@ana:example.org","origin_server_ts":1793000000000,"content":{},"unsigned":{"redacted_because":{}}}]}`)
	case r.Method == "PUT" && strings.HasPrefix(path, "/rooms/"+ops+"/send/m.room.message/"):
		txn := strings.TrimPrefix(path, "/rooms/"+ops+"/send/m.room.message/")
		if f.txns[txn] || !strings.HasPrefix(txn, "conduit-") {
			w.WriteHeader(400)
			return
		}
		f.txns[txn] = true
		f.sent = append(f.sent, body)
		io.WriteString(w, `{"event_id":"$sent1"}`)
	case path == "/rooms/"+ops+"/event/$sent1":
		io.WriteString(w, `{"event_id":"$sent1","type":"m.room.message","sender":"@bot:example.org","origin_server_ts":1793000000000,"content":{"msgtype":"m.notice","body":"hello room"}}`)
	case r.Method == "PUT" && strings.HasPrefix(path, "/rooms/"+ops+"/redact/"):
		parts := strings.Split(strings.TrimPrefix(path, "/rooms/"+ops+"/redact/"), "/")
		reason, _ := body["reason"].(string)
		f.redacted[parts[0]] = reason
		io.WriteString(w, `{"event_id":"$red"}`)
	case path == "/rooms/"+ops+"/joined_members":
		io.WriteString(w, `{"joined":{"@a:example.org":{},"@b:example.org":{},"@bot:example.org":{}}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errcode":"M_UNRECOGNIZED","error":"Unrecognized request"}`)
	}
}

func setup(t *testing.T, tok string, rooms ...string) (*Module, *fake) {
	f := &fake{txns: map[string]bool{}, redacted: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{Homeserver: srv.URL, Token: "secret://mx", AllowedRooms: rooms})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mx": tok}), "x", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "x", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMatrix(t *testing.T) {
	m, f := setup(t, "mxtok", ops)
	if h := m.Health(context.Background(), "x"); h.Status != "ok" || !strings.Contains(h.Message, "@bot:example.org") {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "rooms", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `{"allowed":true,"name":"Ops","room":"!ops:example.org"}`) || !strings.Contains(string(r.Output), `{"allowed":false,"room":"!dm:example.org"}`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "messages", `{"room":"!ops:example.org","limit":2}`, false)
	if err != nil {
		t.Fatal(err)
	}
	out := string(r.Output)
	if !strings.Contains(out, `"encrypted":1`) || !strings.Contains(out, `"text":"deploy done"`) || strings.Index(out, `"$1"`) > strings.Index(out, `"$2"`) || !strings.Contains(out, `"redacted":true`) {
		t.Fatal(out)
	}

	p, err := invoke(m, "send_message", `{"room":"!ops:example.org","text":"hello room","notice":true}`, true)
	if err != nil || p.Plan == nil || len(f.sent) != 0 {
		t.Fatal(p.Plan, err)
	}
	r, err = invoke(m, "send_message", `{"room":"!ops:example.org","text":"hello room","notice":true}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "redact" || f.sent[0]["msgtype"] != "m.notice" || f.sent[0]["body"] != "hello room" {
		t.Fatalf("%+v %v %v", r, err, f.sent)
	}
	if _, err := invoke(m, "send_message", `{"room":"!ops:example.org","text":"again"}`, false); err != nil || len(f.txns) != 2 {
		t.Fatal("transaction ids repeat", err)
	}
	p, err = invoke(m, "redact", string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, `"hello room"`) || len(f.redacted) != 0 {
		t.Fatal(p.Plan, err)
	}
	if _, err := invoke(m, "redact", `{"room":"!ops:example.org","event":"$sent1","reason":"oops"}`, false); err != nil || f.redacted["$sent1"] != "oops" {
		t.Fatal(err, f.redacted)
	}
	r, err = invoke(m, "members", `{"room":"!ops:example.org"}`, false)
	if err != nil || string(r.Output) != `{"members":3,"room":"!ops:example.org"}` {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestMatrixValidation(t *testing.T) {
	m, f := setup(t, "mxtok", ops)
	f.seen = nil
	for _, c := range [][2]string{
		{"messages", `{"room":"` + other + `"}`}, // joined but not allowed
		{"messages", `{"room":"!ops:example.org/../../x"}`},
		{"send_message", `{"room":"` + other + `","text":"hi"}`},
		{"send_message", `{"room":"!ops:example.org","text":"  "}`},
		{"redact", `{"room":"!ops:example.org","event":"../x"}`},
		{"redact", `{"room":"` + other + `","event":"$x"}`},
		{"members", `{"room":"#ops:example.org"}`},
	} {
		if _, err := invoke(m, c[0], c[1], false); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
	if len(f.seen) != 0 {
		t.Fatal("bad input reached the server:", f.seen)
	}
	for _, c := range []Config{
		{Homeserver: "https://matrix.example.org", Token: "syt_plain"},
		{Homeserver: "https://matrix.example.org/_matrix", Token: "secret://mx"},
		{Homeserver: "https://matrix.example.org", Token: "secret://mx", AllowedRooms: []string{"#alias:example.org"}},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "y", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	none, _ := setup(t, "mxtok")
	if h := none.Health(context.Background(), "x"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	bad, _ := setup(t, "wrong", ops)
	if h := bad.Health(context.Background(), "x"); h.Status != "down" || !strings.Contains(h.Message, "refused the access token") {
		t.Fatalf("%+v", h)
	}
}

func TestMatrixRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{Homeserver: srv.URL, Token: "secret://mx", AllowedRooms: []string{ops}})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mx": "mxtok"}), "x", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "x"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
