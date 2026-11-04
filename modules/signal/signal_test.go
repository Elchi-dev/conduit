package signal

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
	me      = "+4915100000001"
	ana     = "+4915100000002"
	eve     = "+4915100000003"
	groupID = "group.YWJjZGVmZ2hpamtsbW5vcA=="
)

type fake struct {
	mu      sync.Mutex
	seen    []string
	queue   []string // envelopes waiting
	sent    []map[string]any
	mode    string
	receive int
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "conduit" || p != "pw" {
		w.WriteHeader(401)
		io.WriteString(w, "Unauthorized")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/signal")
	f.seen = append(f.seen, r.Method+" "+path)
	switch {
	case path == "/v1/about":
		io.WriteString(w, `{"versions":["v1","v2"],"build":2,"mode":"`+f.mode+`","version":"0.92"}`)
	case path == "/v1/accounts":
		io.WriteString(w, `["`+me+`","+4915199999999"]`)
	case path == "/v1/receive/"+me:
		f.receive++
		if f.mode == "json-rpc" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"Receive not possible in json-rpc mode. Use the websocket endpoint instead."}`)
			return
		}
		if r.URL.Query().Get("timeout") != "1" || r.URL.Query().Get("send_read_receipts") != "false" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, "["+strings.Join(f.queue, ",")+"]")
		f.queue = nil
	case r.Method == "POST" && path == "/v2/send":
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		f.sent = append(f.sent, b)
		w.WriteHeader(201)
		io.WriteString(w, `{"timestamp":"1793000000123"}`)
	case path == "/v1/groups/"+me:
		io.WriteString(w, `[{"name":"Family","id":"`+groupID+`","internal_id":"x","members":["`+me+`","`+ana+`"],"admins":[],"blocked":false}]`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, pw string) (*Module, *fake) {
	f := &fake{mode: "native", queue: []string{
		`{"envelope":{"source":"` + ana + `","sourceNumber":"` + ana + `","sourceName":"Ana","timestamp":1793000000000,"dataMessage":{"timestamp":1793000000000,"message":"dinner at 7?"}},"account":"` + me + `"}`,
		`{"envelope":{"source":"` + ana + `","timestamp":1793000000500,"receiptMessage":{"isDelivery":true}},"account":"` + me + `"}`,
		`{"envelope":{"source":"` + ana + `","sourceNumber":"` + ana + `","timestamp":1793000001000,"dataMessage":{"message":"in the group","groupInfo":{"groupId":"` + groupID + `"}}},"account":"` + me + `"}`,
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{Address: srv.URL + "/signal/", Number: me, Username: "conduit", Password: "secret://sig", AllowedRecipients: []string{ana, groupID}})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sig": pw}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestSignal(t *testing.T) {
	m, f := setup(t, "pw")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || !strings.Contains(h.Message, "native") {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "accounts", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `{"number":"`+me+`","this":true}`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "receive", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"new":2`) || !strings.Contains(string(r.Output), `"text":"dinner at 7?"`) || !strings.Contains(string(r.Output), `"group":"`+groupID+`"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	// The server handed them out once; the buffer still shows them.
	r, err = invoke(m, "receive", `{"limit":1}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"new":0`) || !strings.Contains(string(r.Output), "in the group") || strings.Contains(string(r.Output), "dinner") {
		t.Fatalf("%s %v", r.Output, err)
	}
	// buffered reads only what was received, never the server's queue.
	calls := f.receive
	r, err = invoke(m, "buffered", `{"limit":5}`, false)
	if err != nil || f.receive != calls || !strings.Contains(string(r.Output), `"text":"dinner at 7?"`) {
		t.Fatalf("%s %v (receive calls %d→%d)", r.Output, err, calls, f.receive)
	}
	for _, a := range m.Manifest().Actions {
		switch {
		case a.Name == "receive" && a.Risk != sdk.RiskWrite:
			t.Fatal("receive consumes the queue: it's a write")
		case a.Name == "buffered" && (a.Risk != sdk.RiskRead || !a.Sensitive):
			t.Fatal("buffered is a sensitive read")
		}
	}
	p, err := invoke(m, "send", `{"recipients":["`+ana+`"],"text":"yes!"}`, true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, ana) || len(f.sent) != 0 {
		t.Fatal(p.Plan, err)
	}
	r, err = invoke(m, "send", `{"recipients":["`+ana+`","`+groupID+`","`+ana+`"],"text":"yes!"}`, false)
	if err != nil || r.Undo != nil || !strings.Contains(string(r.Output), `"timestamp":1793000000123`) {
		t.Fatalf("%+v %v", r, err)
	}
	if b := f.sent[0]; b["number"] != me || b["message"] != "yes!" || len(b["recipients"].([]any)) != 2 {
		t.Fatal(b)
	}
	r, err = invoke(m, "groups", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"allowed":true`) || !strings.Contains(string(r.Output), `"members":2`) {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestSignalValidation(t *testing.T) {
	m, f := setup(t, "pw")
	for _, c := range []string{
		`{"recipients":["` + eve + `"],"text":"hi"}`, // not allowed
		`{"recipients":["../v1/accounts"],"text":"hi"}`,
		`{"recipients":[],"text":"hi"}`,
		`{"recipients":["` + ana + `"],"text":" "}`,
	} {
		if _, err := invoke(m, "send", c, false); err == nil {
			t.Fatalf("accepted %s", c)
		}
	}
	if len(f.seen) != 0 || len(f.sent) != 0 {
		t.Fatal("bad input reached the server:", f.seen)
	}
	for _, c := range []Config{
		{Address: "http://signal:8080", Number: "015100000001"},
		{Address: "signal:8080", Number: me},
		{Address: "http://signal:8080", Number: me, Username: "u", Password: "plain"},
		{Address: "http://signal:8080", Number: me, Token: "plain"},
		{Address: "http://signal:8080", Number: me, Password: "secret://x"},
		{Address: "http://signal:8080", Number: me, AllowedRecipients: []string{"everyone"}},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "nope")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	rpc, rf := setup(t, "pw")
	rf.mode = "json-rpc"
	if h := rpc.Health(context.Background(), "s"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(rpc, "receive", `{}`, false); err == nil || !strings.Contains(err.Error(), "native") {
		t.Fatal(err)
	}
}

func TestSignalRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{Address: srv.URL, Number: me, Token: "secret://t", AllowedRecipients: []string{ana}})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "tok"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
