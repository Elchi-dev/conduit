package buttondown

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
	goodKey = "0123abcd-4567-89ef-0123-456789abcdef"
	sentID  = "11111111-1111-4111-8111-111111111111"
	draftID = "22222222-2222-4222-8222-222222222222"
	newID   = "33333333-3333-4333-8333-333333333333"
	privID  = "44444444-4444-4444-8444-444444444444"
)

type fake struct {
	mu      sync.Mutex
	seen    []string
	emails  map[string]map[string]any
	created map[string]any
	keepOff bool // answers a create as if it had been sent
}

func newFake() *fake {
	return &fake{emails: map[string]map[string]any{
		sentID: {"id": sentID, "subject": "October", "status": "sent", "email_type": "public", "creation_date": "2026-10-01T08:00:00Z", "publish_date": "2026-10-01T09:00:00Z",
			"absolute_url": "https://buttondown.com/acme/archive/october", "analytics": map[string]any{"recipients": 120, "opens": 80, "clicks": 12}},
		draftID: {"id": draftID, "subject": "November", "status": "draft", "email_type": "public", "creation_date": "2026-11-01T08:00:00Z", "filters": map[string]any{"filters": []any{}, "groups": []any{}, "predicate": "and"}},
		privID:  {"id": privID, "subject": "Segment", "status": "draft", "email_type": "public", "filters": map[string]any{"filters": []any{map[string]any{"field": "tag", "value": "x"}}}},
	}}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Token "+goodKey {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":"Invalid token."}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1")
	f.seen = append(f.seen, r.Method+" "+path)
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	out := func(v any) { json.NewEncoder(w).Encode(v) }
	switch {
	case path == "/subscribers":
		n := map[string]int{"regular": 100, "premium": 20, "gifted": 2, "trialed": 3}[r.URL.Query().Get("type")]
		out(map[string]any{"count": n, "results": []any{map[string]any{"email_address": "LEAKME@x.test"}}})
	case path == "/newsletters":
		out(map[string]any{"results": []any{map[string]any{"name": "Acme Weekly", "username": "acme"}}})
	case path == "/emails" && r.Method == "GET":
		res := []any{}
		for _, id := range []string{draftID, sentID} {
			if e := f.emails[id]; e != nil && (r.URL.Query().Get("status") == "" || e["status"] == r.URL.Query().Get("status")) {
				res = append(res, e)
			}
		}
		out(map[string]any{"results": res, "count": len(res)})
	case path == "/emails" && r.Method == "POST":
		f.created = body
		st := body["status"]
		if f.keepOff {
			st = "about_to_send"
		}
		e := map[string]any{"id": newID, "subject": body["subject"], "status": st, "email_type": "public"}
		f.emails[newID] = e
		w.WriteHeader(201)
		out(e)
	case strings.HasPrefix(path, "/emails/"):
		e := f.emails[strings.TrimPrefix(path, "/emails/")]
		if e == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"detail":"Not found."}`)
			return
		}
		switch r.Method {
		case "GET":
			out(e)
		case "PATCH":
			e["status"] = body["status"]
			out(e)
		case "DELETE":
			delete(f.emails, e["id"].(string))
			w.WriteHeader(204)
		}
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, key string) (*Module, *fake) {
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL + "/v1"
	raw, _ := json.Marshal(Config{Key: "secret://bd"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bd": key}), "d", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestButtondown(t *testing.T) {
	m, f := setup(t, goodKey)
	if h := m.Health(context.Background(), "d"); h.Status != "ok" || h.Message != "Acme Weekly: 100 subscribers" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"subscribers_count", `{}`, `{"subscribers":100,"type":"regular"}`},
		{"subscribers_count", `{"type":"premium"}`, `"subscribers":20`},
		{"emails", `{}`, `"opens":80`},
		{"emails", `{"status":"draft"}`, `"subject":"November"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if out := string(r.Output); err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, goodKey) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// A draft: the body in full in the preview, status draft always sent.
	in := `{"subject":"December","body":"# Hi\n\n<b>bold</b> & more"}`
	p, err := invoke(m, "create_draft", in, true)
	if err != nil || p.Plan == nil || !strings.Contains(string(p.Plan.Changes[0].After), `"body":"# Hi\n\n<b>bold</b> & more"`) || f.created != nil {
		t.Fatal(p.Plan, err)
	}
	r, err := invoke(m, "create_draft", in, false)
	if err != nil || f.created["status"] != "draft" || r.Undo == nil || r.Undo.Action != "delete_draft" {
		t.Fatalf("%+v %v %v", r, err, f.created)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.emails[newID] != nil {
		t.Fatal(err)
	}
	f.keepOff = true
	if r, err := invoke(m, "create_draft", in, false); err == nil || r.Undo != nil || !strings.Contains(err.Error(), "draft") {
		t.Fatal("reported a draft Buttondown didn't keep", err)
	}

	// Sending: the preview names the newsletter, count and subject.
	p, err = invoke(m, "send_email", `{"email":"`+draftID+`"}`, true)
	if err != nil || p.Plan == nil || !strings.HasPrefix(p.Plan.Summary, `Email "November" from Acme Weekly to 125 subscribers now (public email: regular 100, premium 20, gifted 2, trialed 3)`) || f.emails[draftID]["status"] != "draft" {
		t.Fatal(p.Plan, err)
	}
	if _, err := invoke(m, "send_email", `{"email":"`+draftID+`"}`, false); err != nil || f.emails[draftID]["status"] != "about_to_send" {
		t.Fatal(err)
	}
	if r, err := invoke(m, "send_email", `{"email":"`+sentID+`"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "send_email", `{"email":"`+privID+`"}`, false); err == nil || f.emails[privID]["status"] != "draft" {
		t.Fatal("sent a filtered email it can't count", err)
	}
	if _, err := invoke(m, "delete_draft", `{"email":"`+sentID+`"}`, false); err == nil {
		t.Fatal("deleted a sent email")
	}
}

func TestButtondownValidation(t *testing.T) {
	m, f := setup(t, goodKey)
	for _, c := range [][2]string{
		{"create_draft", `{"subject":"x"}`},
		{"create_draft", `{"subject":"x\nBcc: a@b.c","body":"b"}`},
		{"create_draft", `{"subject":"x","body":"hi <script src=\"https://evil.test/x.js\"></script>"}`},
		{"send_email", `{"email":"../subscribers"}`},
		{"delete_draft", `{"email":"x"}`},
		{"subscribers_count", `{"type":"everyone"}`},
		{"emails", `{"status":"all"}`},
	} {
		if _, err := invoke(m, c[0], c[1], false); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
	if len(f.seen) != 0 {
		t.Fatal("bad input reached the server:", f.seen)
	}
	raw, _ := json.Marshal(Config{Key: goodKey})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
		t.Fatal("accepted a plain key")
	}
	bad, _ := setup(t, "ffffffff-ffff-ffff-ffff-ffffffffffff")
	if h := bad.Health(context.Background(), "d"); h.Status != "down" || h.Message != "Buttondown refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestButtondownRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Key: "secret://bd"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bd": goodKey}), "d", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "d"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
