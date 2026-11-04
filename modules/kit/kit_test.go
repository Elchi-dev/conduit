package kit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const goodKey = "kit_0123456789abcdef0123456789abcdef"

type fake struct {
	mu         sync.Mutex
	seen       []string
	broadcasts map[int]map[string]any
	lastPut    map[string]any
}

func newFake() *fake {
	return &fake{broadcasts: map[int]map[string]any{
		1: {"id": 1, "created_at": "2026-10-01T08:00:00Z", "subject": "October", "content": "<p>Oct</p>", "public": false, "send_at": "2026-10-01T09:00:00Z",
			"subscriber_filter": []any{map[string]any{"all": []any{map[string]any{"type": "all_subscribers"}}}}},
		2: {"id": 2, "created_at": "2026-11-01T08:00:00Z", "subject": "November", "content": "<p>Nov</p>", "public": false, "send_at": nil, "email_address": "news@acme.test",
			"subscriber_filter": []any{map[string]any{"any": []any{map[string]any{"type": "tag", "ids": []int{5, 6}}}}}},
		3: {"id": 3, "created_at": "2026-11-02T08:00:00Z", "subject": "Segmented", "content": "<p>Seg</p>", "send_at": nil,
			"subscriber_filter": []any{map[string]any{"all": []any{map[string]any{"type": "segment", "ids": []int{9}}}}}},
	}}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Kit-Api-Key") != goodKey {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":["The access token is invalid"]}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v4")
	f.seen = append(f.seen, r.Method+" "+path)
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	out := func(v any) { json.NewEncoder(w).Encode(v) }
	count := func(n int) {
		if r.URL.Query().Get("include_total_count") != "true" {
			w.WriteHeader(400)
			return
		}
		out(map[string]any{"subscribers": []any{map[string]any{"email_address": "LEAKME@x.test", "first_name": "LEAKME"}}, "pagination": map[string]any{"total_count": n}})
	}
	switch {
	case path == "/account":
		out(map[string]any{"user": map[string]any{"email": "owner@acme.test"}, "account": map[string]any{"name": "Acme", "plan_type": "creator", "primary_email_address": "hello@acme.test"}})
	case path == "/subscribers":
		count(map[string]int{"active": 150, "all": 170}[r.URL.Query().Get("status")])
	case path == "/tags/5/subscribers":
		count(40)
	case path == "/tags/6/subscribers":
		count(10)
	case path == "/tags":
		out(map[string]any{"tags": []any{map[string]any{"id": 5, "name": "Beta"}, map[string]any{"id": 6, "name": "VIP"}}})
	case path == "/broadcasts" && r.Method == "GET":
		res := []any{}
		for _, id := range []int{1, 2, 3, 4} {
			if b := f.broadcasts[id]; b != nil {
				res = append(res, b)
			}
		}
		out(map[string]any{"broadcasts": res})
	case path == "/broadcasts" && r.Method == "POST":
		body["id"] = 4
		f.broadcasts[4] = body
		out(map[string]any{"broadcast": body})
	case path == "/broadcasts/1/stats":
		out(map[string]any{"broadcast": map[string]any{"id": 1, "stats": map[string]any{"recipients": 150, "open_rate": 52.5, "emails_opened": 79, "status": "completed"}}})
	case strings.HasPrefix(path, "/broadcasts/"):
		id, _ := strconv.Atoi(strings.TrimPrefix(path, "/broadcasts/"))
		b := f.broadcasts[id]
		if b == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"errors":["Not Found"]}`)
			return
		}
		switch r.Method {
		case "GET":
			out(map[string]any{"broadcast": b})
		case "PUT":
			f.lastPut = body
			for k, v := range body {
				b[k] = v
			}
			out(map[string]any{"broadcast": b})
		case "DELETE":
			delete(f.broadcasts, id)
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
	m.Base = srv.URL + "/v4"
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{Key: "secret://kit"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://kit": key}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestKit(t *testing.T) {
	m, f := setup(t, goodKey)
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || h.Message != "Acme: 150 active subscribers" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"subscribers_count", `{}`, `{"status":"active","subscribers":150}`},
		{"subscribers_count", `{"tag":5}`, `"subscribers":40`},
		{"tags", `{}`, `"name":"VIP"`},
		{"broadcasts", `{"limit":2}`, `[{"broadcast":3`},
		{"broadcasts", `{}`, `"status":"sent"`},
		{"broadcast_stats", `{"broadcast":1}`, `"openRate":52.5`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if out := string(r.Output); err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, goodKey) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// A draft for a tag, never public; undo deletes it.
	in := `{"subject":"December","tags":[6],"html":"<h1>Hi</h1>"}`
	p, err := invoke(m, "create_draft", in, true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, "subscribers tagged VIP") || !strings.Contains(string(p.Plan.Changes[0].After), `"content":"<h1>Hi</h1>"`) || f.broadcasts[4] != nil {
		t.Fatal(p.Plan, err)
	}
	r, err := invoke(m, "create_draft", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_draft" || f.broadcasts[4]["public"] != false || f.broadcasts[4]["send_at"] != nil {
		t.Fatalf("%+v %v %v", r, err, f.broadcasts[4])
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.broadcasts[4] != nil {
		t.Fatal(err)
	}

	// Scheduling: the preview names tags, count, subject and sender.
	p, err = invoke(m, "schedule_broadcast", `{"broadcast":2,"at":"2026-11-10T09:00:00Z"}`, true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, `"November" from news@acme.test to 50 subscribers tagged Beta (40), VIP (10) at 2026-11-10T09:00:00Z`) || f.lastPut != nil {
		t.Fatal(p.Plan, err)
	}
	r, err = invoke(m, "schedule_broadcast", `{"broadcast":2,"at":"2026-11-10T09:00:00Z"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "unschedule_broadcast" || f.lastPut["send_at"] != "2026-11-10T09:00:00Z" || f.lastPut["content"] != "<p>Nov</p>" || f.lastPut["email_address"] != "news@acme.test" {
		t.Fatal(r, err, f.lastPut)
	}
	if r, err := invoke(m, "schedule_broadcast", `{"broadcast":2,"at":"2026-11-10T10:00:00+01:00"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "schedule_broadcast", `{"broadcast":2,"at":"2026-11-11T09:00:00Z"}`, false); err == nil {
		t.Fatal("moved a scheduled broadcast")
	}
	r, err = invoke(m, "unschedule_broadcast", `{"broadcast":2}`, false)
	if err != nil || f.broadcasts[2]["send_at"] != nil || r.Undo == nil || string(r.Undo.Input) != `{"at":"2026-11-10T09:00:00Z","broadcast":2}` {
		t.Fatal(r.Undo, err)
	}
	if r, err := invoke(m, "unschedule_broadcast", `{"broadcast":2}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}
	if r, err := invoke(m, "schedule_broadcast", `{"broadcast":1,"at":"2026-11-10T09:00:00Z"}`, false); err != nil || !strings.Contains(string(r.Output), "already gone out") {
		t.Fatal(err)
	}
	// A filter Conduit can't count isn't scheduled.
	n := len(f.seen)
	if _, err := invoke(m, "schedule_broadcast", `{"broadcast":3,"at":"2026-11-10T09:00:00Z"}`, false); err == nil || f.seen[len(f.seen)-1] != "GET /broadcasts/3" || len(f.seen) != n+1 {
		t.Fatal("scheduled a segment broadcast", err)
	}
	if _, err := invoke(m, "delete_draft", `{"broadcast":1}`, false); err == nil {
		t.Fatal("deleted a sent broadcast")
	}
}

func TestKitValidation(t *testing.T) {
	m, f := setup(t, goodKey)
	for _, c := range [][2]string{
		{"create_draft", `{"subject":"x"}`},
		{"create_draft", `{"subject":"x\nBcc: a@b.c","text":"t"}`},
		{"create_draft", `{"subject":"x","text":"t","tags":[-1]}`},
		{"create_draft", `{"subject":"x","html":"<p>a</p><script src=\"https://evil.test/a.js\"></script>"}`},
		{"create_draft", `{"subject":"x","text":"t","emailAddress":"nope"}`},
		{"schedule_broadcast", `{"broadcast":2,"at":"soon"}`},
		{"schedule_broadcast", `{"broadcast":2,"at":"2026-01-01T09:00:00Z"}`},
		{"schedule_broadcast", `{"broadcast":0,"at":"2026-11-10T09:00:00Z"}`},
		{"broadcast_stats", `{"broadcast":"1/../../account"}`},
		{"subscribers_count", `{"status":"everyone"}`},
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
	bad, _ := setup(t, "kit_ffffffffffffffffffffffffffffffff")
	if h := bad.Health(context.Background(), "k"); h.Status != "down" || h.Message != "Kit refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestKitRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Kit-Api-Key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Key: "secret://kit"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://kit": goodKey}), "k", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "k"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
