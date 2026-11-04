package listmonk

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

type fake struct {
	mu        sync.Mutex
	seen      []string
	campaigns map[int]map[string]any
	statusPut []string
}

func newFake() *fake {
	return &fake{campaigns: map[int]map[string]any{
		1: {"id": 1, "name": "October", "subject": "News for October", "status": "finished", "lists": []any{map[string]any{"id": 1, "name": "Newsletter"}}, "sent": 120, "to_send": 120, "views": 80, "clicks": 12, "bounces": 1},
		2: {"id": 2, "name": "November", "subject": "News for November", "status": "draft", "lists": []any{map[string]any{"id": 1, "name": "Newsletter"}, map[string]any{"id": 2, "name": "Beta"}},
			"body": "# Hi", "content_type": "markdown", "template_id": 1, "messenger": "email"},
	}}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "token conduit:lmtok" {
		w.WriteHeader(403)
		io.WriteString(w, `{"message":"invalid API credentials"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api")
	f.seen = append(f.seen, r.Method+" "+path)
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	data := func(v any) { json.NewEncoder(w).Encode(map[string]any{"data": v}) }
	q := r.URL.Query()
	switch {
	case path == "/lists":
		io.WriteString(w, `{"data":{"results":[
			{"id":2,"name":"Beta","type":"private","optin":"double","subscriber_count":40,"subscriber_statuses":{"confirmed":30,"unconfirmed":10}},
			{"id":1,"name":"Newsletter","type":"public","optin":"single","subscriber_count":125,"subscriber_statuses":{"unconfirmed":120,"unsubscribed":5}}],"total":2}}`)
	case path == "/subscribers":
		if q.Get("per_page") != "1" {
			w.WriteHeader(400)
			return
		}
		n := 160
		if q.Get("list_id") == "2" && q.Get("subscription_status") == "confirmed" {
			n = 30
		}
		data(map[string]any{"total": n, "results": []any{}})
	case path == "/campaigns" && r.Method == "GET":
		res := []any{}
		for _, id := range []int{2, 1} {
			if c := f.campaigns[id]; c != nil && (q.Get("status") == "" || c["status"] == q.Get("status")) {
				res = append(res, c)
			}
		}
		data(map[string]any{"results": res, "total": len(res)})
	case path == "/campaigns" && r.Method == "POST":
		lists := []any{}
		for _, l := range body["lists"].([]any) {
			lists = append(lists, map[string]any{"id": l, "name": "Newsletter"})
		}
		body["id"], body["status"], body["lists"] = 3, "draft", lists
		f.campaigns[3] = body
		data(body)
	case path == "/campaigns/running/stats":
		data([]any{map[string]any{"id": 2, "rate": 42.5}})
	case strings.HasPrefix(path, "/campaigns/"):
		parts := strings.Split(strings.TrimPrefix(path, "/campaigns/"), "/")
		id, _ := strconv.Atoi(parts[0])
		c := f.campaigns[id]
		if c == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Campaign not found."}`)
			return
		}
		switch {
		case r.Method == "GET" && len(parts) == 1:
			data(c)
		case r.Method == "PUT" && len(parts) == 2 && parts[1] == "status":
			st := body["status"].(string)
			f.statusPut = append(f.statusPut, parts[0]+"="+st)
			c["status"] = st
			data(c)
		case r.Method == "DELETE" && len(parts) == 1:
			delete(f.campaigns, id)
			data(true)
		default:
			w.WriteHeader(404)
		}
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{Address: srv.URL, Username: "conduit", Token: "secret://lm"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://lm": tok}), "l", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "l", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestListmonk(t *testing.T) {
	m, f := setup(t, "lmtok")
	if h := m.Health(context.Background(), "l"); h.Status != "ok" || h.Message != "2 lists" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "lists", `{}`, false)
	if err != nil || !strings.HasPrefix(string(r.Output), `[{"byStatus":{"unconfirmed":120,"unsubscribed":5},"list":1`) || !strings.Contains(string(r.Output), `"reach":120`) || !strings.Contains(string(r.Output), `"reach":30`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "subscribers_count", `{"list":2,"status":"confirmed"}`, false)
	if err != nil || string(r.Output) != `{"list":2,"status":"confirmed","subscribers":30}` {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "campaigns", `{"status":"finished"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"views":80`) || strings.Contains(string(r.Output), "November") {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Create a draft, then undo it.
	in := `{"name":"December","subject":"News for December","lists":[1],"body":"# Hi"}`
	p, err := invoke(m, "create_campaign", in, true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, "Newsletter (120)") || f.campaigns[3] != nil {
		t.Fatal(p.Plan, err)
	}
	r, err = invoke(m, "create_campaign", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_campaign" || f.campaigns[3]["content_type"] != "markdown" || f.campaigns[3]["type"] != "regular" {
		t.Fatalf("%+v %v %v", r, err, f.campaigns[3])
	}
	p, err = invoke(m, "delete_campaign", string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, "draft campaign \"December\"") {
		t.Fatal(p.Plan, err)
	}
	if _, err := invoke(m, "delete_campaign", string(r.Undo.Input), false); err != nil || f.campaigns[3] != nil {
		t.Fatal(err)
	}

	// Sending: the preview shows each list's reach and sends nothing.
	p, err = invoke(m, "send_campaign", `{"campaign":2}`, true)
	sum := shaIn(p)
	if err != nil || p.Plan == nil || p.Plan.Summary != `Email "News for November" to up to 150 subscribers now: Newsletter (120), Beta (30) (campaign sha256 `+sum+`). Sent emails can't be recalled. To run it, give that sha256; it's refused if the campaign changed.` || len(f.statusPut) != 0 {
		t.Fatal(p.Plan, err)
	}
	// The run needs the sha256 the preview showed, of the campaign as it is.
	if _, err := invoke(m, "send_campaign", `{"campaign":2}`, false); err == nil || len(f.statusPut) != 0 || !strings.Contains(err.Error(), sum) {
		t.Fatal("sent without the previewed sha256", err)
	}
	n := len(f.seen)
	if _, err := invoke(m, "send_campaign", `{"campaign":2,"sha256":"ABC"}`, false); err == nil || len(f.seen) != n {
		t.Fatal("took a malformed sha256", err)
	}
	f.campaigns[2]["body"] = "# Hi, changed"
	if _, err := invoke(m, "send_campaign", `{"campaign":2,"sha256":"`+sum+`"}`, false); err == nil || len(f.statusPut) != 0 || !strings.Contains(err.Error(), "changed since it was previewed") {
		t.Fatal("sent a changed campaign", err)
	}
	if p, err := invoke(m, "send_campaign", `{"campaign":2,"sha256":"`+sum+`"}`, true); err != nil || !strings.Contains(p.Plan.Summary, "will be refused") {
		t.Fatal(p.Plan, err)
	}
	f.campaigns[2]["body"] = "# Hi"
	if _, err := invoke(m, "send_campaign", `{"campaign":2,"sha256":"`+sum+`"}`, false); err != nil || f.statusPut[0] != "2=running" {
		t.Fatal(err, f.statusPut)
	}
	r, err = invoke(m, "campaign", `{"campaign":2}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"ratePerMinute":42.5`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "delete_campaign", `{"campaign":2}`, false); err == nil {
		t.Fatal("deleted a running campaign")
	}
	r, err = invoke(m, "pause_campaign", `{"campaign":2}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "send_campaign" || f.statusPut[1] != "2=paused" || string(r.Undo.Input) != `{"campaign":2,"sha256":"`+sum+`"}` {
		t.Fatal(r, err)
	}
	p, err = invoke(m, "send_campaign", string(r.Undo.Input), true)
	if err != nil || !strings.HasPrefix(p.Plan.Summary, "Resume emailing") || strings.Contains(p.Plan.Summary, "To run it") {
		t.Fatal(p.Plan, err)
	}
	if _, err := invoke(m, "send_campaign", `{"campaign":1}`, false); err == nil || !strings.Contains(err.Error(), "finished") {
		t.Fatal("re-sent a finished campaign", err)
	}

	// A draft with a future send time is scheduled, not sent now.
	f.campaigns[2]["status"], f.campaigns[2]["send_at"] = "draft", "2026-11-10T09:00:00Z"
	p, err = invoke(m, "send_campaign", `{"campaign":2}`, true)
	if err != nil || !strings.HasPrefix(p.Plan.Summary, "Schedule emailing") || strings.Contains(p.Plan.Summary, sum) {
		t.Fatal(p.Plan, err)
	}
	sum = shaIn(p)
	if _, err := invoke(m, "send_campaign", `{"campaign":2,"sha256":"`+sum+`"}`, false); err != nil || f.statusPut[2] != "2=scheduled" {
		t.Fatal(err, f.statusPut)
	}

	// Pausing a scheduled campaign: undo schedules it again for its
	// original time, instead of sending it now.
	r, err = invoke(m, "pause_campaign", `{"campaign":2}`, false)
	if err != nil || r.Undo == nil || string(r.Undo.Input) != `{"campaign":2,"sendAt":"2026-11-10T09:00:00Z","sha256":"`+sum+`"}` {
		t.Fatal(r.Undo, err)
	}
	p, err = invoke(m, "send_campaign", string(r.Undo.Input), true)
	if err != nil || !strings.HasPrefix(p.Plan.Summary, "Schedule emailing") || !strings.Contains(p.Plan.Summary, "at 2026-11-10T09:00:00Z") {
		t.Fatal(p.Plan, err)
	}
	if _, err := invoke(m, "send_campaign", `{"campaign":2,"sendAt":"2026-11-11T09:00:00Z","sha256":"`+sum+`"}`, false); err == nil {
		t.Fatal("scheduled for a time the campaign doesn't have")
	}
	if _, err := invoke(m, "send_campaign", string(r.Undo.Input), false); err != nil || f.statusPut[len(f.statusPut)-1] != "2=scheduled" {
		t.Fatal(err, f.statusPut)
	}
}

func TestListmonkValidation(t *testing.T) {
	m, f := setup(t, "lmtok")
	for _, c := range [][2]string{
		{"create_campaign", `{"name":"x","subject":"y","lists":[],"body":"b"}`},
		{"create_campaign", `{"name":"x","subject":"y\nBcc: a@b.c","lists":[1],"body":"b"}`},
		{"create_campaign", `{"name":"x","subject":"y","lists":[1],"body":"b","contentType":"pdf"}`},
		{"create_campaign", `{"name":"x","subject":"y","lists":[-1],"body":"b"}`},
		{"create_campaign", `{"name":"x","subject":"y","lists":[1],"body":"b","fromEmail":"nope"}`},
		{"send_campaign", `{"campaign":0}`},
		{"campaign", `{"campaign":"1/../../settings"}`},
		{"subscribers_count", `{"status":"confirmed"}`},
		{"campaigns", `{"status":"all"}`},
	} {
		if _, err := invoke(m, c[0], c[1], false); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
	if len(f.seen) != 0 {
		t.Fatal("bad input reached the server:", f.seen)
	}
	for _, c := range []Config{
		{Address: "https://lists.example.com", Username: "conduit", Token: "plain"},
		{Address: "https://lists.example.com", Username: "a b", Token: "secret://lm"},
		{Address: "lists.example.com", Username: "conduit", Token: "secret://lm"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "wrong")
	if h := bad.Health(context.Background(), "l"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestListmonkRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{Address: srv.URL, Username: "conduit", Token: "secret://lm"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://lm": "lmtok"}), "l", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "l"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// shaIn is the campaign sha256 a send preview shows.
func shaIn(r sdk.Result) string {
	if r.Plan == nil {
		return ""
	}
	_, after, _ := strings.Cut(r.Plan.Summary, "sha256 ")
	if len(after) < 64 || !shaRe.MatchString(after[:64]) {
		return ""
	}
	return after[:64]
}
