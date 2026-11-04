package mailchimp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const goodKey = "0123456789abcdefFAKEtestKEY00000-us21"

type fake struct {
	mu        sync.Mutex
	seen      []string
	campaigns map[string]map[string]any
	tests     []string
}

func newFake() *fake {
	return &fake{campaigns: map[string]map[string]any{
		"c1": {"id": "c1", "type": "regular", "status": "sent", "send_time": "2026-10-01T09:00:00Z", "emails_sent": 120,
			"recipients":     map[string]any{"list_id": "l1", "list_name": "Newsletter", "recipient_count": 120},
			"settings":       map[string]any{"subject_line": "October", "title": "Oct", "from_name": "Acme", "reply_to": "news@acme.test"},
			"report_summary": map[string]any{"opens": 80, "open_rate": 0.66, "clicks": 12, "click_rate": 0.1}},
		"c2": {"id": "c2", "type": "regular", "status": "save",
			"recipients": map[string]any{"list_id": "l1", "list_name": "Newsletter", "recipient_count": 0},
			"settings":   map[string]any{"subject_line": "November", "title": "Nov", "from_name": "Acme", "reply_to": "news@acme.test"}},
	}}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, pw, ok := r.BasicAuth(); !ok || pw != goodKey {
		w.WriteHeader(401)
		io.WriteString(w, `{"type":"x","title":"API Key Invalid","status":401,"detail":"Your API key may be invalid."}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/3.0")
	f.seen = append(f.seen, r.Method+" "+path)
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	out := func(v any) { json.NewEncoder(w).Encode(v) }
	switch {
	case path == "/" || path == "":
		out(map[string]any{"account_name": "Acme", "total_subscribers": 125, "email": "Owner@acme.test"})
	case path == "/lists":
		out(map[string]any{"lists": []any{map[string]any{"id": "l1", "name": "Newsletter", "campaign_defaults": map[string]any{"from_name": "Acme", "from_email": "news@acme.test"},
			"stats": map[string]any{"member_count": 125, "unsubscribe_count": 5, "cleaned_count": 2}, "members": []any{"LEAKME@x.test"}}}, "total_items": 1})
	case path == "/lists/l1":
		out(map[string]any{"id": "l1", "name": "Newsletter", "campaign_defaults": map[string]any{"from_name": "Acme", "from_email": "news@acme.test"}, "stats": map[string]any{"member_count": 125}})
	case path == "/campaigns" && r.Method == "GET":
		res := []any{}
		for _, id := range []string{"c2", "c1"} {
			if c := f.campaigns[id]; c != nil && (r.URL.Query().Get("status") == "" || c["status"] == r.URL.Query().Get("status")) {
				res = append(res, c)
			}
		}
		out(map[string]any{"campaigns": res, "total_items": len(res)})
	case path == "/campaigns" && r.Method == "POST":
		rec := body["recipients"].(map[string]any)
		c := map[string]any{"id": "c3", "type": body["type"], "status": "save", "settings": body["settings"],
			"recipients": map[string]any{"list_id": rec["list_id"], "list_name": "Newsletter"}}
		f.campaigns["c3"] = c
		out(c)
	case path == "/reports/c1":
		out(map[string]any{"id": "c1", "subject_line": "October", "list_name": "Newsletter", "emails_sent": 120, "opens": map[string]any{"opens_total": 90, "unique_opens": 80}, "bounces": map[string]any{"hard_bounces": 1}})
	case strings.HasPrefix(path, "/campaigns/"):
		parts := strings.Split(strings.TrimPrefix(path, "/campaigns/"), "/")
		c := f.campaigns[parts[0]]
		if c == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"title":"Resource Not Found","status":404,"detail":"The requested resource could not be found."}`)
			return
		}
		switch {
		case r.Method == "GET" && len(parts) == 1:
			out(c)
		case r.Method == "DELETE" && len(parts) == 1:
			delete(f.campaigns, parts[0])
			w.WriteHeader(204)
		case r.Method == "PUT" && len(parts) == 2 && parts[1] == "content":
			c["content"] = body
			out(body)
		case r.Method == "GET" && len(parts) == 2 && parts[1] == "content":
			if ct, ok := c["content"]; ok {
				out(ct)
				return
			}
			out(map[string]any{"html": "<p>November news</p>", "plain_text": "November news"})
		case r.Method == "POST" && len(parts) == 3 && parts[2] == "test":
			for _, e := range body["test_emails"].([]any) {
				f.tests = append(f.tests, e.(string))
			}
			w.WriteHeader(204)
		case r.Method == "POST" && len(parts) == 3 && parts[2] == "schedule":
			c["status"], c["send_time"] = "schedule", body["schedule_time"]
			w.WriteHeader(204)
		case r.Method == "POST" && len(parts) == 3 && parts[2] == "unschedule":
			c["status"], c["send_time"] = "save", ""
			w.WriteHeader(204)
		case r.Method == "POST" && len(parts) == 3 && parts[2] == "send":
			c["status"] = "sending"
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, key string, allow []string) (*Module, *fake) {
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL + "/3.0"
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{Key: "secret://mc", TestRecipients: allow})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mc": key}), "m", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "m", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMailchimp(t *testing.T) {
	m, f := setup(t, goodKey, []string{"qa@acme.test"})
	if h := m.Health(context.Background(), "m"); h.Status != "ok" || h.Message != "Acme: 125 subscribers" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"audiences", `{}`, `"subscribed":125`},
		{"campaigns", `{"status":"sent"}`, `"openRate":0.66`},
		{"campaign_report", `{"campaign":"c1"}`, `"uniqueOpens":80`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if out := string(r.Output); err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, goodKey) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// A draft: the preview shows the HTML in full; undo deletes it.
	in := `{"audience":"l1","subject":"December","html":"<h1>Hi</h1><p>All the news</p>"}`
	p, err := invoke(m, "create_draft", in, true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, `audience "Newsletter" (125 subscribers)`) || !strings.Contains(string(p.Plan.Changes[0].After), `<h1>Hi</h1><p>All the news</p>`) || f.campaigns["c3"] != nil {
		t.Fatal(p.Plan, err)
	}
	r, err := invoke(m, "create_draft", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_draft" || f.campaigns["c3"]["content"].(map[string]any)["html"] == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.campaigns["c3"] != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "create_draft", `{"audience":"l1","subject":"Plain","text":"Hello"}`, false); err != nil || f.campaigns["c3"]["type"] != "plaintext" {
		t.Fatal(err, f.campaigns["c3"])
	}

	// Tests go to the allow-list or the owner only.
	if _, err := invoke(m, "send_test", `{"campaign":"c2","to":"someone@else.test"}`, false); err == nil {
		t.Fatal("sent a test to an address that isn't allowed")
	}
	if _, err := invoke(m, "send_test", `{"campaign":"c2"}`, false); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "send_test", `{"campaign":"c2","to":"owner@acme.test"}`, false); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.tests, ",") != "qa@acme.test,owner@acme.test" {
		t.Fatal(f.tests)
	}

	// Scheduling: preview names the audience, count, subject and sender,
	// and shows the content with its sha256, which the run must give.
	p, err = invoke(m, "schedule_campaign", `{"campaign":"c2","at":"2026-11-10T09:15:00Z"}`, true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, `"November" from Acme <news@acme.test> to 125 subscribers of audience "Newsletter" at 2026-11-10T09:15:00Z`) ||
		!strings.Contains(string(p.Plan.Changes[0].After), `"content":"<p>November news</p>"`) {
		t.Fatal(p.Plan, err)
	}
	sum := planSHA(t, p)
	if _, err := invoke(m, "schedule_campaign", `{"campaign":"c2","at":"2026-11-10T09:15:00Z"}`, false); err == nil || !strings.Contains(err.Error(), sum) || f.campaigns["c2"]["status"] != "save" {
		t.Fatal("scheduled without the preview's sha256", err)
	}
	r, err = invoke(m, "schedule_campaign", `{"campaign":"c2","at":"2026-11-10T09:15:00Z","sha256":"`+sum+`"}`, false)
	if err != nil || f.campaigns["c2"]["status"] != "schedule" || r.Undo == nil || r.Undo.Action != "unschedule_campaign" {
		t.Fatal(r, err)
	}
	if r, err := invoke(m, "schedule_campaign", `{"campaign":"c2","at":"2026-11-10T10:15:00+01:00"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output), err)
	}
	if _, err := invoke(m, "send_campaign", `{"campaign":"c2"}`, false); err == nil {
		t.Fatal("sent a scheduled campaign")
	}
	r, err = invoke(m, "unschedule_campaign", `{"campaign":"c2"}`, false)
	if err != nil || f.campaigns["c2"]["status"] != "save" || r.Undo == nil || string(r.Undo.Input) != `{"at":"2026-11-10T09:15:00Z","campaign":"c2","sha256":"`+sum+`"}` {
		t.Fatal(r.Undo, err)
	}
	if r, err := invoke(m, "unschedule_campaign", `{"campaign":"c2"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}

	// Sending: the content approved is the content sent. An edit after the
	// preview (in Mailchimp, or by another call) makes the send refused.
	p, err = invoke(m, "send_campaign", `{"campaign":"c2"}`, true)
	if err != nil || p.Plan == nil || !strings.HasPrefix(p.Plan.Summary, `Email "November" from Acme <news@acme.test> to 125 subscribers`) || f.campaigns["c2"]["status"] != "save" || planSHA(t, p) != sum {
		t.Fatal(p.Plan, err)
	}
	f.mu.Lock()
	f.campaigns["c2"]["content"] = map[string]any{"html": "<p>Something else</p>", "plain_text": "Something else"}
	f.mu.Unlock()
	if _, err := invoke(m, "send_campaign", `{"campaign":"c2","sha256":"`+sum+`"}`, false); err == nil || !strings.Contains(err.Error(), "changed since it was previewed") || f.campaigns["c2"]["status"] != "save" {
		t.Fatal("sent content that changed after the preview", err)
	}
	if p, _ := invoke(m, "send_campaign", `{"campaign":"c2","sha256":"`+sum+`"}`, true); p.Plan == nil || !strings.Contains(p.Plan.Summary, "will be refused") {
		t.Fatal(p.Plan)
	}
	f.mu.Lock()
	f.campaigns["c2"]["settings"].(map[string]any)["subject_line"] = "Changed"
	f.mu.Unlock()
	p, _ = invoke(m, "send_campaign", `{"campaign":"c2"}`, true)
	if sum2 := planSHA(t, p); sum2 == sum {
		t.Fatal("a new subject kept the sha256")
	} else if _, err := invoke(m, "send_campaign", `{"campaign":"c2","sha256":"`+sum2+`"}`, false); err != nil || f.campaigns["c2"]["status"] != "sending" {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.campaigns["c4"] = map[string]any{"id": "c4", "type": "variate", "status": "save", "recipients": map[string]any{"list_id": "l1", "list_name": "Newsletter"}, "settings": map[string]any{}}
	f.mu.Unlock()
	if _, err := invoke(m, "send_campaign", `{"campaign":"c4"}`, true); err == nil || !strings.Contains(err.Error(), "variate") {
		t.Fatal("previewed sending an A/B campaign", err)
	}
	if r, err := invoke(m, "send_campaign", `{"campaign":"c1"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_draft", `{"campaign":"c1"}`, false); err == nil {
		t.Fatal("deleted a sent campaign")
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "send_campaign" || a.Name == "schedule_campaign") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestMailchimpValidation(t *testing.T) {
	m, f := setup(t, goodKey, nil)
	for _, c := range [][2]string{
		{"create_draft", `{"audience":"l1","subject":"x"}`},
		{"create_draft", `{"audience":"l1","subject":"x","text":"a","html":"<p>b</p>"}`},
		{"create_draft", `{"audience":"l1","subject":"x\nBcc: a@b.c","text":"a"}`},
		{"create_draft", `{"audience":"../lists","subject":"x","text":"a"}`},
		{"create_draft", `{"audience":"l1","subject":"x","html":"<p>hi</p><script src=\"https://evil.test/x.js\"></script>"}`},
		{"create_draft", `{"audience":"l1","subject":"x","html":"<SCRIPT>alert(1)</SCRIPT>"}`},
		{"create_draft", `{"audience":"l1","subject":"x","html":"<a href=\"javascript:alert(1)\">x</a>"}`},
		{"create_draft", `{"audience":"l1","subject":"x","html":"<img src=x onerror=alert(1)>"}`},
		{"send_campaign", `{"campaign":"c2","sha256":"nothex"}`},
		{"create_draft", `{"audience":"l1","subject":"x","text":"a","replyTo":"nope"}`},
		{"send_campaign", `{"campaign":"c1/../../lists"}`},
		{"campaign_report", `{"campaign":"a b"}`},
		{"send_test", `{"campaign":"c2","to":"not an address"}`},
		{"schedule_campaign", `{"campaign":"c2","at":"tomorrow"}`},
		{"schedule_campaign", `{"campaign":"c2","at":"2026-11-10T09:10:00Z"}`},
		{"schedule_campaign", `{"campaign":"c2","at":"2026-01-01T09:00:00Z"}`},
		{"campaigns", `{"status":"all"}`},
	} {
		if _, err := invoke(m, c[0], c[1], false); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
	if len(f.seen) != 0 {
		t.Fatal("bad input reached the server:", f.seen)
	}
	for _, c := range []Config{{Key: goodKey}, {Key: "secret://mc", TestRecipients: []string{"a b"}}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "fedcba9876543210FAKEbadKEY000000-us21", nil)
	if h := bad.Health(context.Background(), "m"); h.Status != "down" || h.Message != "Mailchimp refused the API key" {
		t.Fatalf("%+v", h)
	}
}

type recorder struct {
	mu    sync.Mutex
	hosts []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.hosts = append(r.hosts, req.URL.Host)
	r.mu.Unlock()
	return nil, errors.New("offline")
}

func TestMailchimpDataCenter(t *testing.T) {
	for _, key := range []string{
		"0123456789abcdefFAKEtestKEY00000-us21.evil.test",
		"0123456789abcdefFAKEtestKEY00000-evil.test/x",
		"0123456789abcdefFAKEtestKEY00000-us21@evil.test",
		"0123456789abcdefFAKEtestKEY00000-us21#",
		"0123456789abcdefFAKEtestKEY00000-US21",
		"0123456789abcdefFAKEtestKEY00000-21us",
		"0123456789abcdef0123456789abcdef",
	} {
		rec := &recorder{}
		m := New()
		m.HTTP = &http.Client{Transport: rec}
		raw, _ := json.Marshal(Config{Key: "secret://mc"})
		if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mc": key}), "m", raw); err != nil {
			t.Fatal(err)
		}
		h := m.Health(context.Background(), "m")
		if h.Status != "down" || len(rec.hosts) != 0 || strings.Contains(h.Message, key) {
			t.Fatalf("%q: %+v %v", key, h, rec.hosts)
		}
	}
	rec := &recorder{}
	m := New()
	m.HTTP = &http.Client{Transport: rec}
	raw, _ := json.Marshal(Config{Key: "secret://mc"})
	m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mc": goodKey}), "m", raw)
	if h := m.Health(context.Background(), "m"); h.Status != "down" || strings.Join(rec.hosts, ",") != "us21.api.mailchimp.com" || strings.Contains(h.Message, goodKey) {
		t.Fatalf("%+v %v", h, rec.hosts)
	}
}

func TestMailchimpRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Key: "secret://mc"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mc": goodKey}), "m", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "m"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

func planSHA(t *testing.T, p sdk.Result) string {
	t.Helper()
	var v struct {
		SHA string `json:"sha256"`
	}
	if p.Plan == nil || json.Unmarshal(p.Plan.Changes[0].After, &v) != nil || len(v.SHA) != 64 || !strings.Contains(p.Plan.Summary, v.SHA) {
		t.Fatalf("no sha256 in %+v", p.Plan)
	}
	return v.SHA
}
