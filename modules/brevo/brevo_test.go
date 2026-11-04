package brevo

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

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const goodKey = "xkeysib-0123456789abcdefFAKEtestKEY00000-AbCdEf"

type fake struct {
	mu        sync.Mutex
	seen      []string
	campaigns map[int]map[string]any
	created   map[string]any
	tests     []string
	sent      []int
}

func newFake() *fake {
	return &fake{campaigns: map[int]map[string]any{
		1: {"id": 1, "name": "October", "subject": "News for October", "type": "classic", "status": "sent", "sentDate": "2026-10-01T09:00:00Z",
			"sender": map[string]any{"name": "Acme", "email": "news@acme.test"}, "recipients": map[string]any{"lists": []int{2}},
			"statistics": map[string]any{"globalStats": map[string]any{"sent": 120, "delivered": 118, "uniqueViews": 80, "uniqueClicks": 12}}},
		2: {"id": 2, "name": "November", "subject": "News for November", "type": "classic", "status": "draft", "htmlContent": "<p>November news</p>",
			"sender": map[string]any{"name": "Acme", "email": "news@acme.test"}, "recipients": map[string]any{"lists": []int{2, 3}, "exclusionLists": []int{4}}},
	}}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("api-key") != goodKey {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":"unauthorized","message":"Key not found"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v3")
	f.seen = append(f.seen, r.Method+" "+path)
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	out := func(v any) { json.NewEncoder(w).Encode(v) }
	switch {
	case path == "/account":
		out(map[string]any{"email": "Owner@acme.test", "companyName": "Acme", "firstName": "LEAKME"})
	case path == "/contacts/lists":
		out(map[string]any{"lists": []any{
			map[string]any{"id": 2, "name": "Newsletter", "totalSubscribers": 120, "uniqueSubscribers": 120, "totalBlacklisted": 3},
			map[string]any{"id": 3, "name": "Beta", "totalSubscribers": 30, "uniqueSubscribers": 30}}, "count": 2})
	case path == "/senders":
		out(map[string]any{"senders": []any{map[string]any{"id": 7, "name": "Acme", "email": "news@acme.test", "active": true}, map[string]any{"id": 8, "name": "Old", "email": "old@acme.test", "active": false}}})
	case path == "/smtp/statistics/aggregatedReport":
		out(map[string]any{"range": "2026-10-28|2026-11-04", "requests": 50, "delivered": 49, "opens": 30, "hardBounces": 1})
	case path == "/emailCampaigns" && r.Method == "GET":
		res := []any{}
		for _, id := range []int{2, 1} {
			if c := f.campaigns[id]; c != nil && (r.URL.Query().Get("status") == "" || c["status"] == r.URL.Query().Get("status")) {
				res = append(res, c)
			}
		}
		out(map[string]any{"campaigns": res, "count": len(res)})
	case path == "/emailCampaigns" && r.Method == "POST":
		f.created = body
		f.campaigns[3] = map[string]any{"id": 3, "name": body["name"], "subject": body["subject"], "status": "draft"}
		w.WriteHeader(201)
		out(map[string]any{"id": 3})
	case strings.HasPrefix(path, "/emailCampaigns/"):
		parts := strings.Split(strings.TrimPrefix(path, "/emailCampaigns/"), "/")
		id, _ := strconv.Atoi(parts[0])
		c := f.campaigns[id]
		if c == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"code":"document_not_found","message":"Campaign does not exist"}`)
			return
		}
		switch {
		case r.Method == "GET" && len(parts) == 1:
			cp := map[string]any{}
			for k, v := range c {
				if k != "htmlContent" || r.URL.Query().Get("excludeHtmlContent") == "false" {
					cp[k] = v
				}
			}
			out(cp)
		case r.Method == "DELETE" && len(parts) == 1:
			delete(f.campaigns, id)
			w.WriteHeader(204)
		case r.Method == "POST" && len(parts) == 2 && parts[1] == "sendTest":
			for _, e := range body["emailTo"].([]any) {
				f.tests = append(f.tests, e.(string))
			}
			w.WriteHeader(204)
		case r.Method == "POST" && len(parts) == 2 && parts[1] == "sendNow":
			f.sent = append(f.sent, id)
			c["status"] = "in_process"
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
	m.Base = srv.URL + "/v3"
	raw, _ := json.Marshal(Config{Key: "secret://bv", TestRecipients: allow})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bv": key}), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestBrevo(t *testing.T) {
	m, f := setup(t, goodKey, nil)
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || h.Message != "Acme: 2 contact lists" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"lists", `{}`, `"subscribers":120`},
		{"campaigns", `{"status":"sent"}`, `"uniqueOpens":80`},
		{"campaign", `{"campaign":2}`, `"exclusionLists":[4]`},
		{"transactional_stats", `{"days":7}`, `"delivered":49`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if out := string(r.Output); err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, goodKey) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// Plain text becomes escaped HTML, shown in full in the preview.
	in := `{"name":"December","subject":"News for December","lists":[2],"text":"Hi <all>,\n\nnews & more"}`
	p, err := invoke(m, "create_draft", in, true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, "Newsletter (120)") || !strings.Contains(string(p.Plan.Changes[0].After), `<p>Hi &lt;all&gt;,</p>\n<p>news &amp; more</p>`) || f.created != nil {
		t.Fatal(p.Plan, err)
	}
	r, err := invoke(m, "create_draft", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_draft" || f.created["sender"].(map[string]any)["id"] != float64(7) {
		t.Fatalf("%+v %v %v", r, err, f.created)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.campaigns[3] != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "create_draft", `{"name":"x","subject":"y","lists":[2],"text":"t","senderEmail":"old@acme.test"}`, false); err == nil {
		t.Fatal("used an inactive sender")
	}

	// Tests go to the account's address (no allow-list set) and nothing else.
	if _, err := invoke(m, "send_test", `{"campaign":2,"to":"someone@else.test"}`, false); err == nil {
		t.Fatal("sent a test to an address that isn't allowed")
	}
	if _, err := invoke(m, "send_test", `{"campaign":2}`, false); err != nil || strings.Join(f.tests, ",") != "owner@acme.test" {
		t.Fatal(err, f.tests)
	}

	// Sending: the preview names lists, counts, subject and sender, and
	// shows the HTML with its sha256, which the send must give.
	p, err = invoke(m, "send_campaign", `{"campaign":2}`, true)
	if err != nil || p.Plan == nil || len(f.sent) != 0 || len(p.Plan.Changes) != 3 {
		t.Fatal(p.Plan, err)
	}
	var shown struct {
		HTML string `json:"html"`
		SHA  string `json:"sha256"`
	}
	_ = json.Unmarshal(p.Plan.Changes[2].After, &shown)
	sum := shown.SHA
	if p.Plan.Summary != `Email "News for November" from Acme <news@acme.test> to up to 150 contacts now: Newsletter (120), Beta (30), minus 1 exclusion lists (content sha256 `+sum+`). Sent emails can't be recalled.` ||
		shown.HTML != "<p>November news</p>" || len(sum) != 64 {
		t.Fatal(p.Plan.Summary, shown)
	}
	if _, err := invoke(m, "send_campaign", `{"campaign":2}`, false); err == nil || len(f.sent) != 0 {
		t.Fatal("sent without the preview's sha256")
	}
	f.mu.Lock()
	f.campaigns[2]["htmlContent"] = "<p>Edited after the preview</p>"
	f.mu.Unlock()
	if _, err := invoke(m, "send_campaign", `{"campaign":2,"sha256":"`+sum+`"}`, false); err == nil || !strings.Contains(err.Error(), "changed since") || len(f.sent) != 0 {
		t.Fatal("sent content that changed after the preview", err)
	}
	f.mu.Lock()
	f.campaigns[2]["htmlContent"] = "<p>November news</p>"
	f.mu.Unlock()
	if _, err := invoke(m, "send_campaign", `{"campaign":2,"sha256":"`+sum+`"}`, false); err != nil || len(f.sent) != 1 {
		t.Fatal(err)
	}
	if r, err := invoke(m, "send_campaign", `{"campaign":2}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || len(f.sent) != 1 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_draft", `{"campaign":1}`, false); err == nil {
		t.Fatal("deleted a sent campaign")
	}
}

func TestBrevoValidation(t *testing.T) {
	m, f := setup(t, goodKey, []string{"qa@acme.test"})
	for _, c := range [][2]string{
		{"create_draft", `{"name":"x","subject":"y","lists":[2]}`},
		{"create_draft", `{"name":"x","subject":"y","lists":[],"text":"t"}`},
		{"create_draft", `{"name":"x","subject":"y\r\nBcc: a@b.c","lists":[2],"text":"t"}`},
		{"create_draft", `{"name":"x","subject":"y","lists":[-2],"text":"t"}`},
		{"create_draft", `{"name":"x","subject":"y","lists":[2],"html":"<script src=\"//evil.test/x.js\"></script>"}`},
		{"create_draft", `{"name":"x","subject":"y","lists":[2],"text":"t","senderEmail":"nope"}`},
		{"send_campaign", `{"campaign":0}`},
		{"send_campaign", `{"campaign":2,"sha256":"ABC"}`},
		{"create_draft", `{"name":"x","subject":"y","lists":[2],"html":"<a href=\"jav&#x61;script:x()\">x</a>"}`},
		{"campaign", `{"campaign":"1/../../account"}`},
		{"send_test", `{"campaign":2,"to":"a@b"}`},
		{"transactional_stats", `{"days":400}`},
		{"campaigns", `{"status":"all"}`},
	} {
		if _, err := invoke(m, c[0], c[1], false); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
	if len(f.seen) != 0 {
		t.Fatal("bad input reached the server:", f.seen)
	}
	for _, c := range []Config{{Key: goodKey}, {Key: "secret://bv", TestRecipients: []string{"x"}}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "xkeysib-ffffffffffffffffffffffffffffffff-zzz", nil)
	if h := bad.Health(context.Background(), "b"); h.Status != "down" || h.Message != "Brevo refused the API key" {
		t.Fatalf("%+v", h)
	}
	odd, of := setup(t, "not-a-brevo-key", nil)
	if h := odd.Health(context.Background(), "b"); h.Status != "down" || strings.Contains(h.Message, "not-a-brevo-key") || len(of.seen) != 0 {
		t.Fatalf("%+v", h)
	}
}

func TestBrevoRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("api-key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Key: "secret://bv"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bv": goodKey}), "b", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "b"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// A campaign that also goes to segments, or to a list that can't be read,
// isn't sent: the preview couldn't show how many it reaches.
func TestBrevoUncountableRecipients(t *testing.T) {
	m, f := setup(t, goodKey, nil)
	f.mu.Lock()
	f.campaigns[2]["recipients"] = map[string]any{"lists": []int{2}, "segmentIds": []int{9}}
	f.campaigns[4] = map[string]any{"id": 4, "subject": "S", "status": "draft", "htmlContent": "<p>x</p>", "recipients": map[string]any{"lists": []int{99}}}
	f.mu.Unlock()
	if _, err := invoke(m, "send_campaign", `{"campaign":2}`, true); err == nil || !strings.Contains(err.Error(), "segments") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "send_campaign", `{"campaign":4}`, true); err == nil || !strings.Contains(err.Error(), "list 99") {
		t.Fatal(err)
	}
}
