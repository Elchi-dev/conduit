package postmark

import (
	"context"
	"encoding/json"
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

const goodToken = "0c5e1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b"

type fakePostmark struct {
	mu       sync.Mutex
	seen     []string
	inactive bool
}

func (f *fakePostmark) bounce(id int64) map[string]any {
	b := map[string]any{"ID": id, "Type": "HardBounce", "Name": "Hard bounce", "Email": "jane@example.org", "From": "billing@example.com", "BouncedAt": "2026-11-01T10:00:00Z", "Description": "The server was unable to deliver your message", "Details": "smtp;550 5.1.1 user unknown", "Inactive": f.inactive, "CanActivate": true, "MessageStream": "outbound", "Subject": "Your invoice", "Content": "<html>private body</html>", "DumpAvailable": true}
	if id == 2 {
		b["Type"], b["CanActivate"], b["Inactive"] = "SpamComplaint", false, true
	}
	return b
}

func (f *fakePostmark) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Postmark-Server-Token") != goodToken {
		w.WriteHeader(401)
		io.WriteString(w, `{"ErrorCode":10,"Message":"The Server Token you provided in the X-Postmark-Server-Token request header was invalid."}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+r.URL.RawQuery)
	enc := json.NewEncoder(w)
	switch r.Method + " " + r.URL.Path {
	case "GET /server":
		io.WriteString(w, `{"ID":1,"Name":"Production","ApiTokens":["`+goodToken+`"],"InboundHash":"abc"}`)
	case "GET /stats/outbound":
		q := r.URL.Query()
		if q.Get("fromdate") != "2026-10-29" || q.Get("todate") != "2026-11-04" || q.Get("messagestream") != "outbound" {
			w.WriteHeader(422)
			io.WriteString(w, `{"ErrorCode":0,"Message":"bad query `+r.URL.RawQuery+`"}`)
			return
		}
		io.WriteString(w, `{"Sent":615,"Bounced":64,"SMTPApiErrors":25,"BounceRate":10.406,"SpamComplaints":10,"SpamComplaintsRate":1.626,"Opens":166,"UniqueOpens":26,"Tracked":111}`)
	case "GET /bounces":
		if r.URL.Query().Get("count") != "50" || r.URL.Query().Get("type") != "HardBounce" || r.URL.Query().Get("inactive") != "true" {
			w.WriteHeader(422)
			return
		}
		enc.Encode(map[string]any{"TotalCount": 1, "Bounces": []any{f.bounce(1)}})
	case "GET /bounces/1":
		enc.Encode(f.bounce(1))
	case "GET /bounces/2":
		enc.Encode(f.bounce(2))
	case "PUT /bounces/1/activate":
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(415)
			return
		}
		f.inactive = false
		enc.Encode(map[string]any{"Message": "OK", "Bounce": f.bounce(1)})
	case "GET /message-streams":
		if r.URL.Query().Get("MessageStreamType") != "All" {
			w.WriteHeader(422)
			return
		}
		io.WriteString(w, `{"MessageStreams":[{"ID":"outbound","ServerID":1,"Name":"Default Transactional Stream","MessageStreamType":"Transactional","CreatedAt":"2026-01-01T00:00:00Z","ArchivedAt":null,"SubscriptionManagementConfiguration":{"UnsubscribeHandlingType":"None"}},{"ID":"broadcast","Name":"Newsletters","MessageStreamType":"Broadcasts","SubscriptionManagementConfiguration":{"UnsubscribeHandlingType":"Postmark"}}],"TotalCount":2}`)
	default:
		w.WriteHeader(422)
		io.WriteString(w, `{"ErrorCode":701,"Message":"This bounce was not found."}`)
	}
}

var secrets = map[string]string{"secret://pm": goodToken, "secret://bad": "11111111-2222-4333-8444-555555555555", "secret://junk": "server token"}

func setup(t *testing.T, ref string) (*Module, *fakePostmark) {
	t.Helper()
	f := &fakePostmark{inactive: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{Token: ref})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestPostmarkReads(t *testing.T) {
	m, _ := setup(t, "secret://pm")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "connected to server Production" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"stats", `{"days":7,"stream":"outbound"}`, `"bounceRate":10.406`},
		{"bounces", `{"type":"HardBounce","inactive":true}`, `"email":"jane@example.org"`},
		{"bounces", `{"type":"HardBounce","inactive":true}`, `"canActivate":true`},
		{"message_streams", `{}`, `"unsubscribeHandling":"Postmark"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		if strings.Contains(out, "private body") || strings.Contains(out, goodToken) {
			t.Fatalf("%s leaked: %s", c.action, out)
		}
		if c.action != "bounces" && strings.Contains(out, "@") {
			t.Fatalf("%s returned an address: %s", c.action, out)
		}
	}
	for _, a := range m.Manifest().Actions {
		sens := a.Name == "bounces" || a.Name == "reactivate_bounce"
		if a.Sensitive != sens {
			t.Fatalf("%s: sensitive %v", a.Name, a.Sensitive)
		}
		if a.Name == "reactivate_bounce" && (a.Risk != sdk.RiskDestructive || !a.DryRun || a.Reversible) {
			t.Fatalf("%+v", a)
		}
	}
}

func TestPostmarkReactivate(t *testing.T) {
	m, f := setup(t, "secret://pm")
	r, err := invoke(m, "reactivate_bounce", `{"bounce":1}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Reactivate jane@example.org: Postmark will send to it again, though it bounced (HardBounce) on 2026-11-01T10:00:00Z" || !f.inactive {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "reactivate_bounce", `{"bounce":1}`, false)
	if err != nil || f.inactive || r.Undo != nil || !strings.Contains(string(r.Output), `"reactivated":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "reactivate_bounce", `{"bounce":1}`, false)
	if err != nil || !strings.Contains(string(r.Output), "active already") {
		t.Fatalf("%s %v", r.Output, err)
	}
	n := len(f.seen)
	if _, err := invoke(m, "reactivate_bounce", `{"bounce":2}`, false); err == nil || !strings.Contains(err.Error(), "won't reactivate") {
		t.Fatal(err)
	}
	if len(f.seen) != n+1 || strings.Contains(f.seen[n], "activate") {
		t.Fatalf("%v", f.seen[n:])
	}
	if _, err := invoke(m, "reactivate_bounce", `{"bounce":99}`, true); err == nil || !strings.Contains(err.Error(), "no bounce 99") {
		t.Fatal(err)
	}
}

func TestPostmarkValidation(t *testing.T) {
	m, f := setup(t, "secret://pm")
	for _, c := range []struct{ action, in string }{
		{"reactivate_bounce", `{}`},
		{"reactivate_bounce", `{"bounce":-1}`},
		{"reactivate_bounce", `{"bounce":"1/../../server"}`},
		{"bounces", `{"type":"Everything"}`},
		{"bounces", `{"offset":-5}`},
		{"bounces", `{"stream":"../server"}`},
		{"stats", `{"stream":"Out Bound"}`},
		{"stats", `{"tag":"a\nb"}`},
		{"nope", `{}`},
	} {
		for _, dry := range []bool{false, true} {
			if _, err := invoke(m, c.action, c.in, dry); err == nil {
				t.Fatalf("%s accepted %s", c.action, c.in)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Postmark: %v", f.seen)
	}
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(`{"token":"`+goodToken+`"}`)); err == nil {
		t.Fatal("accepted a plain token")
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || !strings.Contains(h.Message, "refused the server token") {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, "secret://junk")
	if _, err := invoke(junk, "stats", `{}`, false); err == nil || len(fj.seen) != 0 {
		t.Fatal(err)
	}
}

func TestPostmarkRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(secrets), "p", json.RawMessage(`{"token":"secret://pm"}`)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
