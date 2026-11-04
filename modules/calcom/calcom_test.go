package calcom

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

const goodKey = "cal_live_0123456789abcdef0123456789abcdef"

type fakeCal struct {
	mu        sync.Mutex
	seen      []string
	status    string
	start     string
	uid       string
	lastBody  map[string]any
	versioned map[string]string
}

func (f *fakeCal) booking() map[string]any {
	end, _ := time.Parse(time.RFC3339, f.start)
	return map[string]any{"id": 11, "uid": f.uid, "title": "30 min between Ada and Jane Doe", "status": f.status, "start": f.start, "end": end.Add(30 * time.Minute).Format(time.RFC3339),
		"duration": 30, "eventTypeId": 5, "meetingUrl": "https://meet.example/LEAKME", "location": "https://meet.example/LEAKME",
		"attendees": []any{map[string]any{"name": "Jane Doe", "email": "jane@example.org", "timeZone": "Europe/Berlin"}}, "hosts": []any{map[string]any{"name": "Ada"}}}
}

func (f *fakeCal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+goodKey {
		w.WriteHeader(401)
		io.WriteString(w, `{"status":"error","error":{"code":"UnauthorizedException","message":"Invalid API Key"}}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	f.versioned[r.URL.Path] = r.Header.Get("cal-api-version")
	enc := json.NewEncoder(w)
	ok := func(v any) { enc.Encode(map[string]any{"status": "success", "data": v}) }
	switch r.Method + " " + r.URL.Path {
	case "GET /v2/me":
		ok(map[string]any{"id": 1, "username": "ada", "email": "ada@example.org", "timeZone": "Europe/Berlin"})
	case "GET /v2/event-types":
		ok([]any{map[string]any{"id": 5, "title": "30 min", "slug": "30min", "lengthInMinutes": 30, "hidden": false}})
	case "GET /v2/bookings":
		if r.URL.Query().Get("status") != "upcoming" || r.URL.Query().Get("take") != "20" {
			w.WriteHeader(400)
			return
		}
		ok([]any{f.booking()})
	case "GET /v2/bookings/" + f.uid:
		ok(f.booking())
	case "POST /v2/bookings/" + f.uid + "/cancel":
		json.Unmarshal(body, &f.lastBody)
		f.status = "cancelled"
		ok(f.booking())
	case "POST /v2/bookings/" + f.uid + "/reschedule":
		json.Unmarshal(body, &f.lastBody)
		f.start = f.lastBody["start"].(string)
		f.uid = f.uid + "x"
		ok(f.booking())
	case "GET /v2/slots":
		q := r.URL.Query()
		if q.Get("eventTypeId") != "5" || q.Get("timeZone") != "Europe/Berlin" || q.Get("start") != "2026-11-05" || q.Get("end") != "2026-11-12" {
			w.WriteHeader(400)
			io.WriteString(w, `{"status":"error","error":{"message":"bad slots query"}}`)
			return
		}
		ok(map[string]any{"2026-11-06": []any{map[string]any{"start": "2026-11-06T09:00:00.000+01:00"}, map[string]any{"start": "2026-11-06T09:30:00.000+01:00"}}})
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"status":"error","error":{"code":"NotFoundException","message":"Booking not found"}}`)
	}
}

var secrets = map[string]string{"secret://cal": goodKey, "secret://bad": "cal_live_ffffffffffffffffffffffffffffffff", "secret://junk": "hunter2"}

func setup(t *testing.T, key string) (*Module, *fakeCal) {
	t.Helper()
	f := &fakeCal{status: "accepted", start: "2026-11-10T14:00:00Z", uid: "bQ7b9zKcSDyC2Gd8", versioned: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{URL: srv.URL + "/v2/", Key: key})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestCalcomReads(t *testing.T) {
	m, f := setup(t, "secret://cal")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "connected as ada" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"event_types", `{}`, `"slug":"30min"`},
		{"bookings", `{}`, `"email":"jane@example.org"`},
		{"availability", `{"eventType":5,"timeZone":"Europe/Berlin"}`, `"total":2`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		if c.action != "bookings" && (strings.Contains(out, "jane") || strings.Contains(out, "Jane")) {
			t.Fatalf("%s returned personal data: %s", c.action, out)
		}
	}
	if f.versioned["/v2/bookings"] != bookingsVersion || f.versioned["/v2/event-types"] != eventTypesVersion || f.versioned["/v2/slots"] != slotsVersion {
		t.Fatal(f.versioned)
	}
	for _, a := range m.Manifest().Actions {
		if a.Sensitive != (a.Name == "bookings") {
			t.Fatalf("%s: sensitive %v", a.Name, a.Sensitive)
		}
		if strings.HasSuffix(a.Name, "_booking") && (a.Risk != sdk.RiskDestructive || !a.DryRun) {
			t.Fatalf("%s must be destructive with a preview", a.Name)
		}
	}
}

func TestCalcomChanges(t *testing.T) {
	m, f := setup(t, "secret://cal")
	in := `{"booking":"bQ7b9zKcSDyC2Gd8","start":"2026-11-11T09:00:00+01:00","reason":"Conflict"}`
	r, err := invoke(m, "reschedule_booking", in, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Move booking bQ7b9zKcSDyC2Gd8 from 2026-11-10T14:00:00Z to 2026-11-11T08:00:00Z (1 attendee is told)" || f.start != "2026-11-10T14:00:00Z" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	plan, _ := json.Marshal(r.Plan)
	if strings.Contains(string(plan), "Jane") || strings.Contains(string(plan), "jane") {
		t.Fatalf("the preview names people: %s", plan)
	}
	r, err = invoke(m, "reschedule_booking", in, false)
	if err != nil || f.start != "2026-11-11T08:00:00Z" || f.lastBody["reschedulingReason"] != "Conflict" || r.Undo == nil ||
		string(r.Undo.Input) != `{"booking":"bQ7b9zKcSDyC2Gd8x","start":"2026-11-10T14:00:00Z"}` || strings.Contains(string(r.Output), "Jane") {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if r, err := invoke(m, "reschedule_booking", `{"booking":"bQ7b9zKcSDyC2Gd8x","start":"2026-11-11T08:00:00Z"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.start != "2026-11-10T14:00:00Z" {
		t.Fatal(err)
	}

	r, err = invoke(m, "cancel_booking", `{"booking":"`+f.uid+`","reason":"Sick"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "can't be undone") || f.status != "accepted" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "cancel_booking", `{"booking":"`+f.uid+`","reason":"Sick"}`, false)
	if err != nil || f.status != "cancelled" || r.Undo != nil || f.lastBody["cancellationReason"] != "Sick" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "cancel_booking", `{"booking":"`+f.uid+`"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "reschedule_booking", `{"booking":"`+f.uid+`","start":"2026-11-12T09:00:00Z"}`, false); err == nil || !strings.Contains(err.Error(), "can't be rescheduled") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "cancel_booking", `{"booking":"nosuchbooking"}`, false); err == nil || !strings.Contains(err.Error(), "no booking") {
		t.Fatal(err)
	}
}

func TestCalcomValidation(t *testing.T) {
	m, f := setup(t, "secret://cal")
	for _, c := range []struct{ action, in string }{
		{"bookings", `{"status":"all"}`},
		{"bookings", `{"eventType":"5&x=1"}`},
		{"bookings", `{"skip":-1}`},
		{"availability", `{}`},
		{"availability", `{"eventType":5,"timeZone":"Europe/Berlin&x=1"}`},
		{"availability", `{"eventType":5,"start":"2026-11-01","end":"2026-12-15"}`},
		{"availability", `{"eventType":5,"start":"2026-11-10","end":"2026-11-01"}`},
		{"availability", `{"eventType":5,"start":"tomorrow"}`},
		{"cancel_booking", `{"booking":"../me"}`},
		{"cancel_booking", `{}`},
		{"reschedule_booking", `{"booking":"bQ7b9zKcSDyC2Gd8","start":"next tuesday"}`},
		{"reschedule_booking", `{"booking":"bQ7b9zKcSDyC2Gd8","start":"2020-01-01T00:00:00Z"}`},
		{"reschedule_booking", `{"booking":"bQ7b9zKcSDyC2Gd8","start":"2026-11-11T09:00:00Z","reason":"` + strings.Repeat("x", 501) + `"}`},
		{"nope", `{}`},
	} {
		for _, dry := range []bool{false, true} {
			if _, err := invoke(m, c.action, c.in, dry); err == nil {
				t.Fatalf("%s accepted %s", c.action, c.in)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Cal.com: %v", f.seen)
	}
	for _, c := range []Config{{Key: goodKey}, {URL: "cal.example.com", Key: "secret://cal"}, {URL: "https://u:p@cal.example.com", Key: "secret://cal"}, {URL: "https://cal.example.com/?x=1", Key: "secret://cal"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || h.Message != "Cal.com refused the API key" {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, "secret://junk")
	if _, err := invoke(junk, "event_types", `{}`, false); err == nil || len(fj.seen) != 0 || strings.Contains(err.Error(), "hunter2") {
		t.Fatal(err)
	}
}

func TestCalcomRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Key: "secret://cal"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
