package monica

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
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeMonica struct {
	mu    sync.Mutex
	seen  []string
	notes map[int]string
	n     int
}

const contacts = `[
 {"id":1,"first_name":"Ada","last_name":"Lovelace","complete_name":"Ada Lovelace","nickname":"","description":"Met at the conference","is_starred":true,"is_partial":false,"is_dead":false,"information":{"dates":{"birthdate":{"is_age_based":false,"is_year_unknown":false,"date":"1990-11-10T00:00:00Z"}}}},
 {"id":2,"first_name":"Bob","last_name":"","complete_name":"Bob","is_partial":false,"information":{"dates":{"birthdate":{"is_age_based":false,"is_year_unknown":true,"date":"2026-02-01T00:00:00Z"}}}},
 {"id":3,"first_name":"Partial","complete_name":"Partial","is_partial":true,"information":{"dates":{"birthdate":{"date":null}}}}
]`

func (f *fakeMonica) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"Unauthenticated.","error_code":42}}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	path := strings.TrimPrefix(r.URL.Path, "/api")
	switch {
	case path == "/me":
		io.WriteString(w, `{"data":{"id":9,"first_name":"Me"}}`)
	case path == "/contacts":
		fmt.Fprintf(w, `{"data":%s,"meta":{"current_page":1,"last_page":1,"total":3}}`, contacts)
	case path == "/contacts/1":
		var all []json.RawMessage
		json.Unmarshal([]byte(contacts), &all)
		fmt.Fprintf(w, `{"data":%s}`, all[0])
	case path == "/contacts/1/notes":
		io.WriteString(w, `{"data":[{"id":5,"body":"Likes tea","is_favorited":true,"created_at":"2026-10-01T10:00:00Z"}]}`)
	case strings.HasPrefix(path, "/contacts/"):
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"message":"The resource has not been found","error_code":31}}`)
	case path == "/reminders":
		io.WriteString(w, `{"data":[
		 {"id":1,"title":"Wish happy birthday to Ada Lovelace","frequency_type":"year","frequency_number":1,"initial_date":"1991-11-10T00:00:00Z","contact":{"id":1,"complete_name":"Ada Lovelace"}},
		 {"id":2,"title":"Call about the move","frequency_type":"one_time","frequency_number":1,"initial_date":"2026-11-20","contact":{"id":2,"complete_name":"Bob"}},
		 {"id":3,"title":"Old thing","frequency_type":"one_time","initial_date":"2026-01-01","contact":{"id":2,"complete_name":"Bob"}},
		 {"id":4,"title":"Monthly check-in","frequency_type":"month","frequency_number":2,"initial_date":"2025-01-31","contact":{"id":2,"complete_name":"Bob"}}
		],"meta":{"current_page":1,"last_page":1}}`)
	case path == "/notes" && r.Method == "POST":
		var b struct {
			Body      string `json:"body"`
			ContactID int    `json:"contact_id"`
		}
		json.Unmarshal(body, &b)
		f.n++
		id := 100 + f.n
		f.notes[id] = b.Body
		fmt.Fprintf(w, `{"data":{"id":%d,"body":%q,"contact":{"id":%d,"complete_name":"Ada Lovelace"}}}`, id, b.Body, b.ContactID)
	case strings.HasPrefix(path, "/notes/"):
		id, _ := strconv.Atoi(strings.TrimPrefix(path, "/notes/"))
		b, ok := f.notes[id]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":{"message":"The resource has not been found","error_code":31}}`)
			return
		}
		if r.Method == "DELETE" {
			delete(f.notes, id)
			fmt.Fprintf(w, `{"deleted":true,"id":%d}`, id)
			return
		}
		fmt.Fprintf(w, `{"data":{"id":%d,"body":%q,"created_at":"2026-11-04T10:00:00Z","contact":{"id":1,"complete_name":"Ada Lovelace"}}}`, id, b)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeMonica) {
	f := &fakeMonica{notes: map[int]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "good", "secret://bad": "nope"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMonica(t *testing.T) {
	m, f := setup(t, "secret://k")
	for _, a := range m.Manifest().Actions {
		if !a.Sensitive {
			t.Fatalf("%s isn't sensitive: everything in Monica is about people", a.Name)
		}
	}
	if h := m.Health(context.Background(), "k"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"contacts", `{"query":"ada"}`, `{"contacts":[{"birthday":"1990-11-10","id":1,"name":"Ada Lovelace","starred":true},{"birthday":"--02-01","id":2,"name":"Bob"}],"total":3}`},
		{"contact", `{"contact":1}`, `"notes":[{"body":"Likes tea","created":"2026-10-01T10:00:00Z","favorite":true,"id":5}]`},
		// Ada's birthday once (Monica's reminder for it is dropped), Bob's
		// one-off call, and the two-monthly check-in on 31 Jan + 22 months.
		{"upcoming", `{"days":30}`, `"upcoming":[{"contact":1,"date":"2026-11-10","kind":"birthday","name":"Ada Lovelace","turns":36},{"contact":2,"date":"2026-11-20","kind":"reminder","name":"Bob","title":"Call about the move"},{"contact":2,"date":"2026-12-01","kind":"reminder","name":"Bob","title":"Monthly check-in"}]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	if !strings.Contains(f.seen[1], "query=ada") {
		t.Fatal(f.seen)
	}

	r, err := invoke(m, "add_note", `{"contact":1,"body":"Ask about the trip"}`, true)
	if err != nil || r.Plan == nil || len(f.notes) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "add_note", `{"contact":1,"body":"Ask about the trip"}`, false)
	if err != nil || f.notes[101] != "Ask about the trip" || r.Undo == nil || r.Undo.Action != "delete_note" || string(r.Undo.Input) != `{"note":101}` {
		t.Fatalf("%+v %v", r, err)
	}
	p, err := invoke(m, "delete_note", string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || !strings.Contains(string(p.Plan.Changes[0].Before), "Ask about the trip") {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.notes) != 0 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_note", `{"note":101}`, false); err == nil || !strings.Contains(err.Error(), "no note") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "add_note", `{"contact":7,"body":"x"}`, false); err == nil || !strings.Contains(err.Error(), "no contact") {
		t.Fatal(err)
	}
}

func TestReminderNext(t *testing.T) {
	from := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		r    reminder
		want string
	}{
		{reminder{FrequencyType: "week", FrequencyNumber: 2, InitialDate: "2026-01-01"}, "2026-11-05"},
		{reminder{FrequencyType: "year", FrequencyNumber: 1, InitialDate: "2000-11-04"}, "2026-11-04"},
		{reminder{FrequencyType: "one_time", InitialDate: "2026-11-03"}, ""},
	} {
		got, ok := c.r.next(from)
		if (c.want == "" && ok) || (c.want != "" && got.Format("2006-01-02") != c.want) {
			t.Errorf("%+v: %v %v", c.r, got, ok)
		}
	}
	if got := nextBirthday(time.February, 29, from); got.Format("2006-01-02") != "2027-02-28" {
		t.Error(got)
	}
}

func TestMonicaValidation(t *testing.T) {
	m, f := setup(t, "secret://k")
	for _, c := range []struct{ action, in string }{
		{"contacts", `{"query":"` + strings.Repeat("x", 201) + `"}`},
		{"contact", `{}`},
		{"contact", `{"contact":"1/../../me"}`},
		{"upcoming", `{"days":367}`},
		{"upcoming", `{"days":-1}`},
		{"add_note", `{"contact":1,"body":"  "}`},
		{"add_note", `{"contact":1,"body":"` + strings.Repeat("x", 10001) + `"}`},
		{"add_note", `{"body":"hello"}`},
		{"delete_note", `{}`},
		{"delete_note", `{"note":-5}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://app.monicahq.com", Token: "plaintoken"}, {URL: "app.monicahq.com", Token: "secret://k"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "k"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestMonicaRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "good"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "k"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
