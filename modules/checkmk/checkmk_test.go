package checkmk

import (
	"context"
	"encoding/json"
	"fmt"
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

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type dt struct {
	id, host, service, comment, start, end string
}

type fakeCMK struct {
	mu        sync.Mutex
	seen      []string
	acked     map[string]bool
	downtimes []dt
	next      int
	twin      bool // a POST makes two identical downtimes
}

func (f *fakeCMK) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer automation cmk-good-secret" {
		w.WriteHeader(401)
		io.WriteString(w, `{"title":"Unauthorized","status":401,"detail":"You need to be authenticated to use the REST API."}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	p := strings.TrimPrefix(r.URL.Path, "/mysite/check_mk/api/1.0")
	query := r.URL.Query().Get("query")
	switch r.Method + " " + p {
	case "GET /version":
		io.WriteString(w, `{"site":"mysite","versions":{"checkmk":"2.3.0p12"},"edition":"cre"}`)
	case "GET /domain-types/host/collections/all":
		rows := []string{
			fmt.Sprintf(`{"name":"web1","address":"10.0.0.5","state":1,"plugin_output":"CRIT - 10.0.0.5: rta nan, lost 100%% token=abcdefSECRET123","acknowledged":%d,"scheduled_downtime_depth":0,"last_state_change":1762250000,"num_services_crit":2,"has_been_checked":1}`, b2i(f.acked["web1"])),
			`{"name":"db1","address":"10.0.0.6","state":0,"plugin_output":"OK","acknowledged":0,"has_been_checked":1}`,
		}
		out := []string{}
		for _, row := range rows {
			if strings.Contains(query, `"right":"db1"`) && !strings.Contains(row, `"db1"`) || strings.Contains(query, `"right":"web1"`) && !strings.Contains(row, `"web1"`) {
				continue
			}
			if strings.Contains(query, `"left":"state","op":"!="`) && strings.Contains(row, `"state":0`) {
				continue
			}
			out = append(out, `{"id":"x","extensions":`+row+`}`)
		}
		io.WriteString(w, `{"value":[`+strings.Join(out, ",")+`]}`)
	case "GET /domain-types/service/collections/all":
		fmt.Fprintf(w, `{"value":[{"extensions":{"host_name":"db1","description":"Filesystem /var","state":1,"plugin_output":"WARN - 85%% used","acknowledged":%d,"scheduled_downtime_depth":0,"last_state_change":1762251000}},
			{"extensions":{"host_name":"db1","description":"CPU load","state":2,"plugin_output":"CRIT - load 30","acknowledged":0,"last_state_change":1762252000}}]}`, b2i(f.acked["db1/Filesystem /var"]))
	case "POST /domain-types/acknowledge/collections/host", "POST /domain-types/acknowledge/collections/service":
		var b map[string]any
		json.Unmarshal(body, &b)
		k := b["host_name"].(string)
		if s, ok := b["service_description"].(string); ok {
			k += "/" + s
		}
		f.acked[k] = true
		w.WriteHeader(204)
	case "GET /domain-types/downtime/collections/all":
		out := []string{}
		for _, d := range f.downtimes {
			if h := r.URL.Query().Get("host_name"); h != "" && h != d.host {
				continue
			}
			isSvc := "no"
			if d.service != "" {
				isSvc = "yes"
			}
			out = append(out, fmt.Sprintf(`{"id":%q,"extensions":{"site_id":"mysite","host_name":%q,"service_description":%q,"is_service":%q,"author":"automation","comment":%q,"start_time":%q,"end_time":%q,"recurring":"no"}}`,
				d.id, d.host, d.service, isSvc, d.comment, d.start, d.end))
		}
		io.WriteString(w, `{"value":[`+strings.Join(out, ",")+`]}`)
	case "POST /domain-types/downtime/collections/host", "POST /domain-types/downtime/collections/service":
		var b struct {
			Host     string   `json:"host_name"`
			Services []string `json:"service_descriptions"`
			Comment  string   `json:"comment"`
			Start    string   `json:"start_time"`
			End      string   `json:"end_time"`
		}
		json.Unmarshal(body, &b)
		f.next++
		d := dt{id: fmt.Sprint(f.next), host: b.Host, comment: b.Comment, start: strings.Replace(b.Start, "Z", "+00:00", 1), end: strings.Replace(b.End, "Z", "+00:00", 1)}
		if len(b.Services) > 0 {
			d.service = b.Services[0]
		}
		f.downtimes = append(f.downtimes, d)
		if f.twin {
			f.next++
			d.id = fmt.Sprint(f.next)
			f.downtimes = append(f.downtimes, d)
		}
		w.WriteHeader(204)
	case "POST /domain-types/downtime/actions/delete/invoke":
		var b map[string]string
		json.Unmarshal(body, &b)
		for i, d := range f.downtimes {
			if d.id == b["downtime_id"] && b["site_id"] == "mysite" && b["delete_type"] == "by_id" {
				f.downtimes = append(f.downtimes[:i], f.downtimes[i+1:]...)
				break
			}
		}
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"title":"Not Found","status":404}`)
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func setup(t *testing.T, secret string) (*Module, *fakeCMK) {
	f := &fakeCMK{acked: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.now = func() time.Time { return now }
	raw, _ := json.Marshal(Config{URL: srv.URL + "/mysite/check_mk/", Username: "automation", Secret: secret})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cmk": "cmk-good-secret", "secret://bad": "nope"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestCheckmk(t *testing.T) {
	m, f := setup(t, "secret://cmk")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "site mysite · Checkmk 2.3.0p12 (cre)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"hosts", `{}`, `"state":"DOWN"`},
		{"hosts", `{"problemsOnly":true}`, `"servicesCrit":2`},
		{"services", `{"host":"db1"}`, `"service":"CPU load"`},
		{"problems", `{}`, `"services":[{"acknowledged":false,"host":"db1","inDowntime":false,"output":"CRIT - load 30"`},
		{"problems", `{"unhandledOnly":true}`, `"hosts":[{"acknowledged":false,"address":"10.0.0.5"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "abcdefSECRET123") || strings.Contains(out, "cmk-good-secret") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if !strings.Contains(f.seen[len(f.seen)-2], "acknowledged") {
		t.Fatal("unhandledOnly isn't in the host filter", f.seen)
	}

	// Acknowledge: preview, real, nothing to change, and an OK service.
	in := `{"host":"db1","service":"Filesystem /var","comment":"cleaning up"}`
	r, err := invoke(m, "acknowledge", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, `service "Filesystem /var" on db1`) || f.acked["db1/Filesystem /var"] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "acknowledge", in, false); err != nil || !f.acked["db1/Filesystem /var"] {
		t.Fatal(err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], `"sticky":true`) || !strings.Contains(f.seen[len(f.seen)-1], `"notify":false`) {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	if r, err := invoke(m, "acknowledge", in, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "acknowledge", `{"host":"db1","comment":"x"}`, false); err == nil || !strings.Contains(err.Error(), "is UP") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "acknowledge", `{"host":"db1","service":"Nope","comment":"x"}`, false); err == nil || !strings.Contains(err.Error(), "no service") {
		t.Fatal(err)
	}

	// Downtime: preview, real with undo, nothing to change, end and undo.
	in = `{"host":"web1","durationMinutes":90,"comment":"rack move"}`
	if r, err := invoke(m, "schedule_downtime", in, true); err != nil || r.Plan == nil || len(f.downtimes) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "schedule_downtime", in, false)
	if err != nil || len(f.downtimes) != 1 || r.Undo == nil || r.Undo.Action != "end_downtime" || string(r.Undo.Input) != `{"id":"1","site":"mysite"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if again, err := invoke(m, "schedule_downtime", `{"host":"web1","durationMinutes":30,"comment":"rack move"}`, false); err != nil || !strings.Contains(string(again.Output), "nothing to change") || len(f.downtimes) != 1 {
		t.Fatalf("%s %v", again.Output, err)
	}
	if r, err := invoke(m, "downtimes", `{"host":"web1"}`, false); err != nil || !strings.Contains(string(r.Output), `"comment":"rack move"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	m.now = func() time.Time { return now.Add(30 * time.Minute) }
	if r, err := invoke(m, "end_downtime", string(r.Undo.Input), true); err != nil || r.Plan == nil || len(f.downtimes) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "end_downtime", string(r.Undo.Input), false)
	if err != nil || len(f.downtimes) != 0 || r.Undo == nil || r.Undo.Action != "schedule_downtime" || !strings.Contains(string(r.Undo.Input), `"durationMinutes":60`) {
		t.Fatalf("%+v %v", r, err)
	}
	if again, err := invoke(m, "end_downtime", `{"id":"1","site":"mysite"}`, false); err != nil || !strings.Contains(string(again.Output), "nothing to change") {
		t.Fatalf("%s %v", again.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.downtimes) != 1 {
		t.Fatal(err)
	}
	// A service downtime.
	if r, err := invoke(m, "schedule_downtime", `{"host":"db1","service":"CPU load","comment":"tuning"}`, false); err != nil || r.Undo == nil || f.downtimes[1].service != "CPU load" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "acknowledge" || a.Name == "schedule_downtime") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s must be destructive", a.Name)
		}
	}
}

func TestCheckmkValidation(t *testing.T) {
	m, f := setup(t, "secret://cmk")
	for _, c := range []struct{ action, in string }{
		{"services", `{}`},
		{"services", `{"host":"../../version"}`},
		{"services", `{"host":"a b"}`},
		{"downtimes", `{"host":"x\"y"}`},
		{"acknowledge", `{"host":"web1"}`},
		{"acknowledge", `{"host":"web1","service":"a\u0000b","comment":"x"}`},
		{"schedule_downtime", `{"host":"web1","comment":"x","durationMinutes":50000}`},
		{"schedule_downtime", `{"host":"web1","comment":"` + strings.Repeat("a", 1001) + `"}`},
		{"end_downtime", `{"id":"1"}`},
		{"end_downtime", `{"id":"1 or 1","site":"mysite"}`},
		{"end_downtime", `{"id":"1","site":"../x"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://cmk.example.com/mysite", Username: "automation", Secret: "plain"},
		{URL: "https://cmk.example.com/mysite", Secret: "secret://cmk"},
		{URL: "https://cmk.example.com/", Username: "automation", Secret: "secret://cmk"},
		{URL: "https://u:p@cmk.example.com/mysite", Username: "automation", Secret: "secret://cmk"},
		{URL: "https://cmk.example.com/mysite?x=1", Username: "automation", Secret: "secret://cmk"},
		{URL: "cmk.example.com/mysite", Username: "automation", Secret: "secret://cmk"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || h.Message != "Checkmk refused the automation user or secret" {
		t.Fatalf("%+v", h)
	}
}

func TestCheckmkRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/mysite", Username: "automation", Secret: "secret://cmk"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cmk": "s"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// The undo of schedule_downtime must end the downtime this call made, never
// one that was there before (someone else's, with the same comment and end).
func TestCheckmkDowntimeUndoSkipsOthers(t *testing.T) {
	m, f := setup(t, "secret://cmk")
	end := now.Add(90 * time.Minute).Format("2006-01-02T15:04:05+00:00")
	// Starts a minute from now, so it doesn't cover the new one: one is
	// made, and its id is lower than the old one's.
	f.downtimes = []dt{{id: "99", host: "web1", comment: "rack move", start: now.Add(time.Minute).Format("2006-01-02T15:04:05+00:00"), end: end}}
	r, err := invoke(m, "schedule_downtime", `{"host":"web1","durationMinutes":90,"comment":"rack move"}`, false)
	if err != nil || len(f.downtimes) != 2 || r.Undo == nil || string(r.Undo.Input) != `{"id":"1","site":"mysite"}` {
		t.Fatalf("%+v %v", r, err)
	}
	// Two new ones fit (someone made the same at the same moment): which
	// is ours can't be told, so there's no undo.
	m, f = setup(t, "secret://cmk")
	f.twin = true
	r, err = invoke(m, "schedule_downtime", `{"host":"web1","durationMinutes":90,"comment":"rack move"}`, false)
	if err != nil || len(f.downtimes) != 2 || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
}

// Ending a downtime that hasn't started has no undo: scheduling it again
// would start it now.
func TestCheckmkFutureDowntimeNoUndo(t *testing.T) {
	m, f := setup(t, "secret://cmk")
	f.downtimes = []dt{{id: "7", host: "web1", comment: "next week", start: now.Add(48 * time.Hour).Format("2006-01-02T15:04:05+00:00"), end: now.Add(50 * time.Hour).Format("2006-01-02T15:04:05+00:00")}}
	r, err := invoke(m, "end_downtime", `{"id":"7","site":"mysite"}`, false)
	if err != nil || len(f.downtimes) != 0 || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
}
