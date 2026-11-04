package uptimerobot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fake struct {
	mu       sync.Mutex
	seen     []string
	monitors map[int64]map[string]any
	nextID   int64
	readOnly bool
}

func newFake() *fake {
	return &fake{nextID: 900, monitors: map[int64]map[string]any{
		101: {"id": 101, "friendly_name": "Blog", "url": "https://user:pw@blog.example.com/health?token=abc", "type": 1, "interval": 300, "status": 2, "create_datetime": 1700000000, "custom_uptime_ratio": "100.000-99.950-99.120",
			"logs": []any{map[string]any{"type": 2, "datetime": 1762000600, "duration": 100}, map[string]any{"type": 1, "datetime": 1762000000, "duration": 600, "reason": map[string]any{"code": "503", "detail": "Service Unavailable"}}}},
		102: {"id": 102, "friendly_name": "API", "url": "https://api.example.com", "type": 2, "interval": 60, "status": 9, "custom_uptime_ratio": "90.000-98.000-99.000",
			"logs": []any{map[string]any{"type": 1, "datetime": 1762100000, "duration": 120, "reason": map[string]any{"code": 333333, "detail": "Connection Timeout"}}}},
		103: {"id": 103, "friendly_name": "Cron", "url": "https://heartbeat.uptimerobot.com/m103-secretpushtoken", "type": 5, "interval": 300, "status": 0},
	}}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	enc := json.NewEncoder(w)
	if form.Get("api_key") != "urkey" && form.Get("api_key") != "rokey" {
		enc.Encode(map[string]any{"stat": "fail", "error": map[string]any{"type": "invalid_parameter", "parameter_name": "api_key", "passed_value": form.Get("api_key"), "message": "api_key is invalid."}})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	form.Del("api_key")
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+form.Encode())
	method := strings.TrimPrefix(r.URL.Path, "/")
	if method != "getMonitors" && method != "getAccountDetails" && form.Get("api_key") == "" && f.readOnly {
		enc.Encode(map[string]any{"stat": "fail", "error": map[string]any{"type": "not_authorized", "message": "The API key is read-only."}})
		return
	}
	switch method {
	case "getAccountDetails":
		io.WriteString(w, `{"stat":"ok","account":{"email":"private@example.com","up_monitors":1,"down_monitors":1,"paused_monitors":1}}`)
	case "getMonitors":
		var list []any
		for id := int64(100); id <= f.nextID; id++ {
			mo, ok := f.monitors[id]
			if !ok {
				continue
			}
			if want := form.Get("monitors"); want != "" && want != fmt.Sprint(id) {
				continue
			}
			if st := form.Get("statuses"); st != "" && !strings.Contains("-"+st+"-", fmt.Sprintf("-%d-", mo["status"])) {
				continue
			}
			cp := map[string]any{}
			for k, v := range mo {
				if k != "logs" || form.Get("logs") == "1" {
					cp[k] = v
				}
			}
			list = append(list, cp)
		}
		enc.Encode(map[string]any{"stat": "ok", "pagination": map[string]any{"offset": 0, "limit": 50, "total": len(list)}, "monitors": list})
	case "editMonitor":
		var id int64
		fmt.Sscan(form.Get("id"), &id)
		mo := f.monitors[id]
		if mo == nil {
			io.WriteString(w, `{"stat":"fail","error":{"type":"not_found","message":"Monitor not found."}}`)
			return
		}
		if form.Get("status") == "0" {
			mo["status"] = 0
		} else {
			mo["status"] = 1
		}
		fmt.Fprintf(w, `{"stat":"ok","monitor":{"id":%d}}`, id)
	case "newMonitor":
		f.nextID++
		f.monitors[f.nextID] = map[string]any{"id": f.nextID, "friendly_name": form.Get("friendly_name"), "url": form.Get("url"), "type": 1, "interval": json.Number(form.Get("interval")), "status": 1}
		fmt.Fprintf(w, `{"stat":"ok","monitor":{"id":%d,"status":1}}`, f.nextID)
	case "deleteMonitor":
		var id int64
		fmt.Sscan(form.Get("id"), &id)
		delete(f.monitors, id)
		fmt.Fprintf(w, `{"stat":"ok","monitor":{"id":%d}}`, id)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, key string) (*Module, *fake) {
	t.Helper()
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ur": "urkey", "secret://bad": "badkey-should-not-leak"}), "u", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "u", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestUptimeRobotReads(t *testing.T) {
	m, _ := setup(t, "secret://ur")
	if h := m.Health(context.Background(), "u"); h.Status != "degraded" || h.Message != "1 up · 1 down · 1 paused" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"monitors", `{}`, `"uptime":{"1d":100,"30d":99.12,"7d":99.95}`},
		{"monitors", `{"status":"down"}`, `"status":"down"`},
		{"monitor", `{"id":101}`, `"reason":"503 Service Unavailable"`},
		{"recent_downs", `{}`, `"ongoing":true`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		for _, leak := range []string{"pw@", "token=abc", "secretpushtoken", "private@"} {
			if strings.Contains(out, leak) {
				t.Fatalf("%s leaked %s: %s", c.action, leak, out)
			}
		}
	}
	r, _ := invoke(m, "monitors", `{"status":"down"}`, false)
	if strings.Contains(string(r.Output), "Blog") {
		t.Fatalf("status filter ignored: %s", r.Output)
	}
	r, _ = invoke(m, "recent_downs", `{"limit":5}`, false)
	var d struct{ Downs []map[string]any }
	json.Unmarshal(r.Output, &d)
	if len(d.Downs) != 2 || d.Downs[0]["monitor"] != float64(102) || d.Downs[1]["ongoing"] != nil {
		t.Fatalf("%s", r.Output)
	}
}

func TestUptimeRobotWrites(t *testing.T) {
	m, f := setup(t, "secret://ur")

	// Pause with a preview, then undo resumes.
	r, err := invoke(m, "pause_monitor", `{"id":101}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Pause monitor Blog") || f.monitors[101]["status"] != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "pause_monitor", `{"id":101}`, false)
	if err != nil || f.monitors[101]["status"] != 0 || r.Undo == nil || r.Undo.Action != "resume_monitor" || string(r.Undo.Input) != `{"id":101}` {
		t.Fatalf("%+v %v", r, err)
	}
	if again, err := invoke(m, "pause_monitor", `{"id":101}`, false); err != nil || again.Undo != nil || !strings.Contains(string(again.Output), "already paused") {
		t.Fatalf("%+v %v", again, err)
	}
	if u, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.monitors[101]["status"] != 1 || u.Undo.Action != "pause_monitor" {
		t.Fatalf("%+v %v", u, err)
	}

	// Create with a preview, then undo deletes it.
	in := `{"name":"Shop","url":"https://shop.example.com/?k=v","interval":120}`
	if r, err := invoke(m, "create_monitor", in, true); err != nil || r.Plan == nil || len(f.monitors) != 3 || strings.Contains(r.Plan.Summary, "k=v") {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "create_monitor", in, false)
	if err != nil || f.monitors[901] == nil || f.monitors[901]["url"] != "https://shop.example.com/?k=v" || r.Undo == nil || r.Undo.Action != "delete_monitor" {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], "interval=120") || !strings.Contains(f.seen[len(f.seen)-1], "type=1") {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.monitors[901] != nil {
		t.Fatal(err)
	}

	// Delete previews what goes, then deletes.
	if r, err := invoke(m, "delete_monitor", `{"id":102}`, true); err != nil || r.Plan == nil || f.monitors[102] == nil || r.Plan.Changes[0].Op != "delete" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "delete_monitor", `{"id":102}`, false); err != nil || f.monitors[102] != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_monitor", `{"id":555}`, false); err == nil || !strings.Contains(err.Error(), "no monitor 555") {
		t.Fatal(err)
	}

	risks := map[string]sdk.Risk{}
	for _, a := range m.Manifest().Actions {
		risks[a.Name] = a.Risk
		if a.Risk != sdk.RiskRead && !a.DryRun {
			t.Fatalf("%s has no preview", a.Name)
		}
	}
	if risks["delete_monitor"] != sdk.RiskDestructive || risks["pause_monitor"] != sdk.RiskWrite || risks["create_monitor"] != sdk.RiskWrite {
		t.Fatalf("%v", risks)
	}
}

func TestUptimeRobotValidation(t *testing.T) {
	m, f := setup(t, "secret://ur")
	for _, c := range []struct{ action, in string }{
		{"monitor", `{}`},
		{"monitor", `{"id":-1}`},
		{"monitor", `{"id":"101-102"}`},
		{"monitors", `{"status":"all"}`},
		{"monitors", `{"search":"` + strings.Repeat("x", 101) + `"}`},
		{"recent_downs", `{"limit":1000}`},
		{"pause_monitor", `{"id":0}`},
		{"create_monitor", `{"name":"x","url":"ftp://example.com"}`},
		{"create_monitor", `{"name":"x","url":"https://u:p@example.com"}`},
		{"create_monitor", `{"name":"","url":"https://example.com"}`},
		{"create_monitor", `{"name":"x\ny","url":"https://example.com"}`},
		{"create_monitor", `{"name":"x","url":"https://example.com","interval":5}`},
		{"delete_monitor", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	raw, _ := json.Marshal(Config{APIKey: "u1234567-plainkey"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
		t.Fatal("accepted a plain key")
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "u")
	if h.Status != "down" || h.Message != "UptimeRobot refused the API key" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "monitors", `{}`, false); err == nil || strings.Contains(err.Error(), "should-not-leak") {
		t.Fatal(err)
	}
}

func TestUptimeRobotReadOnlyKey(t *testing.T) {
	m, f := setup(t, "secret://ur")
	f.readOnly = true
	if _, err := invoke(m, "pause_monitor", `{"id":101}`, false); err == nil || !strings.Contains(err.Error(), "may only read") {
		t.Fatal(err)
	}
}

func TestUptimeRobotRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: "secret://ur"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ur": "urkey"}), "u", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "u"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// Addresses come out cut to scheme://host and the first path segment, and
// the search never reaches UptimeRobot (whose search matches whole URLs, an
// oracle for a token in one).
func TestUptimeRobotShownURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://hooks.example.com/AbC123def456ghi789/x":    "https://hooks.example.com/…/…",
		"https://user:pw@blog.example.com/health?token=abc": "https://blog.example.com/health?…",
	} {
		if got := shownURL(monitor{URL: in, Type: 1}); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
	if shownURL(monitor{URL: "https://heartbeat.uptimerobot.com/m1-x", Type: 5}) != "" {
		t.Error("a heartbeat's push address came out")
	}
	m, f := setup(t, "secret://ur")
	for search, want := range map[string]string{"blog": "Blog", "token=a": "", "secretpush": "", "api.example": "API"} {
		r, err := invoke(m, "monitors", `{"search":"`+search+`"}`, false)
		if err != nil {
			t.Fatal(err)
		}
		if want == "" && strings.Contains(string(r.Output), `"name"`) || want != "" && !strings.Contains(string(r.Output), `"name":"`+want+`"`) {
			t.Errorf("%s: %s", search, r.Output)
		}
	}
	for _, s := range f.seen {
		if strings.Contains(s, "search") {
			t.Fatalf("the search went to UptimeRobot: %s", s)
		}
	}
}
