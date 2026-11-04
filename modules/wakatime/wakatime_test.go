package wakatime

import (
	"context"
	"encoding/base64"
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

const goodKey = "waka_0123456789abcdef"

type fakeWaka struct {
	mu     sync.Mutex
	prefix string
	seen   []string
}

func (f *fakeWaka) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(goodKey)) {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Unauthorized"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	q := r.URL.Query()
	switch r.URL.Path {
	case f.prefix + "/users/current":
		io.WriteString(w, `{"data":{"id":"u1","username":"ada","email":"LEAKME@example.com"}}`)
	case f.prefix + "/users/current/summaries":
		if q.Get("start") != "2026-10-29" || q.Get("end") != "2026-11-04" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"bad range"}`)
			return
		}
		io.WriteString(w, `{"data":[{"grand_total":{"total_seconds":7260.5,"text":"2 hrs 1 min"},"range":{"date":"2026-11-04"},"projects":[{"name":"conduit","total_seconds":7000,"percent":96.4,"text":"1 hr 56 mins"}],"languages":[{"name":"Go","total_seconds":6000,"text":"1 hr 40 mins"}]}],"cumulative_total":{"seconds":7260.5,"text":"2 hrs 1 min"}}`)
	case f.prefix + "/users/current/stats/last_30_days":
		io.WriteString(w, `{"data":{"total_seconds":36000,"human_readable_total":"10 hrs","daily_average":1200,"human_readable_daily_average":"20 mins","languages":[{"name":"Go","total_seconds":30000,"percent":83.3,"text":"8 hrs 20 mins"}],"projects":[],"editors":[{"name":"VS Code","total_seconds":36000,"percent":100,"text":"10 hrs"}],"operating_systems":[],"best_day":{"date":"2026-11-03","text":"4 hrs","total_seconds":14400},"is_up_to_date":false}}`)
	case f.prefix + "/users/current/projects":
		io.WriteString(w, `{"data":[{"id":"p1","name":"conduit","last_heartbeat_at":"2026-11-04T09:00:00Z","repository":{"url":"https://LEAKME"}},{"id":"p2","name":"dotfiles"}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Not found"}`)
	}
}

func setup(t *testing.T, key, prefix, url string) (*Module, *fakeWaka) {
	f := &fakeWaka{prefix: prefix}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC) }
	if url == "" {
		m.Base = srv.URL + "/api/v1" // the WakaTime default, pointed at the fake
	} else {
		url = srv.URL + url
	}
	raw, _ := json.Marshal(Config{URL: url, Key: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://w": goodKey, "secret://bad": "nope"}), "w", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "w", Action: action, Input: json.RawMessage(in)})
}

func TestWakaTime(t *testing.T) {
	m, _ := setup(t, "secret://w", "/api/v1", "")
	if h := m.Health(context.Background(), "w"); h.Status != "ok" || h.Message != "signed in as ada" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"summaries", `{}`, `"seconds":7260,"time":"2 hrs 1 min"`},
		{"summaries", `{"start":"2026-10-29","end":"2026-11-04"}`, `"projects":[{"name":"conduit","percent":96.4`},
		{"stats", `{"range":"last_30_days"}`, `"bestDay":{"date":"2026-11-03"`},
		{"stats", `{"range":"last_30_days"}`, `"note":"WakaTime is still calculating`},
		{"projects", `{}`, `"lastActive":"2026-11-04T09:00:00Z"`},
		{"projects", `{"query":"DOT"}`, `[{"name":"dotfiles"}]`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, goodKey) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestWakapi(t *testing.T) {
	// A bare Wakapi address uses its WakaTime-compatible API.
	m, f := setup(t, "secret://w", "/api/compat/wakatime/v1", "/")
	if h := m.Health(context.Background(), "w"); h.Status != "ok" {
		t.Fatalf("%+v %v", h, f.seen)
	}
}

func TestWakaTimeValidation(t *testing.T) {
	m, f := setup(t, "secret://w", "/api/v1", "")
	for _, c := range []struct{ action, in string }{
		{"summaries", `{"start":"yesterday"}`},
		{"summaries", `{"end":"2026-02-30"}`},
		{"summaries", `{"start":"2026-11-05","end":"2026-11-04"}`},
		{"summaries", `{"start":"2020-01-01","end":"2026-11-04"}`},
		{"summaries", `{"project":"` + strings.Repeat("p", 201) + `"}`},
		{"stats", `{"range":"../../users"}`},
		{"stats", `{"range":"last_7_days?x=1"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Key: "waka_plain"}, {URL: "wakapi.example.com", Key: "secret://w"}, {URL: "https://u:p@wakapi.example.com", Key: "secret://w"}, {URL: "https://wakapi.example.com/#x", Key: "secret://w"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", "/api/v1", "")
	if h := bad.Health(context.Background(), "w"); h.Status != "down" || h.Message != "the server refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestWakaTimeRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "hit" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api/v1", Key: "secret://w"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://w": goodKey}), "w", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "w"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
