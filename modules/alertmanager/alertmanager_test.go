package alertmanager

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

type fakeAM struct {
	mu       sync.Mutex
	seen     []string
	silences map[string]map[string]any
	n        int
}

func (f *fakeAM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "conduit" || p != "am-good-pass" {
		w.WriteHeader(401)
		io.WriteString(w, "Unauthorized")
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v2/status":
		io.WriteString(w, `{"cluster":{"status":"ready","name":"01ABC","peers":[{"name":"01ABC","address":"10.0.0.1:9094"}]},"versionInfo":{"version":"0.27.0"},"uptime":"2026-11-01T00:00:00Z",
			"config":{"original":"receivers:\n- name: mail\n  email_configs:\n  - auth_password: LEAKME\n"}}`)
	case r.Method == "GET" && r.URL.Path == "/api/v2/receivers":
		io.WriteString(w, `[{"name":"pager"},{"name":"mail"}]`)
	case r.Method == "GET" && r.URL.Path == "/api/v2/alerts":
		io.WriteString(w, `[{"labels":{"alertname":"DiskFull","severity":"critical","instance":"web-1"},"annotations":{"summary":"disk 95% full"},"startsAt":"2026-11-04T10:00:00Z",
			"generatorURL":"http://admin:LEAKME@prometheus:9090/graph?g0.expr=x","fingerprint":"abc123","receivers":[{"name":"pager"}],"status":{"state":"active","silencedBy":[],"inhibitedBy":[]}},
			{"labels":{"alertname":"Watchdog"},"annotations":{},"startsAt":"2026-11-04T11:00:00Z","fingerprint":"def456","receivers":[{"name":"mail"}],"status":{"state":"active"}}]`)
	case r.Method == "GET" && r.URL.Path == "/api/v2/silences":
		out := []map[string]any{}
		for _, s := range f.silences {
			out = append(out, s)
		}
		json.NewEncoder(w).Encode(out)
	case r.Method == "POST" && r.URL.Path == "/api/v2/silences":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.n++
		id := fmt.Sprintf("0000000%d-aaaa-bbbb-cccc-dddddddddddd", f.n)
		b["id"] = id
		b["status"] = map[string]any{"state": "active"}
		f.silences[id] = b
		fmt.Fprintf(w, `{"silenceID":%q}`, id)
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v2/silence/"):
		s, ok := f.silences[strings.TrimPrefix(r.URL.Path, "/api/v2/silence/")]
		if !ok {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(s)
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/api/v2/silence/"):
		s := f.silences[strings.TrimPrefix(r.URL.Path, "/api/v2/silence/")]
		s["status"] = map[string]any{"state": "expired"}
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, pass string) (*Module, *fakeAM) {
	f := &fakeAM{silences: map[string]map[string]any{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.now = func() time.Time { return now }
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "conduit", Password: pass})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://am": "am-good-pass", "secret://bad": "nope"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestAlertmanager(t *testing.T) {
	m, f := setup(t, "secret://am")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "Alertmanager 0.27.0 · cluster ready, 1 peers" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"status", `{}`, `"version":"0.27.0"`},
		{"receivers", `{}`, `["mail","pager"]`},
		{"alerts", `{}`, `"summary":"disk 95% full"`},
		{"alerts", `{}`, `"link":"http://prometheus:9090/graph?g0.expr=x"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "am-good-pass") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	// Newest first; the label filter is quoted.
	r, _ := invoke(m, "alerts", `{"labels":{"severity":"crit\"ical"}}`, false)
	if !strings.Contains(string(r.Output), `"alerts":[{"fingerprint":"def456"`) || !strings.Contains(f.seen[len(f.seen)-1], "filter=severity%3D%22crit%5C%22ical%22") {
		t.Fatalf("%s %s", r.Output, f.seen[len(f.seen)-1])
	}

	// Create: preview, real, nothing to change, undo.
	in := `{"matchers":[{"name":"alertname","value":"DiskFull"}],"durationMinutes":60,"comment":"replacing the disk"}`
	r, err := invoke(m, "create_silence", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, `alertname="DiskFull" for 1h0m0s`) || len(f.silences) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_silence", in, false)
	if err != nil || len(f.silences) != 1 || r.Undo == nil || r.Undo.Action != "expire_silence" {
		t.Fatalf("%+v %v", r, err)
	}
	id := strings.TrimSuffix(strings.TrimPrefix(string(r.Undo.Input), `{"id":"`), `"}`)
	if again, err := invoke(m, "create_silence", in, false); err != nil || !strings.Contains(string(again.Output), "nothing to change") || len(f.silences) != 1 || again.Undo != nil {
		t.Fatalf("%s %v", again.Output, err)
	}
	if r, err := invoke(m, "silences", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"matchers":"alertname=\"DiskFull\""`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	// Expire: the undo recreates it for the time left.
	m.now = func() time.Time { return now.Add(30 * time.Minute) }
	r, err = invoke(m, "expire_silence", `{"id":"`+id+`"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "create_silence" || !strings.Contains(string(r.Undo.Input), `"durationMinutes":30`) {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "expire_silence", `{"id":"`+id+`"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "create_silence", string(r.Undo.Input), false); err != nil || len(f.silences) != 2 {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "create_silence" && a.Risk != sdk.RiskDestructive {
			t.Fatal("create_silence must be destructive")
		}
	}
}

func TestAlertmanagerValidation(t *testing.T) {
	m, f := setup(t, "secret://am")
	for _, c := range []struct{ action, in string }{
		{"create_silence", `{"comment":"x"}`},
		{"create_silence", `{"matchers":[{"name":"alertname","value":"x"}]}`},
		{"create_silence", `{"matchers":[{"name":"bad name","value":"x"}],"comment":"x"}`},
		{"create_silence", `{"matchers":[{"name":"a","value":"(","isRegex":true}],"comment":"x"}`},
		{"create_silence", `{"matchers":[{"name":"a","value":"x","isEqual":false}],"comment":"x"}`},
		{"create_silence", `{"matchers":[{"name":"a","value":"x"}],"comment":"x","durationMinutes":50000}`},
		{"expire_silence", `{"id":"../status"}`},
		{"expire_silence", `{}`},
		{"alerts", `{"labels":{"a b":"x"}}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "http://am:9093", Token: "plain-token"},
		{URL: "http://am:9093", Username: "u", Password: "plain"},
		{URL: "http://am:9093", Username: "u"},
		{URL: "http://am:9093", Token: "secret://t", Username: "u", Password: "secret://p"},
		{URL: "am:9093"},
		{URL: "http://u:p@am:9093"},
		{URL: "http://am:9093/?x=1"},
		{URL: "http://am:9093/#x"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	// No auth at all is fine (Alertmanager's default).
	raw, _ := json.Marshal(Config{URL: "http://am:9093"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
		t.Fatal(err)
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || h.Message != "Alertmanager refused the credentials" || strings.Contains(h.Message, "nope") {
		t.Fatalf("%+v", h)
	}
}

func TestAlertmanagerRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://t"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "tok"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
