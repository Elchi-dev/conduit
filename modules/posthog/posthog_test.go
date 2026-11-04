package posthog

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fake struct {
	mu      sync.Mutex
	seen    []string
	patches []string
	queries []map[string]any
	flags   map[string]map[string]any
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer phx_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"type":"authentication_error","code":"authentication_failed","detail":"Personal API key found in request Authorization header is invalid."}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	enc := json.NewEncoder(w)
	path := strings.TrimPrefix(r.URL.Path, "/api")
	switch {
	case r.Method == "GET" && path == "/projects/":
		enc.Encode(map[string]any{"results": []any{map[string]any{"id": 2, "name": "Web", "timezone": "UTC"}}})
	case r.Method == "GET" && path == "/projects/2/insights/":
		enc.Encode(map[string]any{"results": []any{map[string]any{"id": 11, "short_id": "AbC1", "name": "", "derived_name": "Pageview count", "favorited": true}}})
	case r.Method == "POST" && path == "/projects/2/query/":
		var in struct {
			Query map[string]any `json:"query"`
		}
		json.Unmarshal(body, &in)
		f.queries = append(f.queries, in.Query)
		q := in.Query["query"].(string)
		switch {
		case strings.Contains(q, "toDate(timestamp)"):
			enc.Encode(map[string]any{"results": [][]any{{"2026-11-03", 120, 40}, {"2026-11-04", 80, 30}}})
		case strings.Contains(q, "$exception"):
			enc.Encode(map[string]any{"results": [][]any{{"TypeError", "x is undefined for token=abcdef1234567890", 12, 3, "2026-11-04T08:00:00Z"}}})
		default:
			enc.Encode(map[string]any{"results": [][]any{{"$pageview", 200, 70}, {"signup", 5, 5}}})
		}
	case r.Method == "GET" && path == "/projects/2/feature_flags/":
		var list []any
		for _, id := range []string{"21", "22"} {
			list = append(list, f.flags[id])
		}
		enc.Encode(map[string]any{"results": list, "next": nil})
	case strings.HasPrefix(path, "/projects/2/feature_flags/"):
		parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "/projects/2/feature_flags/"), "/"), "/")
		fl := f.flags[parts[0]]
		if fl == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"detail":"Not found."}`)
			return
		}
		switch {
		case r.Method == "GET" && len(parts) == 2 && parts[1] == "status":
			enc.Encode(map[string]any{"status": "ACTIVE", "reason": "Flag was evaluated recently"})
		case r.Method == "GET" && len(parts) == 1:
			enc.Encode(fl)
		case r.Method == "PATCH" && len(parts) == 1:
			f.patches = append(f.patches, string(body))
			var in map[string]any
			json.Unmarshal(body, &in)
			for k, v := range in {
				fl[k] = v
			}
			enc.Encode(fl)
		default:
			w.WriteHeader(405)
		}
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not found."}`)
	}
}

func newFake() *fake {
	return &fake{flags: map[string]map[string]any{
		"21": {"id": 21, "key": "new-checkout", "name": "New checkout", "active": true, "filters": map[string]any{
			"groups": []any{map[string]any{"properties": []any{}, "rollout_percentage": 20}}, "payloads": map[string]any{}}},
		"22": {"id": 22, "key": "beta", "name": "Beta", "active": false, "filters": map[string]any{
			"groups": []any{map[string]any{"properties": []any{map[string]any{"key": "email"}}, "rollout_percentage": nil}, map[string]any{"properties": []any{}, "rollout_percentage": 5}}}},
	}}
}

func setup(t *testing.T, key string) (*Module, *fake) {
	t.Helper()
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(map[string]any{"host": srv.URL, "apiKey": key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ph": "phx_good", "secret://bad": "phx_nope"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestPostHogReads(t *testing.T) {
	m, f := setup(t, "secret://ph")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "1 projects" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"name":"Web"`},
		{"insights", `{}`, `"name":"Pageview count"`},
		{"trends", `{}`, `"total":200`},
		{"trends", `{"event":"signup' OR 1=1 --","days":30,"project":2}`, `"event":"signup' OR 1=1 --"`},
		{"events", `{"days":3}`, `{"event":"signup","events":5,"users":5}`},
		{"errors", `{}`, `"occurrences":12`},
		{"flags", `{}`, `"on":1`},
		{"flag", `{"flag":"new-checkout"}`, `"rollout":20`},
		{"flag", `{"flag":22}`, `"status":"active"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	// The event goes as a placeholder value, never into the query text.
	q := f.queries[1]
	if strings.Contains(q["query"].(string), "signup") || q["values"].(map[string]any)["event"] != "signup' OR 1=1 --" || !strings.Contains(q["query"].(string), "INTERVAL 30 DAY") {
		t.Fatalf("%+v", q)
	}
	r, _ := invoke(m, "errors", `{}`, false)
	if strings.Contains(string(r.Output), "abcdef1234567890") {
		t.Fatalf("exception message not redacted: %s", r.Output)
	}
	spec := map[string]sdk.ActionSpec{}
	for _, a := range m.Manifest().Actions {
		spec[a.Name] = a
	}
	if spec["set_flag"].Risk != sdk.RiskDestructive || !spec["set_flag"].DryRun || !spec["errors"].Sensitive || spec["flags"].Risk != sdk.RiskRead {
		t.Fatalf("%+v", spec)
	}
}

func TestPostHogSetFlag(t *testing.T) {
	m, f := setup(t, "secret://ph")
	r, err := invoke(m, "set_flag", `{"flag":"new-checkout","rollout":50}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "from 20% to 50%") || len(f.patches) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if string(r.Plan.Changes[0].Before) != `{"active":true,"group":1,"rollout":20}` || string(r.Plan.Changes[0].After) != `{"active":true,"group":1,"rollout":50}` {
		t.Fatalf("%s %s", r.Plan.Changes[0].Before, r.Plan.Changes[0].After)
	}
	r, err = invoke(m, "set_flag", `{"flag":"new-checkout","rollout":50,"active":false}`, false)
	if err != nil || r.Undo == nil || len(f.patches) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	var sent map[string]any
	json.Unmarshal([]byte(f.patches[0]), &sent)
	g := sent["filters"].(map[string]any)["groups"].([]any)[0].(map[string]any)
	if sent["active"] != false || g["rollout_percentage"] != float64(50) || sent["filters"].(map[string]any)["payloads"] == nil {
		t.Fatalf("%s", f.patches[0])
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	fl := f.flags["21"]
	if fl["active"] != true || fl["filters"].(map[string]any)["groups"].([]any)[0].(map[string]any)["rollout_percentage"] != float64(20) {
		t.Fatalf("undo: %+v", fl)
	}
	// Several release conditions need a group.
	if _, err := invoke(m, "set_flag", `{"flag":"beta","rollout":10}`, true); err == nil || !strings.Contains(err.Error(), "group") {
		t.Fatal(err)
	}
	if r, err := invoke(m, "set_flag", `{"flag":"beta","rollout":10,"group":2}`, true); err != nil || !strings.Contains(r.Plan.Summary, "from 5% to 10%") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "set_flag", `{"flag":"beta","rollout":10,"group":3}`, false); err == nil {
		t.Fatal("accepted a group that doesn't exist")
	}
	if r, err := invoke(m, "set_flag", `{"flag":"beta","active":false}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "already") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "set_flag", `{"flag":"nope","active":true}`, false); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestPostHogValidation(t *testing.T) {
	m, f := setup(t, "secret://ph")
	for _, c := range []struct{ action, in string }{
		{"flag", `{"flag":"../insights"}`},
		{"flag", `{"flag":"a b"}`},
		{"flag", `{}`},
		{"flag", `{"flag":"x","project":"2/../3"}`},
		{"trends", `{"days":91}`},
		{"trends", `{"event":"a\nb"}`},
		{"trends", `{"event":"` + strings.Repeat("x", 201) + `"}`},
		{"events", `{"limit":1000}`},
		{"errors", `{"days":31}`},
		{"insights", `{"limit":-1}`},
		{"set_flag", `{"flag":"new-checkout"}`},
		{"set_flag", `{"flag":"new-checkout","rollout":101}`},
		{"set_flag", `{"flag":"new-checkout","rollout":-1}`},
		{"set_flag", `{"flag":"new-checkout","active":true,"group":1}`},
		{"set_flag", `{"flag":"new-checkout","rollout":5,"group":0}`},
		{"set_flag", `{"flag":"new-checkout","active":"yes"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []map[string]any{
		{"host": "us", "apiKey": "phx_plain"},
		{"host": "mars", "apiKey": "secret://ph"},
		{"host": "https://us.i.posthog.com", "apiKey": "secret://ph"},
		{"host": "https://u:p@posthog.example.com", "apiKey": "secret://ph"},
		{"host": "eu", "apiKey": "secret://ph", "project": "web"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for _, h := range []string{"us", "EU", ""} {
		raw, _ := json.Marshal(map[string]any{"host": h, "apiKey": "secret://ph", "project": 2})
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
			t.Fatalf("%q: %v", h, err)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || h.Message != "PostHog refused the personal API key" {
		t.Fatalf("%+v", h)
	}
}

func TestPostHogRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(map[string]any{"host": srv.URL, "apiKey": "secret://ph"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ph": "phx_good"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
