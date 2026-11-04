package growthbook

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

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeGB struct {
	mu      sync.Mutex
	seen    []string
	toggles []string
	on      bool // new-checkout in production
	ignore  bool
}

func (f *fakeGB) feature(id string) string {
	return fmt.Sprintf(`{"id":%q,"description":"New checkout","archived":false,"valueType":"boolean","defaultValue":"LEAKME-default","owner":"leakme@example.com","project":"prj_web","tags":["web"],"dateUpdated":"2026-11-04T10:00:00Z",
		"environments":{"dev":{"enabled":true,"rules":[]},"production":{"enabled":%t,"defaultValue":"LEAKME","rules":[
			{"id":"fr_1","type":"force","condition":"{\"email\":\"leakme@example.com\"}","value":"true","enabled":true},
			{"id":"fr_2","type":"rollout","coverage":0.25,"value":"LEAKME","enabled":true},
			{"id":"fr_3","type":"experiment-ref","enabled":false}]}}}`, id, f.on)
}

func (f *fakeGB) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer secret_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Invalid API key"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	switch r.Method + " " + r.URL.Path {
	case "GET /gb/api/v1/features":
		if r.URL.Query().Get("offset") == "1" {
			fmt.Fprintf(w, `{"features":[%s],"limit":100,"offset":1,"count":1,"total":2,"hasMore":false}`, f.feature("dark-mode"))
			return
		}
		fmt.Fprintf(w, `{"features":[%s],"limit":100,"offset":0,"count":1,"total":2,"hasMore":true,"nextOffset":1}`, f.feature("new-checkout"))
	case "GET /gb/api/v1/features/new-checkout":
		fmt.Fprintf(w, `{"feature":%s}`, f.feature("new-checkout"))
	case "GET /gb/api/v1/features/other":
		fmt.Fprintf(w, `{"feature":%s}`, f.feature("new-checkout")) // answers with another feature
	case "POST /gb/api/v1/features/new-checkout/toggle":
		f.toggles = append(f.toggles, string(body))
		var in struct {
			Environments map[string]bool `json:"environments"`
		}
		json.Unmarshal(body, &in)
		if v, ok := in.Environments["production"]; ok && !f.ignore {
			f.on = v
		}
		fmt.Fprintf(w, `{"feature":%s}`, f.feature("new-checkout"))
	case "GET /gb/api/v1/experiments":
		io.WriteString(w, `{"experiments":[{"id":"exp_1","trackingKey":"checkout-test","name":"Checkout test","type":"standard","project":"prj_web","hypothesis":"Faster wins","owner":"leakme@example.com","archived":false,"status":"running",
			"variations":[{"variationId":"v0","key":"0","name":"Control"},{"variationId":"v1","key":"1","name":"Fast"}],
			"phases":[{"name":"Main","dateStarted":"2026-11-01T00:00:00Z","coverage":0.5,"trafficSplit":[{"variationId":"v0","weight":0.5}],"targetingCondition":"{\"email\":\"leakme@example.com\"}"}],
			"resultSummary":{"status":"won","winner":"v1","conclusions":"","releasedVariationId":"v1"}}],"limit":100,"offset":0,"count":1,"total":1,"hasMore":false}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Could not find feature"}`)
	}
}

func setup(t *testing.T, key string) (*Module, *fakeGB) {
	f := &fakeGB{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/gb/api/v1", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://gb": "secret_good", "secret://bad": "secret_bad"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestGrowthBook(t *testing.T) {
	m, f := setup(t, "secret://gb")
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || h.Message != "2 features" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"features", `{}`, `"key":"dark-mode"`},
		{"features", `{"project":"prj_web"}`, `"production":{"activeRulesByKind":{"force":1,"rollout":1},"enabled":false,"rules":3}`},
		{"features", `{}`, `"total":2`},
		{"experiments", `{}`, `"variations":["Control","Fast"]`},
		{"experiments", `{}`, `"result":{"released":"v1","status":"won","winner":"v1"}`},
		{"experiments", `{}`, `"coverage":0.5`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(strings.ToLower(out), "leakme") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	in := `{"feature":"new-checkout","environment":"production"}`
	r, err := invoke(m, "turn_on", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "new-checkout on in production (project prj_web)") || f.on || len(f.toggles) != 0 ||
		string(r.Plan.Changes[0].Before) != `{"enabled":false}` {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "turn_on", `{"feature":"new-checkout","environment":"production","reason":"launch"}`, false)
	if err != nil || !f.on || f.toggles[0] != `{"environments":{"production":true},"reason":"launch"}` || r.Undo == nil || r.Undo.Action != "turn_off" ||
		string(r.Undo.Input) != `{"environment":"production","feature":"new-checkout"}` {
		t.Fatalf("%+v %v %v", r, err, f.toggles)
	}
	if r, err := invoke(m, "turn_on", in, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.on {
		t.Fatal(err)
	}
	f.ignore = true
	if _, err := invoke(m, "turn_on", in, false); err == nil || !strings.Contains(err.Error(), "kept") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "turn_on", `{"feature":"new-checkout","environment":"staging"}`, false); err == nil || !strings.Contains(err.Error(), "dev, production") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "turn_on", `{"feature":"nope","environment":"production"}`, false); err == nil || !strings.Contains(err.Error(), "no feature nope") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasPrefix(a.Name, "turn_") && (a.Risk != sdk.RiskDestructive || !a.DryRun || !a.Reversible) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestGrowthBookValidation(t *testing.T) {
	m, f := setup(t, "secret://gb")
	for _, c := range []struct{ action, in string }{
		{"turn_on", `{"environment":"production"}`},
		{"turn_on", `{"feature":"x"}`},
		{"turn_off", `{"feature":"../x","environment":"production"}`},
		{"turn_off", `{"feature":"a b","environment":"production"}`},
		{"turn_off", `{"feature":"x","environment":"prod?x=1"}`},
		{"turn_off", `{"feature":"x","environment":"production","reason":"a\nb"}`},
		{"features", `{"project":"prj/../x"}`},
		{"experiments", `{"project":"a b"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	if _, err := invoke(m, "turn_on", `{"feature":"other","environment":"production"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("changed another feature: %v %v", err, f.seen)
	}
	for _, c := range []Config{{APIKey: "secret_plain"}, {URL: "growthbook.example.com", APIKey: "secret://gb"}, {URL: "https://gb.example.com/?x=1", APIKey: "secret://gb"},
		{URL: "https://u:p@gb.example.com", APIKey: "secret://gb"}, {URL: "https://gb.example.com/#a", APIKey: "secret://gb"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "g"); h.Status != "down" || h.Message != "GrowthBook refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestGrowthBookRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://gb"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://gb": "secret_good"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "g"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
