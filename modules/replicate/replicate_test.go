package replicate

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

type fake struct {
	mu     sync.Mutex
	seen   []string
	status map[string]string
}

func (f *fake) pred(id string, full bool) string {
	s := fmt.Sprintf(`{"id":%q,"model":"acme/sdxl","version":"v1","status":%q,"source":"api","created_at":"2026-11-04T10:00:00.000Z","started_at":"2026-11-04T10:00:01Z",
		"webhook":"https://hooks.example.com/x?secret=LEAKME","urls":{"stream":"https://stream.replicate.com/LEAKME","cancel":"https://api.replicate.com/v1/predictions/%s/cancel"},
		"metrics":{"predict_time":4.5},"error":null`, id, f.status[id], id)
	if full {
		s += `,"input":{"prompt":"a portrait of Jane Doe"},"output":["https://replicate.delivery/out.png"],"logs":"step 1\nstep 2"`
	}
	return s + "}"
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	if r.Header.Get("Authorization") != "Bearer r8_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"title":"Unauthenticated","detail":"You did not pass a valid authentication token","status":401}`)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /account":
		io.WriteString(w, `{"type":"user","username":"ada","name":"Ada L","github_url":"https://github.com/ada"}`)
	case "GET /models":
		io.WriteString(w, `{"next":"https://api.replicate.com/v1/models?cursor=cD0yMDI2","results":[{"owner":"acme","name":"sdxl","description":"Images","visibility":"public","run_count":42,"url":"https://replicate.com/acme/sdxl","latest_version":{"id":"v1","created_at":"2026-01-01T00:00:00Z"}}]}`)
	case "GET /models/acme/sdxl":
		io.WriteString(w, `{"owner":"acme","name":"sdxl","visibility":"public","run_count":42}`)
	case "GET /predictions":
		fmt.Fprintf(w, `{"next":null,"results":[%s,%s]}`, f.pred("abc123", false), f.pred("done456", false))
	case "GET /predictions/abc123", "GET /predictions/done456":
		io.WriteString(w, f.pred(strings.TrimPrefix(r.URL.Path, "/predictions/"), true))
	case "GET /predictions/other789":
		io.WriteString(w, f.pred("abc123", true))
	case "POST /predictions/abc123/cancel":
		f.status["abc123"] = "canceled"
		io.WriteString(w, f.pred("abc123", false))
	case "GET /deployments":
		io.WriteString(w, `{"next":null,"results":[{"owner":"ada","name":"api","current_release":{"number":3,"model":"acme/sdxl","version":"v1","created_at":"2026-10-01T00:00:00Z","configuration":{"hardware":"gpu-a100-large","min_instances":0,"max_instances":2}}}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not found."}`)
	}
}

var secrets = map[string]string{"secret://rep": "r8_good", "secret://bad": "r8_bad"}

func setup(t *testing.T, ref string) (*Module, *fake) {
	f := &fake{status: map[string]string{"abc123": "processing", "done456": "succeeded"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: ref})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "r", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "r", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestReplicate(t *testing.T) {
	m, f := setup(t, "secret://rep")
	if h := m.Health(context.Background(), "r"); h.Status != "ok" || h.Message != "signed in as ada" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"account", ``, `"username":"ada"`},
		{"models", `{}`, `"next":"cD0yMDI2"`},
		{"models", `{"model":"acme/sdxl"}`, `"runs":42`},
		{"predictions", `{}`, `"runSeconds":4.5`},
		{"prediction", `{"prediction":"abc123"}`, `"prompt":"a portrait of Jane Doe"`},
		{"prediction", `{"prediction":"abc123"}`, `"logs":"step 1\nstep 2"`},
		{"deployments", `{}`, `"hardware":"gpu-a100-large"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "r8_good") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "predictions", `{}`, false); strings.Contains(string(r.Output), "Jane Doe") {
		t.Fatal("the list carries inputs")
	}

	// Cancel: preview, real, then nothing to change.
	r, err := invoke(m, "cancel_prediction", `{"prediction":"abc123"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Cancel the processing prediction abc123 of acme/sdxl") || f.status["abc123"] != "processing" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if strings.Contains(string(r.Plan.Changes[0].Before), "Jane Doe") {
		t.Fatal("the preview carries the input")
	}
	r, err = invoke(m, "cancel_prediction", `{"prediction":"abc123"}`, false)
	if err != nil || f.status["abc123"] != "canceled" || !strings.Contains(string(r.Output), `"status":"canceled"`) || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "cancel_prediction", `{"prediction":"done456"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "prediction", `{"prediction":"nope"}`, false); err == nil || !strings.Contains(err.Error(), "no prediction") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		switch {
		case a.Name == "cancel_prediction" && a.Risk != sdk.RiskDestructive,
			a.Name == "prediction" && !a.Sensitive,
			a.Name != "cancel_prediction" && a.Risk != sdk.RiskRead:
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestReplicateValidation(t *testing.T) {
	m, f := setup(t, "secret://rep")
	for _, c := range []struct{ action, in string }{
		{"prediction", `{}`},
		{"prediction", `{"prediction":"../account"}`},
		{"cancel_prediction", `{"prediction":"ABC 1"}`},
		{"cancel_prediction", `{"prediction":"a?b=1"}`},
		{"models", `{"model":"acme"}`},
		{"models", `{"model":"acme/../x"}`},
		{"models", `{"cursor":"a&b"}`},
		{"start_prediction", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s %s accepted", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// The prediction cancelled is the one asked for, whatever the server answers.
	if _, err := invoke(m, "cancel_prediction", `{"prediction":"other789"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("%v %v", err, f.seen)
	}
	for _, raw := range []string{`{}`, `{"token":"r8_good"}`, `{"token":7}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "r"); h.Status != "down" || h.Message != "Replicate refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestReplicateRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "hit" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://rep"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "r", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "r"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
