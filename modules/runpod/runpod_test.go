package runpod

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
	mu      sync.Mutex
	seen    []string
	status  map[string]string
	queries []string
	ignore  bool
}

func (f *fake) pod(id string) string {
	typ := "RESERVED"
	if id == "spot1" {
		typ = "INTERRUPTABLE"
	}
	return fmt.Sprintf(`{"id":%q,"name":"train-%s","desiredStatus":%q,"podType":%q,"costPerHr":0.69,"gpuCount":1,"vcpuCount":8,"memoryInGb":62,"containerDiskInGb":20,"volumeInGb":50,
		"imageName":"runpod/pytorch:2.4","lastStatusChange":"Rented by User: Mon Nov 03 2026","machine":{"gpuDisplayName":"RTX 4090","location":"EU-RO-1"},"runtime":{"uptimeInSeconds":3600},
		"env":["HF_TOKEN=LEAKME"]}`, id, id, f.status[id], typ)
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, string(body))
	if r.Header.Get("Authorization") != "Bearer rpa_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"message":"Unauthorized"}]}`)
		return
	}
	var q struct {
		Query     string `json:"query"`
		Variables struct {
			Input struct {
				PodID    string `json:"podId"`
				GPUCount int    `json:"gpuCount"`
			} `json:"input"`
		} `json:"variables"`
	}
	json.Unmarshal(body, &q)
	f.queries = append(f.queries, q.Query)
	id := q.Variables.Input.PodID
	switch {
	case strings.HasPrefix(q.Query, "query Pods"):
		fmt.Fprintf(w, `{"data":{"myself":{"pods":[%s,%s]}}}`, f.pod("abc123"), f.pod("def456"))
	case strings.HasPrefix(q.Query, "query Pod("):
		switch id {
		case "abc123", "def456", "spot1", "gone1":
			fmt.Fprintf(w, `{"data":{"pod":%s}}`, f.pod(id))
		case "other1":
			fmt.Fprintf(w, `{"data":{"pod":%s}}`, f.pod("abc123"))
		default:
			io.WriteString(w, `{"data":{"pod":null}}`)
		}
	case strings.HasPrefix(q.Query, "mutation Start"):
		if q.Variables.Input.GPUCount != 1 {
			io.WriteString(w, `{"errors":[{"message":"gpuCount required"}]}`)
			return
		}
		if !f.ignore {
			f.status[id] = "RUNNING"
		}
		fmt.Fprintf(w, `{"data":{"podResume":{"id":%q,"desiredStatus":%q,"costPerHr":0.69}}}`, id, f.status[id])
	case strings.HasPrefix(q.Query, "mutation Stop"):
		f.status[id] = "EXITED"
		fmt.Fprintf(w, `{"data":{"podStop":{"id":%q,"desiredStatus":"EXITED"}}}`, id)
	case strings.HasPrefix(q.Query, "query Endpoints"):
		io.WriteString(w, `{"data":{"myself":{"endpoints":[{"id":"ep1","name":"whisper","gpuIds":"AMPERE_16,ADA_24","workersMin":0,"workersMax":3,"idleTimeout":5,"scalerType":"QUEUE_DELAY","scalerValue":4,"locations":null,"template":{"env":[{"key":"K","value":"LEAKME"}]}}]}}}`)
	case strings.HasPrefix(q.Query, "query Balance"):
		io.WriteString(w, `{"data":{"myself":{"clientBalance":20.5,"currentSpendPerHr":0.69,"spendLimit":80}}}`)
	default:
		io.WriteString(w, `{"errors":[{"message":"unknown query"}]}`)
	}
}

var secrets = map[string]string{"secret://rp": "rpa_good", "secret://bad": "rpa_bad"}

func setup(t *testing.T, ref string) (*Module, *fake) {
	f := &fake{status: map[string]string{"abc123": "RUNNING", "def456": "EXITED", "spot1": "EXITED", "gone1": "TERMINATED"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestRunPod(t *testing.T) {
	m, f := setup(t, "secret://rp")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "balance $20.50, spending $0.690/hr" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"pods", `{}`, `"gpu":"1x RTX 4090"`},
		{"pods", `{}`, `"runningCostPerHour":0.69`},
		{"pods", `{"running":false}`, `"id":"def456"`},
		{"endpoints", `{}`, `"gpuTypes":["AMPERE_16","ADA_24"]`},
		{"balance", `{}`, `"hoursLeftAtThisRate":29.7`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "rpa_good") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "pods", `{"running":false}`, false); strings.Contains(string(r.Output), "abc123") {
		t.Fatal(string(r.Output))
	}
	for _, q := range f.queries {
		if strings.Contains(q, "env") || strings.Contains(q, "ports") {
			t.Fatalf("asked for secrets: %s", q)
		}
	}

	// Start the stopped pod: preview with the cost, real, undo.
	r, err := invoke(m, "start_pod", `{"pod":"def456"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Start train-def456 on 1x RTX 4090, billed $0.690/hr while it runs" || f.status["def456"] != "EXITED" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "start_pod", `{"pod":"def456"}`, false)
	if err != nil || f.status["def456"] != "RUNNING" || r.Undo == nil || r.Undo.Action != "stop_pod" || string(r.Undo.Input) != `{"pod":"def456"}` {
		t.Fatalf("%+v %v", r, err)
	}
	undo := r.Undo
	r, err = invoke(m, "stop_pod", `{"pod":"def456"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "container disk is cleared; the 50 GB volume stays") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, undo.Action, string(undo.Input), false); err != nil || f.status["def456"] != "EXITED" {
		t.Fatalf("undo didn't stop it: %v", err)
	}
	if r, err := invoke(m, "stop_pod", `{"pod":"def456"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || r.Undo != nil {
		t.Fatalf("no-op: %s %v", r.Output, err)
	}
	for in, want := range map[string]string{
		`{"pod":"spot1"}`: "spot", `{"pod":"gone1"}`: "terminated", `{"pod":"nope1"}`: "no pod", `{"pod":"other1"}`: "another pod",
	} {
		if _, err := invoke(m, "start_pod", in, false); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", in, err)
		}
	}
	f.ignore = true
	f.status["def456"] = "EXITED"
	if _, err := invoke(m, "start_pod", `{"pod":"def456"}`, false); err == nil || !strings.Contains(err.Error(), "left the pod") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasSuffix(a.Name, "_pod") != (a.Risk == sdk.RiskDestructive) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestRunPodValidation(t *testing.T) {
	m, f := setup(t, "secret://rp")
	for _, in := range []string{`{}`, `{"pod":"a b"}`, `{"pod":"x\") { id } }"}`, `{"pod":"../x"}`} {
		if _, err := invoke(m, "start_pod", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := invoke(m, "terminate_pod", `{"pod":"abc123"}`, false); err == nil {
		t.Fatal("unknown action accepted")
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, raw := range []string{`{}`, `{"apiKey":"rpa_good"}`, `[]`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || h.Message != "RunPod refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestRunPodRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: "secret://rp"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "p", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
