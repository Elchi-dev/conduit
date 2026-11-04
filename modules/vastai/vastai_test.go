package vastai

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
	mu        sync.Mutex
	seen      []string
	intended  map[string]string
	destroyed map[string]bool
	refuse    bool
}

func (f *fake) inst(id string) string {
	return fmt.Sprintf(`{"id":%s,"label":"llm-%s","actual_status":%q,"intended_status":%q,"cur_state":%q,"gpu_name":"RTX 4090","num_gpus":2,"dph_total":0.85,"storage_cost":0.15,
		"disk_space":100,"cpu_cores_effective":16,"cpu_ram":65536,"image_uuid":"pytorch/pytorch:latest","geolocation":"Norway, NO","start_date":1762200000.5,"gpu_util":87.5,"is_bid":false,
		"ssh_host":"ssh4.vast.ai","ssh_port":12345,"jupyter_token":"LEAKME","extra_env":[["HF_TOKEN","LEAKME"]],"onstart":"export KEY=LEAKME","instance_api_key":"LEAKME"}`,
		id, id, map[string]string{"running": "running", "stopped": "exited"}[f.intended[id]], f.intended[id], f.intended[id])
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	if r.Header.Get("Authorization") != "Bearer vast_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"success":false,"error":"invalid_user","msg":"Invalid user key"}`)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/users/current/":
		io.WriteString(w, `{"id":1,"username":"ada","email":"ada@example.com","credit":12.4,"api_key":"LEAKME","billaddress_line1":"LEAKME"}`)
	case r.Method == "GET" && r.URL.Path == "/instances/":
		fmt.Fprintf(w, `{"instances":[%s,%s]}`, f.inst("222"), f.inst("111"))
	case r.URL.Path == "/instances/111/" || r.URL.Path == "/instances/222/":
		id := strings.Split(r.URL.Path, "/")[2]
		if f.destroyed[id] {
			w.WriteHeader(404)
			io.WriteString(w, `{"success":false,"error":"no_such_instance","msg":"Instance not found"}`)
			return
		}
		switch r.Method {
		case "GET":
			fmt.Fprintf(w, `{"instances":%s}`, f.inst(id))
		case "PUT":
			if f.refuse {
				io.WriteString(w, `{"success":false,"msg":"resources unavailable"}`)
				return
			}
			var b map[string]string
			json.Unmarshal(body, &b)
			f.intended[id] = b["state"]
			io.WriteString(w, `{"success":true}`)
		case "DELETE":
			f.destroyed[id] = true
			io.WriteString(w, `{"success":true}`)
		}
	case r.URL.Path == "/instances/333/":
		fmt.Fprintf(w, `{"instances":%s}`, f.inst("111"))
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"success":false,"msg":"not found"}`)
	}
}

var secrets = map[string]string{"secret://va": "vast_good", "secret://bad": "vast_bad"}

func setup(t *testing.T, ref string) (*Module, *fake) {
	f := &fake{intended: map[string]string{"111": "running", "222": "stopped"}, destroyed: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "v", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "v", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestVastAI(t *testing.T) {
	m, f := setup(t, "secret://va")
	if h := m.Health(context.Background(), "v"); h.Status != "ok" || h.Message != "credit $12.40" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"instances", `{}`, `"gpu":"2x RTX 4090"`},
		{"instances", `{}`, `"runningCostPerHour":0.85`},
		{"instances", `{"running":false}`, `"id":222`},
		{"instances", `{}`, `"memoryGB":64`},
		{"balance", `{}`, `"hoursLeftAtThisRate":14.5`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "ssh4") || strings.Contains(out, "vast_good") || strings.Contains(out, "ada@") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "instances", `{"running":false}`, false); strings.Contains(string(r.Output), `"id":111`) {
		t.Fatal(string(r.Output))
	}

	// Start the stopped one: preview with the cost, real, undo.
	r, err := invoke(m, "start_instance", `{"instance":222}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Start llm-222 on 2x RTX 4090, billed $0.850/hr while it runs" || f.intended["222"] != "stopped" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "start_instance", `{"instance":"222"}`, false)
	if err != nil || f.intended["222"] != "running" || r.Undo == nil || r.Undo.Action != "stop_instance" || string(r.Undo.Input) != `{"instance":"222"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.intended["222"] != "stopped" {
		t.Fatal(err)
	}
	if r, err := invoke(m, "stop_instance", `{"instance":222}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || r.Undo != nil {
		t.Fatalf("no-op: %s %v", r.Output, err)
	}
	r, err = invoke(m, "stop_instance", `{"instance":111}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "100 GB disk is kept and still billed") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	f.refuse = true
	if _, err := invoke(m, "start_instance", `{"instance":222}`, false); err == nil || !strings.Contains(err.Error(), "resources unavailable") {
		t.Fatal(err)
	}

	// Destroy: preview, real, no undo, then gone.
	r, err = invoke(m, "destroy_instance", `{"instance":111}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "deleted for good") || f.destroyed["111"] || strings.Contains(string(r.Plan.Changes[0].Before), "LEAKME") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "destroy_instance", `{"instance":111}`, false)
	if err != nil || !f.destroyed["111"] || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "destroy_instance", `{"instance":111}`, false); err == nil || !strings.Contains(err.Error(), "no instance") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasSuffix(a.Name, "_instance") != (a.Risk == sdk.RiskDestructive) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestVastAIValidation(t *testing.T) {
	m, f := setup(t, "secret://va")
	for _, in := range []string{`{}`, `{"instance":"../users/current"}`, `{"instance":-1}`, `{"instance":1.5}`, `{"instance":"12?x=1"}`, `{"instance":0}`, `{"instance":[1]}`} {
		if _, err := invoke(m, "destroy_instance", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// The instance changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "destroy_instance", `{"instance":333}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("%v %v", err, f.seen)
	}
	for _, raw := range []string{`{}`, `{"apiKey":"vast_good"}`, `{"apiKey":1}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "v"); h.Status != "down" || h.Message != "Vast.ai refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestVastAIRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "hit" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: "secret://va"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "v", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "v"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
