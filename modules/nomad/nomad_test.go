package nomad

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

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	nodeID   = "aaaaaaaa-1111-2222-3333-444444444444"
	alloc1   = "bbbbbbbb-1111-2222-3333-444444444444"
	alloc2   = "bbbbbbbc-1111-2222-3333-444444444444"
	deployID = "dddddddd-1111-2222-3333-444444444444"
)

type fake struct {
	mu          sync.Mutex
	seen        []string
	eligibility string
	drain       bool
	stopped     bool
	version     int
	restarted   []string
	dispatched  []string
	promoted    []string
	reverted    []string
	answerID    string // when set, node and deployment lookups answer with this ID
}

func (f *fake) job() map[string]any {
	return map[string]any{"ID": "web", "Namespace": "default", "Type": "service", "Status": "running", "Stop": f.stopped, "Version": f.version, "Datacenters": []string{"dc1"},
		"TaskGroups": []any{map[string]any{"Name": "app", "Count": 2, "Tasks": []any{map[string]any{"Name": "server", "Driver": "docker", "Env": map[string]any{"DB_PASSWORD": "hunter2"}}}}}}
}

func allocs() []any {
	return []any{
		map[string]any{"ID": alloc1, "Name": "web.app[0]", "JobID": "web", "TaskGroup": "app", "NodeID": nodeID, "NodeName": "n1", "ClientStatus": "running", "DesiredStatus": "run", "CreateTime": 1700000000000000000,
			"TaskStates": map[string]any{"server": map[string]any{"State": "running", "Restarts": 2}}},
		map[string]any{"ID": alloc2, "Name": "web.app[1]", "JobID": "web", "TaskGroup": "app", "NodeID": nodeID, "NodeName": "n1", "ClientStatus": "running", "DesiredStatus": "run", "CreateTime": 1700000001000000000},
		map[string]any{"ID": "cccccccc-1111-2222-3333-444444444444", "Name": "web.app[0]", "JobID": "web", "TaskGroup": "app", "ClientStatus": "complete", "DesiredStatus": "stop"},
	}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Nomad-Token") != "nmtok" {
		w.WriteHeader(403)
		io.WriteString(w, "Permission denied")
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	switch r.Method + " " + r.URL.EscapedPath() {
	case "GET /v1/status/leader":
		io.WriteString(w, `"10.0.0.1:4647"`)
	case "GET /v1/acl/token/self":
		io.WriteString(w, `{"Name":"ops","Type":"client","SecretID":"nmtok"}`)
	case "GET /v1/jobs":
		io.WriteString(w, `[{"ID":"web","Namespace":"default","Type":"service","Status":"running","JobSummary":{"Summary":{"app":{"Running":2,"Failed":1}}}},{"ID":"batch","Type":"batch","Status":"running","ParameterizedJob":true}]`)
	case "GET /v1/job/web":
		enc.Encode(f.job())
	case "GET /v1/job/web/summary":
		io.WriteString(w, `{"Summary":{"app":{"Running":2}}}`)
	case "GET /v1/job/web/deployment":
		io.WriteString(w, `null`)
	case "GET /v1/job/web/allocations":
		enc.Encode(allocs())
	case "GET /v1/job/web/versions":
		io.WriteString(w, `{"Versions":[{"Version":4,"Stop":true},{"Version":3,"Stop":false,"SubmitTime":1700000000000000000}]}`)
	case "POST /v1/job/web/revert":
		f.reverted = append(f.reverted, string(body))
		f.stopped = false
		f.version++
		io.WriteString(w, `{"EvalID":"e2"}`)
	case "DELETE /v1/job/web":
		f.stopped = true
		f.version++
		io.WriteString(w, `{"EvalID":"e1"}`)
	case "GET /v1/job/batch%2Fdispatch-1-abc", "GET /v1/job/batch":
		io.WriteString(w, `{"ID":"`+strings.ReplaceAll(strings.TrimPrefix(r.URL.EscapedPath(), "/v1/job/"), "%2F", "/")+`","Type":"batch","Version":1,"ParameterizedJob":{"Payload":"optional","MetaRequired":["target"],"MetaOptional":["dry"]}}`)
	case "POST /v1/job/batch/dispatch":
		f.dispatched = append(f.dispatched, string(body))
		io.WriteString(w, `{"DispatchedJobID":"batch/dispatch-1-abc","EvalID":"e3"}`)
	case "GET /v1/allocations":
		enc.Encode(allocs())
	case "POST /v1/client/allocation/" + alloc1 + "/restart", "POST /v1/client/allocation/" + alloc2 + "/restart":
		f.restarted = append(f.restarted, r.URL.Path)
		io.WriteString(w, `{}`)
	case "GET /v1/nodes":
		if p := r.URL.Query().Get("prefix"); p != "" && !strings.HasPrefix(nodeID, p) {
			io.WriteString(w, `[]`)
			return
		}
		enc.Encode([]any{map[string]any{"ID": nodeID, "Name": "n1", "Status": "ready", "SchedulingEligibility": f.eligibility, "Drain": f.drain}})
	case "GET /v1/node/" + nodeID:
		id := nodeID
		if f.answerID != "" {
			id = f.answerID
		}
		enc.Encode(map[string]any{"ID": id, "Name": "n1", "Status": "ready", "SchedulingEligibility": f.eligibility, "Drain": f.drain})
	case "GET /v1/node/" + nodeID + "/allocations":
		enc.Encode(allocs())
	case "POST /v1/node/" + nodeID + "/eligibility":
		var b struct{ Eligibility string }
		json.Unmarshal(body, &b)
		f.eligibility = b.Eligibility
		io.WriteString(w, `{}`)
	case "POST /v1/node/" + nodeID + "/drain":
		var b struct {
			DrainSpec    *struct{ Deadline int64 }
			MarkEligible bool
		}
		json.Unmarshal(body, &b)
		f.drain = b.DrainSpec != nil
		if f.drain {
			f.eligibility = "ineligible"
		} else if b.MarkEligible {
			f.eligibility = "eligible"
		}
		io.WriteString(w, `{}`)
	case "GET /v1/deployments":
		io.WriteString(w, `[{"ID":"`+deployID+`","JobID":"web","Status":"running"}]`)
	case "GET /v1/deployment/" + deployID:
		id := deployID
		if f.answerID != "" {
			id = f.answerID
		}
		io.WriteString(w, `{"ID":"`+id+`","JobID":"web","Namespace":"default","JobVersion":5,"Status":"running","TaskGroups":{"app":{"DesiredCanaries":1,"PlacedCanaries":["x"],"DesiredTotal":2,"HealthyAllocs":0,"UnhealthyAllocs":1}}}`)
	case "POST /v1/deployment/promote/" + deployID:
		f.promoted = append(f.promoted, string(body))
		io.WriteString(w, `{"EvalID":"e4"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, "not found")
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	f := &fake{eligibility: "eligible", version: 3}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Address: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nm": "nmtok", "secret://bad": "nope"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestNomadReads(t *testing.T) {
	m, _ := setup(t, "secret://nm")
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || h.Message != "leader 10.0.0.1:4647 · token ops (client)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"jobs", `{"namespace":"*"}`, `"allocations":{"failed":1,"running":2}`},
		{"job", `{"job":"web"}`, `"tasks":["server (docker)"]`},
		{"allocations", `{"job":"web"}`, `"restarts":2`},
		{"allocations", `{}`, `"node":"n1"`},
		{"nodes", `{}`, `"eligibility":"eligible"`},
		{"deployments", `{}`, `"status":"running"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "hunter2") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	r, _ := invoke(m, "allocations", `{"job":"web"}`, false)
	if strings.Contains(string(r.Output), "cccccccc") {
		t.Fatal("finished allocation listed without all")
	}
}

func TestNomadNodes(t *testing.T) {
	m, f := setup(t, "secret://nm")
	r, err := invoke(m, "node_eligibility", `{"node":"aaaaaaaa","eligible":false}`, true)
	if err != nil || r.Plan == nil || f.eligibility != "eligible" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "node_eligibility", `{"node":"aaaaaaaa","eligible":false}`, false)
	if err != nil || f.eligibility != "ineligible" || r.Undo == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.eligibility != "eligible" {
		t.Fatal(err)
	}
	r, err = invoke(m, "drain_node", `{"node":"`+nodeID+`","deadlineMinutes":30}`, true)
	if err != nil || r.Plan == nil || f.drain || !strings.Contains(r.Plan.Summary, "2 allocation(s) are migrated") || len(r.Plan.Changes) != 3 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "drain_node", `{"node":"`+nodeID+`","deadlineMinutes":30}`, false)
	if err != nil || !f.drain || r.Undo == nil || r.Undo.Action != "cancel_drain" {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], `"Deadline":1800000000000`) {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.drain || f.eligibility != "eligible" {
		t.Fatal(err)
	}
}

func TestNomadJobs(t *testing.T) {
	m, f := setup(t, "secret://nm")
	r, err := invoke(m, "restart_job", `{"job":"web"}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 2 || len(f.restarted) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "restart_job", `{"job":"web","allocation":"bbbbbbbc"}`, false); err != nil || len(f.restarted) != 1 || !strings.Contains(f.restarted[0], alloc2) {
		t.Fatalf("%v %v", f.restarted, err)
	}

	r, err = invoke(m, "stop_job", `{"job":"web"}`, true)
	if err != nil || r.Plan == nil || f.stopped || !strings.Contains(r.Plan.Summary, "2 running allocation(s) stop; undo reverts to version 3") {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "stop_job", `{"job":"web"}`, false)
	if err != nil || !f.stopped || r.Undo == nil || r.Undo.Action != "revert_job" {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], "purge=false") {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	if p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || !strings.Contains(p.Plan.Summary, "starts the stopped job again") {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.stopped || !strings.Contains(f.reverted[0], `"EnforcePriorVersion":4`) || !strings.Contains(f.reverted[0], `"JobVersion":3`) {
		t.Fatalf("%v %v", f.reverted, err)
	}
	if r, err := invoke(m, "stop_job", `{"job":"web","purge":true}`, true); err != nil || !strings.Contains(r.Plan.Summary, "PURGE") {
		t.Fatalf("%+v %v", r, err)
	}

	// Dispatch checks meta and payload against the job's parameters.
	if _, err := invoke(m, "dispatch_job", `{"job":"batch"}`, false); err == nil || !strings.Contains(err.Error(), `needs meta "target"`) {
		t.Fatal(err)
	}
	if _, err := invoke(m, "dispatch_job", `{"job":"batch","meta":{"target":"x","other":"y"}}`, false); err == nil || !strings.Contains(err.Error(), `doesn't take meta "other"`) {
		t.Fatal(err)
	}
	if r, err := invoke(m, "dispatch_job", `{"job":"batch","meta":{"target":"db"},"payload":"hello"}`, true); err != nil || r.Plan == nil || len(f.dispatched) != 0 || !strings.Contains(string(r.Plan.Changes[0].After), `"payload":"hello"`) {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "dispatch_job", `{"job":"batch","meta":{"target":"db"},"payload":"hello"}`, false); err != nil || !strings.Contains(string(r.Output), "batch/dispatch-1-abc") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if !strings.Contains(f.dispatched[0], base64.StdEncoding.EncodeToString([]byte("hello"))) {
		t.Fatal(f.dispatched[0])
	}
	if r, err := invoke(m, "job", `{"job":"batch/dispatch-1-abc"}`, false); err != nil || !strings.Contains(string(r.Output), `"id":"batch/dispatch-1-abc"`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Promote shows canary health.
	r, err = invoke(m, "promote_deployment", `{"deployment":"dddddddd"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "app has 1 UNHEALTHY") || len(f.promoted) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "promote_deployment", `{"deployment":"`+deployID+`"}`, false); err != nil || !strings.Contains(f.promoted[0], `"All":true`) {
		t.Fatalf("%v %v", f.promoted, err)
	}
	for _, a := range m.Manifest().Actions {
		switch a.Name {
		case "drain_node", "restart_job", "stop_job", "dispatch_job", "promote_deployment", "revert_job":
			if a.Risk != sdk.RiskDestructive || !a.DryRun {
				t.Fatalf("%s must be destructive with a preview", a.Name)
			}
		case "node_eligibility":
			if a.Risk != sdk.RiskWrite {
				t.Fatal(a.Name)
			}
		}
	}
}

func TestNomadValidation(t *testing.T) {
	m, f := setup(t, "secret://nm")
	for _, c := range []struct{ action, in string }{
		{"job", `{"job":"../acl/tokens"}`},
		{"job", `{"job":"web?x"}`},
		{"job", `{"job":"/web"}`},
		{"job", `{"job":"web","namespace":"*"}`},
		{"job", `{"job":"web","namespace":"a b"}`},
		{"allocations", `{"job":"a..b"}`},
		{"node_eligibility", `{"node":"abc","eligible":true}`},
		{"node_eligibility", `{"node":"../../x","eligible":true}`},
		{"node_eligibility", `{"node":"aaaaaaaa"}`},
		{"drain_node", `{"node":"aaaaaaaa","deadlineMinutes":5000}`},
		{"restart_job", `{"job":"web","group":"a/b"}`},
		{"restart_job", `{"job":"web","allocation":"xyz"}`},
		{"dispatch_job", `{"job":"batch","meta":{"a b":"x"}}`},
		{"promote_deployment", `{"deployment":"nope"}`},
		{"promote_deployment", `{"deployment":"dddddddd","groups":["../x"]}`},
		{"revert_job", `{"job":"web"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	// Only revert_job's missing version reached the server (it needs the job first).
	for _, s := range f.seen {
		if !strings.HasPrefix(s, "GET /v1/job/web?") {
			t.Fatalf("invalid input reached the server: %v", f.seen)
		}
	}
	for _, c := range []Config{{Address: "http://x:4646", Token: "plain"}, {Address: "ftp://x"}, {Address: "http://u:p@x:4646"}, {Address: "http://x:4646/v1"}, {Address: "http://x:4646", Namespace: "a/b"}, {Address: "http://x:4646", Region: "../x"}, {Address: "https://x", Fingerprint: "zz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "jobs", `{}`, false); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatal(err)
	}
}

func TestNomadNoTokenAndRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Nomad-Token") + "!" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/status/leader" {
			if r.Header.Get("X-Nomad-Token") != "" {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `"10.0.0.1:4647"`)
			return
		}
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{Address: srv.URL})
	if err := m.Configure(context.Background(), fakehost.New(nil), "n", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	m2 := New()
	raw, _ = json.Marshal(Config{Address: srv.URL, Token: "secret://nm"})
	if err := m2.Configure(context.Background(), fakehost.New(map[string]string{"secret://nm": "nmtok"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Invoke(context.Background(), sdk.Call{Instance: "n", Action: "nodes"}); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}

// IDs the server answers with go into later request paths, so a node or
// deployment that comes back with another (or a path-like) ID is refused
// before anything is posted.
func TestNomadServerIDsChecked(t *testing.T) {
	for _, bad := range []string{"../../v1/acl/bootstrap", alloc1, nodeID + "/../x"} {
		m, f := setup(t, "secret://nm")
		f.answerID = bad
		for _, c := range []struct{ action, in string }{
			{"drain_node", `{"node":"` + nodeID + `","deadlineMinutes":30}`},
			{"node_eligibility", `{"node":"` + nodeID + `","eligible":false}`},
			{"promote_deployment", `{"deployment":"` + deployID + `"}`},
		} {
			if _, err := invoke(m, c.action, c.in, false); err == nil || !strings.Contains(err.Error(), "unexpected") {
				t.Fatalf("%s with %q: %v", c.action, bad, err)
			}
		}
		for _, s := range f.seen {
			if strings.HasPrefix(s, "POST") {
				t.Fatalf("posted after a bad ID: %s", s)
			}
		}
	}
}
