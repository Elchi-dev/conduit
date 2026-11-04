package neon

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

const (
	key  = "napi_0123456789abcdefghijklmnopqrstuvwxyz0123456789"
	proj = "spring-example-302709"
	// Planted in answers: none of it may reach an output.
	leak = "postgresql://neondb_owner:npg_LEAKPASS@ep-cool-darkness-123456.eu-central-1.aws.neon.tech/neondb?sslmode=require"
)

type fakeNeon struct {
	mu       sync.Mutex
	seen     []string
	branches []map[string]any
	state    string
	pageSize int // pages the branch list when set
}

func (f *fakeNeon) endpoint() map[string]any {
	return map[string]any{"id": "ep-cool-darkness-123456", "project_id": proj, "branch_id": "br-main-1", "host": "ep-cool-darkness-123456.eu-central-1.aws.neon.tech",
		"type": "read_write", "current_state": f.state, "region_id": "aws-eu-central-1", "autoscaling_limit_min_cu": 0.25, "autoscaling_limit_max_cu": 2,
		"suspend_timeout_seconds": 0, "pooler_enabled": true, "last_active": "2026-11-04T10:00:00Z", "password": "npg_LEAKPASS"}
}

func (f *fakeNeon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+key {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":"","message":"authorization failed"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	pp := "/api/v2/projects/" + proj
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v2/projects":
		fmt.Fprintf(w, `{"projects":[{"id":%q,"name":"shop","region_id":"aws-eu-central-1","pg_version":17,"created_at":"2026-01-01T00:00:00Z","synthetic_storage_size":52428800,"compute_last_active_at":"2026-11-04T09:00:00Z"}],"pagination":{"cursor":"x"}}`, proj)
	case "GET " + pp:
		fmt.Fprintf(w, `{"project":{"id":%q,"name":"shop","compute_time_seconds":7200,"active_time_seconds":3600,"cpu_used_sec":900,"synthetic_storage_size":1073741824,"written_data_bytes":2048,"data_transfer_bytes":4096,"consumption_period_start":"2026-11-01T00:00:00Z","consumption_period_end":"2026-12-01T00:00:00Z"}}`, proj)
	case "GET " + pp + "/branches":
		if f.pageSize == 0 {
			enc.Encode(map[string]any{"branches": f.branches})
			return
		}
		start := 0
		fmt.Sscan(r.URL.Query().Get("cursor"), &start)
		end := min(start+f.pageSize, len(f.branches))
		start = min(start, end)
		enc.Encode(map[string]any{"branches": f.branches[start:end], "pagination": map[string]any{"next": fmt.Sprint(end)}})
	case "GET " + pp + "/endpoints":
		enc.Encode(map[string]any{"endpoints": []any{f.endpoint()}})
	case "GET " + pp + "/endpoints/ep-cool-darkness-123456":
		enc.Encode(map[string]any{"endpoint": f.endpoint()})
	case "POST " + pp + "/endpoints/ep-cool-darkness-123456/suspend":
		f.state = "idle"
		io.WriteString(w, `{"endpoint":{},"operations":[{"id":"op1","action":"suspend_compute","status":"running"}]}`)
	case "POST " + pp + "/endpoints/ep-cool-darkness-123456/start":
		f.state = "active"
		io.WriteString(w, `{"endpoint":{},"operations":[{"id":"op2","action":"start_compute","status":"running"}]}`)
	case "POST " + pp + "/branches":
		var b struct {
			Branch map[string]any `json:"branch"`
		}
		json.Unmarshal(body, &b)
		nb := map[string]any{"id": "br-new-2", "name": b.Branch["name"], "parent_id": b.Branch["parent_id"], "current_state": "init"}
		f.branches = append(f.branches, nb)
		enc.Encode(map[string]any{"branch": nb, "endpoints": []any{f.endpoint()}, "operations": []any{map[string]any{"id": "op3", "action": "create_branch", "status": "running"}},
			"connection_uris": []any{map[string]any{"connection_uri": leak, "connection_parameters": map[string]any{"password": "npg_LEAKPASS"}}},
			"roles":           []any{map[string]any{"name": "neondb_owner", "password": "npg_LEAKPASS"}}})
	default:
		for i, b := range f.branches {
			id := b["id"].(string)
			if r.URL.Path != pp+"/branches/"+id {
				continue
			}
			switch r.Method {
			case "GET":
				enc.Encode(map[string]any{"branch": b})
				return
			case "DELETE":
				f.branches = append(f.branches[:i], f.branches[i+1:]...)
				io.WriteString(w, `{"branch":{},"operations":[{"id":"op4","action":"delete_timeline","status":"running"}]}`)
				return
			}
		}
		w.WriteHeader(404)
		io.WriteString(w, `{"code":"","message":"not found"}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeNeon) {
	f := &fakeNeon{state: "active", branches: []map[string]any{
		{"id": "br-main-1", "name": "main", "default": true, "current_state": "ready", "logical_size": 30000000, "compute_time_seconds": 7000},
		{"id": "br-dev-1", "name": "dev", "parent_id": "br-main-1", "current_state": "ready", "logical_size": 1000, "compute_time_seconds": 200},
		{"id": "br-prot-1", "name": "staging", "parent_id": "br-main-1", "protected": true, "current_state": "ready"},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL + "/api/v2"
	raw, _ := json.Marshal(Config{Token: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://neon": key, "secret://bad": "napi_00000000000000000000000000000000"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func noLeak(t *testing.T, r sdk.Result) {
	t.Helper()
	b, _ := json.Marshal(r)
	if s := string(b); strings.Contains(s, "LEAKPASS") || strings.Contains(s, "postgresql://") {
		t.Fatalf("leaked: %s", s)
	}
}

func TestNeonReads(t *testing.T) {
	m, _ := setup(t, "secret://neon")
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || h.Message != "1 projects" {
		t.Fatalf("%+v", h)
	}
	in := `{"project":"` + proj + `"}`
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"storage":"50.0 MB"`},
		{"branches", in, `"parentName":"main"`},
		{"branches", in, `"default":true`},
		{"endpoints", in, `"branchName":"main"`},
		{"endpoints", in, `"scaleToZero":"default (5 minutes)"`},
		{"usage", in, `"computeTime":"2.00 h"`},
		{"usage", in, `"storage":"1.0 GB"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
		noLeak(t, r)
	}
}

func TestNeonBranches(t *testing.T) {
	m, f := setup(t, "secret://neon")
	in := `{"project":"` + proj + `","name":"preview/x"}`
	r, err := invoke(m, "create_branch", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "from main") || len(f.branches) != 3 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_branch", in, false)
	if err != nil || len(f.branches) != 4 || r.Undo == nil || r.Undo.Action != "delete_branch" || string(r.Undo.Input) != `{"branch":"br-new-2","project":"`+proj+`"}` {
		t.Fatalf("%+v %v", r, err)
	}
	noLeak(t, r)
	if !strings.Contains(f.seen[len(f.seen)-1], `"parent_id":"br-main-1"`) {
		t.Fatal(f.seen)
	}
	if r, err := invoke(m, "create_branch", in, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "for good") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "delete_branch", `{"project":"`+proj+`","branch":"br-new-2"}`, false); err != nil || len(f.branches) != 3 {
		t.Fatal(err)
	}
	for _, b := range []string{"br-main-1", "br-prot-1"} {
		if _, err := invoke(m, "delete_branch", `{"project":"`+proj+`","branch":"`+b+`"}`, false); err == nil || len(f.branches) != 3 {
			t.Fatalf("deleted %s", b)
		}
	}
	if _, err := invoke(m, "delete_branch", `{"project":"`+proj+`","branch":"br-gone-9"}`, false); err == nil || !strings.Contains(err.Error(), "no branch") {
		t.Fatal(err)
	}
	risk := map[string]sdk.Risk{"create_branch": sdk.RiskWrite, "delete_branch": sdk.RiskDestructive, "suspend_endpoint": sdk.RiskDestructive, "start_endpoint": sdk.RiskWrite}
	for _, a := range m.Manifest().Actions {
		if want, ok := risk[a.Name]; ok && (a.Risk != want || !a.DryRun) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestNeonEndpoints(t *testing.T) {
	m, f := setup(t, "secret://neon")
	in := `{"project":"` + proj + `","endpoint":"ep-cool-darkness-123456"}`
	r, err := invoke(m, "suspend_endpoint", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "connections drop") || f.state != "active" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "suspend_endpoint", in, false)
	if err != nil || f.state != "idle" || r.Undo == nil || r.Undo.Action != "start_endpoint" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "suspend_endpoint", in, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.state != "active" || r.Undo == nil || r.Undo.Action != "suspend_endpoint" {
		t.Fatalf("%+v %v", r, err)
	}
	noLeak(t, r)
}

func TestNeonValidation(t *testing.T) {
	m, f := setup(t, "secret://neon")
	for _, c := range []struct{ action, in string }{
		{"branches", `{}`},
		{"branches", `{"project":"../users/me"}`},
		{"usage", `{"project":"Shop Project"}`},
		{"delete_branch", `{"project":"` + proj + `","branch":"main"}`},
		{"delete_branch", `{"project":"` + proj + `","branch":"br-x/../y"}`},
		{"suspend_endpoint", `{"project":"` + proj + `","endpoint":"br-main-1"}`},
		{"start_endpoint", `{"project":"` + proj + `","endpoint":"ep-a?x=1"}`},
		{"create_branch", `{"project":"` + proj + `","name":""}`},
		{"create_branch", `{"project":"` + proj + `","name":"a b"}`},
		{"create_branch", `{"project":"` + proj + `","name":"x","parent":"main"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Token: "napi_plain"}, {Token: "secret://neon", Organization: "../x"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" || h.Message != "Neon refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestNeonRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + r.URL.Path }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://neon": key}), "n", json.RawMessage(`{"token":"secret://neon"}`)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

func TestNeonBranchPages(t *testing.T) {
	m, f := setup(t, "secret://neon")
	f.pageSize = 1
	// The default branch comes last, on the third page.
	f.branches[0], f.branches[2] = f.branches[2], f.branches[0]
	r, err := invoke(m, "branches", `{"project":"`+proj+`"}`, false)
	if err != nil || strings.Count(string(r.Output), `"id":`) != 3 {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "create_branch", `{"project":"`+proj+`","name":"dev"}`, false)
	if err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "create_branch", `{"project":"`+proj+`","name":"other"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "from main") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
}
