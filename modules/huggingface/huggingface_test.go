package huggingface

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
	stage   string
	epState string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	auth := r.Header.Get("Authorization")
	if auth != "Bearer hf_write" && auth != "Bearer hf_read" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Invalid credentials in Authorization header"}`)
		return
	}
	if r.Method == http.MethodPost && auth != "Bearer hf_write" {
		w.WriteHeader(403)
		io.WriteString(w, `{"error":"You don't have the rights"}`)
		return
	}
	enc := json.NewEncoder(w)
	ep := func() map[string]any {
		return map[string]any{"name": "llama-ep", "type": "protected",
			"model":    map[string]any{"repository": "meta-llama/Llama-3.1-8B-Instruct", "task": "text-generation"},
			"compute":  map[string]any{"accelerator": "gpu", "instanceType": "nvidia-l4", "instanceSize": "x1", "scaling": map[string]any{"minReplica": 0, "maxReplica": 1, "scaleToZeroTimeout": 15}},
			"provider": map[string]any{"vendor": "aws", "region": "us-east-1"},
			"status":   map[string]any{"state": f.epState, "url": "https://abc123xyz.us-east-1.aws.endpoints.huggingface.cloud", "readyReplica": 1, "targetReplica": 1}}
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/whoami-v2":
		io.WriteString(w, `{"type":"user","name":"ana","fullname":"Ana B","email":"ana@example.com","isPro":true,"orgs":[{"name":"acme"}],"auth":{"type":"access_token","accessToken":{"displayName":"conduit","role":"write"}}}`)
	case "GET /api/models":
		if r.URL.Query().Get("author") == "" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"id":"`+r.URL.Query().Get("author")+`/tiny-bert","private":false,"downloads":120,"likes":3,"pipeline_tag":"fill-mask","library_name":"transformers","createdAt":"2026-01-01T00:00:00.000Z"}]`)
	case "GET /api/datasets":
		io.WriteString(w, `[{"id":"ana/reviews","private":true,"downloads":5,"likes":0,"gated":"manual"}]`)
	case "GET /api/spaces":
		io.WriteString(w, `[{"id":"ana/demo","private":false,"likes":9,"sdk":"gradio"}]`)
	case "GET /api/spaces/ana/demo/runtime":
		enc.Encode(map[string]any{"stage": f.stage, "hardware": map[string]any{"current": "t4-small", "requested": "t4-small"}, "gcTimeout": 3600})
	case "POST /api/spaces/ana/demo/restart":
		f.stage = "BUILDING"
		if r.URL.Query().Get("factory") == "true" {
			f.stage = "BUILDING_FACTORY"
		}
	case "POST /api/spaces/ana/demo/pause":
		f.stage = "PAUSED"
	case "GET /v2/endpoint/ana":
		enc.Encode(map[string]any{"items": []any{ep()}})
	case "GET /v2/endpoint/ana/llama-ep":
		enc.Encode(ep())
	case "POST /v2/endpoint/ana/llama-ep/scale-to-zero":
		f.epState = "scaledToZero"
		enc.Encode(ep())
	case "POST /v2/endpoint/ana/llama-ep/pause":
		f.epState = "paused"
		enc.Encode(ep())
	case "POST /v2/endpoint/ana/llama-ep/resume":
		f.epState = "initializing"
		enc.Encode(ep())
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Repository not found"}`)
	}
}

var secrets = map[string]string{"secret://w": "hf_write", "secret://r": "hf_read", "secret://bad": "hf_nope"}

func setup(t *testing.T, ref string) (*Module, *fake) {
	f := &fake{stage: "RUNNING", epState: "running"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base, m.EndpointsBase = srv.URL, srv.URL
	raw, _ := json.Marshal(Config{Token: ref})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "h", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "h", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestHuggingFaceReads(t *testing.T) {
	m, f := setup(t, "secret://w")
	if h := m.Health(context.Background(), "h"); h.Status != "ok" || h.Message != "signed in as ana (write token)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"whoami", ``, `"orgs":["acme"]`},
		{"models", ``, `"id":"ana/tiny-bert"`},
		{"models", `{"author":"acme","search":"bert"}`, `"id":"acme/tiny-bert"`},
		{"datasets", ``, `"gated":"manual"`},
		{"spaces", ``, `"sdk":"gradio"`},
		{"space_status", `{"space":"ana/demo"}`, `"stage":"RUNNING"`},
		{"endpoints", ``, `"state":"running"`},
		{"endpoint_status", `{"name":"llama-ep"}`, `"hardware":"nvidia-l4 x1"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "ana@example.com") || strings.Contains(out, "hf_write") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if !strings.Contains(strings.Join(f.seen, "\n"), "author=acme&direction=-1&limit=50&search=bert&sort=lastModified") {
		t.Fatal(f.seen)
	}
}

func TestHuggingFaceSpaceControl(t *testing.T) {
	m, f := setup(t, "secret://w")
	r, err := invoke(m, "pause_space", `{"space":"ana/demo"}`, true)
	if err != nil || r.Plan == nil || f.stage != "RUNNING" || !strings.Contains(r.Plan.Summary, "now running on t4-small") {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "pause_space", `{"space":"ana/demo"}`, false); err != nil || !strings.Contains(string(r.Output), `"stage":"PAUSED"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "restart_space", `{"space":"ana/demo","factory":true}`, false); err != nil || !strings.Contains(string(r.Output), `"stage":"BUILDING_FACTORY"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "pause_space", `{"space":"ana/demo","factory":true}`, false); err == nil {
		t.Fatal("factory pause accepted")
	}
}

func TestHuggingFaceEndpointControl(t *testing.T) {
	m, f := setup(t, "secret://w")
	r, err := invoke(m, "resume_endpoint", `{"name":"llama-ep"}`, true)
	if err != nil || r.Plan == nil || f.epState != "running" || !strings.Contains(r.Plan.Summary, "billed by the hour on nvidia-l4 x1") {
		t.Fatalf("%+v %v", r, err)
	}
	for action, want := range map[string]string{"scale_endpoint_to_zero": "scaledToZero", "pause_endpoint": "paused", "resume_endpoint": "initializing"} {
		if r, err := invoke(m, action, `{"name":"llama-ep","namespace":"ana"}`, false); err != nil || f.epState != want || !strings.Contains(string(r.Output), `"state":"`+want+`"`) {
			t.Fatalf("%s: %s %v", action, r.Output, err)
		}
	}
	risk := map[string]sdk.Risk{}
	for _, a := range m.Manifest().Actions {
		risk[a.Name] = a.Risk
		if a.Risk != sdk.RiskRead && !a.DryRun {
			t.Fatalf("%s has no preview", a.Name)
		}
	}
	for n, want := range map[string]sdk.Risk{"restart_space": sdk.RiskDestructive, "pause_space": sdk.RiskDestructive, "pause_endpoint": sdk.RiskDestructive, "resume_endpoint": sdk.RiskDestructive, "scale_endpoint_to_zero": sdk.RiskDestructive} {
		if risk[n] != want {
			t.Fatalf("%s is %s", n, risk[n])
		}
	}
}

func TestHuggingFaceRefusals(t *testing.T) {
	m, f := setup(t, "secret://w")
	n := len(f.seen)
	for _, c := range []struct{ action, in string }{
		{"space_status", `{"space":"demo"}`},
		{"space_status", `{"space":"ana/../../api/whoami"}`},
		{"restart_space", `{"space":"ana/demo/restart?factory=true"}`},
		{"pause_space", `{"space":"../x"}`},
		{"models", `{"author":"a/b"}`},
		{"models", `{"author":"ana","search":"x&author=evil"}`},
		{"endpoint_status", `{"name":"Llama_EP"}`},
		{"resume_endpoint", `{"name":"llama-ep/../../x"}`},
		{"resume_endpoint", `{"name":"llama-ep","namespace":"../acme"}`},
		{"delete_space", `{"space":"ana/demo"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s %s accepted", c.action, c.in)
		}
	}
	if len(f.seen) != n {
		t.Fatalf("bad input reached the server: %v", f.seen[n:])
	}
	if _, err := invoke(m, "space_status", `{"space":"ana/nope"}`, false); err == nil || !strings.Contains(err.Error(), "no Space ana/nope") {
		t.Fatal(err)
	}
	ro, _ := setup(t, "secret://r")
	if _, err := invoke(ro, "pause_space", `{"space":"ana/demo"}`, false); err == nil || !strings.Contains(err.Error(), "lacks the permission") {
		t.Fatal(err)
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "h"); h.Status != "down" || h.Message != "Hugging Face refused the token" {
		t.Fatalf("%+v", h)
	}
	for _, raw := range []string{`{}`, `{"token":"hf_plain"}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
}

func TestHuggingFaceRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base, m.EndpointsBase = srv.URL, srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://w"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "h", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "h"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
	if _, err := invoke(m, "endpoints", `{"namespace":"ana"}`, false); err == nil || hit {
		t.Fatal("followed the redirect")
	}
}
