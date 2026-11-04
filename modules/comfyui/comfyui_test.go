package comfyui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const apiWorkflow = `{
 "3":{"class_type":"KSampler","inputs":{"seed":42,"steps":20,"model":["4",0],"positive":["6",0]}},
 "4":{"class_type":"CheckpointLoaderSimple","inputs":{"ckpt_name":"sdxl.safetensors"}},
 "6":{"class_type":"CLIPTextEncode","inputs":{"text":"a lighthouse at dusk","clip":["4",1]},"_meta":{"title":"Positive"}},
 "9":{"class_type":"FaceDetailer","inputs":{"noise_seed":["10",0]}},
 "11":{"class_type":"SaveImage","inputs":{"filename_prefix":"lh"}}}`

type fake struct {
	mu      sync.Mutex
	seen    []string
	prompts []map[string]any
	pending int
	running bool
	token   string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	if f.token != "" && r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(401)
		return
	}
	enc := json.NewEncoder(w)
	switch r.Method + " " + r.URL.Path {
	case "GET /system_stats":
		io.WriteString(w, `{"system":{"os":"posix","ram_total":64000000000,"ram_free":32000000000,"comfyui_version":"0.3.66","python_version":"3.12.3","pytorch_version":"2.8.0","argv":["main.py","--listen","--secret-flag"]},"devices":[{"name":"cuda:0 NVIDIA GeForce RTX 4090 : cudaMallocAsync","type":"cuda","index":0,"vram_total":25757220864,"vram_free":20000000000}]}`)
	case "GET /queue":
		run := []any{}
		if f.running {
			run = append(run, []any{7, "11111111-2222-3333-4444-555555555555", map[string]any{"6": map[string]any{"class_type": "CLIPTextEncode", "inputs": map[string]any{"text": "private prompt"}}}, map[string]any{}, []string{"9"}})
		}
		pend := []any{}
		for i := 0; i < f.pending; i++ {
			pend = append(pend, []any{8 + i, "aaaaaaaa-0000-0000-0000-00000000000" + string(rune('0'+i)), map[string]any{}, map[string]any{}, []string{}})
		}
		enc.Encode(map[string]any{"queue_running": run, "queue_pending": pend})
	case "GET /history":
		if r.URL.Query().Get("max_items") == "" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{
		"p-old":{"prompt":[5,"p-old",{"6":{"class_type":"CLIPTextEncode","inputs":{"text":"old prompt"}}},{},["9"]],"outputs":{},"status":{"status_str":"error","completed":false,"messages":[]}},
		"p-new":{"prompt":[6,"p-new",{"6":{"class_type":"CLIPTextEncode","inputs":{"text":"a lighthouse at dusk"}},"7":{"class_type":"CLIPTextEncodeSDXL","inputs":{"text_g":"stormy","text_l":["4",1]}}},{},["9"]],
		 "outputs":{"9":{"images":[{"filename":"lh_00001_.png","subfolder":"","type":"output"},{"filename":"preview.png","subfolder":"","type":"temp"}]},"12":{"gifs":[{"filename":"clip.mp4","subfolder":"vid","type":"output"}]}},
		 "status":{"status_str":"success","completed":true,"messages":[["execution_start",{"prompt_id":"p-new","timestamp":1762250000000}],["execution_success",{"prompt_id":"p-new","timestamp":1762250012500}]]}}}`)
	case "GET /object_info":
		io.WriteString(w, `{"KSampler":{"python_module":"nodes"},"CheckpointLoaderSimple":{"python_module":"nodes"},"CLIPTextEncode":{"python_module":"nodes"},"SaveImage":{"python_module":"nodes"},"FaceDetailer":{"python_module":"custom_nodes.ComfyUI-Impact-Pack"}}`)
	case "POST /prompt":
		var b map[string]any
		_ = json.Unmarshal(body, &b)
		f.prompts = append(f.prompts, b)
		io.WriteString(w, `{"prompt_id":"bbbbbbbb-0000-0000-0000-000000000001","number":12,"node_errors":{}}`)
	case "POST /interrupt":
		f.running = false
		w.WriteHeader(200)
	case "POST /queue":
		var b map[string]any
		_ = json.Unmarshal(body, &b)
		if b["clear"] == true {
			f.pending = 0
		}
		w.WriteHeader(200)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fake, string) {
	dir := t.TempDir()
	wf := filepath.Join(dir, "workflows")
	if err := os.Mkdir(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(wf, "lighthouse.json"), []byte(apiWorkflow), 0o644)
	os.WriteFile(filepath.Join(wf, "editor.json"), []byte(`{"last_node_id":3,"nodes":[{"id":1,"type":"KSampler"}],"links":[]}`), 0o644)
	os.WriteFile(filepath.Join(dir, "outside.json"), []byte(apiWorkflow), 0o644)
	_ = os.Symlink(filepath.Join(dir, "outside.json"), filepath.Join(wf, "escape.json"))
	f := &fake{pending: 2, running: true}
	if cfg.Token != "" {
		f.token = "comfy-token"
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cfg.URL = srv.URL
	if cfg.WorkflowsDir == "set" {
		cfg.WorkflowsDir = wf
	}
	m := New()
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "comfy-token", "secret://bad": "nope"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f, wf
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestComfyReads(t *testing.T) {
	m, _, _ := setup(t, Config{Token: "secret://c", WorkflowsDir: "set"})
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || !strings.Contains(h.Message, "0.3.66, NVIDIA GeForce RTX 4090 with 20.0 of 25.8 GB free") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"system_stats", ``, `"name":"NVIDIA GeForce RTX 4090"`},
		{"queue", ``, `"pendingCount":2`},
		{"history", `{"limit":5}`, `"promptId":"p-new","number":6,"status":"success","completed":true,"started":"2025-11-04T09:53:20Z","seconds":12.5,"prompts":["a lighthouse at dusk","stormy"],"outputs":["lh_00001_.png","vid/clip.mp4"]`},
		{"workflows", ``, `{"bytes":`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "secret-flag") || strings.Contains(out, "private prompt") || strings.Contains(out, "preview.png") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	r, _ := invoke(m, "history", ``, false)
	if s := string(r.Output); strings.Index(s, "p-new") > strings.Index(s, "p-old") {
		t.Fatal("not newest first: " + s)
	}
	r, _ = invoke(m, "workflows", ``, false)
	s := string(r.Output)
	if !strings.Contains(s, `"file":"lighthouse.json"`) || !strings.Contains(s, `"usable":true`) || !strings.Contains(s, "Export (API)") || strings.Contains(s, "escape.json") {
		t.Fatal(s)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "history" && !a.Sensitive {
			t.Fatal("history must be sensitive")
		}
	}
}

func TestComfyQueueControl(t *testing.T) {
	m, f, _ := setup(t, Config{WorkflowsDir: "set"})
	r, err := invoke(m, "clear_queue", ``, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 2 || f.pending != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "clear_queue", ``, false); err != nil || f.pending != 0 || !strings.Contains(string(r.Output), `"removed":2`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "interrupt", ``, false); err != nil || f.running || !strings.Contains(string(r.Output), `"interrupted":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if !strings.Contains(strings.Join(f.seen, "\n"), `POST /interrupt {"prompt_id":"11111111-2222-3333-4444-555555555555"}`) {
		t.Fatal(f.seen)
	}
	if r, _ := invoke(m, "interrupt", ``, false); !strings.Contains(string(r.Output), "nothing is running") {
		t.Fatal(string(r.Output))
	}
}

func TestComfyQueueWorkflow(t *testing.T) {
	m, f, _ := setup(t, Config{WorkflowsDir: "set"})
	r, err := invoke(m, "queue_workflow", `{"file":"lighthouse.json","seed":7}`, true)
	if err != nil || r.Plan == nil || len(f.prompts) != 0 || !strings.Contains(r.Plan.Summary, "ComfyUI-Impact-Pack") || !strings.Contains(string(r.Plan.Changes[0].After), `"seed":7`) {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "queue_workflow", `{"file":"lighthouse.json","seed":7}`, false)
	if err != nil || len(f.prompts) != 1 || !strings.Contains(string(r.Output), `"number":12`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	g := f.prompts[0]["prompt"].(map[string]any)
	if g["3"].(map[string]any)["inputs"].(map[string]any)["seed"] != float64(7) {
		t.Fatal(g["3"])
	}
	// A seed that's a link to another node stays a link.
	if _, ok := g["9"].(map[string]any)["inputs"].(map[string]any)["noise_seed"].([]any); !ok {
		t.Fatal(g["9"])
	}
	if !strings.HasPrefix(f.prompts[0]["client_id"].(string), "conduit-") {
		t.Fatal(f.prompts[0])
	}
	risk := map[string]sdk.ActionSpec{}
	for _, a := range m.Manifest().Actions {
		risk[a.Name] = a
	}
	if risk["queue_workflow"].Risk != sdk.RiskDestructive || risk["clear_queue"].Risk != sdk.RiskDestructive || risk["interrupt"].Risk != sdk.RiskWrite {
		t.Fatal(risk)
	}
}

func TestComfyRefusals(t *testing.T) {
	m, f, wf := setup(t, Config{WorkflowsDir: "set"})
	n := len(f.seen)
	for _, in := range []string{
		`{"file":"../outside.json"}`,
		`{"file":"` + filepath.Join(filepath.Dir(wf), "outside.json") + `"}`,
		`{"file":"escape.json"}`,
		`{"file":"editor.json"}`,
		`{"file":"missing.json"}`,
		`{"file":"lighthouse.txt"}`,
		`{"file":"lighthouse.json","seed":-1}`,
		`{"file":"editor.json","seed":1}`,
		`{"workflow":{"1":{"class_type":"ExecutePython","inputs":{"code":"import os"}}}}`,
	} {
		if _, err := invoke(m, "queue_workflow", in, false); err == nil {
			t.Fatalf("%s accepted", in)
		}
		if _, err := invoke(m, "queue_workflow", in, true); err == nil {
			t.Fatalf("%s dry run accepted", in)
		}
	}
	if len(f.seen) != n {
		t.Fatalf("bad input reached the server: %v", f.seen[n:])
	}
	// Without a folder, queueing is off.
	off, f2, _ := setup(t, Config{})
	if _, err := invoke(off, "queue_workflow", `{"file":"lighthouse.json"}`, false); err == nil || !strings.Contains(err.Error(), "queueing is off") || len(f2.prompts) != 0 {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"url":"ftp://h"}`, `{"url":"http://h:8188","token":"plain"}`, `{"url":"http://h:8188","workflowsDir":"relative/dir"}`, `{"url":"http://a:b@h:8188"}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
	bad, _, _ := setup(t, Config{Token: "secret://bad"})
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || !strings.Contains(h.Message, "refused the token") {
		t.Fatalf("%+v", h)
	}
}

func TestComfyRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://c"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "comfy-token"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
