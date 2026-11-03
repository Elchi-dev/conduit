package ollama

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestOllama(t *testing.T) {
	installed := map[string]bool{"llama3.2:3b": true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		switch r.Method + " " + r.URL.Path {
		case "GET /api/version":
			io.WriteString(w, `{"version":"0.12.3"}`)
		case "GET /api/tags":
			io.WriteString(w, `{"models":[{"name":"llama3.2:3b","size":2000000000,"modified_at":"2026-11-01T10:00:00Z","details":{"family":"llama","parameter_size":"3.2B","quantization_level":"Q4_K_M"}}]}`)
		case "GET /api/ps":
			io.WriteString(w, `{"models":[{"name":"llama3.2:3b","size":3000,"size_vram":1500,"expires_at":"2026-11-03T23:00:00Z"}]}`)
		case "POST /api/pull":
			fl := w.(http.Flusher)
			model := b["model"].(string)
			if model == "slow:1b" {
				fmt.Fprintln(w, `{"status":"pulling","total":100,"completed":40}`)
				fl.Flush()
				<-r.Context().Done()
				return
			}
			if model == "missing:1b" {
				fmt.Fprintln(w, `{"error":"pull model manifest: file does not exist"}`)
				return
			}
			for _, l := range []string{`{"status":"pulling manifest"}`, `{"status":"pulling","total":100,"completed":50}`, `{"status":"verifying sha256 digest"}`, `{"status":"success"}`} {
				fmt.Fprintln(w, l)
				fl.Flush()
			}
			installed[model] = true
		case "DELETE /api/delete":
			if !installed[b["model"].(string)] {
				w.WriteHeader(404)
				return
			}
			delete(installed, b["model"].(string))
		case "POST /api/generate":
			if b["stream"] != false {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"response":"Hello!","eval_count":20,"eval_duration":1000000000}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	m.PullTimeout = 300 * time.Millisecond
	h := fakehost.New(nil)
	cfg, _ := json.Marshal(Config{URL: srv.URL})
	if err := m.Configure(ctx, h, "o", cfg); err != nil {
		t.Fatal(err)
	}
	if hl := m.Health(ctx, "o"); hl.Status != "ok" || !strings.Contains(hl.Message, "0.12.3") {
		t.Fatalf("health %+v", hl)
	}
	run := func(action, in string, dry bool) (sdk.Result, error) {
		return m.Invoke(ctx, sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(in), DryRun: dry})
	}
	if r, err := run("models", "", false); err != nil || !strings.Contains(string(r.Output), `"parameters":"3.2B"`) {
		t.Fatalf("models %s %v", r.Output, err)
	}
	if r, err := run("running", "", false); err != nil || !strings.Contains(string(r.Output), `"gpuPercent":50`) {
		t.Fatalf("running %s %v", r.Output, err)
	}
	if r, err := run("pull", `{"model":"qwen3:4b"}`, false); err != nil || !strings.Contains(string(r.Output), `"done"`) || !installed["qwen3:4b"] {
		t.Fatalf("pull %s %v", r.Output, err)
	}
	if r, err := run("pull", `{"model":"slow:1b"}`, false); err != nil || !strings.Contains(string(r.Output), `"percent":40`) {
		t.Fatalf("slow pull %s %v", r.Output, err)
	}
	if _, err := run("pull", `{"model":"missing:1b"}`, false); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("missing pull %v", err)
	}
	if _, err := run("pull", `{"model":"../../etc"}`, false); err == nil {
		t.Fatal("bad model name accepted")
	}
	if r, err := run("delete", `{"model":"qwen3:4b"}`, true); err != nil || r.Plan == nil || !installed["qwen3:4b"] {
		t.Fatalf("delete dry run %v", err)
	}
	if _, err := run("delete", `{"model":"qwen3:4b"}`, false); err != nil || installed["qwen3:4b"] {
		t.Fatalf("delete %v", err)
	}
	if r, err := run("generate", `{"model":"llama3.2:3b","prompt":"Say hello"}`, false); err != nil || !strings.Contains(string(r.Output), `"tokensPerSecond":20`) {
		t.Fatalf("generate %s %v", r.Output, err)
	}
	if err := m.Configure(ctx, h, "x", json.RawMessage(`{"url":"http://h:1","token":"plain"}`)); err == nil {
		t.Fatal("plaintext token accepted")
	}
}
