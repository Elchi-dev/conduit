package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type light struct {
	mu sync.Mutex
	on bool
}

func (l *light) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "light", Name: "Light", Actions: []sdk.ActionSpec{
		{Name: "status", Title: "Status", Risk: sdk.RiskRead},
		{Name: "toggle", Title: "Toggle", Risk: sdk.RiskWrite, DryRun: true},
	}}
}
func (l *light) Configure(context.Context, sdk.Host, string, json.RawMessage) error { return nil }
func (l *light) Health(context.Context, string) sdk.Health                          { return sdk.Health{Status: "ok"} }
func (l *light) Close(string) error                                                 { return nil }
func (l *light) Invoke(_ context.Context, c sdk.Call) (sdk.Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c.Action == "status" {
		return sdk.JSON(map[string]bool{"on": l.on})
	}
	if c.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "toggle"}}, nil
	}
	l.on = !l.on
	return sdk.JSON(map[string]bool{"on": l.on})
}

type secrets map[string]string

func (s secrets) Resolve(_ context.Context, ref string) (string, error) {
	if v, ok := s[ref]; ok {
		return v, nil
	}
	return "", errors.New("no")
}

func setup(t *testing.T) (*core.Engine, *Toolbox, *core.Store, *light) {
	t.Helper()
	ctx := context.Background()
	st, err := core.OpenStore(ctx, t.TempDir()+"/ai.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := core.NewEngine(st, nil)
	l := &light{}
	_ = e.Register(l)
	_, _ = e.SaveInstance(ctx, core.Instance{ID: "lamp", Module: "light", Name: "Desk lamp", Enabled: true})
	tb := &Toolbox{Engine: e, Actor: core.Actor{ID: "assistant-u", Kind: core.ActorAgent, Name: "Assistant"}, Allows: func(string) bool { return true }}
	return e, tb, st, l
}

// fakeModel replies with a tool call on the first request and plain text
// on the next, in the OpenAI or Anthropic wire format.
func fakeModel(t *testing.T, kind string, tool string) (*httptest.Server, *[]map[string]any) {
	var mu sync.Mutex
	var seen []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		mu.Lock()
		seen = append(seen, body)
		n := len(seen)
		mu.Unlock()
		if kind == "openai" {
			if r.Header.Get("Authorization") != "Bearer sk-test" {
				w.WriteHeader(401)
				w.Write([]byte(`{"error":{"message":"bad key"}}`))
				return
			}
			if n == 1 {
				w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"` + tool + `","arguments":"{}"}}]}}]}`))
				return
			}
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Done looking."}}]}`))
			return
		}
		if r.Header.Get("x-api-key") != "sk-test" || r.Header.Get("anthropic-version") == "" {
			w.WriteHeader(401)
			return
		}
		if n == 1 {
			w.Write([]byte(`{"content":[{"type":"text","text":"Let me check."},{"type":"tool_use","id":"tu1","name":"` + tool + `","input":{}}]}`))
			return
		}
		w.Write([]byte(`{"content":[{"type":"text","text":"Done looking."}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestAgentToolLoop(t *testing.T) {
	for _, kind := range []string{"openai", "anthropic"} {
		t.Run(kind, func(t *testing.T) {
			_, tb, st, _ := setup(t)
			srv, seen := fakeModel(t, kind, "lamp__status")
			p := NewProviders(st, secrets{"secret://ai": "sk-test"})
			ctx := context.Background()
			base := srv.URL
			if kind == "openai" {
				base += "/v1"
			}
			if _, err := p.Save(ctx, Provider{Name: "Test", Kind: kind, BaseURL: base, Model: "m", APIKey: "secret://ai"}); err != nil {
				t.Fatal(err)
			}
			a := &Agent{DB: st.DB, Providers: p}
			var steps []Step
			if err := a.Chat(ctx, tb, "u", "Alex", "", "Is the lamp on?", func(s Step) { steps = append(steps, s) }); err != nil {
				t.Fatal(err)
			}
			var types []string
			for _, s := range steps {
				types = append(types, s.Type)
			}
			got := strings.Join(types, ",")
			want := "tool,result,text,done"
			if kind == "anthropic" {
				want = "text,tool,result,text,done"
			}
			if got != want {
				t.Fatalf("steps = %s, want %s (%+v)", got, want, steps)
			}
			if !strings.Contains(steps[len(steps)-3].Text, `"on": false`) {
				t.Fatalf("tool result missing: %+v", steps)
			}
			// The second request must carry the tool result back to the model.
			second, _ := json.Marshal((*seen)[1])
			if !strings.Contains(string(second), `on`) {
				t.Fatalf("tool result not sent back: %s", second)
			}
			conv := steps[len(steps)-1].Conversation
			c, err := a.Get(ctx, "u", conv)
			if err != nil || len(c.Messages) != 4 || c.Title != "Is the lamp on?" {
				t.Fatalf("conversation = %+v, %v", c, err)
			}
			if _, err := a.Get(ctx, "someone-else", conv); err == nil {
				t.Fatal("another user read the conversation")
			}
		})
	}
}

func TestAgentStopsAtApproval(t *testing.T) {
	_, tb, st, l := setup(t)
	srv, _ := fakeModel(t, "openai", "lamp__toggle")
	p := NewProviders(st, secrets{"secret://ai": "sk-test"})
	ctx := context.Background()
	_, _ = p.Save(ctx, Provider{Kind: "openai", BaseURL: srv.URL + "/v1", Model: "m", APIKey: "secret://ai"})
	a := &Agent{DB: st.DB, Providers: p}
	var approval *core.Approval
	_ = a.Chat(ctx, tb, "u", "Alex", "", "Turn on the lamp", func(s Step) {
		if s.Approval != nil {
			approval = s.Approval
		}
	})
	if approval == nil || l.on {
		t.Fatal("assistant must wait for approval before changing anything")
	}
	if approval.Plan == nil {
		t.Fatal("approval should carry the dry-run plan")
	}
}

func TestProviderValidation(t *testing.T) {
	_, _, st, _ := setup(t)
	p := NewProviders(st, secrets{})
	ctx := context.Background()
	bad := []Provider{
		{Kind: "other", BaseURL: "https://x", Model: "m"},
		{Kind: "openai", BaseURL: "http://api.example.com/v1", Model: "m"},
		{Kind: "openai", BaseURL: "https://api.example.com/v1", Model: "m", APIKey: "sk-plaintext"},
		{Kind: "openai", BaseURL: "https://api.example.com/v1"},
	}
	for i, pr := range bad {
		if _, err := p.Save(ctx, pr); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := p.Save(ctx, Provider{Kind: "openai", BaseURL: "http://127.0.0.1:11434/v1", Model: "llama"}); err != nil {
		t.Fatalf("local http should be allowed: %v", err)
	}
	if pr, _ := p.Get(ctx, ""); !pr.Default {
		t.Fatal("first provider becomes the default")
	}
}

func TestToolsHonourScopes(t *testing.T) {
	_, tb, _, _ := setup(t)
	tb.Allows = func(s string) bool { return s == "actions:light:invoke" }
	names := map[string]bool{}
	for _, tl := range tb.Tools() {
		names[tl.Name] = true
	}
	if !names["lamp__status"] || names["conduit_what_changed"] || names["conduit_undo"] {
		t.Fatalf("tools = %v", names)
	}
	tb.Allows = func(string) bool { return false }
	if res := tb.Call(context.Background(), "lamp__status", nil); !res.IsError {
		t.Fatal("tool callable without scope")
	}
}
