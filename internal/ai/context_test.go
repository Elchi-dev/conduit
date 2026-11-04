package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// guide is a module that offers agent context: two documents, a prompt,
// and entries pointing at a write action, which must be ignored.
type guide struct{ calls []string }

func (g *guide) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "guide", Name: "Guide", Actions: []sdk.ActionSpec{
		{Name: "get", Risk: sdk.RiskRead},
		{Name: "brief", Risk: sdk.RiskRead},
		{Name: "save", Risk: sdk.RiskWrite},
	}}
}
func (g *guide) Configure(context.Context, sdk.Host, string, json.RawMessage) error { return nil }
func (g *guide) Health(context.Context, string) sdk.Health                          { return sdk.Health{Status: "ok"} }
func (g *guide) Close(string) error                                                 { return nil }
func (g *guide) Invoke(_ context.Context, c sdk.Call) (sdk.Result, error) {
	g.calls = append(g.calls, c.Action+" "+string(c.Input))
	var in map[string]string
	_ = json.Unmarshal(c.Input, &in)
	switch c.Action {
	case "get":
		return sdk.JSON(map[string]string{"markdown": "# " + in["id"] + "\n- MUST be kind"})
	case "brief":
		return sdk.JSON("Brief for " + in["task"] + " from " + in["id"])
	}
	return sdk.JSON(map[string]bool{"saved": true})
}
func (g *guide) AgentContext(context.Context, string) sdk.AgentContextSpec {
	return sdk.AgentContextSpec{
		Instructions: "Call guide__brief before writing.",
		Resources: []sdk.AgentResource{
			{URI: "conduit://guide/tone", Name: "tone", Title: "Tone", MimeType: "text/markdown", Action: "get", Input: json.RawMessage(`{"id":"tone"}`)},
			{URI: "conduit://guide/a11y", Name: "a11y", Action: "get", Input: json.RawMessage(`{"id":"a11y"}`)},
			{URI: "conduit://guide/sneaky", Name: "sneaky", Action: "save"},
		},
		Prompts: []sdk.AgentPrompt{
			{Name: "kit", Title: "Kit", Action: "brief", Input: json.RawMessage(`{"id":"kit"}`),
				Arguments: []sdk.AgentPromptArgument{{Name: "task", Required: true}}},
			{Name: "sneaky", Action: "save"},
		},
	}
}

func TestMCPResourcesAndPrompts(t *testing.T) {
	e, tb, _, _ := setup(t)
	ctx := context.Background()
	g := &guide{}
	if err := e.Register(g); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SaveInstance(ctx, core.Instance{ID: "guide", Module: "guide", Name: "Guide", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rpc := func(method string, params any) map[string]any {
		t.Helper()
		b, _ := json.Marshal(params)
		res, e := Dispatch(ctx, tb, method, b)
		if e != nil {
			t.Fatalf("%s: %s", method, e.Message)
		}
		out, _ := json.Marshal(res)
		var m map[string]any
		_ = json.Unmarshal(out, &m)
		return m
	}

	init := rpc("initialize", map[string]string{"protocolVersion": "2025-06-18"})
	if ins, _ := init["instructions"].(string); !strings.Contains(ins, "conduit_overview") || !strings.Contains(ins, "guide__brief") {
		t.Fatalf("instructions %q", ins)
	}
	caps, _ := init["capabilities"].(map[string]any)
	if caps["resources"] == nil || caps["prompts"] == nil {
		t.Fatalf("capabilities %v", caps)
	}

	res := rpc("resources/list", nil)["resources"].([]any)
	if len(res) != 2 || res[0].(map[string]any)["uri"] != "conduit://guide/a11y" || res[1].(map[string]any)["title"] != "Tone" {
		t.Fatalf("resources %v", res)
	}
	read := rpc("resources/read", map[string]string{"uri": "conduit://guide/tone"})
	c := read["contents"].([]any)[0].(map[string]any)
	if c["text"] != "# tone\n- MUST be kind" || c["mimeType"] != "text/markdown" {
		t.Fatalf("read %v", c)
	}
	if _, e := Dispatch(ctx, tb, "resources/read", json.RawMessage(`{"uri":"conduit://guide/sneaky"}`)); e == nil || e.Code != -32002 {
		t.Fatalf("a resource backed by a write action was readable: %v", e)
	}

	prompts := rpc("prompts/list", nil)["prompts"].([]any)
	if len(prompts) != 1 || prompts[0].(map[string]any)["name"] != "guide__kit" {
		t.Fatalf("prompts %v", prompts)
	}
	got := rpc("prompts/get", map[string]any{"name": "guide__kit", "arguments": map[string]string{"task": "a launch post"}})
	msg := got["messages"].([]any)[0].(map[string]any)
	if msg["role"] != "user" || msg["content"].(map[string]any)["text"] != "Brief for a launch post from kit" {
		t.Fatalf("prompt %v", got)
	}
	if _, e := Dispatch(ctx, tb, "prompts/get", json.RawMessage(`{"name":"guide__kit"}`)); e == nil {
		t.Fatal("missing required argument accepted")
	}

	// Content went through the engine: audited, as the agent.
	list, err := e.Audit.List(ctx, core.Query{Module: "guide", Limit: 10})
	if err != nil || len(list) != 2 {
		t.Fatalf("audit %d entries, %v", len(list), err)
	}
	for _, en := range list {
		if en.Actor.Kind != core.ActorAgent {
			t.Fatalf("read as %v", en.Actor)
		}
	}

	// Without the module's scope, nothing is listed.
	tb.Allows = func(s string) bool { return s != "actions:guide:invoke" }
	if r := rpc("resources/list", nil)["resources"].([]any); len(r) != 0 {
		t.Fatalf("listed without scope: %v", r)
	}
	if ins := tb.Instructions(ctx); strings.Contains(ins, "guide__brief") {
		t.Fatal("instructions mention a module the caller can't use")
	}
}
