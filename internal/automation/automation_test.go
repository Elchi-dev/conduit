package automation

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "rec", Name: "Recorder", Actions: []sdk.ActionSpec{{Name: "note", Risk: sdk.RiskWrite}, {Name: "get", Risk: sdk.RiskRead}}}
}
func (r *recorder) Configure(context.Context, sdk.Host, string, json.RawMessage) error { return nil }
func (r *recorder) Health(context.Context, string) sdk.Health                          { return sdk.Health{Status: "ok"} }
func (r *recorder) Close(string) error                                                 { return nil }
func (r *recorder) Invoke(_ context.Context, c sdk.Call) (sdk.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c.Action+":"+string(c.Input))
	return sdk.JSON(map[string]any{"count": len(r.calls), "word": "hello"})
}
func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.calls...)
}

var person = core.Actor{ID: "owner", Kind: core.ActorUser}

func setup(t *testing.T) (*Service, *recorder, string, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	st, err := core.OpenStore(ctx, t.TempDir()+"/a.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := core.NewEngine(st, nil)
	rec := &recorder{}
	_ = e.Register(rec)
	in, _ := e.SaveInstance(ctx, core.Instance{Module: "rec", Name: "Rec", Enabled: true})
	s := New(e)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return s, rec, in.ID, ctx
}

func TestPersonSavedAutomationRunsWithoutAsking(t *testing.T) {
	s, rec, inst, ctx := setup(t)
	a, err := s.Save(ctx, Automation{Name: "Two steps", Enabled: true, Trigger: Trigger{Kind: "manual"}, Steps: []Step{
		{Instance: inst, Action: "note", Input: json.RawMessage(`{"text":"first"}`)},
		{Instance: inst, Action: "note", Input: json.RawMessage(`{"prev":"{{steps.0.output.word}} #{{steps.0.output.count}}","n":"{{steps.0.output.count}}"}`)},
	}}, person)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.Run(ctx, a.ID, nil)
	if err != nil || run.Status != "ok" {
		t.Fatalf("run = %+v, %v", run, err)
	}
	calls := rec.all()
	if len(calls) != 2 || calls[1] != `note:{"n":1,"prev":"hello #1"}` {
		t.Fatalf("calls = %v", calls)
	}
	if _, err := s.Run(ctx, a.ID, nil); err == nil {
		t.Fatal("second run within 5 seconds should be refused")
	}
	runs, _ := s.Runs(ctx, a.ID, 10)
	if len(runs) != 1 || runs[0].Status != "ok" || len(runs[0].Steps) != 2 {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestAgentDraftIsDisabledAndAsks(t *testing.T) {
	s, rec, inst, ctx := setup(t)
	agent := core.Actor{ID: "k1", Kind: core.ActorAgent}
	a, err := s.Save(ctx, Automation{Name: "Sneaky", Enabled: true, Trigger: Trigger{Kind: "manual"}, Steps: []Step{{Instance: inst, Action: "note"}}}, agent)
	if err != nil {
		t.Fatal(err)
	}
	if a.Enabled || a.Trusted {
		t.Fatal("agent-saved automation must start disabled and untrusted")
	}
	if _, err := s.SetEnabled(ctx, a.ID, true, agent); err == nil {
		t.Fatal("agent enabled its own automation")
	}
	rctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	run, _ := s.Run(rctx, a.ID, nil)
	if run.Status == "ok" || len(rec.all()) != 0 {
		t.Fatalf("untrusted step ran without approval: %+v", run)
	}
	// A person enabling it makes it trusted.
	a, err = s.SetEnabled(ctx, a.ID, true, person)
	if err != nil || !a.Trusted {
		t.Fatalf("person enable: %+v %v", a, err)
	}
}

func TestEventTriggerWithMatch(t *testing.T) {
	s, rec, inst, ctx := setup(t)
	_, err := s.Save(ctx, Automation{Name: "On down", Enabled: true,
		Trigger: Trigger{Kind: "event", Event: "web.down", Match: map[string]string{"data.name": "Shop"}},
		Steps:   []Step{{Instance: inst, Action: "note", Input: json.RawMessage(`{"site":"{{trigger.data.name}}"}`)}}}, person)
	if err != nil {
		t.Fatal(err)
	}
	// The trigger watcher subscribes in the background, so keep publishing
	// until it has seen an event (a slow CI machine may miss the first).
	deadline := time.Now().Add(10 * time.Second)
	for len(rec.all()) == 0 && time.Now().Before(deadline) {
		s.engine.Bus.Publish(sdk.Event{Type: "web.down", Module: "web", Data: json.RawMessage(`{"name":"Blog"}`)})
		s.engine.Bus.Publish(sdk.Event{Type: "web.down", Module: "web", Data: json.RawMessage(`{"name":"Shop"}`)})
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	calls := rec.all()
	if len(calls) == 0 {
		t.Fatal("the automation never ran")
	}
	for _, c := range calls {
		if !strings.Contains(c, `"site":"Shop"`) {
			t.Fatalf("an event that doesn't match ran it: %v", calls)
		}
	}
}

func TestValidation(t *testing.T) {
	s, _, inst, ctx := setup(t)
	bad := []Automation{
		{Name: "", Trigger: Trigger{Kind: "manual"}, Steps: []Step{{Instance: inst, Action: "note"}}},
		{Name: "x", Trigger: Trigger{Kind: "schedule", Cron: "every morning"}, Steps: []Step{{Instance: inst, Action: "note"}}},
		{Name: "x", Trigger: Trigger{Kind: "manual"}},
		{Name: "x", Trigger: Trigger{Kind: "manual"}, Steps: []Step{{Instance: inst, Action: "nope"}}},
		{Name: "x", Trigger: Trigger{Kind: "manual"}, Steps: []Step{{Instance: "missing", Action: "note"}}},
	}
	for i, a := range bad {
		if _, err := s.Save(ctx, a, person); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	a, err := s.Save(ctx, Automation{Name: "Hook", Enabled: true, Trigger: Trigger{Kind: "webhook"}, Steps: []Step{{Instance: inst, Action: "get"}}}, person)
	if err != nil || !strings.HasPrefix(a.HookURL, "/hooks/") {
		t.Fatalf("webhook: %+v %v", a, err)
	}
	got, err := s.ByHookToken(ctx, strings.TrimPrefix(a.HookURL, "/hooks/"))
	if err != nil || got.ID != a.ID {
		t.Fatal("lookup by hook token failed")
	}
	a2, _ := s.Save(ctx, a, person)
	if a2.HookURL != a.HookURL {
		t.Fatal("hook URL must stay stable across edits")
	}
}
