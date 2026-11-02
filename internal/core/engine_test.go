package core

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// counter is a test module with one reversible, dry-runnable write.
type counter struct {
	mu sync.Mutex
	n  map[string]int
}

func (c *counter) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "counter", Name: "Counter", Version: "1.0.0", Actions: []sdk.ActionSpec{
		{Name: "get", Risk: sdk.RiskRead},
		{Name: "add", Risk: sdk.RiskWrite, Reversible: true, DryRun: true},
		{Name: "reset", Risk: sdk.RiskDestructive},
	}}
}

func (c *counter) Configure(context.Context, sdk.Host, string, json.RawMessage) error { return nil }
func (c *counter) Health(context.Context, string) sdk.Health                          { return sdk.Health{Status: "ok"} }
func (c *counter) Close(string) error                                                 { return nil }

func (c *counter) Invoke(_ context.Context, call sdk.Call) (sdk.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[string]int{}
	}
	var in struct{ By int }
	_ = json.Unmarshal(call.Input, &in)
	switch call.Action {
	case "get":
		b, _ := json.Marshal(c.n[call.Instance])
		return sdk.Result{Output: b}, nil
	case "add":
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "add", Changes: []sdk.Change{{Target: call.Instance, Op: "update"}}}}, nil
		}
		c.n[call.Instance] += in.By
		undo, _ := json.Marshal(map[string]int{"By": -in.By})
		return sdk.Result{Undo: &sdk.Undo{Action: "add", Input: undo, Description: "subtract again"}}, nil
	case "reset":
		c.n[call.Instance] = 0
		return sdk.Result{}, nil
	}
	return sdk.Result{}, errors.New("unknown action")
}

func (c *counter) value(id string) int { c.mu.Lock(); defer c.mu.Unlock(); return c.n[id] }

func newTestEngine(t *testing.T) (*Engine, *counter, string) {
	t.Helper()
	ctx := context.Background()
	st, err := OpenStore(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := NewEngine(st, nil)
	c := &counter{}
	if err := e.Register(c); err != nil {
		t.Fatal(err)
	}
	in, err := e.SaveInstance(ctx, Instance{Module: "counter", Name: "c1", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return e, c, in.ID
}

var (
	user  = Actor{ID: "owner", Kind: ActorUser}
	agent = Actor{ID: "test-agent", Kind: ActorAgent}
)

func add(by int) json.RawMessage { b, _ := json.Marshal(map[string]int{"By": by}); return b }

func TestUserActsDirectly(t *testing.T) {
	e, c, id := newTestEngine(t)
	if _, err := e.Invoke(context.Background(), user, sdk.Call{Instance: id, Action: "add", Input: add(2)}, InvokeOptions{}); err != nil {
		t.Fatal(err)
	}
	if c.value(id) != 2 {
		t.Fatalf("value = %d", c.value(id))
	}
}

func TestAgentDefaultPresetAsksForWrites(t *testing.T) {
	e, c, id := newTestEngine(t)
	ctx := context.Background()

	if _, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "get"}, InvokeOptions{}); err != nil {
		t.Fatalf("read should be allowed: %v", err)
	}
	out, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "add", Input: add(5)}, InvokeOptions{NoWait: true})
	if !errors.Is(err, ErrPending) || out.Approval == nil {
		t.Fatalf("want pending approval, got %v", err)
	}
	if out.Approval.Plan == nil {
		t.Fatal("approval should carry the dry-run plan")
	}

	// Blocking path: approve from another goroutine.
	done := make(chan error, 1)
	go func() {
		_, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "add", Input: add(3)}, InvokeOptions{})
		done <- err
	}()
	var pending []Approval
	for i := 0; i < 100; i++ {
		pending, _ = e.Approvals.List(ctx, "pending")
		if len(pending) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(pending) != 2 {
		t.Fatalf("pending = %d", len(pending))
	}
	if err := e.Approvals.Decide(ctx, pending[0].ID, true, user.Subject()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if c.value(id) != 3 {
		t.Fatalf("value = %d, want 3", c.value(id))
	}
}

func TestDeniedApprovalIsAudited(t *testing.T) {
	e, _, id := newTestEngine(t)
	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		_, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "reset"}, InvokeOptions{})
		done <- err
	}()
	var p []Approval
	for len(p) == 0 {
		p, _ = e.Approvals.List(ctx, "pending")
		time.Sleep(5 * time.Millisecond)
	}
	_ = e.Approvals.Decide(ctx, p[0].ID, false, "user:owner")
	if err := <-done; !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	entries, _ := e.Audit.List(ctx, Query{})
	if len(entries) == 0 || entries[0].Status != "denied" {
		t.Fatalf("last audit entry should be denied: %+v", entries)
	}
}

func TestRulesOverridePreset(t *testing.T) {
	e, _, id := newTestEngine(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	_ = e.Policy.PutRule(ctx, Rule{Subject: agent.Subject(), Module: "counter", Action: "add", Effect: Allow, ExpiresAt: &exp})
	_ = e.Policy.PutRule(ctx, Rule{Position: 1, Subject: "kind:agent", Risk: "destructive", Effect: Deny})
	if _, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "add", Input: add(1)}, InvokeOptions{}); err != nil {
		t.Fatalf("rule should allow: %v", err)
	}
	if _, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "reset"}, InvokeOptions{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("rule should deny: %v", err)
	}
	past := time.Now().Add(-time.Minute)
	_ = e.Policy.PutRule(ctx, Rule{ID: "expired", Position: -1, Subject: "*", Effect: Deny, ExpiresAt: &past})
	if _, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "get"}, InvokeOptions{}); err != nil {
		t.Fatalf("expired rule must not apply: %v", err)
	}
}

func TestPresets(t *testing.T) {
	cases := map[Preset][3]Effect{ // read, write, destructive
		PresetReadOnly:       {Allow, Deny, Deny},
		PresetAskWrites:      {Allow, Ask, Ask},
		PresetAskDestructive: {Allow, Allow, Ask},
		PresetFullAutonomy:   {Allow, Allow, Allow},
	}
	for p, want := range cases {
		for i, r := range []sdk.Risk{sdk.RiskRead, sdk.RiskWrite, sdk.RiskDestructive} {
			if got := p.decide(r); got != want[i] {
				t.Errorf("%s/%s = %s, want %s", p, r, got, want[i])
			}
		}
	}
}

func TestUndo(t *testing.T) {
	e, c, id := newTestEngine(t)
	ctx := context.Background()
	out, err := e.Invoke(ctx, user, sdk.Call{Instance: id, Action: "add", Input: add(7)}, InvokeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Undo(ctx, user, out.Audit.Seq, InvokeOptions{}); err != nil {
		t.Fatal(err)
	}
	if c.value(id) != 0 {
		t.Fatalf("value after undo = %d", c.value(id))
	}
	if _, err := e.Undo(ctx, user, out.Audit.Seq, InvokeOptions{}); err == nil {
		t.Fatal("second undo should fail")
	}
	got, _ := e.Audit.Get(ctx, out.Audit.Seq)
	if got.UndoneBy == nil {
		t.Fatal("entry should be marked undone")
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	e, _, id := newTestEngine(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, _ = e.Invoke(ctx, user, sdk.Call{Instance: id, Action: "add", Input: add(1)}, InvokeOptions{})
	}
	// Undo marks are outside the hash; undoing must not break the chain.
	list, _ := e.Audit.List(ctx, Query{Limit: 1})
	_, _ = e.Undo(ctx, user, list[0].Seq, InvokeOptions{})
	if v, _ := e.Audit.Verify(ctx); !v.OK || v.Entries != 6 {
		t.Fatalf("verify = %+v", v)
	}
	_, _ = e.Store.DB.Exec(`UPDATE audit_log SET input = '{"By":1000}' WHERE seq = 3`)
	v, _ := e.Audit.Verify(ctx)
	if v.OK || v.BrokenAt != 3 {
		t.Fatalf("tampering not detected: %+v", v)
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	e, c, id := newTestEngine(t)
	out, err := e.Invoke(context.Background(), agent, sdk.Call{Instance: id, Action: "add", Input: add(9), DryRun: true}, InvokeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Plan == nil || c.value(id) != 0 || out.Audit.Status != "planned" {
		t.Fatalf("dry run: plan=%v value=%d status=%s", out.Result.Plan, c.value(id), out.Audit.Status)
	}
}

func TestPanicFreezesAgents(t *testing.T) {
	e, _, id := newTestEngine(t)
	ctx := context.Background()
	_ = e.Policy.SetPreset(ctx, PresetFullAutonomy)
	_, _ = e.Invoke(ctx, Actor{ID: "k", Kind: ActorKey}, sdk.Call{Instance: id, Action: "reset"}, InvokeOptions{NoWait: true})
	if _, err := e.Panic(ctx, user); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "get"}, InvokeOptions{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("frozen agent read should be denied: %v", err)
	}
	if _, err := e.Invoke(ctx, user, sdk.Call{Instance: id, Action: "add", Input: add(1)}, InvokeOptions{}); err != nil {
		t.Fatalf("user must still act during panic: %v", err)
	}
	_ = e.Unpanic(ctx, user)
	if _, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "get"}, InvokeOptions{}); err != nil {
		t.Fatalf("after unpanic: %v", err)
	}
}

func TestBusPrefix(t *testing.T) {
	b := NewBus()
	ch, stop := b.Subscribe("mail.", 4)
	defer stop()
	b.Publish(sdk.Event{Type: "server.down"})
	b.Publish(sdk.Event{Type: "mail.received"})
	select {
	case ev := <-ch:
		if ev.Type != "mail.received" {
			t.Fatalf("got %s", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
}
