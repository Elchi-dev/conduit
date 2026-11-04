package daemon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// safe has a sensitive action whose preview quotes private content.
type safe struct{}

func (safe) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "safe", Name: "Safe", Version: "1.0.0", Actions: []sdk.ActionSpec{
		{Name: "shred", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true},
	}}
}
func (safe) Configure(context.Context, sdk.Host, string, json.RawMessage) error { return nil }
func (safe) Health(context.Context, string) sdk.Health                          { return sdk.Health{Status: "ok"} }
func (safe) Close(string) error                                                 { return nil }
func (safe) Invoke(_ context.Context, c sdk.Call) (sdk.Result, error) {
	if c.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Shred PRIVATE-LETTER", Changes: []sdk.Change{{Target: "letter", Op: "delete", Before: json.RawMessage(`"PRIVATE-LETTER"`)}}}}, nil
	}
	return sdk.Result{}, nil
}

// A sensitive action's approval plan is shown in full only to people who
// can decide approvals; an agent key that can read approvals gets it
// redacted, from the call, the list and the approval itself.
func TestApprovalPlanOnlyForDeciders(t *testing.T) {
	app, c, _, _ := setup(t)
	if err := app.Engine.Register(safe{}); err != nil {
		t.Fatal(err)
	}
	var in core.Instance
	if code := c.do("POST", "/api/v1/instances", map[string]any{"module": "safe", "name": "Safe"}, &in); code != 201 {
		t.Fatalf("create instance = %d", code)
	}
	var k keyResp
	if code := c.do("POST", "/api/v1/keys", map[string]any{"name": "agent", "kind": "agent", "scopes": []string{"actions:*:invoke", "modules:*:read", "approvals:*:read"}}, &k); code != 201 {
		t.Fatalf("create key = %d", code)
	}
	agent := client{t: t, base: c.base, token: k.Secret}

	var pending core.Outcome
	if code := agent.do("POST", "/api/v1/instances/"+in.ID+"/actions/shred", map[string]any{}, &pending); code != 202 || pending.Approval == nil {
		t.Fatalf("agent call = %d", code)
	}
	leaks := func(v any) bool { b, _ := json.Marshal(v); return strings.Contains(string(b), "PRIVATE-LETTER") }
	if leaks(pending) {
		t.Fatalf("the caller got the private plan: %+v", pending.Approval)
	}
	var one core.Approval
	var list []core.Approval
	agent.do("GET", "/api/v1/approvals/"+pending.Approval.ID, nil, &one)
	agent.do("GET", "/api/v1/approvals?status=pending", nil, &list)
	if one.ID == "" || leaks(one) || len(list) != 1 || leaks(list) || one.Plan == nil || !one.PlanPrivate {
		t.Fatalf("a reader who can't decide sees the plan: %+v %+v", one, list)
	}
	// The owner, who decides, sees it all.
	one, list = core.Approval{}, nil
	c.do("GET", "/api/v1/approvals/"+pending.Approval.ID, nil, &one)
	c.do("GET", "/api/v1/approvals?status=pending", nil, &list)
	if !leaks(one) || !leaks(list) {
		t.Fatalf("the decider doesn't see the plan: %+v %+v", one, list)
	}
	// The audit log never has it (nor a dry run's entry).
	if code := c.do("POST", "/api/v1/instances/"+in.ID+"/actions/shred", map[string]any{"dryRun": true}, nil); code != 200 {
		t.Fatalf("dry run = %d", code)
	}
	if code := c.do("POST", "/api/v1/approvals/"+pending.Approval.ID+"/deny", nil, nil); code != 200 {
		t.Fatalf("deny = %d", code)
	}
	var entries json.RawMessage
	c.do("GET", "/api/v1/audit?module=safe", nil, &entries)
	if !strings.Contains(string(entries), `"shred"`) || leaks(entries) {
		t.Fatalf("audit log: %s", entries)
	}
}
