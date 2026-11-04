package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/automation"
	"github.com/elchi-dev/conduit/internal/core"
	vaultmod "github.com/elchi-dev/conduit/modules/vault"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// briefSetup is a daemon with a calendar holding one private event today,
// and an agent key that may invoke actions.
func briefSetup(t *testing.T) (*App, client, client, keyResp, core.Instance) {
	t.Helper()
	app, c, _, _ := setup(t)
	if err := registerBuiltins(app); err != nil {
		t.Fatal(err)
	}
	if err := ensureSingletons(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	day := time.Now().Format("20060102")
	ics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/calendar")
		io.WriteString(w, "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//x//EN\r\nBEGIN:VEVENT\r\nUID:1@x\r\nDTSTAMP:"+day+"T000000Z\r\nDTSTART;VALUE=DATE:"+day+"\r\nSUMMARY:PRIVATE consult\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	}))
	t.Cleanup(ics.Close)
	if code := c.do("POST", "/api/v1/vault/setup", map[string]string{"passphrase": "a long vault passphrase"}, nil); code != 200 {
		t.Fatalf("vault setup = %d", code)
	}
	if code := c.do("POST", "/api/v1/instances/"+vaultmod.InstanceID+"/actions/set", map[string]any{"input": map[string]string{"name": "cal/feed", "value": ics.URL + "/p.ics"}}, nil); code != 200 {
		t.Fatalf("set = %d", code)
	}
	var cal core.Instance
	if code := c.do("POST", "/api/v1/instances", map[string]any{"module": "calendar", "name": "Personal", "config": map[string]any{"mode": "ics", "feed": "secret://cal/feed"}}, &cal); code != 201 {
		t.Fatalf("calendar instance = %d", code)
	}
	var k keyResp
	if code := c.do("POST", "/api/v1/keys", map[string]any{"name": "agent", "kind": "agent", "scopes": []string{"actions:*:invoke", "modules:*:read"}}, &k); code != 201 {
		t.Fatalf("key = %d", code)
	}
	return app, c, client{t: t, base: c.base, token: k.Secret}, k, cal
}

func rule(t *testing.T, c client, subject, module string, effect core.Effect) {
	t.Helper()
	if code := c.do("POST", "/api/v1/policy/rules", map[string]any{"subject": subject, "module": module, "effect": effect}, nil); code != 200 {
		t.Fatalf("rule = %d", code)
	}
}

func briefOf(t *testing.T, c client) Brief {
	t.Helper()
	var out core.Outcome
	if code := c.do("POST", "/api/v1/instances/"+briefID+"/actions/brief", map[string]any{}, &out); code != 200 {
		t.Fatalf("brief = %d", code)
	}
	var br Brief
	if err := json.Unmarshal(out.Result.Output, &br); err != nil {
		t.Fatal(err)
	}
	return br
}

// The brief reads other modules as its caller: a section the caller's
// policy denies is left out, and the reads are audited under the caller.
func TestBriefReadsAsCaller(t *testing.T) {
	app, owner, agent, k, cal := briefSetup(t)
	rule(t, owner, "agent:"+k.Key.ID, "calendar", core.Deny)

	if br := briefOf(t, agent); len(br.Agenda) != 0 || len(br.Failures) != 0 {
		t.Fatalf("agent denied the calendar got %+v", br)
	}
	br := briefOf(t, owner)
	if len(br.Agenda) != 1 || br.Agenda[0].Title != "PRIVATE consult" {
		t.Fatalf("owner's brief agenda = %+v", br.Agenda)
	}
	entries, err := app.Engine.Audit.List(context.Background(), core.Query{Module: "calendar", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Actor.Kind == core.ActorSystem {
			t.Fatalf("calendar read as %s", e.Actor.Subject())
		}
		if e.Actor.ID == k.Key.ID && e.Status != "denied" {
			t.Fatalf("agent's calendar read %s: %+v", e.Status, e)
		}
	}
	_ = cal
}

// Failures come from the audit log: only for callers who may read it, and
// as module and action without the error text.
func TestBriefFailuresNeedAuditScope(t *testing.T) {
	app, owner, agent, _, _ := briefSetup(t)
	_, err := app.Engine.Audit.Append(context.Background(), core.Entry{Actor: systemActor, Module: "mail", Instance: "m", Action: "send", Risk: sdk.RiskWrite, Decision: core.Allow, Status: "error", Error: "550 rejected: secret-recipient@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if br := briefOf(t, agent); len(br.Failures) != 0 {
		t.Fatalf("agent without audit:*:read got failures %v", br.Failures)
	}
	br := briefOf(t, owner)
	if len(br.Failures) != 1 || br.Failures[0] != "mail send" {
		t.Fatalf("owner's failures = %v", br.Failures)
	}
}

// send previews the exact text per channel (the generic line for a channel
// that hides details), and the notify call runs as the caller, so a
// caller denied a channel can't reach it through the brief.
func TestBriefSendPreviewAndCallerRules(t *testing.T) {
	_, owner, agent, k, _ := briefSetup(t)
	var mu sync.Mutex
	var got []string
	ntfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, string(b))
		mu.Unlock()
	}))
	defer ntfy.Close()
	var open, private core.Instance
	if code := owner.do("POST", "/api/v1/instances", map[string]any{"module": "notify", "name": "Open", "config": map[string]any{"channel": "ntfy", "server": ntfy.URL, "topic": "a"}}, &open); code != 201 {
		t.Fatalf("notify = %d", code)
	}
	if code := owner.do("POST", "/api/v1/instances", map[string]any{"module": "notify", "name": "Hidden", "config": map[string]any{"channel": "ntfy", "server": ntfy.URL, "topic": "b", "private": true}}, &private); code != 201 {
		t.Fatalf("notify = %d", code)
	}

	var out core.Outcome
	if code := owner.do("POST", "/api/v1/instances/"+briefID+"/actions/send", map[string]any{"dryRun": true}, &out); code != 200 || out.Result.Plan == nil {
		t.Fatalf("dry run = %d %+v", code, out.Result)
	}
	if len(out.Result.Plan.Changes) != 2 {
		t.Fatalf("plan = %+v", out.Result.Plan)
	}
	for _, ch := range out.Result.Plan.Changes {
		after := string(ch.After)
		switch {
		case strings.Contains(ch.Target, private.ID):
			if strings.Contains(after, "PRIVATE consult") || !strings.Contains(after, "Something needs your attention") {
				t.Fatalf("private channel preview = %s", after)
			}
		case strings.Contains(ch.Target, open.ID):
			if !strings.Contains(after, "PRIVATE consult") {
				t.Fatalf("open channel preview = %s", after)
			}
		default:
			t.Fatalf("unexpected target %q", ch.Target)
		}
	}
	mu.Lock()
	if len(got) != 0 {
		t.Fatalf("dry run sent %v", got)
	}
	mu.Unlock()

	// The agent may run the brief but not use notifications.
	rule(t, owner, "agent:"+k.Key.ID, "brief", core.Allow)
	rule(t, owner, "agent:"+k.Key.ID, "notify", core.Deny)
	var res struct {
		Result struct {
			Output struct {
				SentTo  []string `json:"sentTo"`
				Refused []string `json:"refused"`
			} `json:"output"`
		} `json:"result"`
	}
	if code := agent.do("POST", "/api/v1/instances/"+briefID+"/actions/send", map[string]any{}, &res); code != 200 {
		t.Fatalf("agent send = %d", code)
	}
	if len(res.Result.Output.SentTo) != 0 || len(res.Result.Output.Refused) != 2 {
		t.Fatalf("agent send = %+v", res.Result.Output)
	}
	mu.Lock()
	if len(got) != 0 {
		t.Fatalf("agent denied notify reached it through the brief: %v", got)
	}
	mu.Unlock()

	// The owner's send reaches both, the private one with the generic line.
	if code := owner.do("POST", "/api/v1/instances/"+briefID+"/actions/send", map[string]any{}, &res); code != 200 || len(res.Result.Output.SentTo) != 2 {
		t.Fatalf("owner send = %d %+v", code, res.Result.Output)
	}
	mu.Lock()
	defer mu.Unlock()
	leaked := 0
	for _, g := range got {
		if strings.Contains(g, "PRIVATE consult") {
			leaked++
		}
	}
	if len(got) != 2 || leaked != 1 {
		t.Fatalf("delivered %q", got)
	}
}

// A brief run by an automation a person saved acts as that person; one an
// agent drafted acts as the automation, under its own rules.
func TestBriefAutomationActsAsOwner(t *testing.T) {
	app, owner, _, _, _ := briefSetup(t)
	ctx := context.Background()
	steps := []automation.Step{{Instance: briefID, Action: "brief"}}
	var trusted automation.Automation
	if code := owner.do("POST", "/api/v1/automations", map[string]any{"name": "Morning", "enabled": true, "trigger": map[string]string{"kind": "manual"}, "steps": steps}, &trusted); code != 201 && code != 200 {
		t.Fatalf("save = %d", code)
	}
	draft, err := app.Automations.Save(ctx, automation.Automation{Name: "Drafted", Trigger: automation.Trigger{Kind: "manual"}, Steps: steps}, core.Actor{ID: "x", Kind: core.ActorAgent})
	if err != nil {
		t.Fatal(err)
	}
	// Neither automation may read the calendar by its own rules.
	rule(t, owner, "automation:"+trusted.ID, "calendar", core.Deny)
	rule(t, owner, "automation:"+draft.ID, "calendar", core.Deny)

	agenda := func(id string) int {
		run, err := app.Automations.Run(ctx, id, nil)
		if err != nil || len(run.Steps) != 1 || run.Steps[0].Status != "ok" {
			t.Fatalf("run %s: %v %+v", id, err, run)
		}
		var br Brief
		_ = json.Unmarshal(run.Steps[0].Output, &br)
		return len(br.Agenda)
	}
	if n := agenda(trusted.ID); n != 1 {
		t.Fatalf("trusted automation's brief has %d events, want the owner's 1", n)
	}
	if n := agenda(draft.ID); n != 0 {
		t.Fatalf("drafted automation's brief has %d events", n)
	}
}

// Ambient push changes the light and Discord as its caller.
func TestAmbientPushAsCaller(t *testing.T) {
	app, _, _, _ := setup(t)
	if err := registerBuiltins(app); err != nil {
		t.Fatal(err)
	}
	a := app.ambient()
	if _, err := a.Invoke(context.Background(), sdk.Call{Instance: ambientID, Action: "push"}); err == nil {
		t.Fatal("push outside the engine should be refused")
	}
}
