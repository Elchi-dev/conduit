package core

// Regression tests: private content reaching the audit log, events and
// approvals through plans and undo tokens of real modules, and dry runs
// getting around a deny on a module's reads.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/modules/bookstack"
	"github.com/elchi-dev/conduit/modules/firefly"
	"github.com/elchi-dev/conduit/modules/freshdesk"
	"github.com/elchi-dev/conduit/modules/matrix"
	"github.com/elchi-dev/conduit/modules/outline"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type leakSecrets map[string]string

func (m leakSecrets) Resolve(_ context.Context, ref string) (string, error) {
	if v, ok := m[ref]; ok {
		return v, nil
	}
	return "", errors.New("no secret")
}

func leakEngine(t *testing.T) *Engine {
	t.Helper()
	e, _, _ := newTestEngine(t)
	e.SetSecrets(leakSecrets{"secret://ff": "tok", "secret://bs": "id:sec", "secret://ol": "tok", "secret://mx": "tok", "secret://fd": "tok"})
	return e
}

func saveInst(t *testing.T, e *Engine, module, cfg string) string {
	t.Helper()
	in, err := e.SaveInstance(context.Background(), Instance{Module: module, Name: module, Enabled: true, Config: json.RawMessage(cfg)})
	if err != nil {
		t.Fatal(err)
	}
	return in.ID
}

// noLeak fails if the audit entry, marshalled, holds any of secrets.
func noLeak(t *testing.T, e *Engine, seq int64, secrets ...string) {
	t.Helper()
	ent, err := e.Audit.Get(context.Background(), seq)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ent)
	for _, s := range secrets {
		if strings.Contains(string(b), s) {
			t.Fatalf("audit entry %d holds %q: %s", seq, s, b)
		}
	}
}

func contains(v any, s string) bool {
	b, _ := json.Marshal(v)
	return strings.Contains(string(b), s)
}

const fireflyTx = `{"data":{"id":"5","attributes":{"transactions":[{"type":"withdrawal","date":"2026-11-01","amount":"4321.00","currency_code":"EUR","description":"Therapy invoice Dr. X","source_name":"Joint account","destination_name":"Clinic"}]}}}`

func fireflyEngine(t *testing.T) (*Engine, string) {
	e := leakEngine(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/transactions/5" {
			w.Write([]byte(fireflyTx))
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	m := firefly.New()
	m.HTTP = srv.Client()
	if err := e.Register(m); err != nil {
		t.Fatal(err)
	}
	return e, saveInst(t, e, "firefly", `{"url":"`+srv.URL+`","token":"secret://ff"}`)
}

// A sensitive action's dry-run plan is redacted in the audit log and the
// event; the caller, who may run it, still gets it in full.
func TestSensitivePlanRedactedInLogAndEvents(t *testing.T) {
	e, id := fireflyEngine(t)
	ctx := context.Background()
	events, stop := e.Bus.Subscribe("action.", 16)
	defer stop()

	out, err := e.Invoke(ctx, user, sdk.Call{Instance: id, Action: "create_transaction", DryRun: true,
		Input: json.RawMessage(`{"type":"withdrawal","amount":"999.99","description":"rent","source":"Checking","destination":"Landlord","notes":"PRIVATE-NOTE-iban-DE00"}`)}, InvokeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(out.Result.Plan, "999.99") {
		t.Fatalf("the caller should see its own preview: %+v", out.Result.Plan)
	}
	noLeak(t, e, out.Audit.Seq, "PRIVATE-NOTE", "999.99", "Landlord", `"rent"`)
	ent, _ := e.Audit.Get(ctx, out.Audit.Seq)
	if !strings.Contains(string(ent.Output), "Change to create_transaction (details hidden)") {
		t.Fatalf("plan not replaced by its shape: %s", ent.Output)
	}
	select {
	case ev := <-events:
		if strings.Contains(string(ev.Data), "999.99") || strings.Contains(string(ev.Data), "PRIVATE-NOTE") {
			t.Fatalf("event leaks the plan: %s", ev.Data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}

	// delete_transaction is sensitive too: its preview shows the transaction.
	out, err = e.Invoke(ctx, user, sdk.Call{Instance: id, Action: "delete_transaction", DryRun: true, Input: json.RawMessage(`{"id":5}`)}, InvokeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, e, out.Audit.Seq, "Therapy", "4321.00", "Clinic")
}

// An approval for a sensitive action keeps its plan for the people who
// decide it; the caller, the bus and View() get it redacted.
func TestSensitiveApprovalPlanOnlyForDeciders(t *testing.T) {
	e := leakEngine(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/event/") {
			w.Write([]byte(`{"event_id":"$ev1","type":"m.room.message","sender":"@ceo:example.org","origin_server_ts":1,"content":{"msgtype":"m.text","body":"PRIVATE-ROOM-MSG layoffs friday"}}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	m := matrix.New()
	m.HTTP = srv.Client()
	if err := e.Register(m); err != nil {
		t.Fatal(err)
	}
	id := saveInst(t, e, "matrix", `{"homeserver":"`+srv.URL+`","token":"secret://mx","allowedRooms":["!room:example.org"]}`)
	ctx := context.Background()
	reqs, stop := e.Bus.Subscribe("approval.requested", 4)
	defer stop()

	in := json.RawMessage(`{"room":"!room:example.org","event":"$ev1"}`)
	out, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "redact", Input: in}, InvokeOptions{NoWait: true})
	if !errors.Is(err, ErrPending) || out.Approval == nil {
		t.Fatalf("want pending, got %v", err)
	}
	if contains(out.Approval, "PRIVATE-ROOM-MSG") || out.Approval.Plan == nil || !out.Approval.PlanPrivate {
		t.Fatalf("the caller sees the private plan: %+v", out.Approval)
	}
	select {
	case ev := <-reqs:
		if strings.Contains(string(ev.Data), "PRIVATE-ROOM-MSG") {
			t.Fatalf("approval.requested leaks the plan: %s", ev.Data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
	full, err := e.Approvals.Get(ctx, out.Approval.ID)
	if err != nil || !contains(full.Plan, "PRIVATE-ROOM-MSG") {
		t.Fatalf("deciders need the full plan: %+v %v", full.Plan, err)
	}
	if contains(full.View(), "PRIVATE-ROOM-MSG") {
		t.Fatal("View() keeps the plan")
	}
	list, _ := e.Approvals.List(ctx, "pending")
	if len(list) != 1 || !list[0].PlanPrivate {
		t.Fatalf("%+v", list)
	}
	_ = e.Approvals.Decide(ctx, out.Approval.ID, false, "user:owner")

	// The agent's own dry run is logged without the message.
	out, err = e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "redact", DryRun: true, Input: in}, InvokeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, e, out.Audit.Seq, "PRIVATE-ROOM-MSG")
}

// A caller denied one of a module's reads can't read the same data through
// a dry run's preview: it gets the plan redacted (and so does its approval
// for anyone who can't decide it).
func TestDryRunRedactedWhenAReadIsDenied(t *testing.T) {
	e, id := fireflyEngine(t)
	ctx := context.Background()
	if err := e.Policy.PutRule(ctx, Rule{Subject: agent.Subject(), Module: "firefly", Instance: "*", Action: "transactions", Risk: "*", Effect: Deny}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "transactions"}, InvokeOptions{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("transactions should be denied: %v", err)
	}
	out, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "delete_transaction", DryRun: true, Input: json.RawMessage(`{"id":5}`)}, InvokeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Plan == nil || contains(out.Result.Plan, "Therapy") || contains(out.Result.Plan, "4321") {
		t.Fatalf("a caller denied transactions reads it through a preview: %+v", out.Result.Plan)
	}
	if len(out.Result.Plan.Changes) != 1 || out.Result.Plan.Changes[0].Op != "delete" {
		t.Fatalf("the plan's shape should stay: %+v", out.Result.Plan)
	}
	noLeak(t, e, out.Audit.Seq, "Therapy", "4321")

	// The approval for the real call: private, so only deciders see it.
	out, err = e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "delete_transaction", Input: json.RawMessage(`{"id":5}`)}, InvokeOptions{NoWait: true})
	if !errors.Is(err, ErrPending) || contains(out.Approval, "Therapy") || !out.Approval.PlanPrivate {
		t.Fatalf("%v %+v", err, out.Approval)
	}
	_ = e.Approvals.Decide(ctx, out.Approval.ID, false, "user:owner")

	// A dry run the policy denies is still refused outright.
	if err := e.Policy.PutRule(ctx, Rule{Subject: agent.Subject(), Module: "firefly", Instance: "*", Action: "delete_transaction", Risk: "*", Effect: Deny}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Invoke(ctx, agent, sdk.Call{Instance: id, Action: "delete_transaction", DryRun: true, Input: json.RawMessage(`{"id":5}`)}, InvokeOptions{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("denied dry run ran: %v", err)
	}
	// Someone with no read denied gets the full preview.
	out, err = e.Invoke(ctx, user, sdk.Call{Instance: id, Action: "delete_transaction", DryRun: true, Input: json.RawMessage(`{"id":5}`)}, InvokeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(out.Result.Plan, "Therapy") {
		t.Fatalf("%+v", out.Result.Plan)
	}
}

// Undo tokens of BookStack and Outline edits never carry the old content.
func TestEditUndoCarriesNoContent(t *testing.T) {
	e := leakEngine(t)
	bs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/pages/7" && r.Method == "GET":
			w.Write([]byte(`{"id":7,"name":"Salaries","markdown":"PRIVATE-PAGE-BODY alice 120k","editor":"markdown"}`))
		case r.URL.Path == "/api/pages/7" && r.Method == "PUT":
			w.Write([]byte(`{"id":7,"name":"Salaries","revision_count":2}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer bs.Close()
	bm := bookstack.New()
	bm.HTTP = bs.Client()
	if err := e.Register(bm); err != nil {
		t.Fatal(err)
	}
	id := saveInst(t, e, "bookstack", `{"url":"`+bs.URL+`","token":"secret://bs"}`)
	out, err := e.Invoke(context.Background(), user, sdk.Call{Instance: id, Action: "update_page", Input: json.RawMessage(`{"id":7,"markdown":"x"}`)}, InvokeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, e, out.Audit.Seq, "PRIVATE-PAGE-BODY")

	const doc = "11111111-2222-3333-4444-555555555555"
	const rev = "22222222-2222-3333-4444-555555555555"
	ol := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/documents.info":
			w.Write([]byte(`{"data":{"id":"` + doc + `","title":"HR notes","text":"PRIVATE-DOC-TEXT bob is on a PIP","updatedAt":"2026-11-01T00:00:00Z"}}`))
		case "/api/revisions.list":
			w.Write([]byte(`{"data":[{"id":"` + rev + `","documentId":"` + doc + `","createdAt":"2026-11-01T00:00:01Z"}]}`))
		case "/api/documents.update":
			w.Write([]byte(`{"data":{"id":"` + doc + `","title":"HR notes"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ol.Close()
	om := outline.New()
	om.HTTP = ol.Client()
	if err := e.Register(om); err != nil {
		t.Fatal(err)
	}
	id = saveInst(t, e, "outline", `{"url":"`+ol.URL+`","token":"secret://ol"}`)
	out, err = e.Invoke(context.Background(), user, sdk.Call{Instance: id, Action: "update_document", Input: json.RawMessage(`{"id":"` + doc + `","text":"x"}`)}, InvokeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, e, out.Audit.Seq, "PRIVATE-DOC-TEXT")
	ent, _ := e.Audit.Get(context.Background(), out.Audit.Seq)
	if ent.Undo == nil || ent.Undo.Action != "restore_revision" || !strings.Contains(string(ent.Undo.Input), rev) {
		t.Fatalf("undo should restore the revision by id: %+v", ent.Undo)
	}
}

// A sensitive action's undo through a sensitive action is kept when its
// token is an identifier alone (Firefly: a recorded transaction is deleted
// by its id).
func TestSensitiveUndoByIDKept(t *testing.T) {
	m := &keystore{kv: map[string]string{}}
	spec := sdk.ActionSpec{Name: "create", Sensitive: true}
	sensitiveTarget := &sdk.Undo{Action: "replace", Input: json.RawMessage(`{"id":42}`)}
	if !keepUndo(m, spec, sensitiveTarget) {
		t.Fatal("an id-only token was dropped")
	}
	// A note is deleted by its ticket's number and its own.
	for _, in := range []string{`{"ticket":"12","note":"345"}`, `{"conversation":7,"note":8}`, `{"ticket":3,"article":"9"}`} {
		if !keepUndo(m, spec, &sdk.Undo{Action: "replace", Input: json.RawMessage(in)}) {
			t.Fatalf("dropped the record references %s", in)
		}
	}
	for _, in := range []string{`{"id":42,"value":"old"}`, `{"key":"db"}`, `{"id":{"nested":"x"}}`, `{}`, `"x"`,
		`{"ticket":"12","text":"old"}`, `{"note":"Jane's card 4242"}`, `{"ticket":"0"}`, `{"note":-1}`, `{"ticket":1.5}`, `{"conversation":"12a"}`} {
		if keepUndo(m, spec, &sdk.Undo{Action: "replace", Input: json.RawMessage(in)}) {
			t.Fatalf("kept %s through a sensitive action", in)
		}
	}
}

func TestRedactPlan(t *testing.T) {
	p := &sdk.Plan{Summary: "Delete \"Therapy\" 4321", Changes: []sdk.Change{{Target: "transaction \"Therapy\"", Op: "delete", Before: json.RawMessage(`{"amount":"4321"}`)}, {Target: "x", Op: "create"}}}
	r := RedactPlan("delete_transaction", p)
	if contains(r, "Therapy") || contains(r, "4321") || r.Summary != "Change to delete_transaction (details hidden)" || len(r.Changes) != 2 || r.Changes[0].Op != "delete" || string(r.Changes[0].Before) != `"[redacted]"` || r.Changes[1].After != nil {
		t.Fatalf("%+v", r)
	}
	if !contains(p, "Therapy") {
		t.Fatal("RedactPlan changed its argument")
	}
}

// A help desk's previews of actions that aren't sensitive (status,
// resolving, assignment) go in the audit log as they are, so they carry no
// subject or requester; notes are sensitive, and a note's undo, which holds
// only the ticket's and the note's numbers, is still kept.
func TestHelpDeskPlansCarryNoCustomerData(t *testing.T) {
	e := leakEngine(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v2/tickets/1":
			w.Write([]byte(`{"id":1,"subject":"Refund card 4111-1111 for Jane Customer","status":2,"requester_id":50,"responder_id":null,"requester":{"id":50,"name":"Jane Customer","email":"jane@example.com"}}`))
		case "GET /api/v2/tickets/1/conversations":
			w.Write([]byte(`[{"id":9,"body_text":"Customer Jane Customer DOB 1980-01-02","private":true,"source":2}]`))
		case "GET /api/v2/agents/7":
			w.Write([]byte(`{"id":7,"contact":{"name":"Sam Agent"}}`))
		case "POST /api/v2/tickets/1/notes":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":10,"private":true,"source":2}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	m := freshdesk.New()
	m.Base, m.HTTP = srv.URL, srv.Client()
	if err := e.Register(m); err != nil {
		t.Fatal(err)
	}
	id := saveInst(t, e, "freshdesk", `{"domain":"acme","apiKey":"secret://fd"}`)
	ctx := context.Background()
	private := []string{"4111-1111", "Jane Customer", "jane@example.com", "DOB 1980"}
	for _, c := range []struct{ action, in string }{
		{"set_status", `{"ticket":1,"status":"pending"}`},
		{"resolve", `{"ticket":1}`},
		{"assign", `{"ticket":1,"assignee":7}`},
		{"delete_note", `{"ticket":1,"note":9}`},
		{"add_note", `{"ticket":1,"text":"Jane Customer's card is 4111-1111"}`},
	} {
		out, err := e.Invoke(ctx, user, sdk.Call{Instance: id, Action: c.action, DryRun: true, Input: json.RawMessage(c.in)}, InvokeOptions{})
		if err != nil || out.Result.Plan == nil {
			t.Fatalf("%s: %v", c.action, err)
		}
		noLeak(t, e, out.Audit.Seq, private...)
	}
	out, err := e.Invoke(ctx, user, sdk.Call{Instance: id, Action: "add_note", Input: json.RawMessage(`{"ticket":1,"text":"Jane Customer's card is 4111-1111"}`)}, InvokeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, e, out.Audit.Seq, private...)
	ent, _ := e.Audit.Get(ctx, out.Audit.Seq)
	if ent.Undo == nil || ent.Undo.Action != "delete_note" || string(ent.Undo.Input) != `{"note":"10","ticket":"1"}` {
		t.Fatalf("the note's undo should be kept by its numbers: %+v", ent.Undo)
	}
}
