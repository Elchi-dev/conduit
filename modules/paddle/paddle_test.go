package paddle

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

const (
	goodKey = "pdl_live_apikey_01gtgztp8fyzbx6uyxmcq0ymqp_abcdefghijklmnopqrstuv"
	subID   = "sub_01h04vsc0qhwtsbsxh3422wjs4"
	ctmID   = "ctm_01h844p3h41s12zs5mn4axja51"
)

type fakePaddle struct {
	mu        sync.Mutex
	seen      []string
	status    string
	scheduled string // pending change: "", "pause" or "cancel"
	bodies    []string
}

func (f *fakePaddle) sub() map[string]any {
	var sc any
	if f.scheduled != "" {
		sc = map[string]any{"action": f.scheduled, "effective_at": "2026-12-01T00:00:00Z", "resume_at": nil}
	}
	return map[string]any{"id": subID, "status": f.status, "customer_id": ctmID, "address_id": "add_01h848pep46enq8y372x7maj0p", "currency_code": "EUR", "collection_mode": "automatic",
		"created_at": "2026-01-01T00:00:00Z", "next_billed_at": "2026-12-01T00:00:00Z", "billing_cycle": map[string]any{"interval": "month", "frequency": 1},
		"current_billing_period": map[string]any{"starts_at": "2026-11-01T00:00:00Z", "ends_at": "2026-12-01T00:00:00Z"}, "scheduled_change": sc,
		"management_urls": map[string]any{"update_payment_method": "https://buyer-portal.paddle.com/LEAKME", "cancel": "https://buyer-portal.paddle.com/LEAKME"},
		"items": []any{map[string]any{"status": "active", "quantity": 1, "recurring": true, "price": map[string]any{"id": "pri_01", "description": "Pro monthly", "product_id": "pro_01",
			"unit_price": map[string]any{"amount": "1900", "currency_code": "EUR"}}, "product": map[string]any{"name": "Pro"}}}}
}

func (f *fakePaddle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+goodKey || r.Header.Get("Paddle-Version") != "1" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"type":"request_error","code":"authentication_malformed","detail":"Authentication header included, but incorrectly formatted"}}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	if r.Method != "GET" {
		f.bodies = append(f.bodies, string(body))
	}
	enc := json.NewEncoder(w)
	meta := map[string]any{"pagination": map[string]any{"per_page": 1, "has_more": true, "estimated_total": 12}}
	switch r.Method + " " + r.URL.Path {
	case "GET /customers":
		if r.URL.Query().Get("search") != "jane" {
			w.WriteHeader(400)
			return
		}
		enc.Encode(map[string]any{"data": []any{map[string]any{"id": ctmID, "name": "Jane Doe", "email": "jane@example.org", "status": "active", "locale": "de", "created_at": "2026-01-01T00:00:00Z"}}, "meta": meta})
	case "GET /subscriptions":
		enc.Encode(map[string]any{"data": []any{f.sub()}, "meta": meta})
	case "GET /transactions":
		if r.URL.Query().Get("subscription_id") != subID && r.URL.Query().Get("subscription_id") != "" {
			w.WriteHeader(400)
			return
		}
		enc.Encode(map[string]any{"data": []any{map[string]any{"id": "txn_01h04vsbhqc62t8hmd4z3b578c", "status": "completed", "customer_id": ctmID, "subscription_id": subID, "invoice_number": "325-10566",
			"origin": "subscription_recurring", "currency_code": "EUR", "created_at": "2026-11-01T00:00:00Z", "billed_at": "2026-11-01T00:00:00Z",
			"details":  map[string]any{"totals": map[string]any{"subtotal": "1597", "tax": "303", "grand_total": "1900", "earnings": "1700"}},
			"payments": []any{map[string]any{"method_details": map[string]any{"card": map[string]any{"last4": "4242", "cardholder_name": "Jane Doe"}}}},
			"checkout": map[string]any{"url": "https://pay.example/LEAKME"}}}, "meta": meta})
	case "GET /subscriptions/" + subID:
		enc.Encode(map[string]any{"data": f.sub()})
	case "POST /subscriptions/" + subID + "/pause":
		if strings.Contains(string(body), `"immediately"`) {
			f.status = "paused"
		} else {
			f.scheduled = "pause"
		}
		enc.Encode(map[string]any{"data": f.sub()})
	case "POST /subscriptions/" + subID + "/cancel":
		if strings.Contains(string(body), `"immediately"`) {
			f.status, f.scheduled = "canceled", ""
		} else {
			f.scheduled = "cancel"
		}
		enc.Encode(map[string]any{"data": f.sub()})
	case "POST /subscriptions/" + subID + "/resume":
		f.status = "active"
		enc.Encode(map[string]any{"data": f.sub()})
	case "PATCH /subscriptions/" + subID:
		if string(body) != `{"scheduled_change":null}` {
			w.WriteHeader(400)
			return
		}
		f.scheduled = ""
		enc.Encode(map[string]any{"data": f.sub()})
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"type":"request_error","code":"not_found","detail":"Entity not found"}}`)
	}
}

var secrets = map[string]string{"secret://pd": goodKey, "secret://bad": "pdl_live_apikey_01gtgztp8fyzbx6uyxmcq0ymqp_zzzzzzzzzzzzzzzzzzzzzz",
	"secret://sandbox": "pdl_sdbx_apikey_01gtgztp8fyzbx6uyxmcq0ymqp_abcdefghijklmnopqrstuv", "secret://junk": "hunter2"}

func setup(t *testing.T, raw string) (*Module, *fakePaddle) {
	t.Helper()
	f := &fakePaddle{status: "active"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(secrets), "p", json.RawMessage(raw)); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

const good = `{"key":"secret://pd"}`

func TestPaddleReads(t *testing.T) {
	m, _ := setup(t, good)
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "connected (live): 12 active subscriptions" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"customers", `{"search":"jane"}`, `"email":"jane@example.org"`},
		{"subscriptions", `{"status":"active","customer":"` + ctmID + `"}`, `"unitPrice":"19.00 EUR"`},
		{"subscriptions", `{}`, `"after":"` + subID + `"`},
		{"transactions", `{"subscription":"` + subID + `"}`, `"total":"19.00 EUR"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "4242") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		if c.action != "customers" && (strings.Contains(out, "jane") || strings.Contains(out, "Jane")) {
			t.Fatalf("%s returned personal data: %s", c.action, out)
		}
	}
	for _, a := range m.Manifest().Actions {
		if a.Sensitive != (a.Name == "customers") {
			t.Fatalf("%s: sensitive %v", a.Name, a.Sensitive)
		}
		if strings.HasSuffix(a.Name, "_subscription") && (a.Risk != sdk.RiskDestructive || !a.DryRun) {
			t.Fatalf("%s must be destructive with a preview", a.Name)
		}
	}
}

func TestPaddleSubscriptionChanges(t *testing.T) {
	m, f := setup(t, good)
	in := `{"subscription":"` + subID + `"}`
	// Cancel at the period end, then take it back.
	r, err := invoke(m, "cancel_subscription", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "at the end of the billing period (2026-12-01T00:00:00Z); undo takes it back") || f.scheduled != "" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "cancel_subscription", in, false)
	if err != nil || f.scheduled != "cancel" || r.Undo == nil || r.Undo.Action != "resume_subscription" || string(r.Undo.Input) != in {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "cancel_subscription", in, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "pause_subscription", in, false); err == nil || !strings.Contains(err.Error(), "set to cancel") {
		t.Fatal(err)
	}
	r, err = invoke(m, "resume_subscription", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Take back the cancel") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "resume_subscription", in, false)
	if err != nil || f.scheduled != "" || r.Undo == nil || r.Undo.Action != "cancel_subscription" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "resume_subscription", in, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Pause now, resume (bills again), and its undo pauses again.
	r, err = invoke(m, "pause_subscription", `{"subscription":"`+subID+`","immediately":true}`, false)
	if err != nil || f.status != "paused" || r.Undo == nil || r.Undo.Action != "resume_subscription" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "pause_subscription", in, false); err != nil || !strings.Contains(string(r.Output), "paused already") {
		t.Fatalf("%s %v", r.Output, err)
	}
	// A paused subscription has no period end to cancel at; Paddle only
	// cancels it immediately, so the preview mustn't promise an undo.
	for _, dry := range []bool{true, false} {
		if _, err := invoke(m, "cancel_subscription", in, dry); err == nil || !strings.Contains(err.Error(), "only immediately") || f.status != "paused" {
			t.Fatal(err)
		}
	}
	r, err = invoke(m, "resume_subscription", in, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "bills the customer") || f.status != "paused" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "resume_subscription", in, false)
	if err != nil || f.status != "active" || r.Undo == nil || string(r.Undo.Input) != `{"immediately":true,"subscription":"`+subID+`"}` {
		t.Fatalf("%+v %v", r, err)
	}

	// Cancelling immediately has no undo.
	r, err = invoke(m, "cancel_subscription", `{"subscription":"`+subID+`","immediately":true}`, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "can't be undone") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "cancel_subscription", `{"subscription":"`+subID+`","immediately":true}`, false)
	if err != nil || f.status != "canceled" || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "resume_subscription", in, false); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "pause_subscription", `{"subscription":"sub_01h04vsc0qhwtsbsxh3422wjzz"}`, false); err == nil || !strings.Contains(err.Error(), "no subscription") {
		t.Fatal(err)
	}
}

func TestPaddleValidation(t *testing.T) {
	m, f := setup(t, good)
	for _, c := range []struct{ action, in string }{
		{"customers", `{"search":"a\nb"}`},
		{"customers", `{"status":"gone"}`},
		{"customers", `{"after":"../x"}`},
		{"subscriptions", `{"status":"lost"}`},
		{"subscriptions", `{"customer":"jane@example.org"}`},
		{"transactions", `{"subscription":"sub_x/../../customers"}`},
		{"transactions", `{"status":"lost"}`},
		{"pause_subscription", `{}`},
		{"pause_subscription", `{"subscription":"sub_01h04vsc0qhwtsbsxh3422wjs4/pause"}`},
		{"cancel_subscription", `{"subscription":"SUB_01H04VSC0QHWTSBSXH3422WJS4"}`},
		{"resume_subscription", `{"subscription":"ctm_01h844p3h41s12zs5mn4axja51"}`},
		{"nope", `{}`},
	} {
		for _, dry := range []bool{false, true} {
			if _, err := invoke(m, c.action, c.in, dry); err == nil {
				t.Fatalf("%s accepted %s", c.action, c.in)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Paddle: %v", f.seen)
	}
	for _, raw := range []string{`{"key":"` + goodKey + `"}`, `{"key":"secret://pd","environment":"staging"}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted settings %s", raw)
		}
	}
	bad, _ := setup(t, `{"key":"secret://bad"}`)
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || h.Message != "Paddle refused the API key" {
		t.Fatalf("%+v", h)
	}
	for _, raw := range []string{`{"key":"secret://junk"}`, `{"key":"secret://sandbox"}`} {
		junk, fj := setup(t, raw)
		if _, err := invoke(junk, "subscriptions", `{}`, false); err == nil || len(fj.seen) != 0 || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "pdl_") {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}

func TestPaddleErrorsHidePersonalData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, `{"error":{"type":"request_error","code":"bad_request","detail":"customer jane@example.org conflicts"}}`)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	if err := m.Configure(context.Background(), fakehost.New(secrets), "p", json.RawMessage(good)); err != nil {
		t.Fatal(err)
	}
	_, err := invoke(m, "subscriptions", `{}`, false)
	if err == nil || strings.Contains(err.Error(), "jane") || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("error: %v", err)
	}
}

func TestPaddleRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	if err := m.Configure(context.Background(), fakehost.New(secrets), "p", json.RawMessage(good)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
