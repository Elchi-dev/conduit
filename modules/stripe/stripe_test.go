package stripe

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

const goodKey = "rk_test_51AbCdEfGhIjKlMnOp"

type fakeStripe struct {
	mu        sync.Mutex
	seen      []string
	idem      []string
	refunded  int64
	cancelEnd bool
	canceled  bool
}

func (f *fakeStripe) charge() map[string]any {
	return map[string]any{"id": "ch_3Abc123", "amount": 5000, "amount_captured": 5000, "amount_refunded": f.refunded, "currency": "usd", "status": "succeeded", "paid": true, "captured": true,
		"customer": "cus_Q1w2e3r4", "payment_intent": "pi_3Abc123", "description": "Pro plan", "created": 1793000000, "livemode": false, "receipt_email": "jane@example.com",
		"billing_details":        map[string]any{"name": "Jane Doe", "email": "jane@example.com", "address": map[string]any{"line1": "1 Secret St"}},
		"payment_method_details": map[string]any{"type": "card", "card": map[string]any{"brand": "visa", "last4": "4242", "exp_month": 12, "exp_year": 2030, "fingerprint": "fpXYZ"}},
		"outcome":                map[string]any{"risk_level": "normal"}}
}

func (f *fakeStripe) sub() map[string]any {
	s := map[string]any{"id": "sub_1Zz9Yy8X", "status": "active", "customer": "cus_Q1w2e3r4", "cancel_at_period_end": f.cancelEnd, "current_period_end": 1795000000, "created": 1790000000,
		"items": map[string]any{"data": []any{map[string]any{"quantity": 1, "price": map[string]any{"id": "price_1", "unit_amount": 1900, "currency": "eur", "product": "prod_1", "recurring": map[string]any{"interval": "month", "interval_count": 1}}}}}}
	if f.canceled {
		s["status"], s["canceled_at"] = "canceled", 1793000500
	}
	return s
}

func (f *fakeStripe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a := r.Header.Get("Authorization"); a != "Bearer "+goodKey && a != "Bearer sk_test_51AbCdEfGhIjKlMnOp" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"Invalid API Key provided: rk_test_****xxxx","type":"invalid_request_error"}}`)
		return
	}
	if r.Header.Get("Stripe-Version") != APIVersion {
		w.WriteHeader(400)
		return
	}
	r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+r.Form.Encode())
	if r.Method == "POST" {
		if r.Header.Get("Idempotency-Key") == "" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":{"message":"missing idempotency key"}}`)
			return
		}
		f.idem = append(f.idem, r.Header.Get("Idempotency-Key"))
	}
	enc := json.NewEncoder(w)
	list := func(items ...any) { enc.Encode(map[string]any{"object": "list", "data": items, "has_more": false}) }
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/balance":
		io.WriteString(w, `{"livemode":false,"available":[{"amount":123456,"currency":"usd"},{"amount":500,"currency":"jpy"}],"pending":[{"amount":100,"currency":"usd"}]}`)
	case "GET /v1/payment_intents":
		list(map[string]any{"id": "pi_3Abc123", "amount": 5000, "amount_received": 5000, "currency": "usd", "status": "succeeded", "customer": "cus_Q1w2e3r4", "latest_charge": "ch_3Abc123", "created": 1793000000})
	case "GET /v1/payment_intents/pi_3Abc123":
		if r.URL.Query().Get("expand[]") != "latest_charge" {
			w.WriteHeader(400)
			return
		}
		enc.Encode(map[string]any{"id": "pi_3Abc123", "status": "succeeded", "latest_charge": f.charge()})
	case "GET /v1/charges":
		list(f.charge())
	case "GET /v1/charges/ch_3Abc123":
		enc.Encode(f.charge())
	case "GET /v1/customers/search":
		if r.URL.Query().Get("query") != `email~"jane" OR name~"jane"` {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":{"message":"bad query `+r.URL.Query().Get("query")+`"}}`)
			return
		}
		list(map[string]any{"id": "cus_Q1w2e3r4", "name": "Jane Doe", "email": "jane@example.com", "address": map[string]any{"line1": "1 Secret St", "city": "Berlin", "country": "DE"}, "created": 1790000000})
	case "GET /v1/subscriptions":
		list(f.sub())
	case "GET /v1/subscriptions/sub_1Zz9Yy8X":
		enc.Encode(f.sub())
	case "POST /v1/subscriptions/sub_1Zz9Yy8X":
		f.cancelEnd = r.PostForm.Get("cancel_at_period_end") == "true"
		enc.Encode(f.sub())
	case "DELETE /v1/subscriptions/sub_1Zz9Yy8X":
		f.canceled = true
		enc.Encode(f.sub())
	case "GET /v1/payouts":
		list(map[string]any{"id": "po_1", "amount": 99000, "currency": "usd", "status": "in_transit", "arrival_date": 1793100000, "method": "standard", "automatic": true})
	case "GET /v1/disputes":
		list(map[string]any{"id": "dp_1", "amount": 5000, "currency": "usd", "status": "needs_response", "reason": "fraudulent", "charge": "ch_3Abc123", "evidence_details": map[string]any{"due_by": 1793500000}})
	case "GET /v1/invoices":
		list(map[string]any{"id": "in_1", "number": "A-0001", "status": "open", "amount_due": 1900, "amount_paid": 0, "amount_remaining": 1900, "currency": "eur", "customer": "cus_Q1w2e3r4", "customer_email": "jane@example.com", "hosted_invoice_url": "https://invoice.stripe.com/secret"})
	case "POST /v1/refunds":
		var amt int64
		json.Unmarshal([]byte(r.PostForm.Get("amount")), &amt)
		f.refunded += amt
		enc.Encode(map[string]any{"id": "re_1", "amount": amt, "currency": "usd", "status": "succeeded"})
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"message":"No such resource","type":"invalid_request_error"}}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeStripe) {
	f := &fakeStripe{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Key: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://st": goodKey, "secret://bad": "rk_test_51WrongWrongWrong", "secret://pk": "pk_test_51AbCdEfGhIjKlMnOp", "secret://sk": "sk_test_51AbCdEfGhIjKlMnOp"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestStripeReads(t *testing.T) {
	m, _ := setup(t, "secret://st")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "connected in test mode" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"balance", `{}`, `"available":"1234.56 USD"`},
		{"balance", `{}`, `"available":"500 JPY"`},
		{"payments", `{"customer":"cus_Q1w2e3r4"}`, `"charge":"ch_3Abc123"`},
		{"charges", `{"payment":"pi_3Abc123"}`, `"card":"visa •••• 4242"`},
		{"customers", `{"query":"jane"}`, `"email":"jane@example.com"`},
		{"subscriptions", `{"status":"active"}`, `"amount":"19.00 EUR per month"`},
		{"payouts", `{}`, `"display":"990.00 USD"`},
		{"disputes", `{}`, `"evidenceDue":`},
		{"invoices", `{"status":"open"}`, `"number":"A-0001"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		for _, leak := range []string{"Secret St", "fpXYZ", "exp_", "invoice.stripe.com"} {
			if strings.Contains(out, leak) {
				t.Fatalf("%s leaked %q: %s", c.action, leak, out)
			}
		}
		if c.action != "customers" && strings.Contains(out, "jane@") {
			t.Fatalf("%s leaked an email: %s", c.action, out)
		}
	}
	r, err := invoke(m, "customers", `{"query":"jane","includeAddress":true}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"address":"1 Secret St, Berlin, DE"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		switch a.Name {
		case "customers":
			if !a.Sensitive {
				t.Fatal("customers must be sensitive")
			}
		case "refund", "cancel_subscription", "keep_subscription": // keep bills the customer again
			if a.Risk != sdk.RiskDestructive || !a.DryRun {
				t.Fatalf("%s must be destructive with a preview", a.Name)
			}
		}
	}
	sk, _ := setup(t, "secret://sk")
	if h := sk.Health(context.Background(), "s"); !strings.Contains(h.Message, "restricted key is safer") {
		t.Fatalf("%+v", h)
	}
}

func TestStripeRefund(t *testing.T) {
	m, f := setup(t, "secret://st")
	r, err := invoke(m, "refund", `{"payment":"pi_3Abc123","amount":1500,"reason":"requested_by_customer"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Partial refund of 15.00 USD to customer cus_Q1w2e3r4 (payment pi_3Abc123, test mode). To run it, give expectedRefunded "0.00 USD" (the payment as previewed); it's refused if the payment changed.` || f.refunded != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if !strings.Contains(string(r.Plan.Changes[0].After), `"currency":"usd"`) || strings.Contains(string(r.Plan.Changes[0].Before), "jane") {
		t.Fatalf("%s %s", r.Plan.Changes[0].Before, r.Plan.Changes[0].After)
	}
	// The run needs what the preview showed.
	if _, err := invoke(m, "refund", `{"payment":"pi_3Abc123","amount":1500}`, false); err == nil || f.refunded != 0 || len(f.idem) != 0 || !strings.Contains(err.Error(), `expectedRefunded "0.00 USD"`) {
		t.Fatalf("refunded without the previewed values: %v", err)
	}
	for _, bad := range []string{"0.00 EUR", "lots", "0.001", "1.00"} {
		if _, err := invoke(m, "refund", `{"payment":"pi_3Abc123","amount":1500,"expectedRefunded":"`+bad+`"}`, false); err == nil || f.refunded != 0 {
			t.Fatalf("%s: %v", bad, err)
		}
	}
	r, err = invoke(m, "refund", `{"payment":"pi_3Abc123","amount":1500,"expectedRefunded":"0.00 USD"}`, false)
	if err != nil || f.refunded != 1500 || r.Undo != nil || !strings.Contains(string(r.Output), `"refund":"re_1"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	// The same approved call again is refused: the payment changed.
	if _, err := invoke(m, "refund", `{"payment":"pi_3Abc123","amount":1500,"expectedRefunded":"0.00 USD"}`, false); err == nil || f.refunded != 1500 || !strings.Contains(err.Error(), "expectedRefunded is 15.00 USD now, not 0.00 USD") {
		t.Fatalf("refunded twice: %v", err)
	}
	if r, err := invoke(m, "refund", `{"payment":"pi_3Abc123","amount":1500,"expectedRefunded":"0.00 USD"}`, true); err != nil || !strings.Contains(r.Plan.Summary, "will be refused") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "refund", `{"payment":"ch_3Abc123","amount":4000,"expectedRefunded":"15 usd"}`, false); err == nil || !strings.Contains(err.Error(), "only 35.00 USD") {
		t.Fatal(err)
	}
	r, err = invoke(m, "refund", `{"payment":"ch_3Abc123","idempotencyKey":"retry-key-1","expectedRefunded":"15.0"}`, false)
	if err != nil || f.refunded != 5000 {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "refund", `{"payment":"ch_3Abc123","expectedRefunded":"50.00 USD"}`, false); err == nil || !strings.Contains(err.Error(), "fully refunded") {
		t.Fatal(err)
	}
	if len(f.idem) != 2 || f.idem[0] == f.idem[1] || f.idem[1] != "retry-key-1" {
		t.Fatalf("idempotency keys: %v", f.idem)
	}
}

func TestStripeCancel(t *testing.T) {
	m, f := setup(t, "secret://st")
	const seen = `"expectedStatus":"active","expectedPeriodEnd":"2026-11-18T11:06:40Z"`
	r, err := invoke(m, "cancel_subscription", `{"subscription":"sub_1Zz9Yy8X"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Cancel sub_1Zz9Yy8X of customer cus_Q1w2e3r4 at the period end, 2026-11-18T11:06:40Z; it runs until then and undo keeps it. To run it, give expectedStatus "active" and expectedPeriodEnd "2026-11-18T11:06:40Z" (the subscription as previewed); it's refused if the subscription changed.` || f.cancelEnd {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "cancel_subscription", `{"subscription":"sub_1Zz9Yy8X"}`, false); err == nil || f.cancelEnd || !strings.Contains(err.Error(), `expectedStatus "active"`) {
		t.Fatalf("cancelled without the previewed values: %v", err)
	}
	if _, err := invoke(m, "cancel_subscription", `{"subscription":"sub_1Zz9Yy8X","expectedStatus":"active"}`, false); err == nil || f.cancelEnd || !strings.Contains(err.Error(), "expectedPeriodEnd") {
		t.Fatalf("cancelled without the previewed values: %v", err)
	}
	// A renewal in between moves the period end: refused.
	if _, err := invoke(m, "cancel_subscription", `{"subscription":"sub_1Zz9Yy8X","expectedStatus":"active","expectedPeriodEnd":"2026-10-18T11:06:40Z"}`, false); err == nil || f.cancelEnd || !strings.Contains(err.Error(), "changed since the preview") {
		t.Fatalf("cancelled a changed subscription: %v", err)
	}
	if _, err := invoke(m, "cancel_subscription", `{"subscription":"sub_1Zz9Yy8X","expectedStatus":"past_due","expectedPeriodEnd":"2026-11-18T11:06:40Z"}`, false); err == nil || f.cancelEnd {
		t.Fatalf("cancelled a changed subscription: %v", err)
	}
	r, err = invoke(m, "cancel_subscription", `{"subscription":"sub_1Zz9Yy8X",`+seen+`}`, false)
	if err != nil || !f.cancelEnd || r.Undo == nil || r.Undo.Action != "keep_subscription" || string(r.Undo.Input) != `{"expectedPeriodEnd":"2026-11-18T11:06:40Z","expectedStatus":"active","subscription":"sub_1Zz9Yy8X"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "keep_subscription", `{"subscription":"sub_1Zz9Yy8X"}`, false); err == nil || !f.cancelEnd || !strings.Contains(err.Error(), "expectedStatus") {
		t.Fatalf("kept without the previewed values: %v", err)
	}
	if r, err := invoke(m, "keep_subscription", `{"subscription":"sub_1Zz9Yy8X"}`, true); err != nil || !strings.Contains(r.Plan.Summary, `To run it, give expectedStatus "active"`) {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.cancelEnd || r.Undo == nil || r.Undo.Action != "cancel_subscription" || string(r.Undo.Input) != `{"expectedPeriodEnd":"2026-11-18T11:06:40Z","expectedStatus":"active","subscription":"sub_1Zz9Yy8X"}` {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "cancel_subscription", `{"subscription":"sub_1Zz9Yy8X","immediately":true,"prorate":true}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "now") || f.canceled {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "cancel_subscription", `{"subscription":"sub_1Zz9Yy8X","immediately":true,"prorate":true}`, false); err == nil || f.canceled {
		t.Fatalf("ended without the previewed values: %v", err)
	}
	r, err = invoke(m, "cancel_subscription", `{"subscription":"sub_1Zz9Yy8X","immediately":true,"prorate":true,`+seen+`}`, false)
	if err != nil || !f.canceled || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], "DELETE /v1/subscriptions/sub_1Zz9Yy8X prorate=true") {
		t.Fatalf("%v", f.seen)
	}
	if r, err := invoke(m, "cancel_subscription", `{"subscription":"sub_1Zz9Yy8X"}`, false); err != nil || !strings.Contains(string(r.Output), "already canceled") {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestStripeValidation(t *testing.T) {
	m, f := setup(t, "secret://st")
	for _, c := range []struct{ action, in string }{
		{"refund", `{"payment":"../v1/balance"}`},
		{"refund", `{"payment":"pi_3Abc123/../x"}`},
		{"refund", `{"payment":"py_123456"}`},
		{"refund", `{"payment":"pi_3Abc123","amount":-1}`},
		{"refund", `{"payment":"pi_3Abc123","reason":"because"}`},
		{"refund", `{"payment":"pi_3Abc123","idempotencyKey":"a b"}`},
		{"cancel_subscription", `{"subscription":"cus_123456"}`},
		{"cancel_subscription", `{"subscription":"sub_1Zz9Yy8X","prorate":true}`},
		{"charges", `{"customer":"jane"}`},
		{"charges", `{"payment":"ch_3Abc123"}`},
		{"payments", `{"after":"x&limit=1"}`},
		{"invoices", `{"status":"lost"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Stripe: %v", f.seen)
	}
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(`{"key":"rk_test_51AbCdEfGhIjKlMnOp"}`)); err == nil {
		t.Fatal("accepted a plain key")
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	pk, fp := setup(t, "secret://pk")
	if _, err := invoke(pk, "balance", `{}`, false); err == nil || !strings.Contains(err.Error(), "publishable") || len(fp.seen) != 0 {
		t.Fatal(err)
	}
}

func TestStripeRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://st": goodKey}), "s", json.RawMessage(`{"key":"secret://st"}`)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
