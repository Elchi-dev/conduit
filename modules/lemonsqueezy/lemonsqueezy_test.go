package lemonsqueezy

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

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const goodKey = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiI5NGQ1OSIsImp0aSI6IjEyMyJ9.c2lnbmF0dXJlc2lnbmF0dXJl"

type fakeLS struct {
	mu        sync.Mutex
	seen      []string
	bodies    []string
	refunded  int64
	cancelled bool
}

func (f *fakeLS) order() map[string]any {
	status := "paid"
	if f.refunded > 0 {
		status = "partial_refund"
	}
	if f.refunded >= 4900 {
		status = "refunded"
	}
	return map[string]any{"type": "orders", "id": "1001", "attributes": map[string]any{"store_id": 7, "customer_id": 55, "identifier": "104e18a2-d755-4d4b-80c4-a6c1dcbe1c10", "order_number": 42, "user_name": "Jane Doe", "user_email": "jane@example.org",
		"currency": "USD", "subtotal": 4500, "tax": 400, "total": 4900, "status": status, "refunded": f.refunded > 0, "refunded_amount": f.refunded, "test_mode": true, "created_at": "2026-11-01T10:00:00.000000Z",
		"first_order_item": map[string]any{"product_name": "Pro license", "variant_name": "Default"}, "urls": map[string]any{"receipt": "https://app.lemonsqueezy.com/my-orders/secret-signature"}}}
}

func (f *fakeLS) sub() map[string]any {
	a := map[string]any{"store_id": 7, "customer_id": 55, "order_id": 1001, "product_name": "Pro", "variant_name": "Monthly", "user_name": "Jane Doe", "user_email": "jane@example.org", "status": "active", "cancelled": false, "pause": nil,
		"renews_at": "2026-12-01T00:00:00.000000Z", "ends_at": nil, "card_brand": "visa", "card_last_four": "4242", "urls": map[string]any{"customer_portal": "https://store.lemonsqueezy.com/billing?signature=secret"}, "created_at": "2026-01-01T00:00:00.000000Z"}
	if f.cancelled {
		a["status"], a["cancelled"], a["ends_at"] = "cancelled", true, "2026-12-01T00:00:00.000000Z"
	}
	return map[string]any{"type": "subscriptions", "id": "301", "attributes": a}
}

func (f *fakeLS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+goodKey {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"detail":"Unauthenticated.","status":"401","title":"Unauthorized"}]}`)
		return
	}
	if r.Header.Get("Accept") != mediaType {
		w.WriteHeader(406)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+r.URL.RawQuery)
	if r.Method != "GET" {
		if r.Header.Get("Content-Type") != mediaType && r.Method != "DELETE" {
			w.WriteHeader(415)
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.bodies = append(f.bodies, string(b))
	}
	w.Header().Set("Content-Type", mediaType)
	enc := json.NewEncoder(w)
	stores := map[string]any{"type": "stores", "id": "7", "attributes": map[string]any{"name": "Acme", "slug": "acme", "domain": "acme.lemonsqueezy.com", "currency": "USD", "plan": "fresh", "total_sales": 120, "total_revenue": 1234567, "thirty_day_sales": 10, "thirty_day_revenue": 49000}}
	page := map[string]any{"page": map[string]any{"currentPage": 1, "lastPage": 3, "total": 41}}
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/stores":
		enc.Encode(map[string]any{"data": []any{stores}})
	case "GET /v1/stores/7":
		enc.Encode(map[string]any{"data": stores})
	case "GET /v1/orders":
		q := r.URL.Query()
		if q.Get("filter[store_id]") != "7" || q.Get("page[size]") != "5" {
			w.WriteHeader(400)
			return
		}
		enc.Encode(map[string]any{"data": []any{f.order()}, "meta": page})
	case "GET /v1/orders/1001":
		enc.Encode(map[string]any{"data": f.order()})
	case "POST /v1/orders/1001/refund":
		var b struct {
			Data struct {
				Type       string `json:"type"`
				ID         string `json:"id"`
				Attributes struct {
					Amount int64 `json:"amount"`
				} `json:"attributes"`
			} `json:"data"`
		}
		json.Unmarshal([]byte(f.bodies[len(f.bodies)-1]), &b)
		if b.Data.Type != "orders" || b.Data.ID != "1001" || b.Data.Attributes.Amount <= 0 {
			w.WriteHeader(422)
			return
		}
		f.refunded += b.Data.Attributes.Amount
		enc.Encode(map[string]any{"data": f.order()})
	case "GET /v1/subscriptions":
		if r.URL.Query().Get("filter[status]") != "active" {
			w.WriteHeader(400)
			return
		}
		enc.Encode(map[string]any{"data": []any{f.sub()}, "meta": page})
	case "GET /v1/subscriptions/301":
		enc.Encode(map[string]any{"data": f.sub()})
	case "DELETE /v1/subscriptions/301":
		f.cancelled = true
		enc.Encode(map[string]any{"data": f.sub()})
	case "PATCH /v1/subscriptions/301":
		if !strings.Contains(f.bodies[len(f.bodies)-1], `"cancelled":false`) {
			w.WriteHeader(422)
			return
		}
		f.cancelled = false
		enc.Encode(map[string]any{"data": f.sub()})
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[{"detail":"Not found.","status":"404","title":"Not Found"}]}`)
	}
}

var secrets = map[string]string{"secret://ls": goodKey, "secret://bad": "aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc", "secret://junk": "plain-key"}

func setup(t *testing.T, raw string) (*Module, *fakeLS) {
	t.Helper()
	f := &fakeLS{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	if err := m.Configure(context.Background(), fakehost.New(secrets), "l", json.RawMessage(raw)); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "l", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

const good = `{"key":"secret://ls","store":"7"}`

func TestLemonSqueezyReads(t *testing.T) {
	m, _ := setup(t, good)
	if h := m.Health(context.Background(), "l"); h.Status != "ok" || h.Message != "connected to store Acme" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"stores", `{}`, `"totalRevenue":"12345.67 USD"`},
		{"revenue", `{}`, `"last30DaysRevenue":"490.00 USD"`},
		{"revenue", `{"store":7}`, `"totalSales":120`},
		{"orders", `{"limit":5}`, `"email":"jane@example.org"`},
		{"orders", `{"limit":5}`, `"lastPage":3`},
		{"orders", `{"limit":5,"status":"refunded"}`, `"items":[]`},
		{"subscriptions", `{"status":"active"}`, `"renewsAt":"2026-12-01T00:00:00.000000Z"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		for _, leak := range []string{"signature", "4242"} {
			if strings.Contains(out, leak) {
				t.Fatalf("%s leaked %q: %s", c.action, leak, out)
			}
		}
		if c.action != "orders" && (strings.Contains(out, "jane@") || strings.Contains(out, "Jane")) {
			t.Fatalf("%s returned personal data: %s", c.action, out)
		}
	}
	for _, a := range m.Manifest().Actions {
		if a.Sensitive != (a.Name == "orders") {
			t.Fatalf("%s: sensitive %v", a.Name, a.Sensitive)
		}
		switch a.Name {
		case "refund_order", "cancel_subscription", "resume_subscription":
			if a.Risk != sdk.RiskDestructive || !a.DryRun {
				t.Fatalf("%s must be destructive with a preview", a.Name)
			}
		}
	}
	other, _ := setup(t, `{"key":"secret://ls","store":"8"}`)
	if h := other.Health(context.Background(), "l"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
}

func TestLemonSqueezyRefund(t *testing.T) {
	m, f := setup(t, good)
	r, err := invoke(m, "refund_order", `{"order":"1001","amount":1500}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Partial refund of 15.00 USD to customer 55 (order #42, id 1001, test mode)" || f.refunded != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	plan, _ := json.Marshal(r.Plan)
	if strings.Contains(string(plan), "jane") || strings.Contains(string(plan), "Jane") {
		t.Fatalf("the preview has personal data: %s", plan)
	}
	r, err = invoke(m, "refund_order", `{"order":1001,"amount":1500}`, false)
	if err != nil || f.refunded != 1500 || r.Undo != nil || !strings.Contains(string(r.Output), `"status":"partial_refund"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "refund_order", `{"order":"1001","amount":4000}`, false); err == nil || !strings.Contains(err.Error(), "only 34.00 USD") {
		t.Fatal(err)
	}
	r, err = invoke(m, "refund_order", `{"order":"1001"}`, true)
	if err != nil || !strings.HasPrefix(r.Plan.Summary, "Partial refund of 34.00 USD") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "refund_order", `{"order":"1001"}`, false); err != nil || f.refunded != 4900 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "refund_order", `{"order":"1001"}`, false); err == nil || !strings.Contains(err.Error(), "is refunded") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "refund_order", `{"order":"999"}`, true); err == nil || !strings.Contains(err.Error(), "no order 999") {
		t.Fatal(err)
	}
}

func TestLemonSqueezyCancel(t *testing.T) {
	m, f := setup(t, good)
	r, err := invoke(m, "cancel_subscription", `{"subscription":"301"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "runs until the paid period ends (2026-12-01") || f.cancelled {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "cancel_subscription", `{"subscription":301}`, false)
	if err != nil || !f.cancelled || r.Undo == nil || r.Undo.Action != "resume_subscription" || string(r.Undo.Input) != `{"subscription":"301"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "cancel_subscription", `{"subscription":"301"}`, false); err != nil || !strings.Contains(string(r.Output), "cancelled already") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "resume_subscription", `{"subscription":"301"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "bills again") || !f.cancelled {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "resume_subscription", `{"subscription":"301"}`, false)
	if err != nil || f.cancelled || r.Undo == nil || r.Undo.Action != "cancel_subscription" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "resume_subscription", `{"subscription":"301"}`, false); err != nil || !strings.Contains(string(r.Output), "isn't cancelled") {
		t.Fatalf("%s %v", r.Output, err)
	}
	// Past the end of the grace period it can't be resumed.
	f.cancelled = true
	m.Now = func() time.Time { return time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := invoke(m, "resume_subscription", `{"subscription":"301"}`, false); err == nil || !strings.Contains(err.Error(), "can't be resumed") {
		t.Fatal(err)
	}
}

func TestLemonSqueezyValidation(t *testing.T) {
	m, f := setup(t, good)
	for _, c := range []struct{ action, in string }{
		{"refund_order", `{"order":"../stores"}`},
		{"refund_order", `{"order":"1001/../../stores"}`},
		{"refund_order", `{"order":-1}`},
		{"refund_order", `{"order":1.5}`},
		{"refund_order", `{"order":"1001","amount":-5}`},
		{"refund_order", `{}`},
		{"cancel_subscription", `{"subscription":"abc"}`},
		{"resume_subscription", `{"subscription":"0"}`},
		{"orders", `{"store":"7&x=1"}`},
		{"orders", `{"email":"a@b.com&filter[x]=1"}`},
		{"orders", `{"status":"lost"}`},
		{"subscriptions", `{"status":"lost"}`},
		{"revenue", `{"store":"../x"}`},
		{"nope", `{}`},
	} {
		for _, dry := range []bool{false, true} {
			if _, err := invoke(m, c.action, c.in, dry); err == nil {
				t.Fatalf("%s accepted %s", c.action, c.in)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Lemon Squeezy: %v", f.seen)
	}
	for _, raw := range []string{`{"key":"` + goodKey + `"}`, `{"key":"secret://ls","store":"acme"}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted settings %s", raw)
		}
	}
	bad, _ := setup(t, `{"key":"secret://bad"}`)
	if h := bad.Health(context.Background(), "l"); h.Status != "down" || h.Message != "Lemon Squeezy refused the API key" {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, `{"key":"secret://junk"}`)
	if _, err := invoke(junk, "stores", `{}`, false); err == nil || len(fj.seen) != 0 {
		t.Fatal(err)
	}
}

func TestLemonSqueezyRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(secrets), "l", json.RawMessage(`{"key":"secret://ls"}`)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "l"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
