package woocommerce

import (
	"context"
	"encoding/json"
	"fmt"
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
	goodKey    = "ck_0123456789abcdef0123456789abcdef01234567"
	goodSecret = "cs_0123456789abcdef0123456789abcdef01234567"
)

var secrets = map[string]string{"secret://ck": goodKey, "secret://cs": goodSecret, "secret://badcs": "cs_ffffffffffffffffffffffffffffffffffffffff", "secret://junk": "hunter2"}

type fakeWoo struct {
	mu         sync.Mutex
	seen       []string
	status     string
	refunds    []string
	lastRefund map[string]any
	currency   string
	total      string
	refundErr  string // the gateway's message for a refused refund
}

func (f *fakeWoo) order() map[string]any {
	rs := []any{}
	for i, r := range f.refunds {
		rs = append(rs, map[string]any{"id": 900 + i, "reason": "", "total": "-" + r})
	}
	cur, total := f.currency, f.total
	if cur == "" {
		cur, total = "EUR", "49.00"
	}
	return map[string]any{"id": 42, "number": "42", "status": f.status, "currency": cur, "date_created": "2026-11-01T10:00:00", "date_paid": "2026-11-01T10:01:00",
		"total": total, "payment_method": "stripe", "payment_method_title": "Credit card (Stripe)", "customer_note": "leave at door",
		"billing":    map[string]any{"first_name": "Jane", "last_name": "Doe", "address_1": "1 Main St", "city": "Berlin", "postcode": "10115", "country": "DE", "email": "jane@example.org", "phone": "+4915112345678"},
		"shipping":   map[string]any{"first_name": "Jane", "last_name": "Doe", "address_1": "1 Main St", "city": "Berlin", "postcode": "10115", "country": "DE"},
		"line_items": []any{map[string]any{"id": 7, "name": "Mug", "sku": "MUG-1", "quantity": 2, "total": "49.00"}},
		"refunds":    rs}
}

func (f *fakeWoo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("consumer_key") != "" || r.URL.Query().Get("consumer_secret") != "" {
		w.WriteHeader(400)
		io.WriteString(w, `{"code":"keys_in_query","message":"keys in the query"}`)
		return
	}
	if k, s, ok := r.BasicAuth(); !ok || k != goodKey || s != goodSecret {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":"woocommerce_rest_authentication_error","message":"Invalid signature - provided signature does not match.","data":{"status":401}}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	switch r.Method + " " + r.URL.Path {
	case "GET /shop/wp-json/wc/v3/orders":
		w.Header().Set("X-WP-Total", "1")
		w.Header().Set("X-WP-TotalPages", "3")
		enc.Encode([]any{f.order()})
	case "GET /shop/wp-json/wc/v3/orders/42":
		enc.Encode(f.order())
	case "GET /shop/wp-json/wc/v3/orders/43": // answers with another order
		enc.Encode(f.order())
	case "PUT /shop/wp-json/wc/v3/orders/42":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.status = b["status"].(string)
		enc.Encode(f.order())
	case "POST /shop/wp-json/wc/v3/orders/42/refunds":
		var b map[string]any
		json.Unmarshal(body, &b)
		if f.refundErr != "" {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]any{"code": "woocommerce_rest_cannot_create_order_refund", "message": f.refundErr})
			return
		}
		f.lastRefund = b
		f.refunds = append(f.refunds, b["amount"].(string))
		fmt.Fprintf(w, `{"id":%d,"amount":%q}`, 900+len(f.refunds), b["amount"])
	case "GET /shop/wp-json/wc/v3/products":
		enc.Encode([]any{
			map[string]any{"id": 3, "name": "Mug", "type": "simple", "status": "publish", "sku": "MUG-1", "price": "24.50", "regular_price": "24.50", "sale_price": "", "stock_status": "instock", "manage_stock": true, "stock_quantity": 2},
			map[string]any{"id": 4, "name": "Cup", "type": "simple", "status": "publish", "sku": "CUP-1", "price": "9.00", "stock_status": "instock", "manage_stock": true, "stock_quantity": 40},
			map[string]any{"id": 5, "name": "Ebook", "type": "simple", "status": "publish", "price": "5.00", "stock_status": "instock", "manage_stock": false, "stock_quantity": nil},
		})
	case "GET /shop/wp-json/wc/v3/system_status":
		io.WriteString(w, `{"environment":{"home_url":"https://shop.example.com","version":"9.3.0","wp_version":"6.6","database":"LEAKME"},"settings":{"currency":"EUR"},"active_plugins":[{"plugin":"LEAKME"}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":"rest_no_route","message":"No route was found matching the URL and request method.","data":{"status":404}}`)
	}
}

func setup(t *testing.T, cs string) (*Module, *fakeWoo) {
	t.Helper()
	f := &fakeWoo{status: "processing"}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/shop/", Key: "secret://ck", Secret: cs})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "w", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "w", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func noSecret(t *testing.T, s string) {
	t.Helper()
	if strings.Contains(s, goodKey) || strings.Contains(s, goodSecret) || strings.Contains(s, "hunter2") || strings.Contains(s, "LEAKME") {
		t.Fatalf("leaked: %s", s)
	}
}

func TestWooReads(t *testing.T) {
	m, _ := setup(t, "secret://cs")
	if h := m.Health(context.Background(), "w"); h.Status != "ok" || h.Message != "connected, 1 orders" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"store", `{}`, `"woocommerce":"9.3.0"`},
		{"orders", `{}`, `"total":"49.00 EUR"`},
		{"orders", `{"status":"processing","since":"2026-11-01"}`, `"nextPage":2`},
		{"order", `{"order":42}`, `"email":"jane@example.org"`},
		{"products", `{"search":"mug","status":"publish","stockStatus":"instock"}`, `"sku":"MUG-1"`},
		{"stock", `{"below":5}`, `"stock":2`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		noSecret(t, out)
		if c.action != "order" && (strings.Contains(out, "Jane") || strings.Contains(out, "jane") || strings.Contains(out, "Main St") || strings.Contains(out, "+49")) {
			t.Fatalf("%s returned personal data: %s", c.action, out)
		}
	}
	if r, _ := invoke(m, "stock", `{"below":5}`, false); strings.Contains(string(r.Output), "CUP-1") || strings.Contains(string(r.Output), "Ebook") {
		t.Fatal(string(r.Output))
	}
	for _, a := range m.Manifest().Actions {
		if a.Sensitive != (a.Name == "order") {
			t.Fatalf("%s: sensitive %v", a.Name, a.Sensitive)
		}
		if a.Risk != sdk.RiskRead && (a.Risk != sdk.RiskDestructive || !a.DryRun) {
			t.Fatalf("%s must be destructive with a preview", a.Name)
		}
	}
}

func TestWooStatus(t *testing.T) {
	m, f := setup(t, "secret://cs")
	r, err := invoke(m, "update_order_status", `{"order":42,"status":"completed"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Set order #42 (total 49.00 EUR) from processing to completed; WooCommerce may email the customer. To run it, give expectedStatus "processing" (the order as previewed); it's refused if the order changed.` || f.status != "processing" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "update_order_status", `{"order":42,"status":"completed"}`, false); err == nil || f.status != "processing" || !strings.Contains(err.Error(), `expectedStatus "processing"`) {
		t.Fatalf("ran without the previewed status: %v", err)
	}
	r, err = invoke(m, "update_order_status", `{"order":42,"status":"completed","expectedStatus":"processing"}`, false)
	if err != nil || f.status != "completed" || r.Undo == nil || r.Undo.Action != "update_order_status" || string(r.Undo.Input) != `{"expectedStatus":"completed","order":42,"status":"processing"}` {
		t.Fatalf("%+v %v", r, err)
	}
	undo := r.Undo
	if r, err := invoke(m, "update_order_status", `{"order":42,"status":"completed"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "update_order_status", `{"order":42,"status":"cancelled"}`, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "Cancel order #42 (total 49.00 EUR)") || !strings.Contains(r.Plan.Summary, "no money is refunded") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, undo.Action, string(undo.Input), false); err != nil || f.status != "processing" {
		t.Fatal(err)
	}
	if _, err := invoke(m, "update_order_status", `{"order":42,"status":"completed","expectedStatus":"processing"}`, false); err != nil || f.status != "completed" {
		t.Fatal(err)
	}
	// The order moved on since a preview: refused, and the preview says so.
	if _, err := invoke(m, "update_order_status", `{"order":42,"status":"cancelled","expectedStatus":"processing"}`, false); err == nil || f.status != "completed" || !strings.Contains(err.Error(), "changed since the preview") {
		t.Fatal(err)
	}
	if r, err := invoke(m, "update_order_status", `{"order":42,"status":"cancelled","expectedStatus":"processing"}`, true); err != nil || !strings.Contains(r.Plan.Summary, "will be refused") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "update_order_status", `{"order":42,"status":"cancelled","expectedStatus":"completed"}`, false); err != nil || r.Undo != nil {
		t.Fatalf("a cancellation has no undo: %+v %v", r, err)
	}
	// An earlier change's undo doesn't bring a since-cancelled order back.
	if _, err := invoke(m, undo.Action, string(undo.Input), false); err == nil || f.status != "cancelled" {
		t.Fatalf("the undo resurrected a cancelled order: %v", err)
	}
	// The order changed is the one asked for, whatever the server answers.
	n := len(f.seen)
	if _, err := invoke(m, "update_order_status", `{"order":43,"status":"completed","expectedStatus":"cancelled"}`, false); err == nil || len(f.seen) != n+1 {
		t.Fatalf("changed another order: %v %v", err, f.seen[n:])
	}
}

func TestWooRefund(t *testing.T) {
	m, f := setup(t, "secret://cs")
	r, err := invoke(m, "refund_order", `{"order":42,"amount":"10.5"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Partial refund of 10.50 EUR on order #42, through Credit card (Stripe). It can't be taken back. To run it, give expectedTotal "49.00 EUR" and expectedRefunded "0.00 EUR" (the order as previewed); it's refused if the order changed.` || len(f.refunds) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	plan, _ := json.Marshal(r.Plan)
	if strings.Contains(string(plan), "Jane") || strings.Contains(string(plan), "jane") {
		t.Fatalf("the preview has personal data: %s", plan)
	}
	if _, err := invoke(m, "refund_order", `{"order":42,"amount":10.5}`, false); err == nil || len(f.refunds) != 0 || !strings.Contains(err.Error(), "expectedTotal") {
		t.Fatalf("refunded without the previewed values: %v", err)
	}
	r, err = invoke(m, "refund_order", `{"order":42,"amount":10.5,"reason":"broken","expectedTotal":"49.00 EUR","expectedRefunded":"0"}`, false)
	if err != nil || r.Undo != nil || !strings.Contains(string(r.Output), `"amount":"10.50 EUR"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if f.lastRefund["amount"] != "10.50" || f.lastRefund["api_refund"] != true || f.lastRefund["reason"] != "broken" {
		t.Fatal(f.lastRefund)
	}
	// A retry after a lost answer names what was refunded before it: refused.
	if _, err := invoke(m, "refund_order", `{"order":42,"amount":10.5,"reason":"broken","expectedTotal":"49.00 EUR","expectedRefunded":"0"}`, false); err == nil || len(f.refunds) != 1 || !strings.Contains(err.Error(), "expectedRefunded is 10.50 EUR now, not 0") {
		t.Fatalf("refunded twice: %v %v", err, f.refunds)
	}
	for _, bad := range []string{`"expectedTotal":"49.00 USD","expectedRefunded":"10.50"`, `"expectedTotal":"490","expectedRefunded":"10.50"`, `"expectedTotal":"lots","expectedRefunded":"10.50"`} {
		if _, err := invoke(m, "refund_order", `{"order":42,"amount":1,`+bad+`}`, false); err == nil || len(f.refunds) != 1 {
			t.Fatalf("%s: %v", bad, err)
		}
	}
	if _, err := invoke(m, "refund_order", `{"order":42,"amount":"40"}`, false); err == nil || !strings.Contains(err.Error(), "only 38.50 EUR of 49.00 EUR") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "refund_order", `{"order":42,"amount":"1.005"}`, false); err == nil || !strings.Contains(err.Error(), "2 decimals") {
		t.Fatal(err)
	}
	r, err = invoke(m, "refund_order", `{"order":42,"gateway":false}`, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "38.50 EUR") || !strings.Contains(r.Plan.Summary, "recorded only") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "refund_order", `{"order":42,"expectedTotal":"49","expectedRefunded":"10.50 eur"}`, false); err != nil || f.refunds[1] != "38.50" {
		t.Fatal(err, f.refunds)
	}
	if _, err := invoke(m, "refund_order", `{"order":42}`, false); err == nil || !strings.Contains(err.Error(), "nothing left") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "refund_order", `{"order":7}`, true); err == nil || !strings.Contains(err.Error(), "no order 7") {
		t.Fatal(err)
	}
}

func TestWooValidation(t *testing.T) {
	m, f := setup(t, "secret://cs")
	for _, c := range []struct{ action, in string }{
		{"order", `{}`},
		{"order", `{"order":"42/../customers"}`},
		{"order", `{"order":-1}`},
		{"orders", `{"status":"processing&per_page=1000"}`},
		{"orders", `{"since":"yesterday"}`},
		{"orders", `{"page":-2}`},
		{"products", `{"search":"x\" OR 1=1 <script>"}`},
		{"products", `{"status":"trash"}`},
		{"products", `{"stockStatus":"lots"}`},
		{"stock", `{"below":-1}`},
		{"update_order_status", `{"order":42}`},
		{"update_order_status", `{"order":42,"status":"refunded"}`},
		{"update_order_status", `{"order":42,"status":"shipped"}`},
		{"update_order_status", `{"status":"completed"}`},
		{"refund_order", `{"order":42,"amount":"-5"}`},
		{"refund_order", `{"order":42,"amount":"0"}`},
		{"refund_order", `{"order":42,"amount":"1e3"}`},
		{"refund_order", `{"order":42,"amount":true}`},
		{"refund_order", `{"order":42,"reason":"a\nb"}`},
		{"refund_order", `{}`},
		{"nope", `{}`},
	} {
		for _, dry := range []bool{false, true} {
			if _, err := invoke(m, c.action, c.in, dry); err == nil {
				t.Fatalf("%s accepted %s", c.action, c.in)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached WooCommerce: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://shop.example.com", Key: goodKey, Secret: "secret://cs"},
		{URL: "https://shop.example.com", Key: "secret://ck", Secret: goodSecret},
		{URL: "http://shop.example.com", Key: "secret://ck", Secret: "secret://cs"},
		{URL: "shop.example.com", Key: "secret://ck", Secret: "secret://cs"},
		{URL: "https://user:pw@shop.example.com", Key: "secret://ck", Secret: "secret://cs"},
		{URL: "https://shop.example.com/?consumer_key=x", Key: "secret://ck", Secret: "secret://cs"},
		{URL: "https://shop.example.com/#x", Key: "secret://ck", Secret: "secret://cs"},
		{URL: "ftp://shop.example.com", Key: "secret://ck", Secret: "secret://cs"},
		{URL: "https://shop.example.com", Key: "secret://ck", Secret: "secret://cs", Fingerprint: "nope"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://badcs")
	if h := bad.Health(context.Background(), "w"); h.Status != "down" || h.Message != "WooCommerce refused the consumer key and secret" {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, "secret://junk")
	if _, err := invoke(junk, "orders", `{}`, false); err == nil || len(fj.seen) != 0 {
		t.Fatal(err)
	} else {
		noSecret(t, err.Error())
	}
}

func TestWooErrorsHideSecretsAndPersonalData(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, `{"code":"x","message":"Customer jane@example.org (+49 151 1234 5678) can't be used with consumer_secret=`+goodSecret+` `+strings.Repeat("padding ", 40)+`"}`)
	}))
	defer srv.Close()
	m := &Module{HTTP: srv.Client()}
	raw, _ := json.Marshal(Config{URL: srv.URL, Key: "secret://ck", Secret: "secret://cs"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "w", raw); err != nil {
		t.Fatal(err)
	}
	_, err := invoke(m, "orders", `{}`, false)
	if err == nil || strings.Contains(err.Error(), "jane") || strings.Contains(err.Error(), "1234") || strings.Contains(err.Error(), "cs_") || len(err.Error()) > 300 {
		t.Fatalf("error: %v", err)
	}
}

func TestWooRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := &Module{HTTP: srv.Client()}
	raw, _ := json.Marshal(Config{URL: srv.URL, Key: "secret://ck", Secret: "secret://cs"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "w", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "w"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

func TestWooRefundCurrenciesAndOddAmounts(t *testing.T) {
	m, f := setup(t, "secret://cs")
	f.currency, f.total = "JPY", "4900"
	if _, err := invoke(m, "refund_order", `{"order":42,"amount":"10.5","expectedTotal":"4900","expectedRefunded":"0"}`, false); err == nil || !strings.Contains(err.Error(), "0 decimals") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "refund_order", `{"order":42,"expectedTotal":"4900 JPY","expectedRefunded":"0 JPY"}`, false); err != nil || f.lastRefund["amount"] != "4900" {
		t.Fatal(err, f.lastRefund)
	}
	f.currency, f.total, f.refunds = "KWD", "12.345", nil
	r, err := invoke(m, "refund_order", `{"order":42,"amount":"0.005"}`, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "0.005 KWD") || !strings.Contains(r.Plan.Summary, `expectedTotal "12.345 KWD"`) {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	// An earlier refund this module can't read never counts as nothing.
	f.currency, f.total, f.refunds = "EUR", "49.00", []string{"5.00000"}
	if _, err := invoke(m, "refund_order", `{"order":42}`, true); err == nil || !strings.Contains(err.Error(), "aren't amounts") {
		t.Fatal(err)
	}
}

func TestWooChangeErrorsHideTheCustomer(t *testing.T) {
	m, f := setup(t, "secret://cs")
	f.refundErr = "Refund failed: card of Jane Doe, 1 Main St, 10115 Berlin was closed"
	_, err := invoke(m, "refund_order", `{"order":42,"expectedTotal":"49.00","expectedRefunded":"0.00"}`, false)
	if err == nil || !strings.Contains(err.Error(), "Refund failed") {
		t.Fatal(err)
	}
	for _, s := range []string{"Jane", "Doe", "Main St", "10115", "Berlin"} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("the error quotes the customer: %v", err)
		}
	}
}
