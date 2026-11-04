package shopify

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

const goodToken = "shpat_FakeTestTokenNotReal0000000"

type fakeShopify struct {
	mu          sync.Mutex
	seen        []string
	queries     []string
	vars        []map[string]any
	fulfilled   bool
	fCancelled  bool
	cancelled   bool
	refunded    float64
	lastRefund  map[string]any
	lastCancel  map[string]any
	lastFulfill map[string]any
	// usd makes the customer pay in USD (1.10 per EUR) in the EUR shop.
	usd bool
	// financial is the order's payment state (PAID when empty).
	financial string
	// total is the order's total (49.00 when empty).
	total string
}

func (f *fakeShopify) order() map[string]any {
	var cancelledAt any
	if f.cancelled {
		cancelledAt = "2026-11-04T12:00:00Z"
	}
	foStatus, fStatus := "OPEN", "UNFULFILLED"
	if f.fulfilled && !f.fCancelled {
		foStatus, fStatus = "CLOSED", "FULFILLED"
	}
	tx := []any{
		map[string]any{"id": "gid://shopify/OrderTransaction/9", "kind": "SALE", "status": "SUCCESS", "gateway": "shopify_payments", "createdAt": "2026-11-01T10:00:00Z", "test": true,
			"amountSet": map[string]any{"shopMoney": map[string]any{"amount": "49.00", "currencyCode": "EUR"}}},
	}
	if f.usd {
		tx[0].(map[string]any)["amountSet"].(map[string]any)["presentmentMoney"] = map[string]any{"amount": "53.90", "currencyCode": "USD"}
	}
	if f.refunded > 0 {
		tx = append(tx, map[string]any{"id": "gid://shopify/OrderTransaction/10", "kind": "REFUND", "status": "SUCCESS", "gateway": "shopify_payments", "test": true,
			"amountSet": map[string]any{"shopMoney": map[string]any{"amount": jsonNum(f.refunded), "currencyCode": "EUR"}}, "parentTransaction": map[string]any{"id": "gid://shopify/OrderTransaction/9"}})
	}
	ms := func(a string) map[string]any {
		return map[string]any{"shopMoney": map[string]any{"amount": a, "currencyCode": "EUR"}}
	}
	if f.usd && f.refunded > 0 {
		tx[1].(map[string]any)["amountSet"] = map[string]any{"shopMoney": map[string]any{"amount": jsonNum(f.refunded / 1.1), "currencyCode": "EUR"},
			"presentmentMoney": map[string]any{"amount": jsonNum(f.refunded), "currencyCode": "USD"}}
	}
	pres := "EUR"
	amt := "49.00"
	if f.total != "" {
		amt = f.total
	}
	total := ms(amt)
	fin := "PAID"
	if f.financial != "" {
		fin = f.financial
	}
	if f.usd {
		pres = "USD"
		total["presentmentMoney"] = map[string]any{"amount": "53.90", "currencyCode": "USD"}
	}
	return map[string]any{"presentmentCurrencyCode": pres, "id": "gid://shopify/Order/1001", "name": "#1001", "createdAt": "2026-11-01T10:00:00Z", "cancelledAt": cancelledAt, "test": true,
		"displayFinancialStatus": fin, "displayFulfillmentStatus": fStatus, "subtotalLineItemsQuantity": 2, "email": "jane@example.org", "phone": "+4915112345678",
		"totalPriceSet": total, "totalRefundedSet": ms(jsonNum(f.refunded)), "totalReceivedSet": ms("49.00"),
		"customer":        map[string]any{"id": "gid://shopify/Customer/5", "displayName": "Jane Doe"},
		"shippingAddress": map[string]any{"name": "Jane Doe", "address1": "1 Main St", "city": "Berlin", "zip": "10115", "countryCodeV2": "DE"},
		"lineItems":       map[string]any{"nodes": []any{map[string]any{"title": "Mug", "sku": "MUG-1", "quantity": 2, "currentQuantity": 2, "originalUnitPriceSet": ms("24.50")}}},
		"fulfillments":    []any{},
		"fulfillmentOrders": map[string]any{"nodes": []any{map[string]any{"id": "gid://shopify/FulfillmentOrder/77", "status": foStatus,
			"lineItems": map[string]any{"nodes": []any{map[string]any{"remainingQuantity": 2}}}}}},
		"transactions": tx}
}

func jsonNum(v float64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (f *fakeShopify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Shopify-Access-Token") != goodToken {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":"[API] Invalid API key or access token (unrecognized login or wrong password)"}`)
		return
	}
	if r.Method != "POST" || r.URL.Path != "/admin/api/"+APIVersion+"/graphql.json" {
		w.WriteHeader(404)
		return
	}
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, req.Query)
	f.queries = append(f.queries, req.Query)
	f.vars = append(f.vars, req.Variables)
	enc := json.NewEncoder(w)
	data := func(v any) { enc.Encode(map[string]any{"data": v}) }
	op := strings.Fields(req.Query)[1]
	if i := strings.IndexByte(op, '('); i > 0 {
		op = op[:i]
	}
	switch op {
	case "Shop":
		data(map[string]any{"shop": map[string]any{"name": "Acme", "myshopifyDomain": "acme.myshopify.com", "currencyCode": "EUR", "ianaTimezone": "Europe/Berlin", "email": "owner@acme.example",
			"primaryDomain": map[string]any{"host": "acme.example"}, "plan": map[string]any{"publicDisplayName": "Basic", "partnerDevelopment": false, "shopifyPlus": false}}})
	case "Orders":
		if req.Variables["query"] != "status:open financial_status:paid created_at:>=2026-11-01" && req.Variables["query"] != nil {
			enc.Encode(map[string]any{"errors": []any{map[string]any{"message": "bad query " + req.Variables["query"].(string)}}})
			return
		}
		data(map[string]any{"orders": map[string]any{"nodes": []any{f.order()}, "pageInfo": map[string]any{"hasNextPage": true, "endCursor": "eyJsYXN0X2lkIjoxMDAxfQ=="}}})
	case "OrderByName":
		if req.Variables["query"] != `name:"#1001"` {
			data(map[string]any{"orders": map[string]any{"nodes": []any{}}})
			return
		}
		data(map[string]any{"orders": map[string]any{"nodes": []any{map[string]any{"id": "gid://shopify/Order/1001", "name": "#1001"}}}})
	case "Order":
		if req.Variables["id"] != "gid://shopify/Order/1001" {
			data(map[string]any{"order": nil})
			return
		}
		data(map[string]any{"order": f.order()})
	case "Products":
		data(map[string]any{"products": map[string]any{"nodes": []any{map[string]any{"id": "gid://shopify/Product/3", "title": "Mug", "handle": "mug", "status": "ACTIVE", "vendor": "Acme", "productType": "Kitchen",
			"totalInventory": 12, "tracksInventory": true, "variants": map[string]any{"nodes": []any{map[string]any{"id": "gid://shopify/ProductVariant/31", "title": "Blue", "sku": "MUG-1", "price": "24.50", "inventoryQuantity": 12}}}}},
			"pageInfo": map[string]any{"hasNextPage": false}}})
	case "Locations", "Location":
		loc := map[string]any{"id": "gid://shopify/Location/8", "name": "Warehouse", "isActive": true, "inventoryLevels": map[string]any{"nodes": []any{
			map[string]any{"quantities": []any{map[string]any{"name": "available", "quantity": 2}, map[string]any{"name": "on_hand", "quantity": 4}, map[string]any{"name": "committed", "quantity": 2}},
				"item": map[string]any{"id": "gid://shopify/InventoryItem/41", "sku": "MUG-1", "tracked": true, "variant": map[string]any{"displayName": "Mug - Blue"}}},
			map[string]any{"quantities": []any{map[string]any{"name": "available", "quantity": 40}}, "item": map[string]any{"id": "gid://shopify/InventoryItem/42", "sku": "CUP-1", "tracked": true}},
		}}}
		if op == "Location" {
			data(map[string]any{"location": loc})
			return
		}
		data(map[string]any{"locations": map[string]any{"nodes": []any{loc, map[string]any{"id": "gid://shopify/Location/9", "name": "Old shop", "isActive": false}}}})
	case "Fulfill":
		f.lastFulfill = req.Variables
		f.fulfilled, f.fCancelled = true, false
		data(map[string]any{"fulfillmentCreate": map[string]any{"fulfillment": map[string]any{"id": "gid://shopify/Fulfillment/55", "name": "#1001-F1", "status": "SUCCESS"}, "userErrors": []any{}}})
	case "Fulfillment":
		if req.Variables["id"] != "gid://shopify/Fulfillment/55" {
			data(map[string]any{"fulfillment": nil})
			return
		}
		st := "SUCCESS"
		if f.fCancelled {
			st = "CANCELLED"
		}
		data(map[string]any{"fulfillment": map[string]any{"id": "gid://shopify/Fulfillment/55", "name": "#1001-F1", "status": st, "order": map[string]any{"name": "#1001"}}})
	case "CancelFulfillment":
		f.fCancelled = true
		data(map[string]any{"fulfillmentCancel": map[string]any{"fulfillment": map[string]any{"status": "CANCELLED"}, "userErrors": []any{}}})
	case "CancelOrder":
		f.lastCancel = req.Variables
		f.cancelled = true
		data(map[string]any{"orderCancel": map[string]any{"job": map[string]any{"id": "gid://shopify/Job/1", "done": false}, "orderCancelUserErrors": []any{}}})
	case "Refund":
		f.lastRefund = req.Variables
		if !strings.Contains(req.Query, "@idempotent(key: $idempotencyKey)") || req.Variables["idempotencyKey"] == "" {
			enc.Encode(map[string]any{"errors": []any{map[string]any{"message": "idempotency key required"}}})
			return
		}
		in := req.Variables["input"].(map[string]any)
		tx := in["transactions"].([]any)[0].(map[string]any)
		var a float64
		json.Unmarshal([]byte(tx["amount"].(string)), &a)
		f.refunded += a
		data(map[string]any{"refundCreate": map[string]any{"refund": map[string]any{"id": "gid://shopify/Refund/66"},
			"order":      map[string]any{"displayFinancialStatus": "PARTIALLY_REFUNDED", "totalRefundedSet": map[string]any{"shopMoney": map[string]any{"amount": jsonNum(f.refunded), "currencyCode": "EUR"}}},
			"userErrors": []any{}}})
	default:
		enc.Encode(map[string]any{"errors": []any{map[string]any{"message": "unknown operation"}}})
	}
}

var secrets = map[string]string{"secret://shop": goodToken, "secret://bad": "shpat_FakeBadTokenNotReal00000000", "secret://junk": "hunter2"}

func setup(t *testing.T, tok string) (*Module, *fakeShopify) {
	t.Helper()
	f := &fakeShopify{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Shop: "acme.myshopify.com", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestShopifyReads(t *testing.T) {
	m, f := setup(t, "secret://shop")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "connected to Acme (Basic)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"shop", `{}`, `"currency":"EUR"`},
		{"orders", `{}`, `"total":"49.00 EUR"`},
		{"orders", `{"status":"open","financialStatus":"paid","since":"2026-11-01"}`, `"after":"eyJsYXN0X2lkIjoxMDAxfQ=="`},
		{"order", `{"order":"#1001"}`, `"email":"jane@example.org"`},
		{"order", `{"order":1001}`, `"city":"Berlin"`},
		{"products", `{"search":"blue mug","status":"active"}`, `"sku":"MUG-1"`},
		{"inventory", `{}`, `"available":2`},
		{"inventory", `{"location":"8","below":5}`, `"name":"Mug - Blue"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		if c.action != "order" && (strings.Contains(out, "jane") || strings.Contains(out, "Jane") || strings.Contains(out, "+49") || strings.Contains(out, "owner@")) {
			t.Fatalf("%s returned personal data: %s", c.action, out)
		}
	}
	if r, _ := invoke(m, "inventory", `{"below":5}`, false); strings.Contains(string(r.Output), "CUP-1") || strings.Contains(string(r.Output), "Old shop") {
		t.Fatal(string(r.Output))
	}
	if v := f.vars[len(f.vars)-1]; v["names"] == nil {
		t.Fatal(v)
	}
	// Input never becomes part of a GraphQL document.
	for _, q := range f.queries {
		if strings.Contains(q, "#1001") || strings.Contains(q, "blue mug") || strings.Contains(q, "2026-11-01") {
			t.Fatalf("input in query text: %s", q)
		}
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

func TestShopifyFulfil(t *testing.T) {
	m, f := setup(t, "secret://shop")
	r, err := invoke(m, "fulfill_order", `{"order":"#1001","trackingNumber":"1Z999","trackingCompany":"UPS","trackingUrl":"https://ups.example/t/1Z999"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Fulfil 2 items of order #1001 (the customer isn't notified, test order)" || f.fulfilled {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "fulfill_order", `{"order":"#1001","trackingNumber":"1Z999"}`, false)
	if err != nil || !f.fulfilled || r.Undo == nil || r.Undo.Action != "cancel_fulfillment" || string(r.Undo.Input) != `{"fulfillment":"55"}` {
		t.Fatalf("%+v %v", r, err)
	}
	fl := f.lastFulfill["fulfillment"].(map[string]any)
	if fl["notifyCustomer"] != false || fl["trackingInfo"].(map[string]any)["number"] != "1Z999" {
		t.Fatal(fl)
	}
	if r, err := invoke(m, "fulfill_order", `{"order":"1001"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "cancel_fulfillment", `{"fulfillment":"55"}`, true)
	if err != nil || r.Plan == nil || f.fCancelled {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Plan.Changes[0].Op+"_fulfillment", `{"fulfillment":"gid://shopify/Fulfillment/55"}`, false); err != nil || !f.fCancelled {
		t.Fatal(err)
	}
	if r, err := invoke(m, "cancel_fulfillment", `{"fulfillment":55}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestShopifyRefundAndCancel(t *testing.T) {
	m, f := setup(t, "secret://shop")
	r, err := invoke(m, "refund_order", `{"order":"#1001","amount":"10.5"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Partial refund of 10.50 EUR on order #1001 via shopify_payments (test order). To run it, give expectedTotal "49.00 EUR" and expectedRefunded "0.00 EUR" (the order as previewed); it's refused if the order changed.` || f.refunded != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	plan, _ := json.Marshal(r.Plan)
	if strings.Contains(string(plan), "jane") || strings.Contains(string(plan), "Jane") {
		t.Fatalf("the preview has personal data: %s", plan)
	}
	// The run needs the values the preview showed.
	if _, err := invoke(m, "refund_order", `{"order":"#1001","amount":10.5}`, false); err == nil || f.refunded != 0 || !strings.Contains(err.Error(), `expectedTotal "49.00 EUR"`) {
		t.Fatalf("refunded without the previewed values: %v", err)
	}
	if _, err := invoke(m, "refund_order", `{"order":"#1001","amount":10.5,"expectedTotal":"49.00 EUR"}`, false); err == nil || f.refunded != 0 || !strings.Contains(err.Error(), `expectedRefunded "0.00 EUR"`) {
		t.Fatalf("refunded without the previewed values: %v", err)
	}
	for _, bad := range []string{`"expectedTotal":"49.00 USD","expectedRefunded":"0"`, `"expectedTotal":"lots","expectedRefunded":"0"`, `"expectedTotal":"50","expectedRefunded":"0"`} {
		if _, err := invoke(m, "refund_order", `{"order":"#1001","amount":10.5,`+bad+`}`, false); err == nil || f.refunded != 0 {
			t.Fatalf("%s: %v", bad, err)
		}
	}
	r, err = invoke(m, "refund_order", `{"order":"#1001","amount":10.5,"idempotencyKey":"retry-key-1","expectedTotal":"49.00 EUR","expectedRefunded":"0.00 EUR"}`, false)
	if err != nil || f.refunded != 10.5 || r.Undo != nil || !strings.Contains(string(r.Output), `"idempotencyKey":"retry-key-1"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	// The same approved call retried (with a new key) is refused: the order changed.
	if _, err := invoke(m, "refund_order", `{"order":"#1001","amount":10.5,"expectedTotal":"49.00 EUR","expectedRefunded":"0.00 EUR"}`, false); err == nil || f.refunded != 10.5 || !strings.Contains(err.Error(), "expectedRefunded is 10.50 EUR now, not 0.00 EUR") {
		t.Fatalf("refunded twice: %v", err)
	}
	if r, err := invoke(m, "refund_order", `{"order":"#1001","amount":10.5,"expectedTotal":"49.00 EUR","expectedRefunded":"0.00 EUR"}`, true); err != nil || !strings.Contains(r.Plan.Summary, "will be refused") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	tx := f.lastRefund["input"].(map[string]any)["transactions"].([]any)[0].(map[string]any)
	if tx["amount"] != "10.50" || tx["parentId"] != "gid://shopify/OrderTransaction/9" || tx["kind"] != "REFUND" {
		t.Fatal(tx)
	}
	if _, err := invoke(m, "refund_order", `{"order":"#1001","amount":"40"}`, false); err == nil || !strings.Contains(err.Error(), "only 38.50 EUR") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "refund_order", `{"order":"#1001","amount":"1.005"}`, false); err == nil || !strings.Contains(err.Error(), "2 decimals") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "refund_order", `{"order":"#1001","expectedTotal":"49","expectedRefunded":"10.50 eur"}`, false); err != nil || f.refunded != 49 {
		t.Fatal(err, f.refunded)
	}
	if _, err := invoke(m, "refund_order", `{"order":"#1001","expectedTotal":"49","expectedRefunded":"49"}`, false); err == nil || !strings.Contains(err.Error(), "nothing left") {
		t.Fatal(err)
	}

	// Everything was refunded already, so cancelling refunds nothing more.
	r, err = invoke(m, "cancel_order", `{"order":"#1001","refund":true,"reason":"customer"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Cancel order #1001 (total 49.00 EUR): refunds 0.00 EUR to the original payment methods, test order. To run it, give expectedRefund "0.00 EUR" (the order as previewed); it's refused if the order changed.` || f.cancelled {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "cancel_order", `{"order":"#1001","refund":true,"reason":"customer"}`, false); err == nil || f.cancelled || !strings.Contains(err.Error(), `expectedRefund "0.00 EUR"`) {
		t.Fatalf("cancelled without the previewed refund: %v", err)
	}
	if _, err := invoke(m, "cancel_order", `{"order":"#1001","refund":true,"expectedRefund":"49.00 EUR"}`, false); err == nil || f.cancelled || !strings.Contains(err.Error(), "changed since the preview") {
		t.Fatalf("cancelled with another refund: %v", err)
	}
	r, err = invoke(m, "cancel_order", `{"order":"#1001","refund":true,"reason":"customer","expectedRefund":"0.00 EUR"}`, false)
	if err != nil || !f.cancelled || r.Undo != nil || f.lastCancel["reason"] != "CUSTOMER" || f.lastCancel["restock"] != true || f.lastCancel["refundMethod"] == nil {
		t.Fatalf("%+v %v %v", r, err, f.lastCancel)
	}
	if r, err := invoke(m, "cancel_order", `{"order":"#1001"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "fulfill_order", `{"order":"#1001"}`, false); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "refund_order", `{"order":"#2002"}`, true); err == nil || !strings.Contains(err.Error(), "no order #2002") {
		t.Fatal(err)
	}
}

func TestShopifyValidation(t *testing.T) {
	m, f := setup(t, "secret://shop")
	for _, c := range []struct{ action, in string }{
		{"order", `{}`},
		{"order", `{"order":"1001) { id } shop { name"}`},
		{"order", `{"order":"gid://shopify/Customer/5"}`},
		{"order", `{"order":"#10 OR name:*"}`},
		{"orders", `{"status":"open OR x"}`},
		{"orders", `{"since":"yesterday"}`},
		{"orders", `{"after":"a\"b"}`},
		{"products", `{"search":"x\" OR status:draft"}`},
		{"inventory", `{"location":"../x"}`},
		{"inventory", `{"below":-1}`},
		{"fulfill_order", `{"order":"1001","trackingUrl":"javascript:alert(1)"}`},
		{"fulfill_order", `{"order":"1001","trackingNumber":"a\nb"}`},
		{"cancel_fulfillment", `{"fulfillment":"x"}`},
		{"cancel_order", `{"order":"1001","reason":"BORED"}`},
		{"cancel_order", `{"order":"abc"}`},
		{"refund_order", `{"order":"1001","amount":"-5"}`},
		{"refund_order", `{"order":"1001","amount":"0"}`},
		{"refund_order", `{"order":"1001","amount":"1e3"}`},
		{"refund_order", `{"order":"1001","idempotencyKey":"short"}`},
		{"refund_order", `{"order":"../1001"}`},
		{"nope", `{}`},
	} {
		for _, dry := range []bool{false, true} {
			if _, err := invoke(m, c.action, c.in, dry); err == nil {
				t.Fatalf("%s accepted %s", c.action, c.in)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Shopify: %v", f.seen)
	}
	for _, c := range []Config{{Shop: "acme", Token: goodToken}, {Shop: "acme.example.com", Token: "secret://shop"}, {Shop: "", Token: "secret://shop"}, {Shop: "evil.com/x?", Token: "secret://shop"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || h.Message != "Shopify refused the access token" {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, "secret://junk")
	if _, err := invoke(junk, "shop", `{}`, false); err == nil || len(fj.seen) != 0 || strings.Contains(err.Error(), "hunter2") {
		t.Fatal(err)
	}
}

func TestShopifyErrorsHidePersonalData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"errors":[{"message":"Customer jane@example.org (+49 151 1234 5678) can't be used, token shpat_FakeTestTokenNotReal0000000"}]}`)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{Shop: "acme", Token: "secret://shop"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "s", raw); err != nil {
		t.Fatal(err)
	}
	_, err := invoke(m, "orders", `{}`, false)
	if err == nil || strings.Contains(err.Error(), "jane") || strings.Contains(err.Error(), "1234") || strings.Contains(err.Error(), "shpat_") {
		t.Fatalf("error: %v", err)
	}
}

func TestShopifyRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Shopify-Access-Token") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{Shop: "acme", Token: "secret://shop"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// In a multi-currency store the customer pays in another currency than the
// shop's; Shopify refunds in that one, so the preview, the limit and the
// amount sent are all in it, and the refund names it.
func TestShopifyRefundInCustomerCurrency(t *testing.T) {
	m, f := setup(t, "secret://shop")
	f.usd = true
	r, err := invoke(m, "refund_order", `{"order":"#1001"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Full refund of 53.90 USD on order #1001 via shopify_payments (test order). To run it, give expectedTotal "53.90 USD" and expectedRefunded "0.00 USD" (the order as previewed); it's refused if the order changed.` {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "refund_order", `{"order":"#1001","amount":"50","expectedTotal":"53.90 USD","expectedRefunded":"0.00 USD"}`, false); err != nil {
		t.Fatal(err)
	}
	in := f.lastRefund["input"].(map[string]any)
	tx := in["transactions"].([]any)[0].(map[string]any)
	if in["currency"] != "USD" || tx["amount"] != "50.00" {
		t.Fatal(in)
	}
	if _, err := invoke(m, "refund_order", `{"order":"#1001","amount":"4","expectedTotal":"53.90 USD","expectedRefunded":"50.00 USD"}`, false); err == nil || !strings.Contains(err.Error(), "only 3.90 USD of 53.90 USD") {
		t.Fatal(err)
	}
	// A cancellation's preview counts what's left after earlier refunds.
	f.usd, f.refunded = false, 10
	r, err = invoke(m, "cancel_order", `{"order":"#1001","refund":true}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "refunds 39.00 EUR") || !strings.Contains(r.Plan.Summary, `expectedRefund "39.00 EUR"`) {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	// Without a refund, a cancellation needs nothing more.
	if r, err := invoke(m, "cancel_order", `{"order":"#1001"}`, true); err != nil || strings.Contains(r.Plan.Summary, "To run it") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "cancel_order", `{"order":"#1001"}`, false); err != nil || !f.cancelled || f.lastCancel["refundMethod"] != nil {
		t.Fatal(err, f.lastCancel)
	}
}

// Fulfilling an order whose payment is only authorised can capture it, so
// that run must name the total the preview showed.
func TestShopifyFulfilCanCharge(t *testing.T) {
	m, f := setup(t, "secret://shop")
	f.financial = "AUTHORIZED"
	r, err := invoke(m, "fulfill_order", `{"order":"#1001"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Fulfil 2 items of order #1001 (the customer isn't notified, test order). Its payment is authorized, so a store that captures on fulfilment charges the customer now (total 49.00 EUR). To run it, give expectedTotal "49.00 EUR" (the order as previewed); it's refused if the order changed.` {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "fulfill_order", `{"order":"#1001"}`, false); err == nil || f.fulfilled || !strings.Contains(err.Error(), `expectedTotal "49.00 EUR"`) {
		t.Fatalf("fulfilled without the previewed total: %v", err)
	}
	f.total = "59.00"
	if _, err := invoke(m, "fulfill_order", `{"order":"#1001","expectedTotal":"49.00 EUR"}`, false); err == nil || f.fulfilled || !strings.Contains(err.Error(), "expectedTotal is 59.00 EUR now") {
		t.Fatalf("fulfilled a changed order: %v", err)
	}
	r, err = invoke(m, "fulfill_order", `{"order":"#1001","expectedTotal":"59.00 EUR"}`, false)
	if err != nil || !f.fulfilled || r.Undo == nil || r.Undo.Action != "cancel_fulfillment" {
		t.Fatalf("%+v %v", r, err)
	}
}
