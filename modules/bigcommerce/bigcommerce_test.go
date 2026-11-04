package bigcommerce

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

const goodToken = "bcTOKEN0123456789abcdefABCDEF01"

var secrets = map[string]string{"secret://bc": goodToken, "secret://bad": "bcBAD00123456789abcdefABCDEF01", "secret://junk": "hunter2!"}

type fakeBC struct {
	mu       sync.Mutex
	seen     []string
	statusID int
	ignore   bool
}

func (f *fakeBC) order(id int) string {
	return fmt.Sprintf(`{"id":%d,"status_id":%d,"status":"x","date_created":"Mon, 02 Nov 2026 10:00:00 +0000","total_inc_tax":"49.0000","refunded_amount":"5.0000","items_total":2,
		"payment_method":"Credit Card","payment_status":"captured","currency_code":"EUR","customer_message":"ring twice",
		"billing_address":{"first_name":"Jane","last_name":"Doe","street_1":"1 Main St","city":"Berlin","zip":"10115","country_iso2":"DE","email":"jane@example.org","phone":"+4915112345678"}}`, id, f.statusID)
}

func (f *fakeBC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth-Token") != goodToken {
		w.WriteHeader(401)
		io.WriteString(w, `[{"status":401,"message":"You are not authorized."}]`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /stores/abc123de45/v2/store":
		io.WriteString(w, `{"name":"Acme","domain":"acme.example","secure_url":"https://acme.example","currency":"EUR","timezone":{"name":"Europe/Berlin"},"plan_name":"Standard","status":"live","admin_email":"owner@LEAKME.example","phone":"LEAKME","address":"LEAKME"}`)
	case "GET /stores/abc123de45/v2/orders":
		if r.URL.Query().Get("status_id") == "5" {
			w.WriteHeader(204)
			return
		}
		fmt.Fprintf(w, `[%s]`, f.order(100))
	case "GET /stores/abc123de45/v2/orders/100":
		io.WriteString(w, f.order(100))
	case "GET /stores/abc123de45/v2/orders/101": // answers with another order
		io.WriteString(w, f.order(100))
	case "GET /stores/abc123de45/v2/orders/100/products":
		io.WriteString(w, `[{"name":"Mug","sku":"MUG-1","quantity":2,"total_inc_tax":"49.0000"}]`)
	case "GET /stores/abc123de45/v2/orders/100/shipping_addresses":
		io.WriteString(w, `[{"first_name":"Jane","last_name":"Doe","street_1":"1 Main St","city":"Berlin","zip":"10115","country_iso2":"DE","email":"jane@example.org"}]`)
	case "PUT /stores/abc123de45/v2/orders/100":
		var b map[string]any
		json.Unmarshal(body, &b)
		if !f.ignore {
			f.statusID = int(b["status_id"].(float64))
		}
		io.WriteString(w, f.order(100))
	case "GET /stores/abc123de45/v3/catalog/products":
		io.WriteString(w, `{"data":[
			{"id":3,"name":"Mug","sku":"MUG-1","price":24.5,"is_visible":true,"availability":"available","inventory_tracking":"product","inventory_level":2},
			{"id":4,"name":"Shirt","sku":"SH","price":19.99,"is_visible":true,"availability":"available","inventory_tracking":"variant","inventory_level":41,
			 "variants":[{"id":40,"sku":"SH-S","inventory_level":1,"option_values":[{"label":"S"}]},{"id":41,"sku":"SH-M","inventory_level":40,"option_values":[{"label":"M"}]}]},
			{"id":5,"name":"Gift card","sku":"GC","price":10,"inventory_tracking":"none","inventory_level":0}],
			"meta":{"pagination":{"total":3,"total_pages":2,"current_page":1}}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `[{"status":404,"message":"The requested resource was not found."}]`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeBC) {
	t.Helper()
	f := &fakeBC{statusID: 11}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{StoreHash: "ABC123de45", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestBigCommerceReads(t *testing.T) {
	m, _ := setup(t, "secret://bc")
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || h.Message != "connected to Acme (Standard)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"store", `{}`, `"currency":"EUR"`},
		{"orders", `{}`, `"total":"49.00 EUR"`},
		{"orders", `{"since":"2026-11-01","limit":1}`, `"refunded":"5.00 EUR"`},
		{"orders", `{"status":"cancelled"}`, `"items":[]`},
		{"order", `{"order":100}`, `"email":"jane@example.org"`},
		{"order", `{"order":100}`, `"street1":"1 Main St"`},
		{"products", `{"search":"mug"}`, `"price":"19.99"`},
		{"products", `{}`, `"nextPage":2`},
		{"inventory", `{"below":5}`, `"name":"Shirt - S"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, goodToken) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		if c.action != "order" && (strings.Contains(out, "Jane") || strings.Contains(out, "jane") || strings.Contains(out, "Main St") || strings.Contains(out, "+49")) {
			t.Fatalf("%s returned personal data: %s", c.action, out)
		}
	}
	if r, _ := invoke(m, "inventory", `{"below":5}`, false); strings.Contains(string(r.Output), "SH-M") || strings.Contains(string(r.Output), "Gift") {
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

func TestBigCommerceStatus(t *testing.T) {
	m, f := setup(t, "secret://bc")
	r, err := invoke(m, "update_order_status", `{"order":100,"status":"shipped"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Set order 100 (total 49.00 EUR) from awaiting_fulfillment to shipped; BigCommerce may email the customer. To run it, give expectedStatus "awaiting_fulfillment" (the order as previewed); it's refused if the order changed.` || f.statusID != 11 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	plan, _ := json.Marshal(r.Plan)
	if strings.Contains(string(plan), "Jane") || strings.Contains(string(plan), "jane") {
		t.Fatalf("the preview has personal data: %s", plan)
	}
	if _, err := invoke(m, "update_order_status", `{"order":100,"status":"shipped"}`, false); err == nil || f.statusID != 11 {
		t.Fatalf("ran without the previewed status: %v", err)
	}
	if _, err := invoke(m, "update_order_status", `{"order":100,"status":"shipped","expectedStatus":"pending"}`, false); err == nil || f.statusID != 11 || !strings.Contains(err.Error(), "changed since the preview") {
		t.Fatal(err)
	}
	r, err = invoke(m, "update_order_status", `{"order":100,"status":"shipped","expectedStatus":"awaiting_fulfillment"}`, false)
	if err != nil || f.statusID != 2 || r.Undo == nil || string(r.Undo.Input) != `{"expectedStatus":"shipped","order":100,"status":"awaiting_fulfillment"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "update_order_status", `{"order":100,"status":"shipped"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.statusID != 11 {
		t.Fatal(err)
	}
	r, err = invoke(m, "update_order_status", `{"order":100,"status":"cancelled"}`, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "total 49.00 EUR") || !strings.Contains(r.Plan.Summary, "no money is refunded") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "update_order_status", `{"order":100,"status":"cancelled","expectedStatus":"awaiting_fulfillment"}`, false); err != nil || r.Undo != nil || f.statusID != 5 {
		t.Fatalf("a cancellation has no undo: %+v %v", r, err)
	}
	// An earlier change's undo doesn't bring the cancelled order back.
	if _, err := invoke(m, "update_order_status", `{"expectedStatus":"shipped","order":100,"status":"awaiting_fulfillment"}`, false); err == nil || f.statusID != 5 {
		t.Fatalf("the undo resurrected a cancelled order: %v", err)
	}
	if r, err := invoke(m, "update_order_status", `{"order":100,"status":"pending"}`, true); err != nil || !strings.Contains(r.Plan.Summary, "becomes active again") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	f.ignore = true
	if _, err := invoke(m, "update_order_status", `{"order":100,"status":"completed","expectedStatus":"cancelled"}`, false); err == nil || !strings.Contains(err.Error(), "kept") {
		t.Fatal(err)
	}
	n := len(f.seen)
	if _, err := invoke(m, "update_order_status", `{"order":101,"status":"completed","expectedStatus":"cancelled"}`, false); err == nil || len(f.seen) != n+1 {
		t.Fatalf("changed another order: %v %v", err, f.seen[n:])
	}
	if _, err := invoke(m, "update_order_status", `{"order":7,"status":"completed"}`, true); err == nil || !strings.Contains(err.Error(), "no order 7") {
		t.Fatal(err)
	}
}

func TestBigCommerceValidation(t *testing.T) {
	m, f := setup(t, "secret://bc")
	for _, c := range []struct{ action, in string }{
		{"order", `{}`},
		{"order", `{"order":"100/products"}`},
		{"orders", `{"status":"open"}`},
		{"orders", `{"since":"yesterday"}`},
		{"orders", `{"page":-1}`},
		{"products", `{"search":"x\" OR <script>"}`},
		{"inventory", `{"below":-1}`},
		{"update_order_status", `{"order":100}`},
		{"update_order_status", `{"order":100,"status":"refunded"}`},
		{"update_order_status", `{"order":100,"status":"incomplete"}`},
		{"update_order_status", `{"status":"shipped"}`},
		{"nope", `{}`},
	} {
		for _, dry := range []bool{false, true} {
			if _, err := invoke(m, c.action, c.in, dry); err == nil {
				t.Fatalf("%s accepted %s", c.action, c.in)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached BigCommerce: %v", f.seen)
	}
	for _, c := range []Config{
		{StoreHash: "abc123de45", Token: goodToken},
		{StoreHash: "", Token: "secret://bc"},
		{StoreHash: "abc/../../x", Token: "secret://bc"},
		{StoreHash: "evil.com#", Token: "secret://bc"},
		{StoreHash: "abc?x=1", Token: "secret://bc"},
		{StoreHash: "abc@evil.com", Token: "secret://bc"},
		{StoreHash: "abc%2f", Token: "secret://bc"},
		{StoreHash: "averyveryverylonghash", Token: "secret://bc"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "b"); h.Status != "down" || h.Message != "BigCommerce refused the access token" {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, "secret://junk")
	if _, err := invoke(junk, "store", `{}`, false); err == nil || len(fj.seen) != 0 || strings.Contains(err.Error(), "hunter2") {
		t.Fatal(err)
	}
}

func TestBigCommerceErrorsHideSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, `{"message":"bad X-Auth-Token `+goodToken+` for jane@example.org +49 151 1234 5678 `+strings.Repeat("z ", 200)+`"}`)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{StoreHash: "abc", Token: "secret://bc"})
	m.Configure(context.Background(), fakehost.New(secrets), "b", raw)
	_, err := invoke(m, "orders", `{}`, false)
	if err == nil || strings.Contains(err.Error(), goodToken) || strings.Contains(err.Error(), "jane") || strings.Contains(err.Error(), "1234") || len(err.Error()) > 300 {
		t.Fatalf("error: %v", err)
	}
}

func TestBigCommerceRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Auth-Token") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{StoreHash: "abc", Token: "secret://bc"})
	m.Configure(context.Background(), fakehost.New(secrets), "b", raw)
	if h := m.Health(context.Background(), "b"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
