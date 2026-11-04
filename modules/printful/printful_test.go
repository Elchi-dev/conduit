package printful

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

const goodToken = "pfTOKEN0123456789abcdefABCDEF0123"

var secrets = map[string]string{"secret://pf": goodToken, "secret://bad": "pfBAD00123456789abcdefABCDEF0123", "secret://junk": "hunter2"}

type fakePrintful struct {
	mu        sync.Mutex
	seen      []string
	status    string
	confirms  int
	lastRates map[string]any
	storeHdr  string
}

func (f *fakePrintful) order() string {
	return fmt.Sprintf(`{"id":77,"external_id":"1001","status":%q,"created":1730700000,"updated":1730700100,"shipping":"STANDARD","shipping_service_name":"Flat Rate (3-4 business days)",
		"recipient":{"name":"Jane Doe","address1":"1 Main St","city":"Berlin","country_code":"DE","zip":"10115","email":"jane@example.org","phone":"+4915112345678"},
		"items":[{"id":1,"variant_id":4012,"quantity":2,"name":"Mug 11oz","sku":"MUG-1"}],
		"costs":{"currency":"EUR","subtotal":"15.90","discount":"0.00","shipping":"5.29","tax":"0.00","vat":"4.03","total":"25.22"},
		"retail_costs":{"currency":"EUR","total":"49.00"},
		"shipments":[{"carrier":"DHL","service":"DHL Paket","tracking_number":"00340434","ship_date":"2026-11-03","shipped_at":1730800000}]}`, f.status)
}

func (f *fakePrintful) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+goodToken {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":401,"result":"Unauthorized","error":{"reason":"Unauthorized","message":"Malformed token"}}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.storeHdr = r.Header.Get("X-PF-Store-Id")
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /stores":
		io.WriteString(w, `{"code":200,"result":[{"id":123,"name":"Acme Prints","type":"native"}]}`)
	case "GET /orders":
		fmt.Fprintf(w, `{"code":200,"result":[%s],"paging":{"total":3,"offset":0,"limit":1}}`, f.order())
	case "GET /orders/77", "GET /orders/@1001":
		fmt.Fprintf(w, `{"code":200,"result":%s}`, f.order())
	case "GET /orders/78": // answers with another order
		fmt.Fprintf(w, `{"code":200,"result":%s}`, f.order())
	case "POST /orders/77/confirm":
		f.confirms++
		f.status = "pending"
		fmt.Fprintf(w, `{"code":200,"result":%s}`, f.order())
	case "POST /shipping/rates":
		json.Unmarshal(body, &f.lastRates)
		io.WriteString(w, `{"code":200,"result":[{"id":"STANDARD","name":"Flat Rate (3-4 business days)","rate":"5.29","currency":"EUR","minDeliveryDays":3,"maxDeliveryDays":4}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":404,"result":"Not found","error":{"reason":"NotFound","message":"Order not found"}}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakePrintful) {
	t.Helper()
	f := &fakePrintful{status: "draft"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{Token: tok, Store: "123"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestPrintfulReads(t *testing.T) {
	m, f := setup(t, "secret://pf")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "connected to Acme Prints" || f.storeHdr != "123" {
		t.Fatalf("%+v %q", h, f.storeHdr)
	}
	for _, c := range []struct{ action, in, want string }{
		{"store", `{}`, `"name":"Acme Prints"`},
		{"orders", `{"status":"draft","limit":1}`, `"cost":"25.22 EUR"`},
		{"orders", `{"limit":1}`, `"nextOffset":1`},
		{"order_status", `{"order":"@1001"}`, `"trackingNumber":"00340434"`},
		{"order_status", `{"order":77}`, `"vat":"4.03 EUR"`},
		{"order", `{"order":"77"}`, `"email":"jane@example.org"`},
		{"shipping_rates", `{"country":"de","zip":"10115","items":[{"variant":4012,"quantity":2}]}`, `"rate":"5.29 EUR"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, goodToken) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		if c.action != "order" && (strings.Contains(out, "Jane") || strings.Contains(out, "jane") || strings.Contains(out, "Main St") || strings.Contains(out, "+49")) {
			t.Fatalf("%s returned personal data: %s", c.action, out)
		}
	}
	rcp := f.lastRates["recipient"].(map[string]any)
	if rcp["country_code"] != "DE" || f.lastRates["items"].([]any)[0].(map[string]any)["variant_id"] != "4012" {
		t.Fatal(f.lastRates)
	}
	for _, a := range m.Manifest().Actions {
		if a.Sensitive != (a.Name == "order") {
			t.Fatalf("%s: sensitive %v", a.Name, a.Sensitive)
		}
	}
}

func TestPrintfulConfirm(t *testing.T) {
	m, f := setup(t, "secret://pf")
	r, err := invoke(m, "confirm_order", `{"order":"@1001"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Confirm order 77 (1001) (2 items, Flat Rate (3-4 business days)): Printful charges your card 25.22 EUR and starts fulfilment" || f.confirms != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	plan, _ := json.Marshal(r.Plan)
	if strings.Contains(string(plan), "Jane") || strings.Contains(string(plan), "jane") {
		t.Fatalf("the preview has personal data: %s", plan)
	}
	r, err = invoke(m, "confirm_order", `{"order":77}`, false)
	if err != nil || f.confirms != 1 || r.Undo != nil || !strings.Contains(string(r.Output), `"charged":"25.22 EUR"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "confirm_order", `{"order":77}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || f.confirms != 1 {
		t.Fatalf("%s %v", r.Output, err)
	}
	f.status = "canceled"
	if _, err := invoke(m, "confirm_order", `{"order":77}`, false); err == nil || f.confirms != 1 {
		t.Fatal(err)
	}
	f.status = "draft"
	if _, err := invoke(m, "confirm_order", `{"order":78}`, false); err == nil || !strings.Contains(err.Error(), "another order") || f.confirms != 1 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "confirm_order", `{"order":"@2002"}`, true); err == nil || !strings.Contains(err.Error(), "no order") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "confirm_order" && (a.Risk != sdk.RiskDestructive || !a.DryRun || a.Reversible) {
			t.Fatalf("%+v", a)
		}
	}
}

func TestPrintfulValidation(t *testing.T) {
	m, f := setup(t, "secret://pf")
	for _, c := range []struct{ action, in string }{
		{"order", `{}`},
		{"order", `{"order":"../stores"}`},
		{"order", `{"order":"@a/b"}`},
		{"order", `{"order":"77?x=1"}`},
		{"order_status", `{"order":-1}`},
		{"confirm_order", `{"order":"1.5"}`},
		{"orders", `{"status":"draft&limit=1000"}`},
		{"orders", `{"offset":-1}`},
		{"shipping_rates", `{"country":"Germany","items":[{"variant":1,"quantity":1}]}`},
		{"shipping_rates", `{"country":"US","items":[{"variant":1,"quantity":1}]}`},
		{"shipping_rates", `{"country":"DE","items":[]}`},
		{"shipping_rates", `{"country":"DE","items":[{"variant":0,"quantity":1}]}`},
		{"shipping_rates", `{"country":"DE","items":[{"variant":1,"quantity":5000}]}`},
		{"shipping_rates", `{"country":"DE","zip":"<script>","items":[{"variant":1,"quantity":1}]}`},
		{"shipping_rates", `{"country":"DE","currency":"euro","items":[{"variant":1,"quantity":1}]}`},
		{"nope", `{}`},
	} {
		for _, dry := range []bool{false, true} {
			if _, err := invoke(m, c.action, c.in, dry); err == nil {
				t.Fatalf("%s accepted %s", c.action, c.in)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Printful: %v", f.seen)
	}
	for _, c := range []Config{{Token: goodToken}, {Token: "secret://pf", Store: "../1"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || h.Message != "Printful refused the token" {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, "secret://junk")
	if _, err := invoke(junk, "store", `{}`, false); err == nil || len(fj.seen) != 0 || strings.Contains(err.Error(), "hunter2") {
		t.Fatal(err)
	}
}

func TestPrintfulErrorsHideSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, `{"code":400,"result":"x","error":{"message":"Recipient jane@example.org +49 151 1234 5678 rejected for token `+goodToken+` `+strings.Repeat("y ", 200)+`"}}`)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{Token: "secret://pf"})
	m.Configure(context.Background(), fakehost.New(secrets), "p", raw)
	_, err := invoke(m, "orders", `{}`, false)
	if err == nil || strings.Contains(err.Error(), goodToken) || strings.Contains(err.Error(), "jane") || strings.Contains(err.Error(), "1234") || len(err.Error()) > 300 {
		t.Fatalf("error: %v", err)
	}
}

func TestPrintfulRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") + r.Header.Get("X-PF-Store-Id")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{Token: "secret://pf", Store: "123"})
	m.Configure(context.Background(), fakehost.New(secrets), "p", raw)
	if h := m.Health(context.Background(), "p"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
