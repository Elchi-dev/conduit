package firefly

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
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeFirefly struct {
	mu     sync.Mutex
	seen   []string
	groups map[int]string
	next   int
}

func (f *fakeFirefly) group(id int, desc, amount string) string {
	return fmt.Sprintf(`{"type":"transactions","id":"%d","attributes":{"group_title":null,"transactions":[{"transaction_journal_id":"%d","type":"withdrawal","date":"2026-11-03T00:00:00+01:00","amount":"%s","currency_code":"EUR","description":"%s","source_id":"1","source_name":"Checking","destination_id":"9","destination_name":"Bakery","category_name":"Food","budget_name":null,"tags":[]}]}}`, id, id, amount, desc)
}

func (f *fakeFirefly) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer pat_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthenticated.","exception":"AuthenticationException"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	q := r.URL.Query()
	page := func(items ...string) {
		fmt.Fprintf(w, `{"data":[%s],"meta":{"pagination":{"total":%d,"total_pages":1,"current_page":1}}}`, strings.Join(items, ","), len(items))
	}
	var id int
	if strings.HasPrefix(r.URL.Path, "/api/v1/transactions/") {
		fmt.Sscanf(r.URL.Path, "/api/v1/transactions/%d", &id)
	}
	switch {
	case r.URL.Path == "/api/v1/about/user":
		io.WriteString(w, `{"data":{"type":"users","id":"1","attributes":{"email":"me@example.com","role":"owner"}}}`)
	case r.URL.Path == "/api/v1/about":
		io.WriteString(w, `{"data":{"version":"6.1.21","api_version":"2.1.0"}}`)
	case r.URL.Path == "/api/v1/accounts" && q.Get("type") == "asset":
		page(`{"id":"1","attributes":{"name":"Checking","type":"asset","account_role":"defaultAsset","active":true,"current_balance":"1200.50","currency_code":"EUR","iban":"DE00SECRET"}}`,
			`{"id":"2","attributes":{"name":"Savings","type":"asset","account_role":"savingAsset","active":true,"current_balance":"300.25","currency_code":"EUR"}}`,
			`{"id":"3","attributes":{"name":"Old","type":"asset","active":false,"current_balance":"0","currency_code":"EUR"}}`)
	case r.URL.Path == "/api/v1/accounts/1":
		io.WriteString(w, `{"data":{"id":"1","attributes":{"name":"Checking","type":"asset"}}}`)
	case r.URL.Path == "/api/v1/accounts/2":
		io.WriteString(w, `{"data":{"id":"2","attributes":{"name":"Savings","type":"asset"}}}`)
	case r.URL.Path == "/api/v1/transactions" && r.Method == "GET":
		var items []string
		for id, desc := range f.groups {
			items = append(items, f.group(id, desc, "4.20"))
		}
		page(items...)
	case r.URL.Path == "/api/v1/transactions" && r.Method == "POST":
		var b struct {
			Dup          bool             `json:"error_if_duplicate_hash"`
			Transactions []map[string]any `json:"transactions"`
		}
		json.Unmarshal(body, &b)
		if !b.Dup || len(b.Transactions) != 1 {
			w.WriteHeader(422)
			io.WriteString(w, `{"message":"bad","errors":{}}`)
			return
		}
		f.next++
		f.groups[f.next] = b.Transactions[0]["description"].(string)
		fmt.Fprintf(w, `{"data":%s}`, f.group(f.next, f.groups[f.next], b.Transactions[0]["amount"].(string)))
	case id > 0:
		desc, ok := f.groups[id]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Resource not found","exception":"NotFoundHttpException"}`)
			return
		}
		if r.Method == "DELETE" {
			delete(f.groups, id)
			w.WriteHeader(204)
			return
		}
		fmt.Fprintf(w, `{"data":%s}`, f.group(id, desc, "4.20"))
	case r.URL.Path == "/api/v1/budgets":
		if q.Get("start") != "2026-11-01" || q.Get("end") != "2026-11-30" {
			w.WriteHeader(400)
			return
		}
		page(`{"id":"5","attributes":{"name":"Groceries","active":true,"spent":[{"sum":"-123.40","currency_code":"EUR"}]}}`)
	case r.URL.Path == "/api/v1/budget-limits":
		page(`{"id":"50","attributes":{"budget_id":"5","amount":"400","currency_code":"EUR"}}`)
	case r.URL.Path == "/api/v1/summary/basic":
		io.WriteString(w, `{"spent-in-EUR":{"key":"spent-in-EUR","monetary_value":"-512.10","currency_code":"EUR","value_parsed":"-€512.10"},"earned-in-EUR":{"key":"earned-in-EUR","monetary_value":"2500","currency_code":"EUR"},"left-to-spend-in-EUR":{"monetary_value":"276.60"}}`)
	case r.URL.Path == "/api/v1/bills":
		page(`{"id":"8","attributes":{"name":"Rent","active":true,"amount_min":"900","amount_max":"900","currency_code":"EUR","repeat_freq":"monthly","next_expected_match":"2026-12-01T00:00:00+01:00","pay_dates":["2026-11-01T00:00:00+01:00"],"paid_dates":[]}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Resource not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeFirefly) {
	f := &fakeFirefly{groups: map[int]string{40: "Bread"}, next: 40}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://f": "pat_good", "secret://bad": "nope"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "f", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestFirefly(t *testing.T) {
	m, f := setup(t, "secret://f")
	if h := m.Health(context.Background(), "f"); h.Status != "ok" || h.Message != "signed in · Firefly III 6.1.21" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"accounts", `{}`, `"assetTotals":{"EUR":"1500.75"}`},
		{"transactions", `{"limit":5}`, `"destination":"Bakery"`},
		{"budgets", `{}`, `"amounts":[{"currency":"EUR","left":"276.60","limit":"400.00","spent":"123.40"}]`},
		{"budgets", `{"month":"2026-11"}`, `"spent":"-512.10"`},
		{"bills", `{}`, `"expected":["2026-11-01"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "SECRET") || strings.Contains(string(r.Output), "me@example") {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	if r, _ := invoke(m, "accounts", `{}`, false); strings.Contains(string(r.Output), `"Old"`) {
		t.Fatal("inactive account listed")
	}
	sensitive := map[string]bool{"accounts": true, "transactions": true, "budgets": true, "bills": true, "create_transaction": true}
	for _, a := range m.Manifest().Actions {
		if sensitive[a.Name] != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
	}

	// Record a transaction; undo deletes it.
	in := `{"type":"withdrawal","amount":"12.50","description":"Groceries","source":"1","destination":"Corner shop","category":"Food","tags":["weekly"]}`
	r, err := invoke(m, "create_transaction", in, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Record a withdrawal of 12.50 from Checking to Corner shop on 2026-11-04 (books only, no money moves)" || len(f.groups) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_transaction", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_transaction" || string(r.Undo.Input) != `{"id":41}` || strings.Contains(r.Undo.Description, "Groceries") {
		t.Fatalf("%+v %v", r, err)
	}
	post := f.seen[len(f.seen)-1]
	for _, want := range []string{`"source_id":"1"`, `"destination_name":"Corner shop"`, `"apply_rules":true`, `"date":"2026-11-04"`} {
		if !strings.Contains(post, want) {
			t.Fatalf("%s missing %s", post, want)
		}
	}
	r, err = invoke(m, "delete_transaction", string(r.Undo.Input), true)
	if err != nil || r.Plan == nil || f.groups[41] == "" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "delete_transaction", `{"id":41}`, false); err != nil || f.groups[41] != "" {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_transaction", `{"id":41}`, false); err == nil || !strings.Contains(err.Error(), "no transaction 41") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "create_transaction", `{"type":"transfer","amount":"5","description":"Save","source":"1","destination":"2"}`, false); err != nil {
		t.Fatal(err)
	}
}

func TestFireflyValidation(t *testing.T) {
	m, f := setup(t, "secret://f")
	base := `"description":"x","source":"1","destination":"Shop"`
	for _, c := range []struct{ action, in string }{
		{"accounts", `{"type":"cash"}`},
		{"transactions", `{"start":"yesterday"}`},
		{"transactions", `{"end":"2026-02-31"}`},
		{"transactions", `{"type":"refund"}`},
		{"transactions", `{"account":-1}`},
		{"budgets", `{"month":"November"}`},
		{"bills", `{"month":"2026-13"}`},
		{"create_transaction", `{"type":"refund","amount":"1",` + base + `}`},
		{"create_transaction", `{"type":"withdrawal","amount":"-5",` + base + `}`},
		{"create_transaction", `{"type":"withdrawal","amount":"0",` + base + `}`},
		{"create_transaction", `{"type":"withdrawal","amount":"1e9",` + base + `}`},
		{"create_transaction", `{"type":"withdrawal","amount":"1","description":" ","source":"1","destination":"Shop"}`},
		{"create_transaction", `{"type":"withdrawal","amount":"1","description":"x","source":"1","destination":"1"}`},
		{"create_transaction", `{"type":"withdrawal","amount":"1","description":"x","source":"1"}`},
		{"create_transaction", `{"type":"transfer","amount":"1","description":"x","source":"1","destination":"Shop"}`},
		{"create_transaction", `{"type":"withdrawal","amount":"1","date":"04/11/2026",` + base + `}`},
		{"create_transaction", `{"type":"withdrawal","amount":"1","currency":"euro",` + base + `}`},
		{"create_transaction", `{"type":"withdrawal","amount":"1","tags":[""],` + base + `}`},
		{"delete_transaction", `{"id":0}`},
		{"delete_transaction", `{"id":"1/../../users"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://money.example.com", Token: "pat_plain"}, {URL: "money.example.com", Token: "secret://f"}, {URL: "https://money.example.com/#x", Token: "secret://f"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "f"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestFireflyRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://f"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://f": "pat_good"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "f"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
