package invoiceninja

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

type inv struct {
	status, amount, balance, number string
	deleted                         bool
	invitations                     string // JSON; the first contact's by default
}

type fakeNinja struct {
	mu       sync.Mutex
	seen     []string
	invoices map[string]*inv
	emailed  []string
	payments []map[string]any
	next     int
}

const clientJSON = `{"id":"Wpmbk5ezJn","number":"0001","name":"Acme Ltd","balance":1200,"paid_to_date":300.5,"address1":"1 Main St","city":"Springfield","postal_code":"12345","custom_value1":"LEAKME","contacts":[{"id":"c1","first_name":"Ada","last_name":"Lovelace","email":"ada@acme.test","phone":"LEAKME","is_primary":true,"send_email":true},{"id":"c2","first_name":"Bob","email":"bob@acme.test","send_email":false},{"id":"c3","first_name":"Cy","email":"cy@acme.test","send_email":true},{"id":"c4","first_name":"Lu","email":"lu@acme.test","send_email":true,"is_locked":true}]}`

func (f *fakeNinja) invoice(id string) string {
	i := f.invoices[id]
	invs := i.invitations
	if invs == "" {
		invs = `[{"key":"LEAKME","client_contact_id":"c1"}]`
	}
	return fmt.Sprintf(`{"id":%q,"number":%q,"client_id":"Wpmbk5ezJn","status_id":%q,"date":"2026-11-01","due_date":"2026-11-15","amount":%s,"balance":%s,"is_deleted":%t,"private_notes":"LEAKME","invitations":%s}`,
		id, i.number, i.status, i.amount, i.balance, i.deleted, invs)
}

func (f *fakeNinja) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-TOKEN") != "ninja_good" || r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
		w.WriteHeader(403)
		io.WriteString(w, `{"message":"Invalid token"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/invoices/")
	switch {
	case r.URL.Path == "/api/v1/ping":
		io.WriteString(w, `{"company_name":"Example GmbH","user_name":"Owner"}`)
	case r.URL.Path == "/api/v1/clients":
		io.WriteString(w, `{"data":[`+clientJSON+`],"meta":{"pagination":{"total":1}}}`)
	case r.URL.Path == "/api/v1/clients/Wpmbk5ezJn":
		io.WriteString(w, `{"data":`+clientJSON+`}`)
	case r.URL.Path == "/api/v1/invoices" && r.Method == "GET":
		items := []string{}
		for id := range f.invoices {
			items = append(items, f.invoice(id))
		}
		io.WriteString(w, `{"data":[`+strings.Join(items, ",")+`]}`)
	case r.URL.Path == "/api/v1/invoices" && r.Method == "POST":
		var b struct {
			ClientID  string `json:"client_id"`
			LineItems []struct {
				Quantity json.Number `json:"quantity"`
				Cost     json.Number `json:"cost"`
			} `json:"line_items"`
		}
		json.Unmarshal(body, &b)
		if b.ClientID != "Wpmbk5ezJn" || len(b.LineItems) == 0 {
			w.WriteHeader(422)
			io.WriteString(w, `{"message":"The given data was invalid."}`)
			return
		}
		f.next++
		nid := fmt.Sprintf("NewInv%d", f.next)
		f.invoices[nid] = &inv{status: "1", amount: "240", balance: "0"}
		io.WriteString(w, `{"data":`+f.invoice(nid)+`}`)
	case r.URL.Path == "/api/v1/invoices/bulk":
		var b struct {
			Action string   `json:"action"`
			IDs    []string `json:"ids"`
		}
		json.Unmarshal(body, &b)
		out := []string{}
		for _, id := range b.IDs {
			i := f.invoices[id]
			switch b.Action {
			case "mark_sent":
				i.status, i.balance, i.number = "2", i.amount, "0042"
			case "email":
				f.emailed = append(f.emailed, id)
				if i.status == "1" {
					i.status = "2"
				}
			}
			out = append(out, f.invoice(id))
		}
		io.WriteString(w, `{"data":[`+strings.Join(out, ",")+`]}`)
	case r.URL.Path == "/api/v1/payments" && r.Method == "GET":
		io.WriteString(w, `{"data":[{"id":"Pay1","number":"0007","client_id":"Wpmbk5ezJn","date":"2026-11-02","amount":300.5,"refunded":0,"transaction_reference":"SEPA-1","paymentables":[{"invoice_id":"Inv1","amount":"300.50"}],"private_notes":"LEAKME"}]}`)
	case r.URL.Path == "/api/v1/payments" && r.Method == "POST":
		var b map[string]any
		d := json.NewDecoder(strings.NewReader(string(body)))
		d.UseNumber()
		d.Decode(&b)
		f.payments = append(f.payments, b)
		io.WriteString(w, `{"data":{"id":"Pay2","number":"0008","amount":`+string(b["amount"].(json.Number))+`}}`)
	case id == "Other1": // answers with another invoice
		io.WriteString(w, `{"data":`+f.invoice("Inv1")+`}`)
	case f.invoices[id] != nil && r.Method == "GET":
		io.WriteString(w, `{"data":`+f.invoice(id)+`}`)
	case f.invoices[id] != nil && r.Method == "DELETE":
		f.invoices[id].deleted = true
		io.WriteString(w, `{"data":`+f.invoice(id)+`}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeNinja) {
	f := &fakeNinja{invoices: map[string]*inv{
		"Inv1":   {status: "2", amount: "1200", balance: "899.5", number: "0041"},
		"Draft1": {status: "1", amount: "500.25", balance: "0"},
		"Draft2": {status: "1", amount: "80", balance: "0"},
		"Paid1":  {status: "4", amount: "50", balance: "0", number: "0040"},
		// Invited when Bob still took email and before Cy was added; Lu is locked.
		"Inv2":  {status: "2", amount: "10.125", balance: "10.125", number: "0043", invitations: `[{"client_contact_id":"c1"},{"client_contact_id":"c2"},{"client_contact_id":"c4"}]`},
		"Gone1": {status: "2", amount: "1", balance: "1", number: "0044", invitations: `[{"client_contact_id":"c9"}]`},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL // the hosted default, pointed at the fake
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://n": "ninja_good", "secret://bad": "ninja_bad"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestInvoiceNinja(t *testing.T) {
	m, f := setup(t, "secret://n")
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || h.Message != "signed in · Example GmbH" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"clients", `{}`, `"paidToDate":"300.50"`},
		{"clients", `{}`, `{"email":"ada@acme.test","name":"Ada Lovelace","primary":true}`},
		{"clients", `{"includeAddress":true}`, `"city":"Springfield"`},
		{"invoices", `{"status":"unpaid"}`, `"balance":"899.50","client":"Acme Ltd"`},
		{"payments", `{}`, `"invoices":[{"amount":"300.50","invoice":"Inv1"}]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "ninja_good") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if r, _ := invoke(m, "clients", `{}`, false); strings.Contains(string(r.Output), "Main St") {
		t.Fatal("address without asking")
	}

	// Create a draft: preview, real, undo deletes it.
	in := `{"client":"Wpmbk5ezJn","items":[{"description":"Design work","quantity":"2","cost":"120.00"},{"description":"Hosting","cost":"0.10","product":"HOST"}],"dueDate":"2026-11-30"}`
	r, err := invoke(m, "create_invoice", in, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Create a draft invoice for Acme Ltd: 2 item(s), 240.10 before tax, dated 2026-11-04 (nothing is sent)" || f.next != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_invoice", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_invoice" || string(r.Undo.Input) != `{"id":"NewInv1"}` || strings.Contains(r.Undo.Description, "Acme") {
		t.Fatalf("%+v %v", r, err)
	}
	post := f.seen[len(f.seen)-1]
	for _, want := range []string{`"quantity":2`, `"cost":120.00`, `"cost":0.10`, `"product_key":"HOST"`, `"due_date":"2026-11-30"`} {
		if !strings.Contains(post, want) {
			t.Fatalf("%s missing %s", post, want)
		}
	}
	if p, err := invoke(m, "delete_invoice", string(r.Undo.Input), true); err != nil || p.Plan == nil || f.invoices["NewInv1"].deleted {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, "delete_invoice", string(r.Undo.Input), false); err != nil || !f.invoices["NewInv1"].deleted {
		t.Fatal(err)
	}
	if r, err := invoke(m, "delete_invoice", `{"id":"NewInv1"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "delete_invoice", `{"id":"Inv1"}`, false); err == nil || !strings.Contains(err.Error(), "not a draft") || f.invoices["Inv1"].deleted {
		t.Fatal(err)
	}

	// Email: the preview names the client, recipients and amount; nothing is sent.
	r, err = invoke(m, "email_invoice", `{"invoice":"Inv1"}`, true)
	sum := shaOf(r)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Email invoice 0041 for 1200.00 (balance 899.50) to Acme Ltd: ada@acme.test. To run it, give sha256 "`+sum+`" (the invoice as previewed); it's refused if the invoice changed.` || len(f.emailed) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	// The run needs the sha256 the preview showed, of the invoice as it is.
	if _, err := invoke(m, "email_invoice", `{"invoice":"Inv1"}`, false); err == nil || len(f.emailed) != 0 || !strings.Contains(err.Error(), sum) {
		t.Fatalf("emailed without the previewed sha256: %v", err)
	}
	n := len(f.seen)
	if _, err := invoke(m, "email_invoice", `{"invoice":"Inv1","sha256":"XYZ"}`, false); err == nil || len(f.emailed) != 0 || len(f.seen) != n {
		t.Fatalf("took a malformed sha256: %v", err)
	}
	f.invoices["Inv1"].amount = "1300"
	if _, err := invoke(m, "email_invoice", `{"invoice":"Inv1","sha256":"`+sum+`"}`, false); err == nil || len(f.emailed) != 0 || !strings.Contains(err.Error(), "changed since the preview") {
		t.Fatalf("emailed a changed invoice: %v", err)
	}
	if r, err := invoke(m, "email_invoice", `{"invoice":"Inv1","sha256":"`+sum+`"}`, true); err != nil || !strings.Contains(r.Plan.Summary, "will be refused") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	f.invoices["Inv1"].amount = "1200"
	if r, err := invoke(m, "email_invoice", `{"invoice":"Inv1","sha256":"`+sum+`"}`, true); err != nil || !strings.HasSuffix(r.Plan.Summary, "(sha256 "+sum+").") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "email_invoice", `{"invoice":"Inv1","sha256":"`+sum+`"}`, false); err != nil || len(f.emailed) != 1 || !strings.Contains(string(r.Output), `"emailedTo":["ada@acme.test"]`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Mark sent: preview, real, then nothing to change.
	if r, err := invoke(m, "mark_sent", `{"invoice":"Draft1"}`, true); err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Acme Ltd for 500.25") || f.invoices["Draft1"].status != "1" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "mark_sent", `{"invoice":"Draft1"}`, false); err != nil || f.invoices["Draft1"].status != "2" || !strings.Contains(string(r.Output), `"status":"sent"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "mark_sent", `{"invoice":"Draft1"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Record a payment: the balance by default, exact decimals.
	if r, err := invoke(m, "record_payment", `{"invoice":"Inv1","amount":"100.25"}`, true); err != nil || r.Plan == nil ||
		r.Plan.Summary != `Record a payment of 100.25 from Acme Ltd on 2026-11-04 against invoice 0041 (balance 899.50, then 799.25). To run it, give expectedBalance "899.50" (the invoice as previewed); it's refused if the invoice changed.` || len(f.payments) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	// The run needs the balance the preview showed, and the invoice as it was.
	if _, err := invoke(m, "record_payment", `{"invoice":"Inv1","reference":"SEPA-2"}`, false); err == nil || len(f.payments) != 0 || !strings.Contains(err.Error(), `expectedBalance "899.50"`) {
		t.Fatalf("recorded without the previewed balance: %v", err)
	}
	for _, bad := range []string{"899.49", "lots", "899.50 EUR"} {
		if _, err := invoke(m, "record_payment", `{"invoice":"Inv1","expectedBalance":"`+bad+`"}`, false); err == nil || len(f.payments) != 0 {
			t.Fatalf("%s: %v", bad, err)
		}
	}
	if _, err := invoke(m, "record_payment", `{"invoice":"Inv1","reference":"SEPA-2","expectedBalance":"899.5"}`, false); err != nil || len(f.payments) != 1 {
		t.Fatal(err)
	}
	// Retried after the payment went through: the balance moved, so it's refused.
	f.invoices["Inv1"].balance = "0"
	if _, err := invoke(m, "record_payment", `{"invoice":"Inv1","reference":"SEPA-2","expectedBalance":"899.50"}`, false); err != nil || len(f.payments) != 1 {
		t.Fatal(err)
	}
	f.invoices["Inv1"].balance = "100"
	if _, err := invoke(m, "record_payment", `{"invoice":"Inv1","reference":"SEPA-2","expectedBalance":"899.50"}`, false); err == nil || len(f.payments) != 1 || !strings.Contains(err.Error(), "its balance is 100.00 now, not 899.50") {
		t.Fatalf("recorded twice: %v", err)
	}
	f.invoices["Inv1"].balance = "899.5"
	if got := fmt.Sprint(f.payments[0]["amount"], f.payments[0]["invoices"], f.payments[0]["transaction_reference"]); got != "899.50[map[amount:899.50 invoice_id:Inv1]]SEPA-2" {
		t.Fatal(got)
	}
	if r, err := invoke(m, "record_payment", `{"invoice":"Paid1"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "record_payment", `{"invoice":"Inv1","amount":"5000","expectedBalance":"899.50"}`, false); err == nil || !strings.Contains(err.Error(), "more than the balance") {
		t.Fatal(err)
	}

	// A draft has no balance yet: it's refused, not "nothing to pay".
	if r, err := invoke(m, "record_payment", `{"invoice":"Draft2"}`, true); err == nil || !strings.Contains(err.Error(), "mark it sent first") {
		t.Fatalf("%s %v", r.Output, err)
	}

	risk := map[string]sdk.Risk{"create_invoice": sdk.RiskWrite, "delete_invoice": sdk.RiskDestructive, "mark_sent": sdk.RiskDestructive, "email_invoice": sdk.RiskDestructive, "record_payment": sdk.RiskDestructive}
	for _, a := range m.Manifest().Actions {
		if !a.Sensitive {
			t.Fatalf("%s isn't sensitive", a.Name)
		}
		if want, ok := risk[a.Name]; ok && a.Risk != want {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

// The preview names whom Invoice Ninja emails: the invoice's invitations
// (whatever send_email says now), not the client's current contacts.
func TestInvoiceNinjaEmailRecipientsAreTheInvitations(t *testing.T) {
	m, f := setup(t, "secret://n")
	r, err := invoke(m, "email_invoice", `{"invoice":"Inv2"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "to Acme Ltd: ada@acme.test, bob@acme.test. To run it") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "email_invoice", `{"invoice":"Inv2","sha256":"`+shaOf(r)+`"}`, false); err != nil || !strings.Contains(string(r.Output), `"emailedTo":["ada@acme.test","bob@acme.test"]`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "email_invoice", `{"invoice":"Gone1"}`, false); err == nil || !strings.Contains(err.Error(), "no longer on the client") || len(f.emailed) != 1 {
		t.Fatalf("%v %v", err, f.emailed)
	}
}

// Amounts keep their decimals: a three-decimal currency's balance is paid
// exactly, and an amount is sent as given rather than rounded.
func TestInvoiceNinjaPaymentKeepsDecimals(t *testing.T) {
	m, f := setup(t, "secret://n")
	r, err := invoke(m, "record_payment", `{"invoice":"Inv2"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Record a payment of 10.125 from Acme Ltd on 2026-11-04 against invoice 0043 (balance 10.125, then 0.00). To run it, give expectedBalance "10.125" (the invoice as previewed); it's refused if the invoice changed.` {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "record_payment", `{"invoice":"Inv2","expectedBalance":"10.12"}`, false); err == nil || len(f.payments) != 0 {
		t.Fatalf("a rounded balance was taken: %v", err)
	}
	if _, err := invoke(m, "record_payment", `{"invoice":"Inv2","expectedBalance":"10.125"}`, false); err != nil || fmt.Sprint(f.payments[0]["amount"]) != "10.125" {
		t.Fatalf("%v %v", f.payments, err)
	}
	if _, err := invoke(m, "record_payment", `{"invoice":"Inv1","amount":"0.0049","expectedBalance":"899.50"}`, false); err != nil || fmt.Sprint(f.payments[1]["amount"]) != "0.0049" {
		t.Fatalf("%v %v", f.payments, err)
	}
	if r, _ := invoke(m, "invoices", `{}`, false); !strings.Contains(string(r.Output), `"balance":"10.125"`) {
		t.Fatal(string(r.Output))
	}
}

func TestInvoiceNinjaValidation(t *testing.T) {
	m, f := setup(t, "secret://n")
	item := `"items":[{"description":"x","cost":"1"}]`
	for _, c := range []struct{ action, in string }{
		{"clients", `{"limit":500}`},
		{"invoices", `{"status":"lost"}`},
		{"invoices", `{"client":"../users"}`},
		{"payments", `{"client":"a b"}`},
		{"create_invoice", `{"client":"Wpmbk5ezJn"}`},
		{"create_invoice", `{"client":"x/y",` + item + `}`},
		{"create_invoice", `{"client":"Wpmbk5ezJn","items":[{"description":"x","cost":"1.5e3"}]}`},
		{"create_invoice", `{"client":"Wpmbk5ezJn","items":[{"description":"x","cost":"-1"}]}`},
		{"create_invoice", `{"client":"Wpmbk5ezJn","items":[{"description":"x","cost":"12,50"}]}`},
		{"create_invoice", `{"client":"Wpmbk5ezJn","items":[{"description":"x","cost":"1","quantity":"0"}]}`},
		{"create_invoice", `{"client":"Wpmbk5ezJn","items":[{"description":" ","cost":"1"}]}`},
		{"create_invoice", `{"client":"Wpmbk5ezJn","items":[{"description":"x","cost":1}]}`},
		{"create_invoice", `{"client":"Wpmbk5ezJn","date":"04.11.2026",` + item + `}`},
		{"create_invoice", `{"client":"Wpmbk5ezJn","date":"2026-11-04","dueDate":"2026-11-01",` + item + `}`},
		{"delete_invoice", `{"id":""}`},
		{"mark_sent", `{"invoice":"Inv1?x=1"}`},
		{"email_invoice", `{}`},
		{"record_payment", `{"invoice":"Inv1","amount":"0"}`},
		{"record_payment", `{"invoice":"Inv1","amount":"NaN"}`},
		{"record_payment", `{"invoice":"Inv1","amount":"1.23456"}`},
		{"record_payment", `{"invoice":"Inv1","amount":"0100"}`},
		{"create_invoice", `{"client":"Wpmbk5ezJn","items":[{"description":"x","cost":"1","quantity":"01"}]}`},
		{"record_payment", `{"invoice":"Inv1","date":"tomorrow"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// The invoice changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "email_invoice", `{"invoice":"Other1"}`, false); err == nil || len(f.seen) != 1 || len(f.emailed) != 0 {
		t.Fatalf("emailed another invoice: %v %v", err, f.seen)
	}
	for _, c := range []Config{{Token: "ninja_plain"}, {URL: "invoices.example.com", Token: "secret://n"}, {URL: "https://u:p@invoices.example.com", Token: "secret://n"}, {URL: "https://invoices.example.com/?x=1", Token: "secret://n"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" || h.Message != "Invoice Ninja refused the API token" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "clients", `{}`, false); err == nil || strings.Contains(err.Error(), "ninja_bad") {
		t.Fatal(err)
	}
}

func TestInvoiceNinjaRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = "hit " + r.Header.Get("X-API-TOKEN") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://n"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://n": "ninja_good"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// shaOf is the sha256 an email preview shows.
func shaOf(r sdk.Result) string {
	if r.Plan == nil || len(r.Plan.Changes) == 0 {
		return ""
	}
	var a struct {
		SHA256 string `json:"sha256"`
	}
	json.Unmarshal(r.Plan.Changes[0].After, &a)
	return a.SHA256
}
