// Package invoiceninja works with Invoice Ninja v5 (the hosted service or a
// self-hosted server) through its API and an API token: clients, invoices
// and payments, creating a draft invoice, and marking an invoice sent,
// emailing it to the client or recording a payment.
//
// Everything here names clients or amounts, so every action is sensitive.
// What reaches a client or the books (marking sent, emailing, recording a
// payment) is destructive, with a preview naming the client and amount. A
// draft is a write whose undo deletes it; only drafts can be deleted here.
package invoiceninja

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Invoice Ninja company.
type Config struct {
	URL                string `json:"url"`   // default https://invoicing.co; self-hosted: the server's address
	Token              string `json:"token"` // secret:// API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

const defaultBase = "https://invoicing.co"

type conn struct {
	api *rest.Client
	now func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://invoicing.co when no address is set (tests).
	Base string
	// Now replaces the clock (tests).
	Now func() time.Time
}

// New returns the Invoice Ninja module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
	dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	// No leading zeros: the strings go into the request as JSON numbers.
	amountRe = regexp.MustCompile(`^(0|[1-9]\d{0,11})(\.\d{1,4})?$`)
	qtyRe    = regexp.MustCompile(`^(0|[1-9]\d{0,8})(\.\d{1,4})?$`)
)

const (
	maxItems = 100
	maxText  = 2000
	maxShort = 255
)

// Invoice Ninja's invoice statuses.
var statuses = map[string]string{"1": "draft", "2": "sent", "3": "partial", "4": "paid", "5": "cancelled", "6": "reversed"}

var listStatus = map[string]bool{"draft": true, "sent": true, "partial": true, "paid": true, "unpaid": true, "overdue": true, "cancelled": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}`
	inv := `{"type":"object","required":["invoice"],"properties":{"invoice":{"type":"string","description":"Invoice id (see invoices)"}}}`
	return sdk.Manifest{
		ID: "invoiceninja", Name: "Invoice Ninja", Version: "0.1.0", Category: "Productivity", Icon: "payment",
		Description: "Invoice Ninja: clients, invoices and payments; draft invoices, and mark sent, email or record a payment with a preview. Client and money data is kept out of logs.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"url":{"type":"string","default":"https://invoicing.co","description":"Invoice Ninja's hosted service, or your server's address, e.g. https://invoices.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API token (Settings, Account Management, API Tokens). It acts as its user"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "clients", Title: "Clients", Description: "Active clients: number, name, balance, paid to date and contacts (name, email); addresses only when asked. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string","description":"Name, number or email to look for"},"includeAddress":{"type":"boolean"},` + limit + `}}`)},
			{Name: "invoices", Title: "Invoices", Description: "Newest invoices: number, client, date, due date, amount, balance and status. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"client":{"type":"string","description":"Only this client's (client id)"},"status":{"type":"string","enum":["","draft","sent","partial","paid","unpaid","overdue","cancelled"]},` + limit + `}}`)},
			{Name: "payments", Title: "Payments", Description: "Newest payments: number, client, date, amount, refunded, reference and the invoices paid. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"client":{"type":"string","description":"Only this client's (client id)"},` + limit + `}}`)},
			{Name: "create_invoice", Title: "Create a draft invoice", Description: "Creates a draft invoice for a client from line items (amounts before tax). Nothing is sent. Undo deletes the draft.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["client","items"],"properties":{
					"client":{"type":"string","description":"Client id (see clients)"},
					"items":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"object","required":["description","cost"],"properties":{
						"description":{"type":"string"},"product":{"type":"string","description":"Product key"},
						"quantity":{"type":"string","default":"1","description":"Decimal, e.g. 2 or 1.5"},
						"cost":{"type":"string","description":"Unit price as a decimal, e.g. 120.00"}}}},
					"date":{"type":"string","description":"YYYY-MM-DD, today by default"},
					"dueDate":{"type":"string","description":"YYYY-MM-DD; the client's terms by default"},
					"poNumber":{"type":"string"},"publicNotes":{"type":"string"}}}`)},
			{Name: "delete_invoice", Title: "Delete a draft invoice", Description: "Deletes a draft invoice (Invoice Ninja keeps it among deleted invoices). Sent invoices are refused: cancel or reverse those in Invoice Ninja.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Invoice id"}}}`)},
			{Name: "mark_sent", Title: "Mark an invoice sent", Description: "Marks a draft invoice sent without emailing it: it gets a number, counts toward the client's balance and becomes due. Can't be undone here.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(inv)},
			{Name: "email_invoice", Title: "Email an invoice", Description: "Emails the invoice to the client's contacts with your invoice template (a draft is marked sent). The preview names the client, recipients and amount.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(inv)},
			{Name: "record_payment", Title: "Record a payment", Description: "Records a payment against an invoice (the balance by default), which marks it paid or partly paid. Moves no money; Invoice Ninja may email the client a receipt, per its settings.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["invoice"],"properties":{"invoice":{"type":"string","description":"Invoice id"},"amount":{"type":"string","description":"Decimal, the invoice's balance by default"},"date":{"type":"string","description":"YYYY-MM-DD, today by default"},"reference":{"type":"string","description":"Transaction reference"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = defaultBase
		if m.Base != "" {
			c.URL = m.Base
		}
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://invoices.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	ref := c.Token
	base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-API-TOKEN", strings.TrimSpace(t))
		r.Header.Set("X-Requested-With", "XMLHttpRequest")
		return nil
	})
	api.HTTP = rest.SameHostOnly(client) // the token is a custom header: never to another host
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden) && strings.Contains(strings.ToLower(err.Error()), "token"):
		return errors.New("Invoice Ninja refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token's user isn't allowed to do this in Invoice Ninja")
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var p struct {
		Company string `json:"company_name"`
	}
	if err := c.do(ctx, http.MethodGet, "/ping", nil, nil, &p); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Invoice Ninja v5 API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in"
	if p.Company != "" {
		msg += " · " + p.Company
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// str reads a JSON string or number as text (Invoice Ninja sends ids and
// statuses as either, depending on version).
type str string

func (s *str) UnmarshalJSON(b []byte) error {
	var t string
	if json.Unmarshal(b, &t) == nil {
		*s = str(t)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*s = str(n)
	return nil
}

// money is an amount as the server wrote it, never a float.
type money = json.Number

func rat(n money) *big.Rat {
	if n == "" {
		return new(big.Rat)
	}
	r, ok := new(big.Rat).SetString(string(n))
	if !ok {
		return new(big.Rat)
	}
	return r
}

func dec(n money) string { return decRat(rat(n)) }

// decRat writes an amount with at least two decimals and as many more as it
// has, up to four: a currency with three decimals (KWD, BHD) keeps them, so
// a balance of 10.125 isn't shown, or paid, as 10.13.
func decRat(r *big.Rat) string {
	s := r.FloatString(4)
	for strings.HasSuffix(s, "0") && len(s)-strings.IndexByte(s, '.') > 3 {
		s = s[:len(s)-1]
	}
	return s
}

type contact struct {
	ID        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	IsPrimary bool   `json:"is_primary"`
	SendEmail *bool  `json:"send_email"`
	IsLocked  bool   `json:"is_locked"`
}

type client struct {
	ID         string    `json:"id"`
	Number     string    `json:"number"`
	Name       string    `json:"name"`
	Balance    money     `json:"balance"`
	PaidToDate money     `json:"paid_to_date"`
	IsDeleted  bool      `json:"is_deleted"`
	Contacts   []contact `json:"contacts"`
	Address1   string    `json:"address1"`
	Address2   string    `json:"address2"`
	City       string    `json:"city"`
	State      string    `json:"state"`
	PostalCode string    `json:"postal_code"`
	VATNumber  string    `json:"vat_number"`
}

func (c client) label() string {
	if c.Name != "" {
		return c.Name
	}
	for _, ct := range c.Contacts {
		if n := strings.TrimSpace(ct.FirstName + " " + ct.LastName); n != "" {
			return n
		}
		if ct.Email != "" {
			return ct.Email
		}
	}
	return "client " + c.ID
}

// recipients are the contacts an invoice email goes to. Invoice Ninja
// emails the invoice's invitations (made for the contacts set to receive
// email when the invoice was created), each whose contact has an email
// address and isn't locked, whatever the contact's send_email says now. An
// invitation whose contact is no longer on the client can't be named, so
// it's refused rather than left out of the preview. Without invitations in
// the answer (older servers), the contacts set to receive email are used.
func (c client) recipients(inv invoice) ([]string, error) {
	out := []string{}
	if inv.Invitations == nil {
		for _, ct := range c.Contacts {
			if ct.Email != "" && !ct.IsLocked && (ct.SendEmail == nil || *ct.SendEmail) {
				out = append(out, ct.Email)
			}
		}
		return out, nil
	}
	byID := map[string]contact{}
	for _, ct := range c.Contacts {
		byID[ct.ID] = ct
	}
	seen := map[string]bool{}
	for _, i := range *inv.Invitations {
		ct, ok := byID[i.ContactID]
		if !ok || i.ContactID == "" {
			return nil, fmt.Errorf("%s is addressed to a contact that's no longer on the client; check its contacts in Invoice Ninja", inv.label())
		}
		if ct.Email != "" && !ct.IsLocked && !seen[ct.Email] {
			seen[ct.Email] = true
			out = append(out, ct.Email)
		}
	}
	return out, nil
}

type invoice struct {
	ID        string `json:"id"`
	Number    string `json:"number"`
	ClientID  string `json:"client_id"`
	StatusID  str    `json:"status_id"`
	Date      string `json:"date"`
	DueDate   string `json:"due_date"`
	Amount    money  `json:"amount"`
	Balance   money  `json:"balance"`
	PONumber  string `json:"po_number"`
	IsDeleted bool   `json:"is_deleted"`
	Archived  int64  `json:"archived_at"`
	// Invitations are whom an email goes to; nil when the server sent none.
	Invitations *[]struct {
		ContactID string `json:"client_contact_id"`
	} `json:"invitations"`
}

func (i invoice) status() string {
	if s := statuses[string(i.StatusID)]; s != "" {
		return s
	}
	return string(i.StatusID)
}

func (i invoice) label() string {
	if i.Number != "" {
		return "invoice " + i.Number
	}
	return "draft invoice " + i.ID
}

func (i invoice) row(clientName string) map[string]any {
	r := map[string]any{"id": i.ID, "number": i.Number, "clientId": i.ClientID, "date": i.Date, "amount": dec(i.Amount), "balance": dec(i.Balance), "status": i.status()}
	if clientName != "" {
		r["client"] = clientName
	}
	if i.DueDate != "" {
		r["dueDate"] = i.DueDate
	}
	if i.PONumber != "" {
		r["poNumber"] = i.PONumber
	}
	if i.IsDeleted {
		r["deleted"] = true
	}
	return r
}

type input struct {
	Query          string `json:"query"`
	IncludeAddress bool   `json:"includeAddress"`
	Limit          int    `json:"limit"`
	Client         string `json:"client"`
	Status         string `json:"status"`
	Invoice        string `json:"invoice"`
	ID             string `json:"id"`
	Items          []struct {
		Description string `json:"description"`
		Product     string `json:"product"`
		Quantity    string `json:"quantity"`
		Cost        string `json:"cost"`
	} `json:"items"`
	Date        string `json:"date"`
	DueDate     string `json:"dueDate"`
	PONumber    string `json:"poNumber"`
	PublicNotes string `json:"publicNotes"`
	Amount      string `json:"amount"`
	Reference   string `json:"reference"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func checkDate(s string) error {
	if s == "" {
		return nil
	}
	if !dateRe.MatchString(s) {
		return fmt.Errorf("%q isn't a date like 2026-11-04", s)
	}
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return fmt.Errorf("%q isn't a date", s)
	}
	return nil
}

func limit(n int) (int, error) {
	if n < 0 || n > 100 {
		return 0, errors.New("limit is 1 to 100")
	}
	if n == 0 {
		n = 25
	}
	return n, nil
}

func checkID(what, s string) (string, error) {
	s = strings.TrimSpace(s)
	if !idRe.MatchString(s) {
		return "", fmt.Errorf("the %s is its id (see %ss)", what, what)
	}
	return s, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "clients":
		return c.clients(ctx, p)
	case "invoices":
		return c.invoices(ctx, p)
	case "payments":
		return c.payments(ctx, p)
	case "create_invoice":
		return c.create(ctx, call, p)
	case "delete_invoice":
		id, err := checkID("invoice", p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.deleteDraft(ctx, call, id)
	case "mark_sent", "email_invoice", "record_payment":
		id, err := checkID("invoice", p.Invoice)
		if err != nil {
			return sdk.Result{}, err
		}
		switch call.Action {
		case "mark_sent":
			return c.markSent(ctx, call, id)
		case "email_invoice":
			return c.email(ctx, call, id)
		}
		return c.pay(ctx, call, id, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) clients(ctx context.Context, p input) (sdk.Result, error) {
	n, err := limit(p.Limit)
	if err != nil {
		return sdk.Result{}, err
	}
	q := strings.TrimSpace(p.Query)
	if len([]rune(q)) > maxShort {
		return sdk.Result{}, fmt.Errorf("the query is at most %d characters", maxShort)
	}
	v := url.Values{"per_page": {strconv.Itoa(n)}, "page": {"1"}, "status": {"active"}}
	if q != "" {
		v.Set("filter", q)
	}
	var d struct {
		Data []client `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/clients", v, nil, &d); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, x := range d.Data {
		contacts := []map[string]any{}
		for _, ct := range x.Contacts {
			cr := map[string]any{"name": strings.TrimSpace(ct.FirstName + " " + ct.LastName), "email": ct.Email}
			if ct.IsPrimary {
				cr["primary"] = true
			}
			contacts = append(contacts, cr)
		}
		r := map[string]any{"id": x.ID, "number": x.Number, "name": x.label(), "balance": dec(x.Balance), "paidToDate": dec(x.PaidToDate), "contacts": contacts}
		if p.IncludeAddress {
			r["address"] = map[string]string{"line1": x.Address1, "line2": x.Address2, "city": x.City, "state": x.State, "postalCode": x.PostalCode}
			if x.VATNumber != "" {
				r["vatNumber"] = x.VATNumber
			}
		}
		out = append(out, r)
	}
	return sdk.JSON(out)
}

// clientNames maps client ids to names, for lists that carry ids.
func (c *conn) clientNames(ctx context.Context) map[string]string {
	var d struct {
		Data []client `json:"data"`
	}
	out := map[string]string{}
	if c.do(ctx, http.MethodGet, "/clients", url.Values{"per_page": {"500"}, "page": {"1"}}, nil, &d) == nil {
		for _, x := range d.Data {
			out[x.ID] = x.label()
		}
	}
	return out
}

func (c *conn) invoices(ctx context.Context, p input) (sdk.Result, error) {
	n, err := limit(p.Limit)
	if err != nil {
		return sdk.Result{}, err
	}
	v := url.Values{"per_page": {strconv.Itoa(n)}, "page": {"1"}, "sort": {"date|desc"}, "is_deleted": {"false"}}
	if p.Client != "" {
		id, err := checkID("client", p.Client)
		if err != nil {
			return sdk.Result{}, err
		}
		v.Set("client_id", id)
	}
	if p.Status != "" {
		if !listStatus[p.Status] {
			return sdk.Result{}, errors.New("status is draft, sent, partial, paid, unpaid, overdue or cancelled")
		}
		v.Set("client_status", p.Status)
	}
	var d struct {
		Data []invoice `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/invoices", v, nil, &d); err != nil {
		return sdk.Result{}, err
	}
	names := c.clientNames(ctx)
	out := []map[string]any{}
	for _, i := range d.Data {
		out = append(out, i.row(names[i.ClientID]))
	}
	return sdk.JSON(out)
}

func (c *conn) payments(ctx context.Context, p input) (sdk.Result, error) {
	n, err := limit(p.Limit)
	if err != nil {
		return sdk.Result{}, err
	}
	v := url.Values{"per_page": {strconv.Itoa(n)}, "page": {"1"}, "sort": {"date|desc"}}
	if p.Client != "" {
		id, err := checkID("client", p.Client)
		if err != nil {
			return sdk.Result{}, err
		}
		v.Set("client_id", id)
	}
	var d struct {
		Data []struct {
			ID        string `json:"id"`
			Number    string `json:"number"`
			ClientID  string `json:"client_id"`
			Date      string `json:"date"`
			Amount    money  `json:"amount"`
			Refunded  money  `json:"refunded"`
			Reference string `json:"transaction_reference"`
			StatusID  str    `json:"status_id"`
			Paid      []struct {
				InvoiceID string `json:"invoice_id"`
				Amount    money  `json:"amount"`
			} `json:"paymentables"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/payments", v, nil, &d); err != nil {
		return sdk.Result{}, err
	}
	names := c.clientNames(ctx)
	out := []map[string]any{}
	for _, x := range d.Data {
		r := map[string]any{"id": x.ID, "number": x.Number, "clientId": x.ClientID, "date": x.Date, "amount": dec(x.Amount)}
		if n := names[x.ClientID]; n != "" {
			r["client"] = n
		}
		if rat(x.Refunded).Sign() > 0 {
			r["refunded"] = dec(x.Refunded)
		}
		if x.Reference != "" {
			r["reference"] = x.Reference
		}
		paid := []map[string]string{}
		for _, pi := range x.Paid {
			if pi.InvoiceID != "" {
				paid = append(paid, map[string]string{"invoice": pi.InvoiceID, "amount": dec(pi.Amount)})
			}
		}
		if len(paid) > 0 {
			r["invoices"] = paid
		}
		out = append(out, r)
	}
	return sdk.JSON(out)
}

func (c *conn) client(ctx context.Context, id string) (client, error) {
	var d struct {
		Data client `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/clients/"+url.PathEscape(id), nil, nil, &d); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return client{}, fmt.Errorf("there's no client %s", id)
		}
		return client{}, err
	}
	if d.Data.ID != id {
		return client{}, fmt.Errorf("Invoice Ninja answered with another client for %s", id)
	}
	return d.Data, nil
}

func (c *conn) invoice(ctx context.Context, id string) (invoice, error) {
	var d struct {
		Data invoice `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/invoices/"+url.PathEscape(id), nil, nil, &d); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return invoice{}, fmt.Errorf("there's no invoice %s", id)
		}
		return invoice{}, err
	}
	if d.Data.ID != id {
		// The id goes into the change and the undo.
		return invoice{}, fmt.Errorf("Invoice Ninja answered with another invoice for %s", id)
	}
	return d.Data, nil
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	cid, err := checkID("client", p.Client)
	if err != nil {
		return sdk.Result{}, err
	}
	if len(p.Items) == 0 || len(p.Items) > maxItems {
		return sdk.Result{}, fmt.Errorf("give 1 to %d line items", maxItems)
	}
	total := new(big.Rat)
	lines := []map[string]any{}
	for i, it := range p.Items {
		desc := strings.TrimSpace(it.Description)
		if desc == "" || len([]rune(desc)) > maxText {
			return sdk.Result{}, fmt.Errorf("item %d: the description is 1 to %d characters", i+1, maxText)
		}
		prod := strings.TrimSpace(it.Product)
		if len([]rune(prod)) > maxShort {
			return sdk.Result{}, fmt.Errorf("item %d: the product key is at most %d characters", i+1, maxShort)
		}
		qty := strings.TrimSpace(it.Quantity)
		if qty == "" {
			qty = "1"
		}
		cost := strings.TrimSpace(it.Cost)
		if !qtyRe.MatchString(qty) || rat(money(qty)).Sign() <= 0 {
			return sdk.Result{}, fmt.Errorf("item %d: the quantity is a positive decimal like 2 or 1.5", i+1)
		}
		if !amountRe.MatchString(cost) {
			return sdk.Result{}, fmt.Errorf("item %d: the cost is a decimal like 120.00", i+1)
		}
		total.Add(total, new(big.Rat).Mul(rat(money(qty)), rat(money(cost))))
		line := map[string]any{"notes": desc, "quantity": json.Number(qty), "cost": json.Number(cost), "type_id": "1"}
		if prod != "" {
			line["product_key"] = prod
		}
		lines = append(lines, line)
	}
	date := p.Date
	if date == "" {
		date = c.now().Format("2006-01-02")
	}
	if err := checkDate(date); err != nil {
		return sdk.Result{}, err
	}
	if err := checkDate(p.DueDate); err != nil {
		return sdk.Result{}, err
	}
	if p.DueDate != "" && p.DueDate < date {
		return sdk.Result{}, errors.New("the due date is before the invoice date")
	}
	po, notes := strings.TrimSpace(p.PONumber), strings.TrimSpace(p.PublicNotes)
	if len([]rune(po)) > maxShort || len([]rune(notes)) > maxText {
		return sdk.Result{}, errors.New("the PO number or notes are too long")
	}
	cl, err := c.client(ctx, cid)
	if err != nil {
		return sdk.Result{}, err
	}
	if cl.IsDeleted {
		return sdk.Result{}, fmt.Errorf("client %s is deleted", cid)
	}
	body := map[string]any{"client_id": cid, "date": date, "line_items": lines}
	if p.DueDate != "" {
		body["due_date"] = p.DueDate
	}
	if po != "" {
		body["po_number"] = po
	}
	if notes != "" {
		body["public_notes"] = notes
	}
	summary := fmt.Sprintf("Create a draft invoice for %s: %d item(s), %s before tax, dated %s (nothing is sent)", cl.label(), len(lines), decRat(total), date)
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "invoice for " + cl.label(), Op: "create", After: mustJSON(body)}}}}, nil
	}
	var d struct {
		Data invoice `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, "/invoices", nil, body, &d); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(d.Data.row(cl.label()))
	if idRe.MatchString(d.Data.ID) {
		// The undo is kept in the audit log: it holds the id alone.
		res.Undo = sdk.UndoWith("delete_invoice", map[string]string{"id": d.Data.ID}, "Delete the draft invoice "+d.Data.ID)
	}
	return res, err
}

func (c *conn) deleteDraft(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	inv, err := c.invoice(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	if inv.IsDeleted {
		return sdk.JSON(map[string]any{"id": id, "deleted": true, "note": "nothing to change: it's already deleted"})
	}
	if inv.status() != "draft" {
		return sdk.Result{}, fmt.Errorf("%s is %s, not a draft; cancel or reverse it in Invoice Ninja instead", inv.label(), inv.status())
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete draft %s (%s)", inv.label(), dec(inv.Amount)),
			Changes: []sdk.Change{{Target: inv.label(), Op: "delete", Before: mustJSON(inv.row(""))}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, "/invoices/"+url.PathEscape(id), nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"id": id, "deleted": true})
}

// usable refuses invoices that can't be sent or paid.
func usable(inv invoice) error {
	switch {
	case inv.IsDeleted:
		return fmt.Errorf("%s is deleted", inv.label())
	case inv.status() == "cancelled" || inv.status() == "reversed":
		return fmt.Errorf("%s is %s", inv.label(), inv.status())
	}
	return nil
}

func (c *conn) bulk(ctx context.Context, action, id string) (invoice, error) {
	var d struct {
		Data []invoice `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, "/invoices/bulk", nil, map[string]any{"action": action, "ids": []string{id}}, &d); err != nil {
		return invoice{}, err
	}
	for _, i := range d.Data {
		if i.ID == id {
			return i, nil
		}
	}
	return invoice{}, nil
}

func (c *conn) markSent(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	inv, err := c.invoice(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	if err := usable(inv); err != nil {
		return sdk.Result{}, err
	}
	if inv.status() != "draft" {
		return sdk.JSON(map[string]any{"id": id, "status": inv.status(), "note": "nothing to change: it's already sent"})
	}
	cl, err := c.client(ctx, inv.ClientID)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Mark %s to %s for %s sent (no email; it becomes due)", inv.label(), cl.label(), dec(inv.Amount)),
			Changes: []sdk.Change{{Target: inv.label(), Op: "mark sent", Before: mustJSON(map[string]string{"status": "draft"}), After: mustJSON(map[string]string{"status": "sent"})}}}}, nil
	}
	after, err := c.bulk(ctx, "mark_sent", id)
	if err != nil {
		return sdk.Result{}, err
	}
	if after.ID == "" {
		if after, err = c.invoice(ctx, id); err != nil {
			return sdk.Result{}, err
		}
	}
	if after.status() == "draft" {
		return sdk.Result{}, errors.New("Invoice Ninja kept the invoice as a draft")
	}
	return sdk.JSON(after.row(cl.label()))
}

func (c *conn) email(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	inv, err := c.invoice(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	if err := usable(inv); err != nil {
		return sdk.Result{}, err
	}
	cl, err := c.client(ctx, inv.ClientID)
	if err != nil {
		return sdk.Result{}, err
	}
	to, err := cl.recipients(inv)
	if err != nil {
		return sdk.Result{}, err
	}
	if len(to) == 0 {
		return sdk.Result{}, fmt.Errorf("%s has no contact with an email address to send to", cl.label())
	}
	if call.DryRun {
		summary := fmt.Sprintf("Email %s for %s (balance %s) to %s: %s", inv.label(), dec(inv.Amount), dec(inv.Balance), cl.label(), strings.Join(to, ", "))
		if inv.status() == "draft" {
			summary += " (the draft is marked sent)"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: inv.label(), Op: "email",
			After: mustJSON(map[string]any{"client": cl.label(), "to": to, "amount": dec(inv.Amount), "balance": dec(inv.Balance)})}}}}, nil
	}
	if _, err := c.bulk(ctx, "email", id); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"id": id, "number": inv.Number, "client": cl.label(), "emailedTo": to, "amount": dec(inv.Amount)})
}

func (c *conn) pay(ctx context.Context, call sdk.Call, id string, p input) (sdk.Result, error) {
	amount := strings.TrimSpace(p.Amount)
	if amount != "" && (!amountRe.MatchString(amount) || rat(money(amount)).Sign() <= 0) {
		return sdk.Result{}, errors.New("amount is a positive decimal like 120.00")
	}
	date := p.Date
	if date == "" {
		date = c.now().Format("2006-01-02")
	}
	if err := checkDate(date); err != nil {
		return sdk.Result{}, err
	}
	ref := strings.TrimSpace(p.Reference)
	if len([]rune(ref)) > maxShort {
		return sdk.Result{}, fmt.Errorf("the reference is at most %d characters", maxShort)
	}
	inv, err := c.invoice(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	if err := usable(inv); err != nil {
		return sdk.Result{}, err
	}
	// A draft's balance is 0 until it's sent: refuse it before saying
	// there's nothing to pay.
	if inv.status() == "draft" {
		return sdk.Result{}, fmt.Errorf("%s is a draft; mark it sent first", inv.label())
	}
	bal := rat(inv.Balance)
	if bal.Sign() <= 0 {
		return sdk.JSON(map[string]any{"id": id, "status": inv.status(), "balance": dec(inv.Balance), "note": "nothing to change: nothing is left to pay"})
	}
	amt := bal
	if amount != "" {
		amt = rat(money(amount))
		if amt.Cmp(bal) > 0 {
			return sdk.Result{}, fmt.Errorf("the amount is more than the balance (%s)", decRat(bal))
		}
	}
	cl, err := c.client(ctx, inv.ClientID)
	if err != nil {
		return sdk.Result{}, err
	}
	a := decRat(amt)
	body := map[string]any{"client_id": inv.ClientID, "amount": json.Number(a), "date": date, "invoices": []map[string]any{{"invoice_id": id, "amount": json.Number(a)}}}
	if ref != "" {
		body["transaction_reference"] = ref
	}
	if call.DryRun {
		left := new(big.Rat).Sub(bal, amt)
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Record a payment of %s from %s on %s against %s (balance %s, then %s)", a, cl.label(), date, inv.label(), decRat(bal), decRat(left)),
			Changes: []sdk.Change{{Target: inv.label(), Op: "record payment", Before: mustJSON(map[string]string{"balance": decRat(bal)}), After: mustJSON(map[string]string{"balance": decRat(left)})}}}}, nil
	}
	var d struct {
		Data struct {
			ID     string `json:"id"`
			Number string `json:"number"`
			Amount money  `json:"amount"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, "/payments", nil, body, &d); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"payment": d.Data.ID, "number": d.Data.Number, "amount": dec(d.Data.Amount), "invoice": id, "client": cl.label(), "date": date})
}
