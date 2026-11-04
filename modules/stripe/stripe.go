// Package stripe reads a Stripe account (balance, payments, charges,
// customers, subscriptions, payouts, disputes, invoices) and can refund a
// payment or cancel a subscription, through a restricted or secret API key.
//
// Money never moves without a preview: refunds and immediate cancellations
// are destructive, show the amount, currency and customer first, and send an
// Idempotency-Key with every POST so a repeated request can't refund twice.
// Card data beyond brand and last four digits, billing details and receipt
// emails are never returned; customer addresses only when asked for.
package stripe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Stripe account.
type Config struct {
	Key string `json:"key"` // secret:// restricted (rk_) or secret (sk_) key
}

// APIVersion pins the shape of Stripe's answers.
const APIVersion = "2024-06-20"

const defaultBase = "https://api.stripe.com"

type conn struct {
	h    sdk.Host
	key  string
	base string
	http *http.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.stripe.com (tests).
	Base string
}

// New returns the Stripe module.
func New() *Module { return &Module{} }

var (
	keyRe      = regexp.MustCompile(`^(sk|rk)_(live|test)_[A-Za-z0-9]{10,255}$`)
	paymentRe  = regexp.MustCompile(`^(pi|ch|py)_[A-Za-z0-9]{6,255}$`)
	subRe      = regexp.MustCompile(`^sub_[A-Za-z0-9]{6,255}$`)
	customerRe = regexp.MustCompile(`^cus_[A-Za-z0-9]{6,255}$`)
	cursorRe   = regexp.MustCompile(`^[a-z]{2,6}_[A-Za-z0-9]{6,255}$`)
	idemRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{8,255}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	list := `"limit":{"type":"integer","default":20,"maximum":100},"after":{"type":"string","description":"Id of the last item of the previous page"}`
	cust := `"customer":{"type":"string","description":"Only this customer (cus_…)"}`
	return sdk.Manifest{
		ID: "stripe", Name: "Stripe", Version: "0.1.0", Category: "Business", Icon: "credit-card",
		Description: "A Stripe account: balance, payments, customers, subscriptions, payouts, disputes, invoices; refunds and cancellations with a preview.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"key":{"type":"string","x-secret":true,"description":"A restricted key (rk_…) with only the permissions you need; a full secret key (sk_…) works but can do anything"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "balance", Title: "Balance", Description: "Available and pending balance per currency.", Risk: sdk.RiskRead},
			{Name: "payments", Title: "Payments", Description: "Recent payment intents: amount, status, customer id, failure reason.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + list + `,` + cust + `}}`)},
			{Name: "charges", Title: "Charges", Description: "Recent charges: amount, refunded amount, status, dispute, card brand and last four digits. No billing details.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + list + `,` + cust + `,"payment":{"type":"string","description":"Only the charges of this payment intent (pi_…)"}}}`)},
			{Name: "customers", Title: "Customers", Description: "Finds customers by email or name (or a Stripe search query), with contact details; addresses only when asked.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string","description":"Email or name to look for, or a Stripe search query like email:'a@b.com'; empty lists the newest"},"limit":{"type":"integer","default":20,"maximum":100},"includeAddress":{"type":"boolean","description":"Include postal and shipping addresses"}}}`)},
			{Name: "subscriptions", Title: "Subscriptions", Description: "Subscriptions with status, plan, amount, renewal date and whether they're set to cancel.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + list + `,` + cust + `,"status":{"type":"string","enum":["","active","past_due","unpaid","canceled","incomplete","incomplete_expired","trialing","paused","all"]}}}`)},
			{Name: "payouts", Title: "Payouts", Description: "Payouts to your bank: amount, status, arrival date, failure.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + list + `,"status":{"type":"string","enum":["","pending","paid","failed","canceled","in_transit"]}}}`)},
			{Name: "disputes", Title: "Disputes", Description: "Disputes (chargebacks): amount, reason, status and the evidence deadline.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + list + `}}`)},
			{Name: "invoices", Title: "Invoices", Description: "Invoices: number, status, amounts due and paid, customer id, due date.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + list + `,` + cust + `,"status":{"type":"string","enum":["","draft","open","paid","uncollectible","void"]}}}`)},
			{Name: "refund", Title: "Refund a payment", Description: "Refunds a payment, fully or partly. Money goes back to the customer and can't be taken back.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["payment"],"properties":{"payment":{"type":"string","description":"Payment intent (pi_…) or charge (ch_…)"},"amount":{"type":"integer","minimum":1,"description":"In the currency's smallest unit (cents); the whole remaining amount when empty"},"reason":{"type":"string","enum":["","duplicate","fraudulent","requested_by_customer"]},"idempotencyKey":{"type":"string","description":"Reuse to make a retried refund safe; one is made up otherwise"}}}`)},
			{Name: "cancel_subscription", Title: "Cancel a subscription", Description: "Cancels at the end of the paid period (undo keeps it), or immediately (can't be undone).", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["subscription"],"properties":{"subscription":{"type":"string","description":"sub_…"},"immediately":{"type":"boolean","description":"End it now instead of at the period end"},"prorate":{"type":"boolean","description":"With immediately: credit the unused time"},"invoiceNow":{"type":"boolean","description":"With immediately: invoice pending usage and prorations now"}}}`)},
			{Name: "keep_subscription", Title: "Keep a subscription", Description: "Takes back a cancellation scheduled for the period end. Undo schedules it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["subscription"],"properties":{"subscription":{"type":"string","description":"sub_…"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Key, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 30*time.Second)
	}
	m.set.Put(id, &conn{h: h, key: c.Key, base: base, http: rest.SameHostOnly(hc)})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) secret(ctx context.Context) (string, error) {
	k, err := c.h.Secret(ctx, c.key)
	if err != nil {
		return "", err
	}
	k = strings.TrimSpace(k)
	if strings.HasPrefix(k, "pk_") {
		return "", errors.New("that's a publishable key; use a restricted key (rk_…) or a secret key (sk_…)")
	}
	if !keyRe.MatchString(k) {
		return "", errors.New("the stored key doesn't look like a Stripe restricted (rk_…) or secret (sk_…) key")
	}
	return k, nil
}

func newIdemKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "conduit-" + hex.EncodeToString(b)
}

// do sends one request. GET and DELETE take q as the query; POST sends it as
// a form with an Idempotency-Key.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, idem string, out any) error {
	key, err := c.secret(ctx)
	if err != nil {
		return err
	}
	u := c.base + path
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(q.Encode())
	} else if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Stripe-Version", APIVersion)
	req.Header.Set("User-Agent", "Conduit")
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if idem == "" {
			idem = newIdemKey()
		}
		req.Header.Set("Idempotency-Key", idem)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		var e struct {
			Error struct {
				Message string `json:"message"`
				Code    string `json:"code"`
			} `json:"error"`
		}
		msg := res.Status
		if json.Unmarshal(raw, &e) == nil && e.Error.Message != "" {
			msg = e.Error.Message
		}
		return &rest.Error{Status: res.StatusCode, Message: "Stripe: " + msg}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return errors.New("unexpected answer from Stripe")
		}
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var b struct {
		Livemode bool `json:"livemode"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/balance", nil, "", &b); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "Stripe refused the key"}
		}
		if rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "degraded", Message: "the key works but can't read the balance; give the restricted key Balance read access"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	mode := "test mode"
	if b.Livemode {
		mode = "live mode"
	}
	k, _ := c.secret(ctx)
	if strings.HasPrefix(k, "sk_") {
		return sdk.Health{Status: "ok", Message: "connected in " + mode + " with a full secret key; a restricted key is safer"}
	}
	return sdk.Health{Status: "ok", Message: "connected in " + mode}
}

var zeroDecimal = map[string]bool{"bif": true, "clp": true, "djf": true, "gnf": true, "jpy": true, "kmf": true, "krw": true, "mga": true, "pyg": true, "rwf": true, "ugx": true, "vnd": true, "vuv": true, "xaf": true, "xof": true, "xpf": true}
var threeDecimal = map[string]bool{"bhd": true, "jod": true, "kwd": true, "omr": true, "tnd": true}

// money renders an amount in minor units, like "12.34 USD".
func money(amount int64, currency string) string {
	cur := strings.ToLower(currency)
	digits := 2
	if zeroDecimal[cur] {
		digits = 0
	} else if threeDecimal[cur] {
		digits = 3
	}
	v := float64(amount) / math.Pow10(digits)
	return strconv.FormatFloat(v, 'f', digits, 64) + " " + strings.ToUpper(cur)
}

func ts(sec int64) string {
	if sec == 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

// ref is a Stripe field that is an id or, when expanded, an object with one.
type ref string

func (r *ref) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*r = ref(s)
		return nil
	}
	var o struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(b, &o) == nil {
		*r = ref(o.ID)
	}
	return nil
}

type charge struct {
	ID             string `json:"id"`
	Amount         int64  `json:"amount"`
	AmountCaptured int64  `json:"amount_captured"`
	AmountRefunded int64  `json:"amount_refunded"`
	Currency       string `json:"currency"`
	Status         string `json:"status"`
	Paid           bool   `json:"paid"`
	Captured       bool   `json:"captured"`
	Refunded       bool   `json:"refunded"`
	Disputed       bool   `json:"disputed"`
	Customer       ref    `json:"customer"`
	PaymentIntent  ref    `json:"payment_intent"`
	Description    string `json:"description"`
	Created        int64  `json:"created"`
	FailureMessage string `json:"failure_message"`
	Livemode       bool   `json:"livemode"`
	Outcome        *struct {
		RiskLevel     string `json:"risk_level"`
		SellerMessage string `json:"seller_message"`
	} `json:"outcome"`
	PaymentMethodDetails *struct {
		Type string `json:"type"`
		Card *struct {
			Brand string `json:"brand"`
			Last4 string `json:"last4"`
		} `json:"card"`
	} `json:"payment_method_details"`
}

func chargeOut(ch charge) map[string]any {
	out := map[string]any{"id": ch.ID, "amount": ch.Amount, "currency": ch.Currency, "display": money(ch.Amount, ch.Currency), "status": ch.Status, "created": ts(ch.Created)}
	if ch.AmountRefunded > 0 {
		out["refunded"] = money(ch.AmountRefunded, ch.Currency)
		out["amountRefunded"] = ch.AmountRefunded
	}
	if ch.Refunded {
		out["fullyRefunded"] = true
	}
	if ch.Disputed {
		out["disputed"] = true
	}
	if !ch.Captured && ch.Status == "succeeded" {
		out["uncaptured"] = true
	}
	if ch.Customer != "" {
		out["customer"] = string(ch.Customer)
	}
	if ch.PaymentIntent != "" {
		out["payment"] = string(ch.PaymentIntent)
	}
	if ch.Description != "" {
		out["description"] = ch.Description
	}
	if ch.FailureMessage != "" {
		out["failure"] = ch.FailureMessage
	}
	if ch.Outcome != nil && ch.Outcome.RiskLevel != "" {
		out["risk"] = ch.Outcome.RiskLevel
	}
	if d := ch.PaymentMethodDetails; d != nil {
		out["method"] = d.Type
		if d.Card != nil {
			out["card"] = strings.TrimSpace(d.Card.Brand + " •••• " + d.Card.Last4)
		}
	}
	return out
}

type paymentIntent struct {
	ID               string          `json:"id"`
	Amount           int64           `json:"amount"`
	AmountReceived   int64           `json:"amount_received"`
	Currency         string          `json:"currency"`
	Status           string          `json:"status"`
	Customer         ref             `json:"customer"`
	Description      string          `json:"description"`
	Created          int64           `json:"created"`
	LatestCharge     json.RawMessage `json:"latest_charge"`
	CanceledReason   string          `json:"cancellation_reason"`
	LastPaymentError *struct {
		Message string `json:"message"`
	} `json:"last_payment_error"`
}

type subscription struct {
	ID                string `json:"id"`
	Status            string `json:"status"`
	Customer          ref    `json:"customer"`
	CancelAtPeriodEnd bool   `json:"cancel_at_period_end"`
	CancelAt          int64  `json:"cancel_at"`
	CanceledAt        int64  `json:"canceled_at"`
	CurrentPeriodEnd  int64  `json:"current_period_end"`
	Created           int64  `json:"created"`
	TrialEnd          int64  `json:"trial_end"`
	Items             struct {
		Data []struct {
			Quantity int64 `json:"quantity"`
			Price    struct {
				ID         string `json:"id"`
				Nickname   string `json:"nickname"`
				UnitAmount *int64 `json:"unit_amount"`
				Currency   string `json:"currency"`
				Product    ref    `json:"product"`
				Recurring  *struct {
					Interval      string `json:"interval"`
					IntervalCount int64  `json:"interval_count"`
				} `json:"recurring"`
			} `json:"price"`
		} `json:"data"`
	} `json:"items"`
}

func subOut(s subscription) map[string]any {
	items := []map[string]any{}
	for _, it := range s.Items.Data {
		o := map[string]any{"price": it.Price.ID, "product": string(it.Price.Product), "quantity": it.Quantity}
		if it.Price.Nickname != "" {
			o["name"] = it.Price.Nickname
		}
		if it.Price.UnitAmount != nil {
			per := ""
			if r := it.Price.Recurring; r != nil {
				per = " per " + r.Interval
				if r.IntervalCount > 1 {
					per = fmt.Sprintf(" every %d %ss", r.IntervalCount, r.Interval)
				}
			}
			o["amount"] = money(*it.Price.UnitAmount, it.Price.Currency) + per
		}
		items = append(items, o)
	}
	out := map[string]any{"id": s.ID, "status": s.Status, "customer": string(s.Customer), "items": items, "created": ts(s.Created)}
	if s.CurrentPeriodEnd > 0 {
		out["periodEnd"] = ts(s.CurrentPeriodEnd)
	}
	if s.CancelAtPeriodEnd {
		out["cancelsAtPeriodEnd"] = true
	}
	if s.CancelAt > 0 {
		out["cancelAt"] = ts(s.CancelAt)
	}
	if s.CanceledAt > 0 {
		out["canceledAt"] = ts(s.CanceledAt)
	}
	if s.TrialEnd > 0 && s.Status == "trialing" {
		out["trialEnd"] = ts(s.TrialEnd)
	}
	return out
}

type address struct {
	Line1      string `json:"line1"`
	Line2      string `json:"line2"`
	City       string `json:"city"`
	State      string `json:"state"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

func (a *address) String() string {
	if a == nil {
		return ""
	}
	parts := []string{}
	for _, p := range []string{a.Line1, a.Line2, a.City, a.State, a.PostalCode, a.Country} {
		if strings.TrimSpace(p) != "" {
			parts = append(parts, strings.TrimSpace(p))
		}
	}
	return strings.Join(parts, ", ")
}

type customer struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Email       string   `json:"email"`
	Phone       string   `json:"phone"`
	Description string   `json:"description"`
	Created     int64    `json:"created"`
	Delinquent  bool     `json:"delinquent"`
	Balance     int64    `json:"balance"`
	Currency    string   `json:"currency"`
	Address     *address `json:"address"`
	Shipping    *struct {
		Name    string   `json:"name"`
		Address *address `json:"address"`
	} `json:"shipping"`
}

type list[T any] struct {
	Data    []T  `json:"data"`
	HasMore bool `json:"has_more"`
}

type input struct {
	Limit          int    `json:"limit"`
	After          string `json:"after"`
	Customer       string `json:"customer"`
	Payment        string `json:"payment"`
	Status         string `json:"status"`
	Query          string `json:"query"`
	IncludeAddress bool   `json:"includeAddress"`
	Amount         int64  `json:"amount"`
	Reason         string `json:"reason"`
	IdempotencyKey string `json:"idempotencyKey"`
	Subscription   string `json:"subscription"`
	Immediately    bool   `json:"immediately"`
	Prorate        bool   `json:"prorate"`
	InvoiceNow     bool   `json:"invoiceNow"`
}

// listQuery builds limit, starting_after and the optional filters.
func listQuery(p input, statuses ...string) (url.Values, error) {
	q := url.Values{}
	limit := p.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	q.Set("limit", strconv.Itoa(limit))
	if p.After != "" {
		if !cursorRe.MatchString(p.After) {
			return nil, errors.New("after is the id of the last item of the previous page")
		}
		q.Set("starting_after", p.After)
	}
	if p.Customer != "" {
		if !customerRe.MatchString(p.Customer) {
			return nil, errors.New("a customer is its id, cus_…")
		}
		q.Set("customer", p.Customer)
	}
	if p.Status != "" {
		ok := false
		for _, s := range statuses {
			ok = ok || s == p.Status
		}
		if !ok {
			return nil, fmt.Errorf("status %q isn't one of %s", p.Status, strings.Join(statuses, ", "))
		}
		q.Set("status", p.Status)
	}
	return q, nil
}

func page(out []map[string]any, more bool) (sdk.Result, error) {
	res := map[string]any{"items": out, "hasMore": more}
	if more && len(out) > 0 {
		res["next"] = out[len(out)-1]["id"]
	}
	return sdk.JSON(res)
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
	case "balance":
		var b struct {
			Available []struct {
				Amount   int64  `json:"amount"`
				Currency string `json:"currency"`
			} `json:"available"`
			Pending []struct {
				Amount   int64  `json:"amount"`
				Currency string `json:"currency"`
			} `json:"pending"`
			Livemode bool `json:"livemode"`
		}
		if err := c.do(ctx, http.MethodGet, "/v1/balance", nil, "", &b); err != nil {
			return sdk.Result{}, err
		}
		cur := map[string]map[string]any{}
		order := []string{}
		get := func(c string) map[string]any {
			if cur[c] == nil {
				cur[c] = map[string]any{"currency": c}
				order = append(order, c)
			}
			return cur[c]
		}
		for _, a := range b.Available {
			get(a.Currency)["available"] = money(a.Amount, a.Currency)
		}
		for _, a := range b.Pending {
			get(a.Currency)["pending"] = money(a.Amount, a.Currency)
		}
		out := []map[string]any{}
		for _, c := range order {
			out = append(out, cur[c])
		}
		return sdk.JSON(map[string]any{"live": b.Livemode, "balances": out})

	case "payments":
		q, err := listQuery(p)
		if err != nil {
			return sdk.Result{}, err
		}
		var l list[paymentIntent]
		if err := c.do(ctx, http.MethodGet, "/v1/payment_intents", q, "", &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, pi := range l.Data {
			o := map[string]any{"id": pi.ID, "amount": pi.Amount, "currency": pi.Currency, "display": money(pi.Amount, pi.Currency), "status": pi.Status, "created": ts(pi.Created)}
			if pi.AmountReceived > 0 && pi.AmountReceived != pi.Amount {
				o["received"] = money(pi.AmountReceived, pi.Currency)
			}
			if pi.Customer != "" {
				o["customer"] = string(pi.Customer)
			}
			if pi.Description != "" {
				o["description"] = pi.Description
			}
			var lc ref
			_ = lc.UnmarshalJSON(pi.LatestCharge)
			if lc != "" {
				o["charge"] = string(lc)
			}
			if pi.LastPaymentError != nil && pi.LastPaymentError.Message != "" {
				o["error"] = pi.LastPaymentError.Message
			}
			if pi.CanceledReason != "" {
				o["canceledReason"] = pi.CanceledReason
			}
			out = append(out, o)
		}
		return page(out, l.HasMore)

	case "charges":
		q, err := listQuery(p)
		if err != nil {
			return sdk.Result{}, err
		}
		if p.Payment != "" {
			if !strings.HasPrefix(p.Payment, "pi_") || !paymentRe.MatchString(p.Payment) {
				return sdk.Result{}, errors.New("payment is a payment intent id, pi_…")
			}
			q.Set("payment_intent", p.Payment)
		}
		var l list[charge]
		if err := c.do(ctx, http.MethodGet, "/v1/charges", q, "", &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, ch := range l.Data {
			out = append(out, chargeOut(ch))
		}
		return page(out, l.HasMore)

	case "customers":
		return c.customers(ctx, p)

	case "subscriptions":
		q, err := listQuery(p, "active", "past_due", "unpaid", "canceled", "incomplete", "incomplete_expired", "trialing", "paused", "all")
		if err != nil {
			return sdk.Result{}, err
		}
		var l list[subscription]
		if err := c.do(ctx, http.MethodGet, "/v1/subscriptions", q, "", &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range l.Data {
			out = append(out, subOut(s))
		}
		return page(out, l.HasMore)

	case "payouts":
		q, err := listQuery(p, "pending", "paid", "failed", "canceled", "in_transit")
		if err != nil {
			return sdk.Result{}, err
		}
		if p.Customer != "" {
			return sdk.Result{}, errors.New("payouts aren't per customer")
		}
		var l list[struct {
			ID             string `json:"id"`
			Amount         int64  `json:"amount"`
			Currency       string `json:"currency"`
			Status         string `json:"status"`
			ArrivalDate    int64  `json:"arrival_date"`
			Method         string `json:"method"`
			Type           string `json:"type"`
			Created        int64  `json:"created"`
			Automatic      bool   `json:"automatic"`
			FailureMessage string `json:"failure_message"`
		}]
		if err := c.do(ctx, http.MethodGet, "/v1/payouts", q, "", &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, po := range l.Data {
			o := map[string]any{"id": po.ID, "amount": po.Amount, "currency": po.Currency, "display": money(po.Amount, po.Currency), "status": po.Status, "arrival": ts(po.ArrivalDate), "method": po.Method, "automatic": po.Automatic, "created": ts(po.Created)}
			if po.FailureMessage != "" {
				o["failure"] = po.FailureMessage
			}
			out = append(out, o)
		}
		return page(out, l.HasMore)

	case "disputes":
		if p.Customer != "" || p.Status != "" {
			return sdk.Result{}, errors.New("disputes take only limit and after")
		}
		q, err := listQuery(p)
		if err != nil {
			return sdk.Result{}, err
		}
		var l list[struct {
			ID              string `json:"id"`
			Amount          int64  `json:"amount"`
			Currency        string `json:"currency"`
			Status          string `json:"status"`
			Reason          string `json:"reason"`
			Charge          ref    `json:"charge"`
			PaymentIntent   ref    `json:"payment_intent"`
			Created         int64  `json:"created"`
			EvidenceDetails struct {
				DueBy       int64 `json:"due_by"`
				HasEvidence bool  `json:"has_evidence"`
				PastDue     bool  `json:"past_due"`
			} `json:"evidence_details"`
		}]
		if err := c.do(ctx, http.MethodGet, "/v1/disputes", q, "", &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range l.Data {
			o := map[string]any{"id": d.ID, "amount": d.Amount, "currency": d.Currency, "display": money(d.Amount, d.Currency), "status": d.Status, "reason": d.Reason, "charge": string(d.Charge), "created": ts(d.Created), "hasEvidence": d.EvidenceDetails.HasEvidence}
			if d.PaymentIntent != "" {
				o["payment"] = string(d.PaymentIntent)
			}
			if d.EvidenceDetails.DueBy > 0 {
				o["evidenceDue"] = ts(d.EvidenceDetails.DueBy)
			}
			if d.EvidenceDetails.PastDue {
				o["pastDue"] = true
			}
			out = append(out, o)
		}
		return page(out, l.HasMore)

	case "invoices":
		q, err := listQuery(p, "draft", "open", "paid", "uncollectible", "void")
		if err != nil {
			return sdk.Result{}, err
		}
		var l list[struct {
			ID              string `json:"id"`
			Number          string `json:"number"`
			Status          string `json:"status"`
			AmountDue       int64  `json:"amount_due"`
			AmountPaid      int64  `json:"amount_paid"`
			AmountRemaining int64  `json:"amount_remaining"`
			Currency        string `json:"currency"`
			Customer        ref    `json:"customer"`
			Subscription    ref    `json:"subscription"`
			DueDate         int64  `json:"due_date"`
			Created         int64  `json:"created"`
			Attempted       bool   `json:"attempted"`
		}]
		if err := c.do(ctx, http.MethodGet, "/v1/invoices", q, "", &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, in := range l.Data {
			o := map[string]any{"id": in.ID, "number": in.Number, "status": in.Status, "currency": in.Currency, "due": money(in.AmountDue, in.Currency), "paid": money(in.AmountPaid, in.Currency), "remaining": money(in.AmountRemaining, in.Currency), "customer": string(in.Customer), "created": ts(in.Created)}
			if in.Subscription != "" {
				o["subscription"] = string(in.Subscription)
			}
			if in.DueDate > 0 {
				o["dueDate"] = ts(in.DueDate)
			}
			if in.Attempted && in.Status == "open" {
				o["paymentAttempted"] = true
			}
			out = append(out, o)
		}
		return page(out, l.HasMore)

	case "refund":
		return c.refund(ctx, call, p)
	case "cancel_subscription", "keep_subscription":
		return c.cancel(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) customers(ctx context.Context, p input) (sdk.Result, error) {
	limit := p.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	path := "/v1/customers"
	query := strings.TrimSpace(p.Query)
	if len(query) > 500 {
		return sdk.Result{}, errors.New("the query is too long")
	}
	if query != "" {
		path = "/v1/customers/search"
		if !strings.ContainsAny(query, ":~") {
			// A plain word: match it in the email or the name.
			esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(query)
			if strings.Contains(query, "@") {
				query = `email:"` + esc + `"`
			} else {
				query = `email~"` + esc + `" OR name~"` + esc + `"`
			}
		}
		q.Set("query", query)
	}
	var l list[customer]
	if err := c.do(ctx, http.MethodGet, path, q, "", &l); err != nil {
		if rest.IsStatus(err, http.StatusBadRequest) && path == "/v1/customers/search" {
			return sdk.Result{}, fmt.Errorf("%w (see Stripe's search query language)", err)
		}
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, cu := range l.Data {
		o := map[string]any{"id": cu.ID, "name": cu.Name, "email": cu.Email, "created": ts(cu.Created)}
		if cu.Phone != "" {
			o["phone"] = cu.Phone
		}
		if cu.Description != "" {
			o["description"] = cu.Description
		}
		if cu.Delinquent {
			o["delinquent"] = true
		}
		if cu.Balance != 0 {
			o["balance"] = money(cu.Balance, cu.Currency)
		}
		if p.IncludeAddress {
			if a := cu.Address.String(); a != "" {
				o["address"] = a
			}
			if cu.Shipping != nil {
				if a := cu.Shipping.Address.String(); a != "" {
					o["shipping"] = strings.TrimPrefix(cu.Shipping.Name+", "+a, ", ")
				}
			}
		}
		out = append(out, o)
	}
	return sdk.JSON(map[string]any{"items": out, "hasMore": l.HasMore})
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// payment finds the charge behind a payment intent or charge id.
func (c *conn) payment(ctx context.Context, id string) (charge, string, error) {
	var ch charge
	if !paymentRe.MatchString(id) || strings.HasPrefix(id, "py_") {
		return ch, "", errors.New("the payment is a payment intent (pi_…) or a charge (ch_…)")
	}
	if strings.HasPrefix(id, "ch_") {
		if err := c.do(ctx, http.MethodGet, "/v1/charges/"+id, nil, "", &ch); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return ch, "", fmt.Errorf("there's no charge %s", id)
			}
			return ch, "", err
		}
		return ch, string(ch.PaymentIntent), nil
	}
	var pi paymentIntent
	if err := c.do(ctx, http.MethodGet, "/v1/payment_intents/"+id, url.Values{"expand[]": {"latest_charge"}}, "", &pi); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return ch, "", fmt.Errorf("there's no payment %s", id)
		}
		return ch, "", err
	}
	if len(pi.LatestCharge) == 0 || string(pi.LatestCharge) == "null" {
		return ch, pi.ID, fmt.Errorf("payment %s is %s and has no charge to refund", pi.ID, pi.Status)
	}
	if err := json.Unmarshal(pi.LatestCharge, &ch); err != nil || ch.ID == "" {
		return ch, pi.ID, errors.New("unexpected answer from Stripe")
	}
	return ch, pi.ID, nil
}

func (c *conn) refund(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	switch p.Reason {
	case "", "duplicate", "fraudulent", "requested_by_customer":
	default:
		return sdk.Result{}, errors.New("reason is duplicate, fraudulent or requested_by_customer")
	}
	if p.Amount < 0 {
		return sdk.Result{}, errors.New("the amount is a positive number of the currency's smallest unit (cents)")
	}
	if p.IdempotencyKey != "" && !idemRe.MatchString(p.IdempotencyKey) {
		return sdk.Result{}, errors.New("the idempotency key is 8 to 255 letters, digits, dashes or underscores")
	}
	ch, pi, err := c.payment(ctx, strings.TrimSpace(p.Payment))
	if err != nil {
		return sdk.Result{}, err
	}
	if ch.Status != "succeeded" || !ch.Paid {
		return sdk.Result{}, fmt.Errorf("charge %s is %s, so there's nothing to refund", ch.ID, ch.Status)
	}
	if !ch.Captured {
		return sdk.Result{}, fmt.Errorf("charge %s was never captured; cancel the payment instead of refunding it", ch.ID)
	}
	if ch.Disputed {
		return sdk.Result{}, fmt.Errorf("charge %s is disputed; respond to the dispute instead (a refund can't reverse a chargeback)", ch.ID)
	}
	captured := ch.AmountCaptured
	if captured == 0 {
		captured = ch.Amount
	}
	left := captured - ch.AmountRefunded
	if left <= 0 {
		return sdk.Result{}, fmt.Errorf("charge %s is already fully refunded", ch.ID)
	}
	amount := p.Amount
	if amount == 0 {
		amount = left
	}
	if amount > left {
		return sdk.Result{}, fmt.Errorf("only %s of %s is left to refund", money(left, ch.Currency), money(captured, ch.Currency))
	}
	kind := "Full refund"
	if amount < left || ch.AmountRefunded > 0 {
		kind = "Partial refund"
	}
	who := "no customer"
	if ch.Customer != "" {
		who = "customer " + string(ch.Customer)
	}
	target := "charge " + ch.ID
	if pi != "" {
		target = "payment " + pi
	}
	if call.DryRun {
		mode := "test mode"
		if ch.Livemode {
			mode = "LIVE"
		}
		sum := fmt.Sprintf("%s of %s to %s (%s, %s)", kind, money(amount, ch.Currency), who, target, mode)
		before := map[string]any{"charged": money(captured, ch.Currency), "refunded": money(ch.AmountRefunded, ch.Currency), "customer": string(ch.Customer)}
		if ch.Description != "" {
			before["description"] = ch.Description
		}
		after := map[string]any{"refund": money(amount, ch.Currency), "amount": amount, "currency": ch.Currency, "refundedAfter": money(ch.AmountRefunded+amount, ch.Currency)}
		if p.Reason != "" {
			after["reason"] = p.Reason
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: "refund", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	form := url.Values{"charge": {ch.ID}, "amount": {strconv.FormatInt(amount, 10)}}
	if p.Reason != "" {
		form.Set("reason", p.Reason)
	}
	form.Set("metadata[conduit]", "refund")
	var r struct {
		ID       string `json:"id"`
		Amount   int64  `json:"amount"`
		Currency string `json:"currency"`
		Status   string `json:"status"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/refunds", form, p.IdempotencyKey, &r); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"refund": r.ID, "status": r.Status, "amount": r.Amount, "currency": r.Currency, "display": money(r.Amount, r.Currency), "charge": ch.ID, "customer": string(ch.Customer)})
}

func (c *conn) cancel(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	id := strings.TrimSpace(p.Subscription)
	if !subRe.MatchString(id) {
		return sdk.Result{}, errors.New("the subscription is its id, sub_…")
	}
	keep := call.Action == "keep_subscription"
	if !p.Immediately && (p.Prorate || p.InvoiceNow) {
		return sdk.Result{}, errors.New("prorate and invoiceNow only apply when cancelling immediately")
	}
	var s subscription
	if err := c.do(ctx, http.MethodGet, "/v1/subscriptions/"+id, nil, "", &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no subscription %s", id)
		}
		return sdk.Result{}, err
	}
	if s.Status == "canceled" || s.Status == "incomplete_expired" {
		return sdk.JSON(map[string]any{"subscription": s.ID, "note": "it is already " + s.Status})
	}
	summary := subOut(s)
	before := map[string]any{"status": s.Status, "customer": string(s.Customer), "items": summary["items"], "periodEnd": summary["periodEnd"], "cancelsAtPeriodEnd": s.CancelAtPeriodEnd}
	label := "subscription " + s.ID
	if keep {
		if !s.CancelAtPeriodEnd {
			return sdk.JSON(map[string]any{"subscription": s.ID, "note": "it isn't set to cancel"})
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Keep %s of customer %s: it renews on %s instead of ending", s.ID, s.Customer, ts(s.CurrentPeriodEnd)), Changes: []sdk.Change{{Target: label, Op: "update", Before: mustJSON(before), After: mustJSON(map[string]any{"cancelsAtPeriodEnd": false})}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/v1/subscriptions/"+s.ID, url.Values{"cancel_at_period_end": {"false"}}, "", &s); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(subOut(s))
		res.Undo = sdk.UndoWith("cancel_subscription", map[string]any{"subscription": s.ID}, "Cancel "+s.ID+" at the period end again")
		return res, err
	}
	if !p.Immediately && s.CancelAtPeriodEnd {
		return sdk.JSON(map[string]any{"subscription": s.ID, "note": "it already cancels at the period end, " + ts(s.CurrentPeriodEnd)})
	}
	if call.DryRun {
		var sum string
		after := map[string]any{}
		if p.Immediately {
			sum = fmt.Sprintf("End %s of customer %s now; it can't be restarted", s.ID, s.Customer)
			after["status"] = "canceled"
			after["prorate"], after["invoiceNow"] = p.Prorate, p.InvoiceNow
		} else {
			sum = fmt.Sprintf("Cancel %s of customer %s at the period end, %s; it runs until then and undo keeps it", s.ID, s.Customer, ts(s.CurrentPeriodEnd))
			after["cancelsAtPeriodEnd"] = true
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: label, Op: "cancel", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	if p.Immediately {
		q := url.Values{}
		if p.Prorate {
			q.Set("prorate", "true")
		}
		if p.InvoiceNow {
			q.Set("invoice_now", "true")
		}
		if err := c.do(ctx, http.MethodDelete, "/v1/subscriptions/"+s.ID, q, "", &s); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(subOut(s))
	}
	if err := c.do(ctx, http.MethodPost, "/v1/subscriptions/"+s.ID, url.Values{"cancel_at_period_end": {"true"}}, "", &s); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(subOut(s))
	res.Undo = sdk.UndoWith("keep_subscription", map[string]any{"subscription": s.ID}, "Keep "+s.ID+" (take back the cancellation)")
	return res, err
}
