// Package paddle works with a Paddle Billing account through an API key:
// customers, subscriptions and transactions, and pausing, resuming and
// cancelling subscriptions.
//
// Every subscription change is destructive and has a preview: pausing and
// cancelling stop billing and the customer's access, and resuming bills the
// customer again. A change scheduled for the end of the billing period can
// be taken back (resume_subscription removes it); an immediate cancellation
// can't. Customer names and emails appear only in customers, which is
// sensitive; payment method details, addresses and the signed customer
// portal links are never returned.
package paddle

import (
	"bytes"
	"context"
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
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Paddle account.
type Config struct {
	Key         string `json:"key"`         // secret:// API key
	Environment string `json:"environment"` // live (default) or sandbox
}

var bases = map[string]string{"live": "https://api.paddle.com", "sandbox": "https://sandbox-api.paddle.com"}

type conn struct {
	api *rest.Client
	env string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.paddle.com or the sandbox (tests).
	Base string
}

// New returns the Paddle module.
func New() *Module { return &Module{} }

var (
	keyRe      = regexp.MustCompile(`^(pdl_(live|sdbx)_apikey_[A-Za-z0-9_]{20,200}|[A-Za-z0-9]{40,80})$`)
	subRe      = regexp.MustCompile(`^sub_[a-z0-9]{20,40}$`)
	customerRe = regexp.MustCompile(`^ctm_[a-z0-9]{20,40}$`)
	cursorRe   = regexp.MustCompile(`^[a-z]{3}_[a-z0-9]{20,40}$`)
	emailRe    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
)

var (
	subStatuses = map[string]bool{"active": true, "canceled": true, "past_due": true, "paused": true, "trialing": true}
	txnStatuses = map[string]bool{"draft": true, "ready": true, "billed": true, "paid": true, "completed": true, "canceled": true, "past_due": true}
	zeroDecimal = map[string]bool{"JPY": true, "KRW": true, "VND": true, "CLP": true, "ISK": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	page := `"limit":{"type":"integer","default":20,"minimum":1,"maximum":200},"after":{"type":"string","description":"after of the previous page"}`
	sub := `"subscription":{"type":"string","description":"Subscription id (sub_…, see subscriptions)"}`
	expect := `"expectedStatus":{"type":"string","description":"The subscription's status as the preview shows it, like active; needed to run"},"expectedScheduledChange":{"type":"string","enum":["none","pause","cancel"],"description":"The change scheduled for the period end as the preview shows it (none when nothing is); needed to run, refused if the subscription changed since"}`
	return sdk.Manifest{
		ID: "paddle", Name: "Paddle", Version: "0.1.0", Category: "Productivity", Icon: "credit-card",
		Description: "Paddle Billing: customers, subscriptions and transactions; pause, resume and cancel subscriptions with a preview.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"key":{"type":"string","x-secret":true,"description":"An API key (Developer tools, Authentication) with only the permissions you need"},
			"environment":{"type":"string","enum":["live","sandbox"],"default":"live","description":"Sandbox for a sandbox account's key"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "customers", Title: "Customers", Description: "Finds customers by name or email, or lists the latest: name, email, status, locale.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Name, email or id to look for"},"status":{"type":"string","enum":["","active","archived"]},` + page + `}}`)},
			{Name: "subscriptions", Title: "Subscriptions", Description: "Subscriptions: status, customer id, items and prices, billing cycle, next billing date and any scheduled pause or cancellation.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["","active","canceled","past_due","paused","trialing"]},"customer":{"type":"string","description":"Only this customer (ctm_…)"},` + page + `}}`)},
			{Name: "transactions", Title: "Transactions", Description: "Transactions: status, origin, totals, invoice number, customer and subscription ids, billing date. No payment details.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["","draft","ready","billed","paid","completed","canceled","past_due"]},"customer":{"type":"string"},` + sub + `,` + page + `}}`)},
			{Name: "pause_subscription", Title: "Pause a subscription", Description: "Pauses a subscription at the end of its billing period, or immediately. Billing stops while it's paused. The run must give the status and scheduled change the preview showed. Undo resumes it.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["subscription"],"properties":{` + sub + `,"immediately":{"type":"boolean","default":false},` + expect + `}}`)},
			{Name: "resume_subscription", Title: "Resume a subscription", Description: "Resumes a paused subscription now (it bills the customer and starts a new period), or takes back a pause or cancellation scheduled for the period end. The run must give the status and scheduled change the preview showed. Undo pauses or cancels it again.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["subscription"],"properties":{` + sub + `,` + expect + `}}`)},
			{Name: "cancel_subscription", Title: "Cancel a subscription", Description: "Cancels at the end of the billing period (undo takes it back until then), or immediately (can't be undone). The run must give the status and scheduled change the preview showed.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["subscription"],"properties":{` + sub + `,"immediately":{"type":"boolean","default":false},` + expect + `}}`)},
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
	env := strings.TrimSpace(c.Environment)
	if env == "" {
		env = "live"
	}
	base, ok := bases[env]
	if !ok {
		return errors.New("the environment is live or sandbox")
	}
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 30*time.Second)
	}
	ref := c.Key
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		k = strings.TrimSpace(k)
		if !keyRe.MatchString(k) {
			return errors.New("the stored key doesn't look like a Paddle API key")
		}
		if (env == "live" && strings.HasPrefix(k, "pdl_sdbx_")) || (env == "sandbox" && strings.HasPrefix(k, "pdl_live_")) {
			return fmt.Errorf("the stored key isn't for the %s environment", env)
		}
		r.Header.Set("Authorization", "Bearer "+k)
		return nil
	})
	api.HTTP = rest.SameHostOnly(hc)
	api.Header.Set("Paddle-Version", "1")
	m.set.Put(id, &conn{api: api, env: env})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func scrub(s string) string {
	s = emailRe.ReplaceAllString(rest.Redact(s), "[email]")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

// do sends one request and decodes the answer into out. It reads Paddle's
// own error shape ({"error":{"detail":…}}), which the shared client doesn't.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	u := c.api.Base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	for k, v := range c.api.Header {
		req.Header[k] = v
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := c.api.Auth(ctx, req); err != nil {
		return err
	}
	res, err := c.api.HTTP.Do(req)
	if err != nil {
		return rest.TransportError(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code   string `json:"code"`
				Detail string `json:"detail"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return &rest.Error{Status: res.StatusCode, Message: "Paddle refused the API key"}
		case http.StatusForbidden:
			return &rest.Error{Status: res.StatusCode, Message: "the API key lacks the permission for this in Paddle"}
		case http.StatusTooManyRequests:
			return &rest.Error{Status: res.StatusCode, Message: "Paddle is limiting requests; try again in a moment"}
		}
		msg := res.Status
		if e.Error.Detail != "" {
			msg = "Paddle: " + scrub(e.Error.Detail)
		}
		return &rest.Error{Status: res.StatusCode, Message: msg}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return errors.New("unexpected answer from Paddle")
		}
	}
	return nil
}

type page struct {
	Meta struct {
		Pagination struct {
			HasMore        bool `json:"has_more"`
			EstimatedTotal int  `json:"estimated_total"`
		} `json:"pagination"`
	} `json:"meta"`
}

type money struct {
	Amount       string `json:"amount"`
	CurrencyCode string `json:"currency_code"`
}

// format renders an amount in the currency's smallest unit, like "12.34 EUR".
func format(amount, currency string) string {
	n, err := strconv.ParseInt(amount, 10, 64)
	if err != nil {
		return amount + " " + currency
	}
	d := 2
	if zeroDecimal[strings.ToUpper(currency)] {
		d = 0
	}
	return strconv.FormatFloat(float64(n)/math.Pow10(d), 'f', d, 64) + " " + strings.ToUpper(currency)
}

type subscription struct {
	ID                   string  `json:"id"`
	Status               string  `json:"status"`
	CustomerID           string  `json:"customer_id"`
	CurrencyCode         string  `json:"currency_code"`
	CollectionMode       string  `json:"collection_mode"`
	CreatedAt            string  `json:"created_at"`
	StartedAt            *string `json:"started_at"`
	NextBilledAt         *string `json:"next_billed_at"`
	PausedAt             *string `json:"paused_at"`
	CanceledAt           *string `json:"canceled_at"`
	CurrentBillingPeriod *struct {
		StartsAt string `json:"starts_at"`
		EndsAt   string `json:"ends_at"`
	} `json:"current_billing_period"`
	BillingCycle struct {
		Interval  string `json:"interval"`
		Frequency int    `json:"frequency"`
	} `json:"billing_cycle"`
	ScheduledChange *struct {
		Action      string  `json:"action"`
		EffectiveAt string  `json:"effective_at"`
		ResumeAt    *string `json:"resume_at"`
	} `json:"scheduled_change"`
	Items []struct {
		Status    string `json:"status"`
		Quantity  int    `json:"quantity"`
		Recurring bool   `json:"recurring"`
		Price     struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			ProductID   string `json:"product_id"`
			UnitPrice   money  `json:"unit_price"`
		} `json:"price"`
		Product *struct {
			Name string `json:"name"`
		} `json:"product"`
	} `json:"items"`
	// Management URLs (signed links to the customer portal) aren't decoded.
}

func (s subscription) scheduled() string {
	if s.ScheduledChange == nil {
		return ""
	}
	return s.ScheduledChange.Action
}

func (s subscription) product() string {
	var names []string
	for _, it := range s.Items {
		n := it.Price.Description
		if it.Product != nil && it.Product.Name != "" {
			n = it.Product.Name
		}
		if n == "" {
			n = it.Price.Name
		}
		names = append(names, n)
	}
	return strings.Join(names, ", ")
}

func subOut(s subscription) map[string]any {
	items := []map[string]any{}
	for _, it := range s.Items {
		row := map[string]any{"price": it.Price.ID, "description": it.Price.Description, "product": it.Price.ProductID, "quantity": it.Quantity, "status": it.Status,
			"unitPrice": format(it.Price.UnitPrice.Amount, it.Price.UnitPrice.CurrencyCode)}
		if it.Product != nil && it.Product.Name != "" {
			row["productName"] = it.Product.Name
		}
		items = append(items, row)
	}
	out := map[string]any{"id": s.ID, "status": s.Status, "customer": s.CustomerID, "currency": s.CurrencyCode, "created": s.CreatedAt, "items": items,
		"billingCycle": fmt.Sprintf("every %d %s", s.BillingCycle.Frequency, s.BillingCycle.Interval), "collectionMode": s.CollectionMode}
	if s.NextBilledAt != nil && *s.NextBilledAt != "" {
		out["nextBilledAt"] = *s.NextBilledAt
	}
	if s.CurrentBillingPeriod != nil {
		out["periodEndsAt"] = s.CurrentBillingPeriod.EndsAt
	}
	if s.PausedAt != nil && *s.PausedAt != "" {
		out["pausedAt"] = *s.PausedAt
	}
	if s.CanceledAt != nil && *s.CanceledAt != "" {
		out["canceledAt"] = *s.CanceledAt
	}
	if sc := s.ScheduledChange; sc != nil {
		c := map[string]any{"action": sc.Action, "effectiveAt": sc.EffectiveAt}
		if sc.ResumeAt != nil {
			c["resumeAt"] = *sc.ResumeAt
		}
		out["scheduledChange"] = c
	}
	return out
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var l struct {
		page
		Data []subscription `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/subscriptions", url.Values{"per_page": {"1"}, "status": {"active"}}, nil, &l); err != nil {
		if rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "degraded", Message: "connected (" + c.env + "), but the key can't read subscriptions"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("connected (%s): %d active subscriptions", c.env, l.Meta.Pagination.EstimatedTotal)}
}

type input struct {
	Search       string `json:"search"`
	Status       string `json:"status"`
	Customer     string `json:"customer"`
	Subscription string `json:"subscription"`
	Limit        int    `json:"limit"`
	After        string `json:"after"`
	Immediately  bool   `json:"immediately"`
	// What the preview showed, checked again when the change runs.
	ExpectedStatus          string `json:"expectedStatus"`
	ExpectedScheduledChange string `json:"expectedScheduledChange"`
}

// errNotPreviewed starts the error of a change run without the values its
// preview showed.
const errNotPreviewed = "give the values the preview showed"

// pending is the change scheduled for the period end as previews name it.
func (s subscription) pending() string {
	if a := s.scheduled(); a != "" {
		return a
	}
	return "none"
}

// expect checks the status and scheduled change the preview showed
// against the subscription now: a payment failing, a renewal or a change
// made in Paddle in between means it isn't the subscription approved.
func expect(p input, s subscription) []error {
	var errs []error
	switch g := strings.ToLower(strings.TrimSpace(p.ExpectedStatus)); {
	case g == "":
		errs = append(errs, fmt.Errorf("%s: expectedStatus %q", errNotPreviewed, s.Status))
	case g != s.Status:
		errs = append(errs, fmt.Errorf("the subscription changed since the preview: its status is %s now, not %s; preview it again", s.Status, clip(g, 40)))
	}
	switch g := strings.ToLower(strings.TrimSpace(p.ExpectedScheduledChange)); {
	case g == "":
		errs = append(errs, fmt.Errorf("%s: expectedScheduledChange %q", errNotPreviewed, s.pending()))
	case g != s.pending():
		errs = append(errs, fmt.Errorf("the subscription changed since the preview: its scheduled change is %s now, not %s; preview it again", s.pending(), clip(g, 40)))
	}
	return errs
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// runNote is added to a preview whose run would be refused as it stands.
func runNote(errs []error) string {
	var missing []string
	for _, err := range errs {
		m, ok := strings.CutPrefix(err.Error(), errNotPreviewed+": ")
		if !ok {
			return " Running this call will be refused: " + err.Error() + "."
		}
		missing = append(missing, m)
	}
	if len(missing) == 0 {
		return ""
	}
	return " To run it, give " + strings.Join(missing, " and ") + " (the subscription as previewed); it's refused if the subscription changed."
}

func pageQuery(p input) (url.Values, error) {
	n := p.Limit
	if n <= 0 || n > 200 {
		n = 20
	}
	q := url.Values{"per_page": {strconv.Itoa(n)}}
	if a := strings.TrimSpace(p.After); a != "" {
		if !cursorRe.MatchString(a) {
			return nil, errors.New("after is the value from the previous page")
		}
		q.Set("after", a)
	}
	return q, nil
}

func pageOut(items []map[string]any, last string, pg page) map[string]any {
	out := map[string]any{"items": items, "hasMore": pg.Meta.Pagination.HasMore}
	if pg.Meta.Pagination.HasMore && last != "" {
		out["after"] = last
	}
	if pg.Meta.Pagination.EstimatedTotal > 0 {
		out["estimatedTotal"] = pg.Meta.Pagination.EstimatedTotal
	}
	return out
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
	case "customers":
		return c.customers(ctx, p)
	case "subscriptions":
		return c.subscriptions(ctx, p)
	case "transactions":
		return c.transactions(ctx, p)
	case "pause_subscription", "resume_subscription", "cancel_subscription":
		id := strings.TrimSpace(p.Subscription)
		if !subRe.MatchString(id) {
			return sdk.Result{}, errors.New("the subscription is its id (sub_…, see subscriptions)")
		}
		return c.change(ctx, call, id, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) customers(ctx context.Context, p input) (sdk.Result, error) {
	q, err := pageQuery(p)
	if err != nil {
		return sdk.Result{}, err
	}
	if s := strings.TrimSpace(p.Search); s != "" {
		if utf8.RuneCountInString(s) > 100 || strings.ContainsAny(s, "\x00\r\n") {
			return sdk.Result{}, errors.New("search is a name, email or id, at most 100 characters")
		}
		q.Set("search", s)
	}
	switch p.Status {
	case "":
	case "active", "archived":
		q.Set("status", p.Status)
	default:
		return sdk.Result{}, fmt.Errorf("status %q isn't active or archived", p.Status)
	}
	var l struct {
		page
		Data []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Email     string `json:"email"`
			Status    string `json:"status"`
			Locale    string `json:"locale"`
			CreatedAt string `json:"created_at"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/customers", q, nil, &l); err != nil {
		return sdk.Result{}, err
	}
	out, last := []map[string]any{}, ""
	for _, x := range l.Data {
		out = append(out, map[string]any{"id": x.ID, "name": x.Name, "email": x.Email, "status": x.Status, "locale": x.Locale, "created": x.CreatedAt})
		last = x.ID
	}
	return sdk.JSON(pageOut(out, last, l.page))
}

func (c *conn) subscriptions(ctx context.Context, p input) (sdk.Result, error) {
	q, err := pageQuery(p)
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Status != "" {
		if !subStatuses[p.Status] {
			return sdk.Result{}, fmt.Errorf("status %q isn't a subscription status", p.Status)
		}
		q.Set("status", p.Status)
	}
	if cu := strings.TrimSpace(p.Customer); cu != "" {
		if !customerRe.MatchString(cu) {
			return sdk.Result{}, errors.New("the customer is its id (ctm_…)")
		}
		q.Set("customer_id", cu)
	}
	var l struct {
		page
		Data []subscription `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/subscriptions", q, nil, &l); err != nil {
		return sdk.Result{}, err
	}
	out, last := []map[string]any{}, ""
	for _, s := range l.Data {
		out = append(out, subOut(s))
		last = s.ID
	}
	return sdk.JSON(pageOut(out, last, l.page))
}

func (c *conn) transactions(ctx context.Context, p input) (sdk.Result, error) {
	q, err := pageQuery(p)
	if err != nil {
		return sdk.Result{}, err
	}
	q.Set("order_by", "created_at[DESC]")
	if p.Status != "" {
		if !txnStatuses[p.Status] {
			return sdk.Result{}, fmt.Errorf("status %q isn't a transaction status", p.Status)
		}
		q.Set("status", p.Status)
	}
	if cu := strings.TrimSpace(p.Customer); cu != "" {
		if !customerRe.MatchString(cu) {
			return sdk.Result{}, errors.New("the customer is its id (ctm_…)")
		}
		q.Set("customer_id", cu)
	}
	if s := strings.TrimSpace(p.Subscription); s != "" {
		if !subRe.MatchString(s) {
			return sdk.Result{}, errors.New("the subscription is its id (sub_…)")
		}
		q.Set("subscription_id", s)
	}
	var l struct {
		page
		Data []struct {
			ID             string  `json:"id"`
			Status         string  `json:"status"`
			CustomerID     *string `json:"customer_id"`
			SubscriptionID *string `json:"subscription_id"`
			InvoiceNumber  *string `json:"invoice_number"`
			Origin         string  `json:"origin"`
			CurrencyCode   string  `json:"currency_code"`
			CollectionMode string  `json:"collection_mode"`
			CreatedAt      string  `json:"created_at"`
			BilledAt       *string `json:"billed_at"`
			Details        struct {
				Totals struct {
					Subtotal   string `json:"subtotal"`
					Tax        string `json:"tax"`
					GrandTotal string `json:"grand_total"`
					Fee        string `json:"fee"`
					Earnings   string `json:"earnings"`
				} `json:"totals"`
			} `json:"details"`
			// Payments (card details), addresses and checkout links aren't decoded.
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/transactions", q, nil, &l); err != nil {
		return sdk.Result{}, err
	}
	out, last := []map[string]any{}, ""
	for _, t := range l.Data {
		tot := t.Details.Totals
		row := map[string]any{"id": t.ID, "status": t.Status, "origin": t.Origin, "currency": t.CurrencyCode, "created": t.CreatedAt,
			"total": format(tot.GrandTotal, t.CurrencyCode), "tax": format(tot.Tax, t.CurrencyCode), "totalAmount": tot.GrandTotal}
		if tot.Earnings != "" {
			row["earnings"] = format(tot.Earnings, t.CurrencyCode)
		}
		for k, v := range map[string]*string{"customer": t.CustomerID, "subscription": t.SubscriptionID, "invoiceNumber": t.InvoiceNumber, "billedAt": t.BilledAt} {
			if v != nil && *v != "" {
				row[k] = *v
			}
		}
		out = append(out, row)
		last = t.ID
	}
	return sdk.JSON(pageOut(out, last, l.page))
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (c *conn) change(ctx context.Context, call sdk.Call, id string, p input) (sdk.Result, error) {
	now := p.Immediately
	var one struct {
		Data subscription `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/subscriptions/"+url.PathEscape(id), nil, nil, &one); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no subscription %s", id)
		}
		return sdk.Result{}, err
	}
	s := one.Data
	if s.ID == "" {
		return sdk.Result{}, fmt.Errorf("there's no subscription %s", id)
	}
	if s.Status == "canceled" {
		if call.Action == "cancel_subscription" {
			return sdk.JSON(map[string]any{"subscription": id, "status": s.Status, "note": "nothing to change: it's canceled already"})
		}
		return sdk.Result{}, fmt.Errorf("subscription %s is canceled; a canceled subscription can't be paused or resumed", id)
	}
	periodEnd := ""
	if s.CurrentBillingPeriod != nil {
		periodEnd = s.CurrentBillingPeriod.EndsAt
	}
	before := map[string]any{"status": s.Status, "customer": s.CustomerID, "product": s.product(), "scheduledChange": s.scheduled()}
	if s.NextBilledAt != nil {
		before["nextBilledAt"] = *s.NextBilledAt
	}
	label := "subscription " + id
	nothing := func(why string) (sdk.Result, error) {
		return sdk.JSON(map[string]any{"subscription": id, "status": s.Status, "scheduledChange": s.scheduled(), "note": "nothing to change: " + why})
	}
	type step struct {
		method, path string
		body         any
		summary, op  string
		after        map[string]any
		undo         string
		undoInput    map[string]any
		undoText     string
	}
	var st step
	when, eff := "at the end of the billing period ("+periodEnd+")", "next_billing_period"
	if now {
		when, eff = "immediately", "immediately"
	}
	switch call.Action {
	case "pause_subscription":
		switch {
		case s.Status == "paused":
			return nothing("it's paused already")
		case s.scheduled() == "pause" && !now:
			return nothing("a pause is scheduled already for " + s.ScheduledChange.EffectiveAt)
		case s.scheduled() == "cancel":
			return sdk.Result{}, fmt.Errorf("subscription %s is set to cancel on %s; take that back with resume_subscription first", id, s.ScheduledChange.EffectiveAt)
		}
		st = step{http.MethodPost, "/subscriptions/" + url.PathEscape(id) + "/pause", map[string]any{"effective_from": eff},
			fmt.Sprintf("Pause subscription %s (%s) of customer %s %s: billing and access stop until it's resumed", id, s.product(), s.CustomerID, when), "pause",
			map[string]any{"pause": eff}, "resume_subscription", map[string]any{"subscription": id}, "Resume subscription " + id}
	case "cancel_subscription":
		switch {
		case s.scheduled() == "cancel" && !now:
			return nothing("it's set to cancel already on " + s.ScheduledChange.EffectiveAt)
		case s.Status == "paused" && !now:
			// A paused subscription has no billing period to run out:
			// Paddle cancels it only immediately, which can't be undone.
			return sdk.Result{}, fmt.Errorf("subscription %s is paused; Paddle cancels a paused subscription only immediately (set immediately, which can't be undone)", id)
		}
		st = step{http.MethodPost, "/subscriptions/" + url.PathEscape(id) + "/cancel", map[string]any{"effective_from": eff},
			fmt.Sprintf("Cancel subscription %s (%s) of customer %s %s", id, s.product(), s.CustomerID, when), "cancel",
			map[string]any{"cancel": eff}, "", nil, ""}
		if now {
			st.summary += "; this can't be undone"
		} else {
			st.summary += "; undo takes it back until then"
			st.undo, st.undoInput, st.undoText = "resume_subscription", map[string]any{"subscription": id}, "Take back the cancellation of "+id
		}
	case "resume_subscription":
		switch {
		case s.Status == "paused":
			st = step{http.MethodPost, "/subscriptions/" + url.PathEscape(id) + "/resume", map[string]any{"effective_from": "immediately"},
				fmt.Sprintf("Resume subscription %s (%s) of customer %s now: it starts a new billing period and bills the customer", id, s.product(), s.CustomerID), "resume",
				map[string]any{"status": "active"}, "pause_subscription", map[string]any{"subscription": id, "immediately": true}, "Pause subscription " + id + " again"}
		case s.scheduled() == "pause" || s.scheduled() == "cancel":
			act := s.scheduled()
			st = step{http.MethodPatch, "/subscriptions/" + url.PathEscape(id), map[string]any{"scheduled_change": nil},
				fmt.Sprintf("Take back the %s of subscription %s (%s) scheduled for %s: it keeps billing customer %s", act, id, s.product(), s.ScheduledChange.EffectiveAt, s.CustomerID), "update",
				map[string]any{"scheduledChange": ""}, act + "_subscription", map[string]any{"subscription": id}, strings.ToUpper(act[:1]) + act[1:] + " subscription " + id + " at the period end again"}
		default:
			return nothing("it isn't paused and has no pause or cancellation scheduled")
		}
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	errs := expect(p, s)
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: st.summary + "." + runNote(errs), Changes: []sdk.Change{{Target: label, Op: st.op, Before: mustJSON(before), After: mustJSON(st.after)}}}}, nil
	}
	if len(errs) > 0 {
		return sdk.Result{}, errs[0]
	}
	var r struct {
		Data subscription `json:"data"`
	}
	if err := c.do(ctx, st.method, st.path, nil, st.body, &r); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(subOut(r.Data))
	if st.undo != "" {
		// The undo runs only while the subscription is still as this left it.
		st.undoInput["expectedStatus"], st.undoInput["expectedScheduledChange"] = r.Data.Status, r.Data.pending()
		res.Undo = sdk.UndoWith(st.undo, st.undoInput, st.undoText)
	}
	return res, err
}
