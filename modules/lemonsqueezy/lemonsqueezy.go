// Package lemonsqueezy reads a Lemon Squeezy account through its JSON:API:
// stores with their revenue, orders and subscriptions. It can refund an
// order (fully or partly) and cancel or resume a subscription.
//
// Money never moves without a preview: refunds are destructive and show the
// amount, currency, order number and customer id first. Cancelling is
// destructive too; within the grace period the undo resumes the
// subscription, which bills the customer again and is destructive itself.
// Customer names and emails appear only in orders, which is sensitive;
// signed receipt, invoice and customer portal links are never returned.
package lemonsqueezy

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Lemon Squeezy account.
type Config struct {
	Key   string `json:"key"`   // secret:// API key
	Store string `json:"store"` // default store id for orders and subscriptions
}

const defaultBase = "https://api.lemonsqueezy.com"

const mediaType = "application/vnd.api+json"

type conn struct {
	api   *rest.Client
	store string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.lemonsqueezy.com (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Lemon Squeezy module.
func New() *Module { return &Module{} }

func (m *Module) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

var (
	keyRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$`)
	idRe    = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	emailRe = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+=?^_{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)
)

var subStatuses = map[string]bool{"on_trial": true, "active": true, "paused": true, "past_due": true, "unpaid": true, "cancelled": true, "expired": true}
var orderStatuses = map[string]bool{"pending": true, "failed": true, "paid": true, "refunded": true, "partial_refund": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	store := `"store":{"type":"string","description":"Store id (default: the one in settings, or all stores)"}`
	page := `"limit":{"type":"integer","default":20,"minimum":1,"maximum":100},"page":{"type":"integer","default":1,"minimum":1}`
	return sdk.Manifest{
		ID: "lemonsqueezy", Name: "Lemon Squeezy", Version: "0.1.0", Category: "Productivity", Icon: "credit-card",
		Description: "A Lemon Squeezy account: stores and revenue, orders, subscriptions; refunds and cancellations with a preview.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"key":{"type":"string","x-secret":true,"description":"An API key (Settings, API); a test-mode key only sees test data"},
			"store":{"type":"string","description":"Default store id for orders and subscriptions"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "stores", Title: "Stores", Description: "Stores with their currency, plan and sales totals.", Risk: sdk.RiskRead},
			{Name: "revenue", Title: "Revenue", Description: "Revenue and sales per store: all time and the last 30 days.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + store + `}}`)},
			{Name: "orders", Title: "Orders", Description: "Recent orders: number, status, total, refunded amount, product, and the customer's name and email.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + store + `,"email":{"type":"string","description":"Only this customer's orders"},"status":{"type":"string","enum":["","pending","failed","paid","refunded","partial_refund"]},` + page + `}}`)},
			{Name: "subscriptions", Title: "Subscriptions", Description: "Subscriptions with status, product and variant, customer id, renewal, end and trial dates. No names or emails.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + store + `,"status":{"type":"string","enum":["","on_trial","active","paused","past_due","unpaid","cancelled","expired"]},` + page + `}}`)},
			{Name: "refund_order", Title: "Refund an order", Description: "Refunds an order, fully or partly. Money goes back to the customer and can't be taken back. The preview shows the amount; the run must give what was refunded before, as the preview showed it.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["order"],"properties":{"order":{"type":"string","description":"Order id (see orders)"},"amount":{"type":"integer","minimum":1,"description":"In the currency's smallest unit (cents); the whole remaining amount when empty"},"expectedRefunded":{"type":"string","description":"What was refunded before, as the preview shows it, like 0.00 USD; needed to run, refused if the order changed since (so a retried refund can't go through twice)"}}}`)},
			{Name: "cancel_subscription", Title: "Cancel a subscription", Description: "Cancels a subscription: it runs until the end of the paid period, then expires. The run must give the status the preview showed. Undo resumes it during that time.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["subscription"],"properties":{"subscription":{"type":"string","description":"Subscription id (see subscriptions)"},"expectedStatus":{"type":"string","description":"The subscription's status as the preview shows it, like active; needed to run, refused if the subscription changed since"}}}`)},
			{Name: "resume_subscription", Title: "Resume a subscription", Description: "Takes back a cancellation before the subscription ends. Destructive: the customer is billed again at renewal. The run must give the status the preview showed. Undo cancels it again.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["subscription"],"properties":{"subscription":{"type":"string","description":"Subscription id (see subscriptions)"},"expectedStatus":{"type":"string","description":"The subscription's status as the preview shows it, like active; needed to run, refused if the subscription changed since"}}}`)},
		},
	}
}

// ident is an id given as a string or a number.
type ident string

func (i *ident) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*i = ident(strings.TrimSpace(s))
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return errors.New("an id is a number")
	}
	*i = ident(n.String())
	return nil
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
	store := strings.TrimSpace(c.Store)
	if store != "" && !idRe.MatchString(store) {
		return errors.New("the store is its numeric id (see stores)")
	}
	base := defaultBase
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
			return errors.New("the stored key doesn't look like a Lemon Squeezy API key")
		}
		r.Header.Set("Authorization", "Bearer "+k)
		return nil
	})
	api.HTTP = rest.SameHostOnly(hc)
	m.set.Put(id, &conn{api: api, store: store})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// do sends one JSON:API request and decodes the answer into out.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	var rd io.Reader
	hdr := http.Header{"Accept": {mediaType}}
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
		hdr.Set("Content-Type", mediaType)
	}
	res, err := c.api.Send(ctx, method, path, q, rd, hdr)
	if err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return errors.New("Lemon Squeezy refused the API key")
		}
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return &rest.Error{Status: res.StatusCode, Message: res.Status}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return errors.New("unexpected answer from Lemon Squeezy")
		}
	}
	return nil
}

type resource[T any] struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes T      `json:"attributes"`
}

type one[T any] struct {
	Data resource[T] `json:"data"`
}

type many[T any] struct {
	Data []resource[T] `json:"data"`
	Meta struct {
		Page struct {
			CurrentPage int `json:"currentPage"`
			LastPage    int `json:"lastPage"`
			Total       int `json:"total"`
		} `json:"page"`
	} `json:"meta"`
}

type store struct {
	Name             string `json:"name"`
	Slug             string `json:"slug"`
	Domain           string `json:"domain"`
	URL              string `json:"url"`
	Currency         string `json:"currency"`
	Plan             string `json:"plan"`
	TotalSales       int64  `json:"total_sales"`
	TotalRevenue     int64  `json:"total_revenue"`
	ThirtyDaySales   int64  `json:"thirty_day_sales"`
	ThirtyDayRevenue int64  `json:"thirty_day_revenue"`
	CreatedAt        string `json:"created_at"`
}

type order struct {
	StoreID        int64  `json:"store_id"`
	CustomerID     int64  `json:"customer_id"`
	Identifier     string `json:"identifier"`
	OrderNumber    int64  `json:"order_number"`
	UserName       string `json:"user_name"`
	UserEmail      string `json:"user_email"`
	Currency       string `json:"currency"`
	Subtotal       int64  `json:"subtotal"`
	Tax            int64  `json:"tax"`
	Total          int64  `json:"total"`
	TotalUSD       int64  `json:"total_usd"`
	Status         string `json:"status"`
	Refunded       bool   `json:"refunded"`
	RefundedAt     string `json:"refunded_at"`
	RefundedAmount int64  `json:"refunded_amount"`
	TestMode       bool   `json:"test_mode"`
	CreatedAt      string `json:"created_at"`
	FirstOrderItem *struct {
		ProductName string `json:"product_name"`
		VariantName string `json:"variant_name"`
	} `json:"first_order_item"`
}

type subscription struct {
	StoreID     int64   `json:"store_id"`
	CustomerID  int64   `json:"customer_id"`
	OrderID     int64   `json:"order_id"`
	ProductName string  `json:"product_name"`
	VariantName string  `json:"variant_name"`
	Status      string  `json:"status"`
	Cancelled   bool    `json:"cancelled"`
	Pause       any     `json:"pause"`
	RenewsAt    string  `json:"renews_at"`
	EndsAt      *string `json:"ends_at"`
	TrialEndsAt *string `json:"trial_ends_at"`
	CreatedAt   string  `json:"created_at"`
	TestMode    bool    `json:"test_mode"`
}

var zeroDecimal = map[string]bool{"bif": true, "clp": true, "djf": true, "gnf": true, "jpy": true, "kmf": true, "krw": true, "mga": true, "pyg": true, "rwf": true, "ugx": true, "vnd": true, "vuv": true, "xaf": true, "xof": true, "xpf": true}

// money renders an amount in minor units, like "12.34 USD".
func money(amount int64, currency string) string {
	cur := strings.ToLower(currency)
	digits := 2
	if zeroDecimal[cur] {
		digits = 0
	}
	return strconv.FormatFloat(float64(amount)/math.Pow10(digits), 'f', digits, 64) + " " + strings.ToUpper(cur)
}

func storeOut(id string, s store) map[string]any {
	return map[string]any{"id": id, "name": s.Name, "slug": s.Slug, "domain": s.Domain, "currency": s.Currency, "plan": s.Plan, "totalSales": s.TotalSales, "totalRevenue": money(s.TotalRevenue, s.Currency), "created": s.CreatedAt}
}

func orderOut(id string, o order, personal bool) map[string]any {
	out := map[string]any{"id": id, "number": o.OrderNumber, "store": o.StoreID, "customer": o.CustomerID, "status": o.Status, "currency": o.Currency, "total": o.Total, "display": money(o.Total, o.Currency), "created": o.CreatedAt}
	if o.RefundedAmount > 0 {
		out["refunded"] = money(o.RefundedAmount, o.Currency)
		out["refundedAmount"] = o.RefundedAmount
	}
	if o.RefundedAt != "" {
		out["refundedAt"] = o.RefundedAt
	}
	if o.Tax > 0 {
		out["tax"] = money(o.Tax, o.Currency)
	}
	if o.FirstOrderItem != nil {
		out["product"] = o.FirstOrderItem.ProductName
		if o.FirstOrderItem.VariantName != "" && o.FirstOrderItem.VariantName != "Default" {
			out["variant"] = o.FirstOrderItem.VariantName
		}
	}
	if o.TestMode {
		out["testMode"] = true
	}
	if personal {
		out["name"], out["email"] = o.UserName, o.UserEmail
	}
	return out
}

func subOut(id string, s subscription) map[string]any {
	out := map[string]any{"id": id, "status": s.Status, "store": s.StoreID, "customer": s.CustomerID, "order": s.OrderID, "product": s.ProductName, "variant": s.VariantName, "created": s.CreatedAt}
	if s.RenewsAt != "" && !s.Cancelled {
		out["renewsAt"] = s.RenewsAt
	}
	if s.EndsAt != nil && *s.EndsAt != "" {
		out["endsAt"] = *s.EndsAt
	}
	if s.TrialEndsAt != nil && *s.TrialEndsAt != "" && s.Status == "on_trial" {
		out["trialEndsAt"] = *s.TrialEndsAt
	}
	if s.Cancelled {
		out["cancelled"] = true
	}
	if s.Pause != nil {
		out["paused"] = true
	}
	if s.TestMode {
		out["testMode"] = true
	}
	return out
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var l many[store]
	if err := c.do(ctx, http.MethodGet, "/v1/stores", nil, nil, &l); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if c.store != "" {
		for _, s := range l.Data {
			if s.ID == c.store {
				return sdk.Health{Status: "ok", Message: "connected to store " + s.Attributes.Name}
			}
		}
		return sdk.Health{Status: "degraded", Message: "connected, but the key can't see store " + c.store}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("connected: %d stores", len(l.Data))}
}

type input struct {
	Store        ident  `json:"store"`
	Email        string `json:"email"`
	Status       string `json:"status"`
	Limit        int    `json:"limit"`
	Page         int    `json:"page"`
	Order        ident  `json:"order"`
	Amount       int64  `json:"amount"`
	Subscription ident  `json:"subscription"`
	// What the preview showed, checked again when the change runs.
	ExpectedRefunded string `json:"expectedRefunded"`
	ExpectedStatus   string `json:"expectedStatus"`
}

// errNotPreviewed starts the error of a change run without the values its
// preview showed.
const errNotPreviewed = "give the values the preview showed"

var decimalRe = regexp.MustCompile(`^[0-9]{1,15}(\.[0-9]{1,2})?$`)

// minor reads an amount as previews show it (12.34, or 12.34 USD) in the
// currency's smallest unit.
func minor(s, currency string) (int64, bool) {
	n, c, _ := strings.Cut(strings.TrimSpace(s), " ")
	if c != "" && !strings.EqualFold(strings.TrimSpace(c), currency) {
		return 0, false
	}
	if !decimalRe.MatchString(n) {
		return 0, false
	}
	digits := 2
	if zeroDecimal[strings.ToLower(currency)] {
		digits = 0
	}
	whole, frac, _ := strings.Cut(n, ".")
	frac = strings.TrimRight(frac, "0")
	if len(frac) > digits {
		return 0, false
	}
	frac += strings.Repeat("0", digits-len(frac))
	v, err := strconv.ParseInt(whole+frac, 10, 64)
	return v, err == nil
}

// expectRefunded checks what the preview showed as refunded before against
// the order now. Lemon Squeezy has no idempotency keys: naming it is what
// keeps a refund retried after a lost answer from going through twice.
func expectRefunded(given string, now int64, currency string) error {
	g := strings.TrimSpace(given)
	if g == "" {
		return fmt.Errorf("%s: expectedRefunded %q", errNotPreviewed, money(now, currency))
	}
	v, ok := minor(g, currency)
	if !ok {
		return fmt.Errorf("expectedRefunded is an amount like %q, as the preview showed it", money(now, currency))
	}
	if v != now {
		return fmt.Errorf("the order changed since the preview: expectedRefunded is %s now, not %s; preview it again", money(now, currency), clip(g, 40))
	}
	return nil
}

// expectStatus checks the status the preview showed against the
// subscription now.
func expectStatus(given, now string) error {
	g := strings.ToLower(strings.TrimSpace(given))
	switch {
	case g == "":
		return fmt.Errorf("%s: expectedStatus %q", errNotPreviewed, now)
	case g != now:
		return fmt.Errorf("the subscription changed since the preview: its status is %s now, not %s; preview it again", now, clip(g, 40))
	}
	return nil
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// runNote is added to a preview whose run would be refused as it stands.
func runNote(what string, err error) string {
	if err == nil {
		return ""
	}
	m, ok := strings.CutPrefix(err.Error(), errNotPreviewed+": ")
	if !ok {
		return " Running this call will be refused: " + err.Error() + "."
	}
	return " To run it, give " + m + " (the " + what + " as previewed); it's refused if the " + what + " changed."
}

func (c *conn) storeOf(p input) (string, error) {
	s := string(p.Store)
	if s == "" {
		s = c.store
	}
	if s != "" && !idRe.MatchString(s) {
		return "", errors.New("the store is its numeric id (see stores)")
	}
	return s, nil
}

func pageQuery(p input) url.Values {
	limit := p.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	pg := p.Page
	if pg <= 0 {
		pg = 1
	}
	return url.Values{"page[size]": {strconv.Itoa(limit)}, "page[number]": {strconv.Itoa(pg)}}
}

func pageOut(items []map[string]any, l interface{ meta() (int, int, int) }) map[string]any {
	cur, last, total := l.meta()
	return map[string]any{"items": items, "page": cur, "lastPage": last, "total": total}
}

func (l many[T]) meta() (int, int, int) {
	return l.Meta.Page.CurrentPage, l.Meta.Page.LastPage, l.Meta.Page.Total
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
	case "stores":
		var l many[store]
		if err := c.do(ctx, http.MethodGet, "/v1/stores", nil, nil, &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range l.Data {
			out = append(out, storeOut(s.ID, s.Attributes))
		}
		return sdk.JSON(map[string]any{"items": out})

	case "revenue":
		st, err := c.storeOf(p)
		if err != nil {
			return sdk.Result{}, err
		}
		var stores []resource[store]
		if st != "" {
			var o one[store]
			if err := c.do(ctx, http.MethodGet, "/v1/stores/"+st, nil, nil, &o); err != nil {
				if rest.IsStatus(err, http.StatusNotFound) {
					return sdk.Result{}, fmt.Errorf("there's no store %s", st)
				}
				return sdk.Result{}, err
			}
			stores = append(stores, o.Data)
		} else {
			var l many[store]
			if err := c.do(ctx, http.MethodGet, "/v1/stores", nil, nil, &l); err != nil {
				return sdk.Result{}, err
			}
			stores = l.Data
		}
		out := []map[string]any{}
		for _, s := range stores {
			a := s.Attributes
			out = append(out, map[string]any{"store": s.ID, "name": a.Name, "currency": a.Currency,
				"totalRevenue": money(a.TotalRevenue, a.Currency), "totalRevenueAmount": a.TotalRevenue, "totalSales": a.TotalSales,
				"last30DaysRevenue": money(a.ThirtyDayRevenue, a.Currency), "last30DaysRevenueAmount": a.ThirtyDayRevenue, "last30DaysSales": a.ThirtyDaySales})
		}
		return sdk.JSON(map[string]any{"stores": out, "asOf": m.now().UTC().Format(time.RFC3339)})

	case "orders":
		st, err := c.storeOf(p)
		if err != nil {
			return sdk.Result{}, err
		}
		if p.Status != "" && !orderStatuses[p.Status] {
			return sdk.Result{}, fmt.Errorf("status %q isn't an order status", p.Status)
		}
		q := pageQuery(p)
		if st != "" {
			q.Set("filter[store_id]", st)
		}
		if e := strings.TrimSpace(p.Email); e != "" {
			if len(e) > 254 || !emailRe.MatchString(e) {
				return sdk.Result{}, errors.New("email is one plain email address")
			}
			q.Set("filter[user_email]", e)
		}
		var l many[order]
		if err := c.do(ctx, http.MethodGet, "/v1/orders", q, nil, &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, o := range l.Data {
			// The API has no status filter for orders: narrow the page here.
			if p.Status != "" && o.Attributes.Status != p.Status {
				continue
			}
			out = append(out, orderOut(o.ID, o.Attributes, true))
		}
		return sdk.JSON(pageOut(out, l))

	case "subscriptions":
		st, err := c.storeOf(p)
		if err != nil {
			return sdk.Result{}, err
		}
		q := pageQuery(p)
		if st != "" {
			q.Set("filter[store_id]", st)
		}
		if p.Status != "" {
			if !subStatuses[p.Status] {
				return sdk.Result{}, fmt.Errorf("status %q isn't a subscription status", p.Status)
			}
			q.Set("filter[status]", p.Status)
		}
		var l many[subscription]
		if err := c.do(ctx, http.MethodGet, "/v1/subscriptions", q, nil, &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range l.Data {
			out = append(out, subOut(s.ID, s.Attributes))
		}
		return sdk.JSON(pageOut(out, l))

	case "refund_order":
		return c.refund(ctx, call, p)
	case "cancel_subscription", "resume_subscription":
		return m.cancel(ctx, c, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (c *conn) refund(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	id := string(p.Order)
	if !idRe.MatchString(id) {
		return sdk.Result{}, errors.New("the order is its numeric id (see orders)")
	}
	if p.Amount < 0 {
		return sdk.Result{}, errors.New("the amount is a positive number of the currency's smallest unit (cents)")
	}
	var o one[order]
	if err := c.do(ctx, http.MethodGet, "/v1/orders/"+id, nil, nil, &o); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no order %s", id)
		}
		return sdk.Result{}, err
	}
	a := o.Data.Attributes
	if a.Status != "paid" && a.Status != "partial_refund" {
		return sdk.Result{}, fmt.Errorf("order %s is %s, so there's nothing to refund", id, a.Status)
	}
	left := a.Total - a.RefundedAmount
	if left <= 0 {
		return sdk.Result{}, fmt.Errorf("order %s is already fully refunded", id)
	}
	amount := p.Amount
	if amount == 0 {
		amount = left
	}
	if amount > left {
		return sdk.Result{}, fmt.Errorf("only %s of %s is left to refund", money(left, a.Currency), money(a.Total, a.Currency))
	}
	kind := "Full refund"
	if amount < left || a.RefundedAmount > 0 {
		kind = "Partial refund"
	}
	expect := expectRefunded(p.ExpectedRefunded, a.RefundedAmount, a.Currency)
	if call.DryRun {
		mode := "LIVE"
		if a.TestMode {
			mode = "test mode"
		}
		before := map[string]any{"total": money(a.Total, a.Currency), "refunded": money(a.RefundedAmount, a.Currency), "status": a.Status, "customer": a.CustomerID}
		if a.FirstOrderItem != nil {
			before["product"] = a.FirstOrderItem.ProductName
		}
		after := map[string]any{"refund": money(amount, a.Currency), "amount": amount, "currency": a.Currency, "refundedAfter": money(a.RefundedAmount+amount, a.Currency)}
		return sdk.Result{Plan: &sdk.Plan{
			Summary: fmt.Sprintf("%s of %s to customer %d (order #%d, id %s, %s).%s", kind, money(amount, a.Currency), a.CustomerID, a.OrderNumber, id, mode, runNote("order", expect)),
			Changes: []sdk.Change{{Target: "order " + id, Op: "refund", Before: mustJSON(before), After: mustJSON(after)}},
		}}, nil
	}
	if expect != nil {
		return sdk.Result{}, expect
	}
	body := map[string]any{"data": map[string]any{"type": "orders", "id": id, "attributes": map[string]any{"amount": amount}}}
	var r one[order]
	if err := c.do(ctx, http.MethodPost, "/v1/orders/"+id+"/refund", nil, body, &r); err != nil {
		return sdk.Result{}, err
	}
	ra := r.Data.Attributes
	return sdk.JSON(map[string]any{"order": id, "number": a.OrderNumber, "status": ra.Status, "refund": money(amount, a.Currency), "amount": amount, "currency": a.Currency, "refundedTotal": money(ra.RefundedAmount, a.Currency), "customer": a.CustomerID})
}

func (m *Module) cancel(ctx context.Context, c *conn, call sdk.Call, p input) (sdk.Result, error) {
	id := string(p.Subscription)
	if !idRe.MatchString(id) {
		return sdk.Result{}, errors.New("the subscription is its numeric id (see subscriptions)")
	}
	resume := call.Action == "resume_subscription"
	var s one[subscription]
	if err := c.do(ctx, http.MethodGet, "/v1/subscriptions/"+id, nil, nil, &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no subscription %s", id)
		}
		return sdk.Result{}, err
	}
	a := s.Data.Attributes
	if a.Status == "expired" {
		return sdk.JSON(map[string]any{"subscription": id, "note": "it has expired; it can't be cancelled or resumed"})
	}
	before := map[string]any{"status": a.Status, "customer": a.CustomerID, "product": a.ProductName, "variant": a.VariantName, "renewsAt": a.RenewsAt}
	if a.EndsAt != nil {
		before["endsAt"] = *a.EndsAt
	}
	label := "subscription " + id
	if resume {
		if !a.Cancelled && a.Status != "cancelled" {
			return sdk.JSON(map[string]any{"subscription": id, "note": "it isn't cancelled"})
		}
		// A cancelled subscription can be resumed only until it ends; when
		// that date is missing or unreadable, refuse rather than risk
		// billing a customer whose subscription is over.
		if a.EndsAt == nil || *a.EndsAt == "" {
			return sdk.Result{}, fmt.Errorf("subscription %s has no end date; it can't be resumed safely", id)
		}
		t, err := time.Parse(time.RFC3339, *a.EndsAt)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("subscription %s has an end date Conduit can't read; it can't be resumed safely", id)
		}
		if !t.After(m.now()) {
			return sdk.Result{}, fmt.Errorf("subscription %s ended on %s; it can't be resumed", id, *a.EndsAt)
		}
		expect := expectStatus(p.ExpectedStatus, a.Status)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Resume subscription %s (%s) of customer %d: it renews and bills again instead of ending.%s", id, a.ProductName, a.CustomerID, runNote("subscription", expect)),
				Changes: []sdk.Change{{Target: label, Op: "update", Before: mustJSON(before), After: mustJSON(map[string]any{"cancelled": false})}}}}, nil
		}
		if expect != nil {
			return sdk.Result{}, expect
		}
		body := map[string]any{"data": map[string]any{"type": "subscriptions", "id": id, "attributes": map[string]any{"cancelled": false}}}
		var r one[subscription]
		if err := c.do(ctx, http.MethodPatch, "/v1/subscriptions/"+id, nil, body, &r); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(subOut(id, r.Data.Attributes))
		// The undo runs only while the subscription is still as this left it.
		res.Undo = sdk.UndoWith("cancel_subscription", map[string]any{"subscription": id, "expectedStatus": r.Data.Attributes.Status}, "Cancel subscription "+id+" again")
		return res, err
	}
	if a.Cancelled || a.Status == "cancelled" {
		ends := ""
		if a.EndsAt != nil {
			ends = *a.EndsAt
		}
		return sdk.JSON(map[string]any{"subscription": id, "note": "it is cancelled already and ends " + ends})
	}
	expect := expectStatus(p.ExpectedStatus, a.Status)
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Cancel subscription %s (%s) of customer %d: it runs until the paid period ends (%s), then expires; undo resumes it until then.%s", id, a.ProductName, a.CustomerID, a.RenewsAt, runNote("subscription", expect)),
			Changes: []sdk.Change{{Target: label, Op: "cancel", Before: mustJSON(before), After: mustJSON(map[string]any{"cancelled": true})}}}}, nil
	}
	if expect != nil {
		return sdk.Result{}, expect
	}
	var r one[subscription]
	if err := c.do(ctx, http.MethodDelete, "/v1/subscriptions/"+id, nil, nil, &r); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(subOut(id, r.Data.Attributes))
	after := r.Data.Attributes.Status
	if after == "" {
		after = "cancelled"
	}
	res.Undo = sdk.UndoWith("resume_subscription", map[string]any{"subscription": id, "expectedStatus": after}, "Resume subscription "+id+" (take back the cancellation)")
	return res, err
}
