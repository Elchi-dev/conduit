// Package woocommerce works with a self-hosted WooCommerce store through its
// REST API and a consumer key and secret: the store, orders, products and
// stock, and changing an order's status or refunding it.
//
// The keys travel only over HTTPS, as Basic auth (never in the query
// string), and only to the store's own host. Money never moves without a
// preview: refunds show the amount and currency and can't exceed what's left
// on the order, and status changes are destructive because WooCommerce emails
// the customer about them. Customer names, emails, phones and addresses
// appear only in order, which is sensitive.
package woocommerce

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// Config is one WooCommerce store.
type Config struct {
	URL                string `json:"url"`    // the store's https address, e.g. https://shop.example.com
	Key                string `json:"key"`    // secret:// consumer key (ck_…)
	Secret             string `json:"secret"` // secret:// consumer secret (cs_…)
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the WooCommerce module.
func New() *Module { return &Module{} }

var (
	pathRe    = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	ckRe      = regexp.MustCompile(`^ck_[A-Za-z0-9]{16,64}$`)
	csRe      = regexp.MustCompile(`^cs_[A-Za-z0-9]{16,64}$`)
	numRe     = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	searchRe  = regexp.MustCompile(`^[\p{L}\p{N} '._&-]{1,80}$`)
	dateRe    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	amountRe  = regexp.MustCompile(`^[0-9]{1,12}(\.[0-9]{1,4})?$`)
	emailRe   = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	phoneRe   = regexp.MustCompile(`\+?[0-9][0-9 ().-]{6,}[0-9]`)
	threeDigs = map[string]bool{"BHD": true, "JOD": true, "KWD": true, "OMR": true, "TND": true}
	zeroDigs  = map[string]bool{"BIF": true, "CLP": true, "DJF": true, "GNF": true, "ISK": true, "JPY": true, "KMF": true, "KRW": true, "PYG": true, "RWF": true, "UGX": true, "VND": true, "VUV": true, "XAF": true, "XOF": true, "XPF": true}
)

var (
	orderStatuses = map[string]bool{"pending": true, "processing": true, "on-hold": true, "completed": true, "cancelled": true, "refunded": true, "failed": true, "checkout-draft": true}
	// What update_order_status may set. Refunded is left out (use
	// refund_order, which moves the money); failed and drafts are
	// WooCommerce's own.
	settable     = map[string]bool{"pending": true, "processing": true, "on-hold": true, "completed": true, "cancelled": true}
	productStats = map[string]bool{"publish": true, "draft": true, "pending": true, "private": true}
	stockStats   = map[string]bool{"instock": true, "outofstock": true, "onbackorder": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	order := `"order":{"type":"integer","minimum":1,"description":"Order id (see orders)"}`
	page := `"limit":{"type":"integer","default":20,"minimum":1,"maximum":100},"page":{"type":"integer","default":1,"minimum":1}`
	return sdk.Manifest{
		ID: "woocommerce", Name: "WooCommerce", Version: "0.1.0", Category: "Productivity", Icon: "cart",
		Description: "A self-hosted WooCommerce store: orders, products and stock; change an order's status or refund it with a preview.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","key","secret"],"properties":{
			"url":{"type":"string","description":"The store's https address, e.g. https://shop.example.com"},
			"key":{"type":"string","x-secret":true,"description":"Consumer key (ck_…) from WooCommerce, Settings, Advanced, REST API"},
			"secret":{"type":"string","x-secret":true,"description":"Consumer secret (cs_…) of the same key"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "store", Title: "Store", Description: "WooCommerce and WordPress versions, the store's currency and address.", Risk: sdk.RiskRead},
			{Name: "orders", Title: "Orders", Description: "Recent orders: number, status, created, total, refunded amount, item count and payment method. No customer details.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["","pending","processing","on-hold","completed","cancelled","refunded","failed","checkout-draft"]},"since":{"type":"string","description":"Only orders created on or after this date (YYYY-MM-DD)"},` + page + `}}`)},
			{Name: "order", Title: "Order details", Description: "One order with its items, refunds, and the customer's name, email, phone, billing and shipping addresses and note.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["order"],"properties":{` + order + `}}`)},
			{Name: "products", Title: "Products", Description: "Products with type, status, SKU, price and stock.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Words to look for in product names"},"status":{"type":"string","enum":["","publish","draft","pending","private"]},"stockStatus":{"type":"string","enum":["","instock","outofstock","onbackorder"]},` + page + `}}`)},
			{Name: "stock", Title: "Stock", Description: "Products whose stock is managed, with the quantity left, optionally only what's running low.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"below":{"type":"integer","minimum":1,"description":"Only products with fewer than this many in stock"},"limit":{"type":"integer","default":100,"minimum":1,"maximum":100}}}`)},
			{Name: "update_order_status", Title: "Change an order's status", Description: "Sets an order to pending, processing, on-hold, completed or cancelled. WooCommerce emails the customer about most of these changes, and cancelling releases the stock; no money is refunded. Undo sets the previous status back, except after a cancellation.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["order","status"],"properties":{` + order + `,"status":{"type":"string","enum":["pending","processing","on-hold","completed","cancelled"]}}}`)},
			{Name: "refund_order", Title: "Refund an order", Description: "Refunds an amount of an order, fully or partly, through its payment gateway (or only records it, with gateway off). Money goes back to the customer and can't be taken back. Items aren't restocked.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["order"],"properties":{` + order + `,"amount":{"type":"string","description":"Like 12.50, in the order's currency (the preview shows it); the whole remaining amount when empty"},"reason":{"type":"string","maxLength":200},"gateway":{"type":"boolean","default":true,"description":"Refund through the payment gateway; off only records the refund in WooCommerce"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is the store's, like https://shop.example.com")
	}
	if u.Scheme != "https" {
		return errors.New("the store's address must start with https://: WooCommerce keys are only sent over HTTPS")
	}
	if !strings.HasPrefix(c.Key, "secret://") || !strings.HasPrefix(c.Secret, "secret://") {
		return errors.New("store the consumer key and secret in the vault and enter their secret:// references")
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
	base := strings.TrimRight(u.Path, "/")
	if i := strings.Index(base, "/wp-json"); i >= 0 {
		base = base[:i]
	}
	keyRef, secretRef := c.Key, c.Secret
	api := rest.New("https://"+u.Host+base+"/wp-json/wc/v3", func(ctx context.Context, r *http.Request) error {
		if r.URL.Scheme != "https" {
			return errors.New("refusing to send the WooCommerce keys without HTTPS")
		}
		k, err := h.Secret(ctx, keyRef)
		if err != nil {
			return err
		}
		s, err := h.Secret(ctx, secretRef)
		if err != nil {
			return err
		}
		k, s = strings.TrimSpace(k), strings.TrimSpace(s)
		if !ckRe.MatchString(k) || !csRe.MatchString(s) {
			return errors.New("the stored keys don't look like a WooCommerce consumer key (ck_…) and secret (cs_…)")
		}
		r.SetBasicAuth(k, s)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// scrub keeps credentials, customer emails and phone numbers out of error
// text, then shortens it.
func scrub(s string) string {
	s = rest.Redact(s)
	s = emailRe.ReplaceAllString(s, "[email]")
	s = phoneRe.ReplaceAllString(s, "[number]")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func friendly(err error) error {
	if err == nil {
		return nil
	}
	var e *rest.Error
	if !errors.As(err, &e) {
		return errors.New(scrub(err.Error()))
	}
	msg := "WooCommerce: " + scrub(e.Message)
	switch e.Status {
	case http.StatusUnauthorized:
		msg = "WooCommerce refused the consumer key and secret"
	case http.StatusForbidden:
		msg = "the key isn't allowed to do this in WooCommerce (it may be read-only)"
	case http.StatusNotFound:
		msg = "WooCommerce didn't find it (is the REST API at /wp-json/wc/v3?)"
	case http.StatusTooManyRequests:
		msg = "the store is limiting requests; try again in a moment"
	}
	// The status stays, so the engine can log "failed (HTTP <status>)".
	return &rest.Error{Status: e.Status, Message: msg}
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) (http.Header, error) {
	hdr, err := c.api.Do(ctx, method, path, q, body, out)
	return hdr, friendly(err)
}

// Money amounts are decimal strings; they're compared in ten-thousandths.
const scale = 10000

func parseAmount(s string) (int64, error) {
	s = strings.TrimSpace(s)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	if !amountRe.MatchString(s) {
		return 0, errors.New("an amount is like 12.50")
	}
	whole, frac, _ := strings.Cut(s, ".")
	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, err
	}
	f, _ := strconv.ParseInt((frac + "0000")[:4], 10, 64)
	v := w*scale + f
	if neg {
		v = -v
	}
	return v, nil
}

func digits(cur string) int {
	switch {
	case zeroDigs[cur]:
		return 0
	case threeDigs[cur]:
		return 3
	}
	return 2
}

func decimal(v int64, cur string) string {
	sign := ""
	if v < 0 {
		sign, v = "-", -v
	}
	d := digits(cur)
	s := sign + strconv.FormatInt(v/scale, 10)
	if d == 0 {
		return s
	}
	return s + "." + fmt.Sprintf("%04d", v%scale)[:d]
}

func money(v int64, cur string) string { return decimal(v, cur) + " " + cur }

func pow10(n int) int64 {
	v := int64(1)
	for ; n > 0; n-- {
		v *= 10
	}
	return v
}

func amount(s string) int64 { v, _ := parseAmount(s); return v }

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var os []json.RawMessage
	hdr, err := c.do(ctx, http.MethodGet, "/orders", url.Values{"per_page": {"1"}}, nil, &os)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "connected"
	if n := hdr.Get("X-WP-Total"); numRe.MatchString(n) || n == "0" {
		msg += ", " + n + " orders"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Status      string `json:"status"`
	Since       string `json:"since"`
	Limit       int    `json:"limit"`
	Page        int    `json:"page"`
	Order       int64  `json:"order"`
	Search      string `json:"search"`
	StockStatus string `json:"stockStatus"`
	Below       int    `json:"below"`
	Amount      any    `json:"amount"`
	Reason      string `json:"reason"`
	Gateway     *bool  `json:"gateway"`
}

func limit(n, def, max int) int {
	if n <= 0 || n > max {
		return def
	}
	return n
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
	if p.Page < 0 || p.Page > 10000 {
		return sdk.Result{}, errors.New("page is a number from 1")
	}
	switch call.Action {
	case "store":
		return c.store(ctx)
	case "orders":
		return c.orders(ctx, p)
	case "order":
		if p.Order <= 0 {
			return sdk.Result{}, errors.New("the order is its id, a number (see orders)")
		}
		return c.orderDetail(ctx, p.Order)
	case "products":
		return c.products(ctx, p)
	case "stock":
		return c.stock(ctx, p)
	case "update_order_status":
		return c.updateStatus(ctx, call, p)
	case "refund_order":
		return c.refund(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) store(ctx context.Context) (sdk.Result, error) {
	// Decoded field by field: system status also lists plugins, paths and
	// database details that have no place in the audit log.
	var s struct {
		Environment struct {
			HomeURL   string `json:"home_url"`
			Version   string `json:"version"`
			WPVersion string `json:"wp_version"`
		} `json:"environment"`
		Settings struct {
			Currency       string `json:"currency"`
			CurrencySymbol string `json:"currency_symbol"`
		} `json:"settings"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/system_status", nil, nil, &s); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"address": rest.StripUserinfo(s.Environment.HomeURL), "woocommerce": s.Environment.Version, "wordpress": s.Environment.WPVersion, "currency": s.Settings.Currency})
}

type refundRef struct {
	ID     int64  `json:"id"`
	Reason string `json:"reason"`
	Total  string `json:"total"` // negative, like "-5.00"
}

// orderRow holds only what isn't personal; orderFull adds the rest.
type orderRow struct {
	ID                 int64       `json:"id"`
	Number             string      `json:"number"`
	Status             string      `json:"status"`
	Currency           string      `json:"currency"`
	DateCreated        string      `json:"date_created"`
	Total              string      `json:"total"`
	PaymentMethod      string      `json:"payment_method"`
	PaymentMethodTitle string      `json:"payment_method_title"`
	DatePaid           *string     `json:"date_paid"`
	Refunds            []refundRef `json:"refunds"`
	LineItems          []struct {
		Name     string `json:"name"`
		SKU      string `json:"sku"`
		Quantity int    `json:"quantity"`
		Total    string `json:"total"`
	} `json:"line_items"`
}

func (o orderRow) refunded() int64 {
	var r int64
	for _, x := range o.Refunds {
		v := amount(x.Total)
		if v < 0 {
			v = -v
		}
		r += v
	}
	return r
}

func (o orderRow) label() string {
	if o.Number != "" {
		return "#" + o.Number
	}
	return "#" + strconv.FormatInt(o.ID, 10)
}

func orderOut(o orderRow) map[string]any {
	items := 0
	for _, li := range o.LineItems {
		items += li.Quantity
	}
	out := map[string]any{"id": o.ID, "number": o.Number, "status": o.Status, "created": o.DateCreated, "total": money(amount(o.Total), o.Currency),
		"items": items, "paymentMethod": o.PaymentMethodTitle}
	if r := o.refunded(); r > 0 {
		out["refunded"] = money(r, o.Currency)
	}
	if o.DatePaid != nil && *o.DatePaid != "" {
		out["paid"] = *o.DatePaid
	}
	return out
}

func (c *conn) orders(ctx context.Context, p input) (sdk.Result, error) {
	q := url.Values{"per_page": {strconv.Itoa(limit(p.Limit, 20, 100))}, "page": {strconv.Itoa(max(p.Page, 1))}, "orderby": {"date"}, "order": {"desc"}}
	if p.Status != "" {
		if !orderStatuses[p.Status] {
			return sdk.Result{}, fmt.Errorf("status %q isn't an order status", p.Status)
		}
		q.Set("status", p.Status)
	}
	if p.Since != "" {
		if _, err := time.Parse("2006-01-02", p.Since); err != nil || !dateRe.MatchString(p.Since) {
			return sdk.Result{}, errors.New("since is a date like 2026-11-01")
		}
		q.Set("after", p.Since+"T00:00:00")
	}
	var os []orderRow
	hdr, err := c.do(ctx, http.MethodGet, "/orders", q, nil, &os)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, o := range os {
		out = append(out, orderOut(o))
	}
	res := map[string]any{"items": out}
	if tp, _ := strconv.Atoi(hdr.Get("X-WP-TotalPages")); tp > max(p.Page, 1) {
		res["nextPage"] = max(p.Page, 1) + 1
	}
	return sdk.JSON(res)
}

type address struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Company   string `json:"company"`
	Address1  string `json:"address_1"`
	Address2  string `json:"address_2"`
	City      string `json:"city"`
	State     string `json:"state"`
	Postcode  string `json:"postcode"`
	Country   string `json:"country"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
}

func (a address) out() map[string]any {
	m := map[string]any{"name": strings.TrimSpace(a.FirstName + " " + a.LastName), "company": a.Company, "address1": a.Address1, "address2": a.Address2,
		"city": a.City, "state": a.State, "postcode": a.Postcode, "country": a.Country}
	if a.Email != "" {
		m["email"] = a.Email
	}
	if a.Phone != "" {
		m["phone"] = a.Phone
	}
	return m
}

type orderFull struct {
	orderRow
	CustomerNote string  `json:"customer_note"`
	Billing      address `json:"billing"`
	Shipping     address `json:"shipping"`
}

func (c *conn) getOrder(ctx context.Context, id int64) (orderFull, error) {
	var o orderFull
	if _, err := c.do(ctx, http.MethodGet, "/orders/"+strconv.FormatInt(id, 10), nil, nil, &o); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return o, fmt.Errorf("there's no order %d", id)
		}
		return o, err
	}
	if o.ID != id {
		// The id goes into the change's path.
		return o, fmt.Errorf("WooCommerce answered with another order for %d", id)
	}
	return o, nil
}

func (c *conn) orderDetail(ctx context.Context, id int64) (sdk.Result, error) {
	o, err := c.getOrder(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	out := orderOut(o.orderRow)
	out["billing"] = o.Billing.out()
	out["shipping"] = o.Shipping.out()
	if o.CustomerNote != "" {
		out["customerNote"] = o.CustomerNote
	}
	items := []map[string]any{}
	for _, li := range o.LineItems {
		items = append(items, map[string]any{"name": li.Name, "sku": li.SKU, "quantity": li.Quantity, "total": money(amount(li.Total), o.Currency)})
	}
	out["lineItems"] = items
	rs := []map[string]any{}
	for _, r := range o.Refunds {
		v := amount(r.Total)
		if v < 0 {
			v = -v
		}
		rs = append(rs, map[string]any{"id": r.ID, "amount": money(v, o.Currency), "reason": r.Reason})
	}
	out["refunds"] = rs
	return sdk.JSON(out)
}

type product struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	Status        string `json:"status"`
	SKU           string `json:"sku"`
	Price         string `json:"price"`
	RegularPrice  string `json:"regular_price"`
	SalePrice     string `json:"sale_price"`
	StockStatus   string `json:"stock_status"`
	ManageStock   bool   `json:"manage_stock"`
	StockQuantity *int   `json:"stock_quantity"`
	TotalSales    any    `json:"total_sales"`
	DateModified  string `json:"date_modified"`
}

func (c *conn) products(ctx context.Context, p input) (sdk.Result, error) {
	q := url.Values{"per_page": {strconv.Itoa(limit(p.Limit, 20, 100))}, "page": {strconv.Itoa(max(p.Page, 1))}}
	if s := strings.TrimSpace(p.Search); s != "" {
		if !searchRe.MatchString(s) {
			return sdk.Result{}, errors.New("search is a few plain words")
		}
		q.Set("search", s)
	}
	if p.Status != "" {
		if !productStats[p.Status] {
			return sdk.Result{}, fmt.Errorf("status %q isn't a product status", p.Status)
		}
		q.Set("status", p.Status)
	}
	if p.StockStatus != "" {
		if !stockStats[p.StockStatus] {
			return sdk.Result{}, fmt.Errorf("stockStatus %q isn't a stock status", p.StockStatus)
		}
		q.Set("stock_status", p.StockStatus)
	}
	var ps []product
	hdr, err := c.do(ctx, http.MethodGet, "/products", q, nil, &ps)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, x := range ps {
		row := map[string]any{"id": x.ID, "name": x.Name, "type": x.Type, "status": x.Status, "sku": x.SKU, "price": x.Price, "stockStatus": x.StockStatus, "updated": x.DateModified}
		if x.SalePrice != "" {
			row["regularPrice"], row["salePrice"] = x.RegularPrice, x.SalePrice
		}
		if x.ManageStock && x.StockQuantity != nil {
			row["stock"] = *x.StockQuantity
		}
		out = append(out, row)
	}
	res := map[string]any{"items": out}
	if tp, _ := strconv.Atoi(hdr.Get("X-WP-TotalPages")); tp > max(p.Page, 1) {
		res["nextPage"] = max(p.Page, 1) + 1
	}
	return sdk.JSON(res)
}

func (c *conn) stock(ctx context.Context, p input) (sdk.Result, error) {
	if p.Below < 0 {
		return sdk.Result{}, errors.New("below is a positive number")
	}
	q := url.Values{"per_page": {strconv.Itoa(limit(p.Limit, 100, 100))}, "orderby": {"title"}, "order": {"asc"}}
	var ps []product
	if _, err := c.do(ctx, http.MethodGet, "/products", q, nil, &ps); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, x := range ps {
		if !x.ManageStock || x.StockQuantity == nil {
			continue
		}
		if p.Below > 0 && *x.StockQuantity >= p.Below {
			continue
		}
		out = append(out, map[string]any{"id": x.ID, "name": x.Name, "sku": x.SKU, "stock": *x.StockQuantity, "stockStatus": x.StockStatus})
	}
	return sdk.JSON(map[string]any{"items": out})
}

func (c *conn) updateStatus(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Order <= 0 {
		return sdk.Result{}, errors.New("the order is its id, a number (see orders)")
	}
	to := strings.ToLower(strings.TrimSpace(p.Status))
	if !settable[to] {
		return sdk.Result{}, fmt.Errorf("status %q isn't one of pending, processing, on-hold, completed, cancelled (refund with refund_order)", p.Status)
	}
	o, err := c.getOrder(ctx, p.Order)
	if err != nil {
		return sdk.Result{}, err
	}
	if o.Status == to {
		return sdk.JSON(map[string]any{"order": o.ID, "status": o.Status, "note": "nothing to change"})
	}
	switch o.Status {
	case "refunded":
		return sdk.Result{}, fmt.Errorf("order %s was refunded; its status stays", o.label())
	case "checkout-draft", "trash":
		return sdk.Result{}, fmt.Errorf("order %s is a %s; change it in WooCommerce", o.label(), o.Status)
	}
	total := money(amount(o.Total), o.Currency)
	if call.DryRun {
		summary := fmt.Sprintf("Set order %s (total %s) from %s to %s; WooCommerce may email the customer", o.label(), total, o.Status, to)
		if to == "cancelled" {
			summary = fmt.Sprintf("Cancel order %s (total %s): its stock is released and no money is refunded; WooCommerce may email the customer", o.label(), total)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "order " + o.label(), Op: "set_status",
			Before: mustJSON(map[string]any{"status": o.Status, "total": total}), After: mustJSON(map[string]any{"status": to})}}}}, nil
	}
	var after orderRow
	if _, err := c.do(ctx, http.MethodPut, "/orders/"+strconv.FormatInt(o.ID, 10), nil, map[string]any{"status": to}, &after); err != nil {
		return sdk.Result{}, err
	}
	if after.ID != 0 && after.Status != to {
		return sdk.Result{}, fmt.Errorf("WooCommerce kept order %s at %s", o.label(), after.Status)
	}
	res, err := sdk.JSON(map[string]any{"order": o.ID, "number": o.Number, "status": to, "was": o.Status})
	if to != "cancelled" && settable[o.Status] {
		res.Undo = sdk.UndoWith("update_order_status", map[string]any{"order": o.ID, "status": o.Status}, "Set order "+o.label()+" back to "+o.Status)
	}
	return res, err
}

func (c *conn) refund(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Order <= 0 {
		return sdk.Result{}, errors.New("the order is its id, a number (see orders)")
	}
	var amountIn string
	switch a := p.Amount.(type) {
	case nil:
	case string:
		amountIn = strings.TrimSpace(a)
	case float64:
		amountIn = strconv.FormatFloat(a, 'f', -1, 64)
	default:
		return sdk.Result{}, errors.New("the amount is like 12.50")
	}
	var want int64
	if amountIn != "" {
		v, err := parseAmount(amountIn)
		if err != nil || v <= 0 {
			return sdk.Result{}, errors.New("the amount is a positive number like 12.50")
		}
		want = v
	}
	reason := strings.TrimSpace(p.Reason)
	if len(reason) > 200 || strings.ContainsAny(reason, "\x00\r\n") {
		return sdk.Result{}, errors.New("the reason is one line of at most 200 characters")
	}
	gateway := true
	if p.Gateway != nil {
		gateway = *p.Gateway
	}
	o, err := c.getOrder(ctx, p.Order)
	if err != nil {
		return sdk.Result{}, err
	}
	cur := o.Currency
	total := amount(o.Total)
	refunded := o.refunded()
	left := total - refunded
	if left <= 0 {
		return sdk.Result{}, fmt.Errorf("order %s has nothing left to refund", o.label())
	}
	switch o.Status {
	case "pending", "failed", "checkout-draft", "cancelled":
		if o.DatePaid == nil || *o.DatePaid == "" {
			return sdk.Result{}, fmt.Errorf("order %s (%s) wasn't paid, so there's nothing to refund", o.label(), o.Status)
		}
	}
	amt := want
	if amt == 0 {
		amt = left
	}
	if amt > left {
		return sdk.Result{}, fmt.Errorf("only %s of %s is left to refund on order %s", money(left, cur), money(total, cur), o.label())
	}
	if step := scale / pow10(digits(cur)); amt%step != 0 {
		return sdk.Result{}, fmt.Errorf("%s has %d decimals", cur, digits(cur))
	}
	full := amt == left && refunded == 0
	kind := "Full refund"
	if !full {
		kind = "Partial refund"
	}
	how := "through " + o.PaymentMethodTitle
	if o.PaymentMethodTitle == "" {
		how = "through the payment gateway"
	}
	if !gateway {
		how = "recorded only (no money moves; pay it back yourself)"
	}
	if call.DryRun {
		before := map[string]any{"total": money(total, cur), "refunded": money(refunded, cur), "status": o.Status}
		after := map[string]any{"refund": money(amt, cur), "refundedAfter": money(refunded+amt, cur), "gateway": gateway}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s of %s on order %s, %s", kind, money(amt, cur), o.label(), how),
			Changes: []sdk.Change{{Target: "order " + o.label(), Op: "refund", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	body := map[string]any{"amount": decimal(amt, cur), "api_refund": gateway, "api_restock": false}
	if reason != "" {
		body["reason"] = reason
	}
	var r struct {
		ID     int64  `json:"id"`
		Amount string `json:"amount"`
	}
	if _, err := c.do(ctx, http.MethodPost, "/orders/"+strconv.FormatInt(o.ID, 10)+"/refunds", nil, body, &r); err != nil {
		return sdk.Result{}, err
	}
	if r.ID == 0 {
		return sdk.Result{}, errors.New("WooCommerce didn't create the refund")
	}
	return sdk.JSON(map[string]any{"order": o.ID, "number": o.Number, "refund": r.ID, "amount": money(amt, cur), "currency": cur, "gateway": gateway, "refundedTotal": money(refunded+amt, cur)})
}
