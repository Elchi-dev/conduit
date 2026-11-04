// Package bigcommerce works with a BigCommerce store through its REST API,
// the store hash and an API account's access token: the store, orders,
// products and inventory, and changing an order's status.
//
// Status changes are destructive: BigCommerce emails the customer about
// them, and cancelling or declining an order can return its stock. Their
// previews show the order's total in its currency. Customer names, emails,
// phones and addresses appear only in order, which is sensitive.
package bigcommerce

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
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one BigCommerce store.
type Config struct {
	StoreHash string `json:"storeHash"` // from the API path, e.g. abc123de45
	Token     string `json:"token"`     // secret:// API account access token
}

const defaultBase = "https://api.bigcommerce.com"

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.bigcommerce.com (tests).
	Base string
}

// New returns the BigCommerce module.
func New() *Module { return &Module{} }

var (
	hashRe    = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	tokenRe   = regexp.MustCompile(`^[A-Za-z0-9]{16,128}$`)
	searchRe  = regexp.MustCompile(`^[\p{L}\p{N} '._&-]{1,80}$`)
	dateRe    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	amountRe  = regexp.MustCompile(`^-?[0-9]{1,12}(\.[0-9]{1,4})?$`)
	emailRe   = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	phoneRe   = regexp.MustCompile(`\+?[0-9][0-9 ().-]{6,}[0-9]`)
	threeDigs = map[string]bool{"BHD": true, "JOD": true, "KWD": true, "OMR": true, "TND": true}
	zeroDigs  = map[string]bool{"BIF": true, "CLP": true, "DJF": true, "GNF": true, "ISK": true, "JPY": true, "KMF": true, "KRW": true, "PYG": true, "RWF": true, "UGX": true, "VND": true, "VUV": true, "XAF": true, "XOF": true, "XPF": true}
)

// Order statuses by name and id.
var statusIDs = map[string]int{
	"incomplete": 0, "pending": 1, "shipped": 2, "partially_shipped": 3, "refunded": 4, "cancelled": 5, "declined": 6, "awaiting_payment": 7,
	"awaiting_pickup": 8, "awaiting_shipment": 9, "completed": 10, "awaiting_fulfillment": 11, "manual_verification_required": 12, "disputed": 13, "partially_refunded": 14,
}

// settable leaves out incomplete (abandoned checkouts) and the refund
// statuses, which say money moved when it didn't.
var settable = map[string]bool{"pending": true, "shipped": true, "partially_shipped": true, "cancelled": true, "declined": true, "awaiting_payment": true,
	"awaiting_pickup": true, "awaiting_shipment": true, "completed": true, "awaiting_fulfillment": true, "manual_verification_required": true, "disputed": true}

func statusName(id int) string {
	for n, v := range statusIDs {
		if v == id {
			return n
		}
	}
	return strconv.Itoa(id)
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	order := `"order":{"type":"integer","minimum":1,"description":"Order id (see orders)"}`
	page := `"limit":{"type":"integer","default":20,"minimum":1,"maximum":250},"page":{"type":"integer","default":1,"minimum":1}`
	set := `["pending","shipped","partially_shipped","cancelled","declined","awaiting_payment","awaiting_pickup","awaiting_shipment","completed","awaiting_fulfillment","manual_verification_required","disputed"]`
	all := `["","incomplete","pending","shipped","partially_shipped","refunded","cancelled","declined","awaiting_payment","awaiting_pickup","awaiting_shipment","completed","awaiting_fulfillment","manual_verification_required","disputed","partially_refunded"]`
	return sdk.Manifest{
		ID: "bigcommerce", Name: "BigCommerce", Version: "0.1.0", Category: "Productivity", Icon: "cart",
		Description: "A BigCommerce store: orders, products and inventory; change an order's status with a preview.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["storeHash","token"],"properties":{
			"storeHash":{"type":"string","description":"The store hash, from the API path https://api.bigcommerce.com/stores/<hash>/"},
			"token":{"type":"string","x-secret":true,"description":"Access token of a store-level API account (Settings, API, Store-level API accounts) with only the scopes you need"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "store", Title: "Store", Description: "The store's name, domain, plan, currency and time zone.", Risk: sdk.RiskRead},
			{Name: "orders", Title: "Orders", Description: "Recent orders: id, status, created, total, refunded amount, item count and payment status. No customer details.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":` + all + `},"since":{"type":"string","description":"Only orders created on or after this date (YYYY-MM-DD)"},` + page + `}}`)},
			{Name: "order", Title: "Order details", Description: "One order with its items, and the customer's billing and shipping names, emails, phones and addresses.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["order"],"properties":{` + order + `}}`)},
			{Name: "products", Title: "Products", Description: "Products with SKU, price, visibility, availability and stock.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Words to look for in names, SKUs and descriptions"},` + page + `}}`)},
			{Name: "inventory", Title: "Inventory", Description: "Stock of products whose inventory is tracked, per variant where tracked by variant, optionally only what's running low.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"below":{"type":"integer","minimum":1,"description":"Only items with fewer than this many in stock"},"limit":{"type":"integer","default":100,"minimum":1,"maximum":250}}}`)},
			{Name: "update_order_status", Title: "Change an order's status", Description: "Sets an order's status, like shipped, completed or cancelled. BigCommerce emails the customer about most changes, and cancelling or declining can return the stock; no money is refunded. Undo sets the previous status back, except after a cancellation or decline.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["order","status"],"properties":{` + order + `,"status":{"type":"string","enum":` + set + `}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	hash := strings.ToLower(strings.TrimSpace(c.StoreHash))
	hash = strings.TrimPrefix(hash, "stores/")
	if !hashRe.MatchString(hash) {
		return errors.New("the store hash is the letters and digits after /stores/ in the API path, like abc123de45")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 30*time.Second)
	}
	ref := c.Token
	api := rest.New(base+"/stores/"+url.PathEscape(hash), func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if !tokenRe.MatchString(t) {
			return errors.New("the stored token doesn't look like a BigCommerce access token")
		}
		r.Header.Set("X-Auth-Token", t)
		return nil
	})
	api.HTTP = rest.SameHostOnly(hc)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

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
	msg := "BigCommerce: " + scrub(e.Message)
	switch e.Status {
	case http.StatusUnauthorized:
		msg = "BigCommerce refused the access token"
	case http.StatusForbidden:
		msg = "the API account isn't allowed to do this in BigCommerce (check its scopes)"
	case http.StatusNotFound:
		msg = "BigCommerce didn't find it (is the store hash right?)"
	case http.StatusTooManyRequests:
		msg = "BigCommerce is limiting requests; try again in a moment"
	}
	return &rest.Error{Status: e.Status, Message: msg}
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

// Money amounts are decimal strings; they're handled in ten-thousandths.
const scale = 10000

func parse(s string) int64 {
	s = strings.TrimSpace(s)
	if !amountRe.MatchString(s) {
		return 0
	}
	neg := strings.HasPrefix(s, "-")
	whole, frac, _ := strings.Cut(strings.TrimPrefix(s, "-"), ".")
	w, _ := strconv.ParseInt(whole, 10, 64)
	f, _ := strconv.ParseInt((frac + "0000")[:4], 10, 64)
	v := w*scale + f
	if neg {
		v = -v
	}
	return v
}

func money(s, cur string) string {
	v := parse(s)
	sign := ""
	if v < 0 {
		sign, v = "-", -v
	}
	d := 2
	switch {
	case zeroDigs[cur]:
		d = 0
	case threeDigs[cur]:
		d = 3
	}
	out := sign + strconv.FormatInt(v/scale, 10)
	if d > 0 {
		out += "." + fmt.Sprintf("%04d", v%scale)[:d]
	}
	return out + " " + cur
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

type storeInfo struct {
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Secure   string `json:"secure_url"`
	Currency string `json:"currency"`
	Timezone struct {
		Name string `json:"name"`
	} `json:"timezone"`
	PlanName  string `json:"plan_name"`
	PlanLevel string `json:"plan_level"`
	Status    string `json:"status"`
	// The owner's email, phone and address aren't decoded.
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s storeInfo
	if err := c.do(ctx, http.MethodGet, "/v2/store", nil, nil, &s); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "connected to " + s.Name
	if s.PlanName != "" {
		msg += " (" + s.PlanName + ")"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Status string `json:"status"`
	Since  string `json:"since"`
	Limit  int    `json:"limit"`
	Page   int    `json:"page"`
	Order  int64  `json:"order"`
	Search string `json:"search"`
	Below  int    `json:"below"`
}

func limit(n, def, most int) int {
	if n <= 0 || n > most {
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
		var s storeInfo
		if err := c.do(ctx, http.MethodGet, "/v2/store", nil, nil, &s); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"name": s.Name, "domain": s.Domain, "url": s.Secure, "currency": s.Currency, "timeZone": s.Timezone.Name, "plan": s.PlanName, "status": s.Status})
	case "orders":
		return c.orders(ctx, p)
	case "order":
		if p.Order <= 0 {
			return sdk.Result{}, errors.New("the order is its id, a number (see orders)")
		}
		return c.orderDetail(ctx, p.Order)
	case "products":
		return c.products(ctx, p)
	case "inventory":
		return c.inventory(ctx, p)
	case "update_order_status":
		return c.updateStatus(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// orderRow holds only what isn't personal (the billing address is left
// out); orderDetail adds it.
type orderRow struct {
	ID             int64  `json:"id"`
	StatusID       int    `json:"status_id"`
	Status         string `json:"status"`
	DateCreated    string `json:"date_created"`
	TotalIncTax    string `json:"total_inc_tax"`
	RefundedAmount string `json:"refunded_amount"`
	ItemsTotal     int    `json:"items_total"`
	PaymentMethod  string `json:"payment_method"`
	PaymentStatus  string `json:"payment_status"`
	CurrencyCode   string `json:"currency_code"`
	IsDeleted      bool   `json:"is_deleted"`
}

func orderOut(o orderRow) map[string]any {
	out := map[string]any{"id": o.ID, "status": statusName(o.StatusID), "created": o.DateCreated, "total": money(o.TotalIncTax, o.CurrencyCode),
		"items": o.ItemsTotal, "paymentMethod": o.PaymentMethod, "paymentStatus": o.PaymentStatus}
	if parse(o.RefundedAmount) > 0 {
		out["refunded"] = money(o.RefundedAmount, o.CurrencyCode)
	}
	return out
}

func (c *conn) orders(ctx context.Context, p input) (sdk.Result, error) {
	page := max(p.Page, 1)
	lim := limit(p.Limit, 20, 250)
	q := url.Values{"limit": {strconv.Itoa(lim)}, "page": {strconv.Itoa(page)}, "sort": {"date_created:desc"}}
	if p.Status != "" {
		id, ok := statusIDs[p.Status]
		if !ok {
			return sdk.Result{}, fmt.Errorf("status %q isn't an order status", p.Status)
		}
		q.Set("status_id", strconv.Itoa(id))
	}
	if p.Since != "" {
		if _, err := time.Parse("2006-01-02", p.Since); err != nil || !dateRe.MatchString(p.Since) {
			return sdk.Result{}, errors.New("since is a date like 2026-11-01")
		}
		q.Set("min_date_created", p.Since)
	}
	// An empty list comes back as 204 with no body.
	var os []orderRow
	if err := c.do(ctx, http.MethodGet, "/v2/orders", q, nil, &os); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, o := range os {
		if !o.IsDeleted {
			out = append(out, orderOut(o))
		}
	}
	res := map[string]any{"items": out}
	if len(os) == lim {
		res["nextPage"] = page + 1
	}
	return sdk.JSON(res)
}

func (c *conn) getOrder(ctx context.Context, id int64) (orderRow, error) {
	var o orderRow
	if err := c.do(ctx, http.MethodGet, "/v2/orders/"+strconv.FormatInt(id, 10), nil, nil, &o); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return o, fmt.Errorf("there's no order %d", id)
		}
		return o, err
	}
	if o.ID == 0 {
		return o, fmt.Errorf("there's no order %d", id)
	}
	if o.ID != id {
		// The id goes into the change's path and the undo.
		return o, fmt.Errorf("BigCommerce answered with another order for %d", id)
	}
	return o, nil
}

type address struct {
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Company     string `json:"company"`
	Street1     string `json:"street_1"`
	Street2     string `json:"street_2"`
	City        string `json:"city"`
	State       string `json:"state"`
	Zip         string `json:"zip"`
	CountryISO2 string `json:"country_iso2"`
	Phone       string `json:"phone"`
	Email       string `json:"email"`
}

func (a address) out() map[string]any {
	return map[string]any{"name": strings.TrimSpace(a.FirstName + " " + a.LastName), "company": a.Company, "street1": a.Street1, "street2": a.Street2,
		"city": a.City, "state": a.State, "zip": a.Zip, "country": a.CountryISO2, "phone": a.Phone, "email": a.Email}
}

func (c *conn) orderDetail(ctx context.Context, id int64) (sdk.Result, error) {
	var o struct {
		orderRow
		CustomerMessage string  `json:"customer_message"`
		BillingAddress  address `json:"billing_address"`
	}
	if err := c.do(ctx, http.MethodGet, "/v2/orders/"+strconv.FormatInt(id, 10), nil, nil, &o); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no order %d", id)
		}
		return sdk.Result{}, err
	}
	if o.ID != id {
		return sdk.Result{}, fmt.Errorf("there's no order %d", id)
	}
	path := "/v2/orders/" + strconv.FormatInt(id, 10)
	var items []struct {
		Name        string `json:"name"`
		SKU         string `json:"sku"`
		Quantity    int    `json:"quantity"`
		TotalIncTax string `json:"total_inc_tax"`
	}
	if err := c.do(ctx, http.MethodGet, path+"/products", nil, nil, &items); err != nil {
		return sdk.Result{}, err
	}
	var ships []address
	if err := c.do(ctx, http.MethodGet, path+"/shipping_addresses", nil, nil, &ships); err != nil {
		return sdk.Result{}, err
	}
	out := orderOut(o.orderRow)
	out["billing"] = o.BillingAddress.out()
	sh := []map[string]any{}
	for _, a := range ships {
		sh = append(sh, a.out())
	}
	out["shipping"] = sh
	li := []map[string]any{}
	for _, it := range items {
		li = append(li, map[string]any{"name": it.Name, "sku": it.SKU, "quantity": it.Quantity, "total": money(it.TotalIncTax, o.CurrencyCode)})
	}
	out["lineItems"] = li
	if o.CustomerMessage != "" {
		out["customerMessage"] = o.CustomerMessage
	}
	return sdk.JSON(out)
}

type variant struct {
	ID             int64  `json:"id"`
	SKU            string `json:"sku"`
	InventoryLevel int    `json:"inventory_level"`
	OptionValues   []struct {
		Label string `json:"label"`
	} `json:"option_values"`
}

type productRow struct {
	ID                int64       `json:"id"`
	Name              string      `json:"name"`
	SKU               string      `json:"sku"`
	Price             json.Number `json:"price"`
	IsVisible         bool        `json:"is_visible"`
	Availability      string      `json:"availability"`
	InventoryTracking string      `json:"inventory_tracking"`
	InventoryLevel    int         `json:"inventory_level"`
	DateModified      string      `json:"date_modified"`
	Variants          []variant   `json:"variants"`
}

type productPage struct {
	Data []productRow `json:"data"`
	Meta struct {
		Pagination struct {
			TotalPages  int `json:"total_pages"`
			CurrentPage int `json:"current_page"`
		} `json:"pagination"`
	} `json:"meta"`
}

func (c *conn) products(ctx context.Context, p input) (sdk.Result, error) {
	page := max(p.Page, 1)
	// v3 sends prices as JSON numbers; they're kept as the digits sent
	// (json.Number), never floats.
	q := url.Values{"limit": {strconv.Itoa(limit(p.Limit, 20, 250))}, "page": {strconv.Itoa(page)}, "sort": {"date_modified"}, "direction": {"desc"},
		"include_fields": {"name,sku,price,is_visible,availability,inventory_tracking,inventory_level,date_modified"}}
	if s := strings.TrimSpace(p.Search); s != "" {
		if !searchRe.MatchString(s) {
			return sdk.Result{}, errors.New("search is a few plain words")
		}
		q.Set("keyword", s)
	}
	var d productPage
	if err := c.do(ctx, http.MethodGet, "/v3/catalog/products", q, nil, &d); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, x := range d.Data {
		row := map[string]any{"id": x.ID, "name": x.Name, "sku": x.SKU, "price": x.Price.String(), "visible": x.IsVisible, "availability": x.Availability,
			"inventoryTracking": x.InventoryTracking, "updated": x.DateModified}
		if x.InventoryTracking != "none" {
			row["stock"] = x.InventoryLevel
		}
		out = append(out, row)
	}
	res := map[string]any{"items": out}
	if d.Meta.Pagination.TotalPages > page {
		res["nextPage"] = page + 1
	}
	return sdk.JSON(res)
}

func (c *conn) inventory(ctx context.Context, p input) (sdk.Result, error) {
	if p.Below < 0 {
		return sdk.Result{}, errors.New("below is a positive number")
	}
	q := url.Values{"limit": {strconv.Itoa(limit(p.Limit, 100, 250))}, "include": {"variants"}, "sort": {"name"},
		"include_fields": {"name,sku,inventory_tracking,inventory_level"}}
	var d productPage
	if err := c.do(ctx, http.MethodGet, "/v3/catalog/products", q, nil, &d); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	low := func(n int) bool { return p.Below > 0 && n >= p.Below }
	for _, x := range d.Data {
		switch x.InventoryTracking {
		case "product":
			if low(x.InventoryLevel) {
				continue
			}
			out = append(out, map[string]any{"product": x.ID, "name": x.Name, "sku": x.SKU, "stock": x.InventoryLevel})
		case "variant":
			for _, v := range x.Variants {
				if low(v.InventoryLevel) {
					continue
				}
				var opts []string
				for _, o := range v.OptionValues {
					opts = append(opts, o.Label)
				}
				name := x.Name
				if len(opts) > 0 {
					name += " - " + strings.Join(opts, " / ")
				}
				out = append(out, map[string]any{"product": x.ID, "variant": v.ID, "name": name, "sku": v.SKU, "stock": v.InventoryLevel})
			}
		}
	}
	return sdk.JSON(map[string]any{"items": out})
}

func (c *conn) updateStatus(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Order <= 0 {
		return sdk.Result{}, errors.New("the order is its id, a number (see orders)")
	}
	to := strings.ToLower(strings.TrimSpace(p.Status))
	if !settable[to] {
		return sdk.Result{}, fmt.Errorf("status %q isn't one you can set here (refunds and abandoned checkouts are handled in BigCommerce)", p.Status)
	}
	o, err := c.getOrder(ctx, p.Order)
	if err != nil {
		return sdk.Result{}, err
	}
	from := statusName(o.StatusID)
	if from == to {
		return sdk.JSON(map[string]any{"order": o.ID, "status": from, "note": "nothing to change"})
	}
	if o.IsDeleted {
		return sdk.Result{}, fmt.Errorf("order %d is archived", o.ID)
	}
	if from == "refunded" || from == "incomplete" {
		return sdk.Result{}, fmt.Errorf("order %d is %s; its status stays", o.ID, from)
	}
	total := money(o.TotalIncTax, o.CurrencyCode)
	if call.DryRun {
		summary := fmt.Sprintf("Set order %d (total %s) from %s to %s; BigCommerce may email the customer", o.ID, total, from, to)
		if to == "cancelled" || to == "declined" {
			summary = fmt.Sprintf("Set order %d (total %s) from %s to %s: no money is refunded, its stock may be returned, and BigCommerce may email the customer", o.ID, total, from, to)
		}
		before := map[string]any{"status": from, "total": total, "paymentStatus": o.PaymentStatus}
		if parse(o.RefundedAmount) > 0 {
			before["refunded"] = money(o.RefundedAmount, o.CurrencyCode)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: fmt.Sprintf("order %d", o.ID), Op: "set_status",
			Before: mustJSON(before), After: mustJSON(map[string]any{"status": to})}}}}, nil
	}
	var after orderRow
	if err := c.do(ctx, http.MethodPut, "/v2/orders/"+strconv.FormatInt(o.ID, 10), nil, map[string]any{"status_id": statusIDs[to]}, &after); err != nil {
		return sdk.Result{}, err
	}
	if after.ID != 0 && after.StatusID != statusIDs[to] {
		return sdk.Result{}, fmt.Errorf("BigCommerce kept order %d at %s", o.ID, statusName(after.StatusID))
	}
	res, err := sdk.JSON(map[string]any{"order": o.ID, "status": to, "was": from})
	if to != "cancelled" && to != "declined" && settable[from] {
		res.Undo = sdk.UndoWith("update_order_status", map[string]any{"order": o.ID, "status": from}, fmt.Sprintf("Set order %d back to %s", o.ID, from))
	}
	return res, err
}
