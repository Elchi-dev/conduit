// Package shopify works with a Shopify store through the Admin GraphQL API
// and an access token: the shop, orders, products and inventory levels, and
// fulfilling, cancelling and refunding orders.
//
// Money never moves without a preview: refunds and cancellations are
// destructive, show the amount and currency first, and every refund carries
// an idempotency key so a repeated request can't refund twice. Fulfilling an
// order is destructive too: it tells the customer and the warehouse that the
// goods shipped and, in stores that capture payment on fulfilment, charges
// the customer. Customer names, emails, phones and addresses appear only in
// order, which is sensitive. Every query is a fixed document; input goes in
// variables.
package shopify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// Config is one Shopify store.
type Config struct {
	Shop  string `json:"shop"`  // the store's myshopify name, e.g. acme or acme.myshopify.com
	Token string `json:"token"` // secret:// Admin API access token
}

// APIVersion pins the shape of Shopify's answers.
const APIVersion = "2026-10"

type conn struct {
	api  *rest.Client
	shop string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://<shop>.myshopify.com (tests).
	Base string
}

// New returns the Shopify module.
func New() *Module { return &Module{} }

var (
	shopRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,59}$`)
	tokenRe   = regexp.MustCompile(`^shp(at|ca|pa)_[A-Za-z0-9]{16,128}$`)
	numRe     = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	nameRe    = regexp.MustCompile(`^#[0-9]{1,12}$`)
	cursorRe  = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{1,1000}$`)
	searchRe  = regexp.MustCompile(`^[\p{L}\p{N} '._&-]{1,80}$`)
	dateRe    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	amountRe  = regexp.MustCompile(`^[0-9]{1,12}(\.[0-9]{1,3})?$`)
	idemRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	trackRe   = regexp.MustCompile(`^[A-Za-z0-9 ._/-]{1,64}$`)
	emailRe   = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	phoneRe   = regexp.MustCompile(`\+?[0-9][0-9 ().-]{6,}[0-9]`)
	threeDigs = map[string]bool{"BHD": true, "JOD": true, "KWD": true, "OMR": true, "TND": true}
	zeroDigs  = map[string]bool{"BIF": true, "CLP": true, "DJF": true, "GNF": true, "ISK": true, "JPY": true, "KMF": true, "KRW": true, "PYG": true, "RWF": true, "UGX": true, "VND": true, "VUV": true, "XAF": true, "XOF": true, "XPF": true}
)

var (
	orderStatus       = map[string]bool{"open": true, "closed": true, "cancelled": true, "any": true}
	financialStatus   = map[string]bool{"paid": true, "pending": true, "authorized": true, "partially_paid": true, "partially_refunded": true, "refunded": true, "voided": true, "unpaid": true}
	fulfillmentStatus = map[string]bool{"unfulfilled": true, "partial": true, "fulfilled": true}
	productStatus     = map[string]bool{"active": true, "draft": true, "archived": true}
	cancelReasons     = map[string]bool{"CUSTOMER": true, "DECLINED": true, "FRAUD": true, "INVENTORY": true, "STAFF": true, "OTHER": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	order := `"order":{"type":"string","description":"Order id (numeric or gid://shopify/Order/…) or its name, like #1001"}`
	page := `"limit":{"type":"integer","default":20,"minimum":1,"maximum":100},"after":{"type":"string","description":"endCursor of the previous page"}`
	return sdk.Manifest{
		ID: "shopify", Name: "Shopify", Version: "0.1.0", Category: "Productivity", Icon: "cart",
		Description: "A Shopify store: shop, orders, products and inventory; fulfil, cancel and refund orders with a preview.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["shop","token"],"properties":{
			"shop":{"type":"string","description":"The store's myshopify name, e.g. acme or acme.myshopify.com"},
			"token":{"type":"string","x-secret":true,"description":"An Admin API access token (shpat_…) from a custom app, with only the scopes you need"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "shop", Title: "Shop", Description: "The store's name, plan, currency, time zone and primary domain.", Risk: sdk.RiskRead},
			{Name: "orders", Title: "Orders", Description: "Recent orders: name, payment and fulfilment status, total, refunded amount, items, cancellation. No customer details.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["","open","closed","cancelled","any"]},"financialStatus":{"type":"string","enum":["","paid","pending","authorized","partially_paid","partially_refunded","refunded","voided","unpaid"]},"fulfillmentStatus":{"type":"string","enum":["","unfulfilled","partial","fulfilled"]},"since":{"type":"string","description":"Only orders created on or after this date (YYYY-MM-DD)"},` + page + `}}`)},
			{Name: "order", Title: "Order details", Description: "One order with its line items, payments, fulfilments, and the customer's name, email, phone and shipping address.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["order"],"properties":{` + order + `}}`)},
			{Name: "products", Title: "Products", Description: "Products with status, vendor, type, total inventory and their variants (SKU, price, stock).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Words to look for in titles, vendors and types"},"status":{"type":"string","enum":["","active","draft","archived"]},` + page + `}}`)},
			{Name: "inventory", Title: "Inventory levels", Description: "Stock per location: available, on hand, committed and incoming for each item, optionally only what's running low.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"location":{"type":"string","description":"Location id (numeric or gid://shopify/Location/…); every active location when empty"},"below":{"type":"integer","minimum":1,"description":"Only items with fewer than this many available"},"limit":{"type":"integer","default":50,"minimum":1,"maximum":250}}}`)},
			{Name: "fulfill_order", Title: "Fulfil an order", Description: "Marks every open item of an order as fulfilled, with tracking details if given. The customer is emailed only when notifyCustomer is on; stores that capture payment on fulfilment charge the customer. Undo cancels the fulfilment.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["order"],"properties":{` + order + `,"notifyCustomer":{"type":"boolean","default":false},"trackingNumber":{"type":"string"},"trackingCompany":{"type":"string","description":"Carrier, e.g. UPS or DHL Express"},"trackingUrl":{"type":"string","description":"https link to the carrier's tracking page"}}}`)},
			{Name: "cancel_fulfillment", Title: "Cancel a fulfilment", Description: "Cancels a fulfilment, so its items are open to fulfil again. Can't be undone from here; fulfil the order again instead.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["fulfillment"],"properties":{"fulfillment":{"type":"string","description":"Fulfilment id (numeric or gid://shopify/Fulfillment/…, see order)"}}}`)},
			{Name: "cancel_order", Title: "Cancel an order", Description: "Cancels an order, optionally refunding it to the original payment methods and restocking its items. Can't be undone. The preview shows the total and what happens to the money.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["order"],"properties":{` + order + `,"reason":{"type":"string","enum":["CUSTOMER","DECLINED","FRAUD","INVENTORY","STAFF","OTHER"],"default":"OTHER"},"refund":{"type":"boolean","default":false,"description":"Refund what was paid to the original payment methods"},"restock":{"type":"boolean","default":true},"notifyCustomer":{"type":"boolean","default":false},"staffNote":{"type":"string","maxLength":255}}}`)},
			{Name: "refund_order", Title: "Refund an order", Description: "Refunds an amount of an order to its original payment, fully or partly. Money goes back to the customer and can't be taken back. Items aren't restocked.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["order"],"properties":{` + order + `,"amount":{"type":"string","description":"Like 12.50, in the order's currency; the whole remaining amount when empty"},"note":{"type":"string","maxLength":255},"notifyCustomer":{"type":"boolean","default":false},"idempotencyKey":{"type":"string","description":"Reuse to make a retried refund safe; one is made up otherwise"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	shop := strings.ToLower(strings.TrimSpace(c.Shop))
	shop = strings.TrimPrefix(strings.TrimPrefix(shop, "https://"), "http://")
	shop = strings.TrimSuffix(strings.TrimSuffix(shop, "/"), ".myshopify.com")
	if !shopRe.MatchString(shop) {
		return errors.New("the shop is its myshopify name, like acme or acme.myshopify.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	base := "https://" + shop + ".myshopify.com"
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 30*time.Second)
	}
	ref := c.Token
	api := rest.New(base+"/admin/api/"+APIVersion+"/graphql.json", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if !tokenRe.MatchString(t) {
			return errors.New("the stored token doesn't look like a Shopify Admin API access token (shpat_…)")
		}
		r.Header.Set("X-Shopify-Access-Token", t)
		return nil
	})
	api.HTTP = rest.SameHostOnly(hc)
	m.set.Put(id, &conn{api: api, shop: shop})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// scrub keeps customer emails and phone numbers out of error text.
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
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Shopify refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the access token's app isn't allowed to do this in Shopify")
	case rest.IsStatus(err, http.StatusPaymentRequired):
		return errors.New("the store is frozen until its Shopify bill is paid")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("there's no Shopify store at this name")
	case rest.IsStatus(err, http.StatusLocked):
		return errors.New("the store is locked by Shopify")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Shopify is limiting requests; try again in a moment")
	}
	return err
}

// gql runs one fixed GraphQL document with its variables.
func (c *conn) gql(ctx context.Context, query string, vars map[string]any, out any) error {
	var res struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message    string `json:"message"`
			Extensions struct {
				Code string `json:"code"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	if vars == nil {
		vars = map[string]any{}
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "", nil, map[string]any{"query": query, "variables": vars}, &res); err != nil {
		return friendly(err)
	}
	if len(res.Errors) > 0 {
		e := res.Errors[0]
		switch e.Extensions.Code {
		case "THROTTLED":
			return errors.New("Shopify is limiting requests; try again in a moment")
		case "ACCESS_DENIED":
			return errors.New("the access token is missing a scope for this: " + scrub(e.Message))
		}
		return errors.New("Shopify: " + scrub(e.Message))
	}
	if out != nil && len(res.Data) > 0 {
		if err := json.Unmarshal(res.Data, out); err != nil {
			return errors.New("unexpected answer from Shopify")
		}
	}
	return nil
}

type userError struct {
	Field   []string `json:"field"`
	Message string   `json:"message"`
}

func userErr(es []userError) error {
	if len(es) == 0 {
		return nil
	}
	return errors.New("Shopify refused: " + scrub(es[0].Message))
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
		return errors.New("an id is a number or a gid://shopify/… id")
	}
	*i = ident(n.String())
	return nil
}

// gid turns a numeric id or a gid of this kind into a gid.
func gid(kind, s string) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "gid://shopify/"+kind+"/")
	if !numRe.MatchString(s) {
		return "", false
	}
	return "gid://shopify/" + kind + "/" + s, true
}

// short is the numeric part of a gid.
func short(g string) string {
	if i := strings.LastIndexByte(g, '/'); i >= 0 {
		return g[i+1:]
	}
	return g
}

// Money amounts are decimal strings; they're compared in ten-thousandths.
const scale = 10000

func parseAmount(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if !amountRe.MatchString(s) {
		return 0, errors.New("an amount is like 12.50")
	}
	whole, frac, _ := strings.Cut(s, ".")
	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, err
	}
	frac = (frac + "0000")[:4]
	f, _ := strconv.ParseInt(frac, 10, 64)
	return w*scale + f, nil
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

// decimal renders an amount for the API (no currency).
func decimal(v int64, cur string) string {
	d := digits(cur)
	s := strconv.FormatInt(v/scale, 10)
	if d == 0 {
		return s
	}
	f := fmt.Sprintf("%04d", v%scale)
	return s + "." + f[:d]
}

func pow10(n int) int {
	v := 1
	for ; n > 0; n-- {
		v *= 10
	}
	return v
}

func money(v int64, cur string) string { return decimal(v, cur) + " " + cur }

type moneySet struct {
	ShopMoney struct {
		Amount       string `json:"amount"`
		CurrencyCode string `json:"currencyCode"`
	} `json:"shopMoney"`
}

func (m moneySet) value() int64 {
	v, _ := parseAmount(m.ShopMoney.Amount)
	return v
}

func (m moneySet) String() string {
	if m.ShopMoney.CurrencyCode == "" {
		return ""
	}
	return money(m.value(), m.ShopMoney.CurrencyCode)
}

const shopQuery = `query Shop { shop { name myshopifyDomain currencyCode ianaTimezone primaryDomain { host } plan { publicDisplayName partnerDevelopment shopifyPlus } } }`

type shopInfo struct {
	Shop struct {
		Name            string `json:"name"`
		MyshopifyDomain string `json:"myshopifyDomain"`
		CurrencyCode    string `json:"currencyCode"`
		IanaTimezone    string `json:"ianaTimezone"`
		PrimaryDomain   struct {
			Host string `json:"host"`
		} `json:"primaryDomain"`
		Plan struct {
			PublicDisplayName  string `json:"publicDisplayName"`
			PartnerDevelopment bool   `json:"partnerDevelopment"`
			ShopifyPlus        bool   `json:"shopifyPlus"`
		} `json:"plan"`
	} `json:"shop"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s shopInfo
	if err := c.gql(ctx, shopQuery, nil, &s); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "connected to " + s.Shop.Name
	if p := s.Shop.Plan.PublicDisplayName; p != "" {
		msg += " (" + p + ")"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Status            string `json:"status"`
	FinancialStatus   string `json:"financialStatus"`
	FulfillmentStatus string `json:"fulfillmentStatus"`
	Since             string `json:"since"`
	Limit             int    `json:"limit"`
	After             string `json:"after"`
	Order             ident  `json:"order"`
	Search            string `json:"search"`
	Location          ident  `json:"location"`
	Below             int    `json:"below"`
	Fulfillment       ident  `json:"fulfillment"`
	NotifyCustomer    bool   `json:"notifyCustomer"`
	TrackingNumber    string `json:"trackingNumber"`
	TrackingCompany   string `json:"trackingCompany"`
	TrackingURL       string `json:"trackingUrl"`
	Reason            string `json:"reason"`
	Refund            bool   `json:"refund"`
	Restock           *bool  `json:"restock"`
	StaffNote         string `json:"staffNote"`
	Amount            any    `json:"amount"`
	Note              string `json:"note"`
	IdempotencyKey    string `json:"idempotencyKey"`
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
	if p.After != "" && !cursorRe.MatchString(p.After) {
		return sdk.Result{}, errors.New("after is the endCursor of the previous page")
	}
	switch call.Action {
	case "shop":
		var s shopInfo
		if err := c.gql(ctx, shopQuery, nil, &s); err != nil {
			return sdk.Result{}, err
		}
		x := s.Shop
		return sdk.JSON(map[string]any{"name": x.Name, "domain": x.MyshopifyDomain, "primaryDomain": x.PrimaryDomain.Host, "currency": x.CurrencyCode,
			"timeZone": x.IanaTimezone, "plan": x.Plan.PublicDisplayName, "shopifyPlus": x.Plan.ShopifyPlus, "development": x.Plan.PartnerDevelopment})
	case "orders":
		return c.orders(ctx, p)
	case "order":
		g, err := c.resolveOrder(ctx, string(p.Order))
		if err != nil {
			return sdk.Result{}, err
		}
		return c.orderDetail(ctx, g)
	case "products":
		return c.products(ctx, p)
	case "inventory":
		return c.inventory(ctx, p)
	case "fulfill_order":
		return c.fulfill(ctx, call, p)
	case "cancel_fulfillment":
		return c.cancelFulfillment(ctx, call, p)
	case "cancel_order":
		return c.cancelOrder(ctx, call, p)
	case "refund_order":
		return c.refund(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type pageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
}

func pageOut(items []map[string]any, pi pageInfo) map[string]any {
	out := map[string]any{"items": items, "hasMore": pi.HasNextPage}
	if pi.HasNextPage {
		out["after"] = pi.EndCursor
	}
	return out
}

const ordersQuery = `query Orders($first: Int!, $after: String, $query: String) {
  orders(first: $first, after: $after, query: $query, sortKey: CREATED_AT, reverse: true) {
    nodes { id name createdAt cancelledAt cancelReason test displayFinancialStatus displayFulfillmentStatus subtotalLineItemsQuantity
      totalPriceSet { shopMoney { amount currencyCode } } totalRefundedSet { shopMoney { amount currencyCode } } }
    pageInfo { hasNextPage endCursor }
  }
}`

type orderRow struct {
	ID                        string   `json:"id"`
	Name                      string   `json:"name"`
	CreatedAt                 string   `json:"createdAt"`
	CancelledAt               *string  `json:"cancelledAt"`
	CancelReason              *string  `json:"cancelReason"`
	Test                      bool     `json:"test"`
	DisplayFinancialStatus    string   `json:"displayFinancialStatus"`
	DisplayFulfillmentStatus  string   `json:"displayFulfillmentStatus"`
	SubtotalLineItemsQuantity int      `json:"subtotalLineItemsQuantity"`
	TotalPriceSet             moneySet `json:"totalPriceSet"`
	TotalRefundedSet          moneySet `json:"totalRefundedSet"`
}

func orderOut(o orderRow) map[string]any {
	out := map[string]any{"id": short(o.ID), "name": o.Name, "created": o.CreatedAt, "financialStatus": o.DisplayFinancialStatus,
		"fulfillmentStatus": o.DisplayFulfillmentStatus, "items": o.SubtotalLineItemsQuantity, "total": o.TotalPriceSet.String()}
	if o.TotalRefundedSet.value() > 0 {
		out["refunded"] = o.TotalRefundedSet.String()
	}
	if o.CancelledAt != nil {
		out["cancelledAt"] = *o.CancelledAt
		if o.CancelReason != nil {
			out["cancelReason"] = *o.CancelReason
		}
	}
	if o.Test {
		out["test"] = true
	}
	return out
}

func (c *conn) orders(ctx context.Context, p input) (sdk.Result, error) {
	var terms []string
	if p.Status != "" {
		if !orderStatus[p.Status] {
			return sdk.Result{}, fmt.Errorf("status %q isn't an order status", p.Status)
		}
		terms = append(terms, "status:"+p.Status)
	}
	if p.FinancialStatus != "" {
		if !financialStatus[p.FinancialStatus] {
			return sdk.Result{}, fmt.Errorf("financialStatus %q isn't a payment status", p.FinancialStatus)
		}
		terms = append(terms, "financial_status:"+p.FinancialStatus)
	}
	if p.FulfillmentStatus != "" {
		if !fulfillmentStatus[p.FulfillmentStatus] {
			return sdk.Result{}, fmt.Errorf("fulfillmentStatus %q isn't a fulfilment status", p.FulfillmentStatus)
		}
		terms = append(terms, "fulfillment_status:"+p.FulfillmentStatus)
	}
	if p.Since != "" {
		if _, err := time.Parse("2006-01-02", p.Since); err != nil || !dateRe.MatchString(p.Since) {
			return sdk.Result{}, errors.New("since is a date like 2026-11-01")
		}
		terms = append(terms, "created_at:>="+p.Since)
	}
	vars := map[string]any{"first": limit(p.Limit, 20, 100)}
	if p.After != "" {
		vars["after"] = p.After
	}
	if len(terms) > 0 {
		vars["query"] = strings.Join(terms, " ")
	}
	var d struct {
		Orders struct {
			Nodes    []orderRow `json:"nodes"`
			PageInfo pageInfo   `json:"pageInfo"`
		} `json:"orders"`
	}
	if err := c.gql(ctx, ordersQuery, vars, &d); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, o := range d.Orders.Nodes {
		out = append(out, orderOut(o))
	}
	return sdk.JSON(pageOut(out, d.Orders.PageInfo))
}

const orderByNameQuery = `query OrderByName($query: String!) { orders(first: 2, query: $query) { nodes { id name } } }`

// resolveOrder turns an order id, gid or #name into its gid.
func (c *conn) resolveOrder(ctx context.Context, s string) (string, error) {
	s = strings.TrimSpace(s)
	if g, ok := gid("Order", s); ok {
		return g, nil
	}
	if !nameRe.MatchString(s) {
		return "", errors.New("the order is its id (numeric or gid://shopify/Order/…) or its name, like #1001")
	}
	var d struct {
		Orders struct {
			Nodes []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"nodes"`
		} `json:"orders"`
	}
	if err := c.gql(ctx, orderByNameQuery, map[string]any{"query": "name:" + strconv.Quote(s)}, &d); err != nil {
		return "", err
	}
	for _, o := range d.Orders.Nodes {
		if o.Name == s {
			return o.ID, nil
		}
	}
	return "", fmt.Errorf("there's no order %s", s)
}

const orderQuery = `query Order($id: ID!) {
  order(id: $id) {
    id name createdAt cancelledAt cancelReason closed test displayFinancialStatus displayFulfillmentStatus subtotalLineItemsQuantity email phone note
    totalPriceSet { shopMoney { amount currencyCode } } totalRefundedSet { shopMoney { amount currencyCode } } totalReceivedSet { shopMoney { amount currencyCode } }
    customer { id displayName }
    shippingAddress { name company address1 address2 city provinceCode zip countryCodeV2 phone }
    lineItems(first: 50) { nodes { title sku quantity currentQuantity variantTitle originalUnitPriceSet { shopMoney { amount currencyCode } } } }
    fulfillments(first: 20) { id name status createdAt trackingInfo(first: 3) { company number url } }
    fulfillmentOrders(first: 20) { nodes { id status lineItems(first: 50) { nodes { remainingQuantity } } } }
    transactions(first: 50) { id kind status gateway createdAt test amountSet { shopMoney { amount currencyCode } } parentTransaction { id } }
  }
}`

type transaction struct {
	ID                string   `json:"id"`
	Kind              string   `json:"kind"`
	Status            string   `json:"status"`
	Gateway           string   `json:"gateway"`
	CreatedAt         string   `json:"createdAt"`
	Test              bool     `json:"test"`
	AmountSet         moneySet `json:"amountSet"`
	ParentTransaction *struct {
		ID string `json:"id"`
	} `json:"parentTransaction"`
}

type fulfillmentOrder struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	LineItems struct {
		Nodes []struct {
			RemainingQuantity int `json:"remainingQuantity"`
		} `json:"nodes"`
	} `json:"lineItems"`
}

type orderFull struct {
	orderRow
	Closed           bool     `json:"closed"`
	Email            string   `json:"email"`
	Phone            string   `json:"phone"`
	Note             string   `json:"note"`
	TotalReceivedSet moneySet `json:"totalReceivedSet"`
	Customer         *struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	} `json:"customer"`
	ShippingAddress *struct {
		Name         string `json:"name"`
		Company      string `json:"company"`
		Address1     string `json:"address1"`
		Address2     string `json:"address2"`
		City         string `json:"city"`
		ProvinceCode string `json:"provinceCode"`
		Zip          string `json:"zip"`
		CountryCode  string `json:"countryCodeV2"`
		Phone        string `json:"phone"`
	} `json:"shippingAddress"`
	LineItems struct {
		Nodes []struct {
			Title                string   `json:"title"`
			SKU                  string   `json:"sku"`
			Quantity             int      `json:"quantity"`
			CurrentQuantity      int      `json:"currentQuantity"`
			VariantTitle         string   `json:"variantTitle"`
			OriginalUnitPriceSet moneySet `json:"originalUnitPriceSet"`
		} `json:"nodes"`
	} `json:"lineItems"`
	Fulfillments []struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		Status       string `json:"status"`
		CreatedAt    string `json:"createdAt"`
		TrackingInfo []struct {
			Company string `json:"company"`
			Number  string `json:"number"`
			URL     string `json:"url"`
		} `json:"trackingInfo"`
	} `json:"fulfillments"`
	FulfillmentOrders struct {
		Nodes []fulfillmentOrder `json:"nodes"`
	} `json:"fulfillmentOrders"`
	Transactions []transaction `json:"transactions"`
}

func (c *conn) getOrder(ctx context.Context, g string) (orderFull, error) {
	var d struct {
		Order *orderFull `json:"order"`
	}
	if err := c.gql(ctx, orderQuery, map[string]any{"id": g}, &d); err != nil {
		return orderFull{}, err
	}
	if d.Order == nil || d.Order.ID == "" {
		return orderFull{}, fmt.Errorf("there's no order %s", short(g))
	}
	return *d.Order, nil
}

func (c *conn) orderDetail(ctx context.Context, g string) (sdk.Result, error) {
	o, err := c.getOrder(ctx, g)
	if err != nil {
		return sdk.Result{}, err
	}
	out := orderOut(o.orderRow)
	out["closed"] = o.Closed
	out["email"], out["phone"] = o.Email, o.Phone
	if o.Note != "" {
		out["note"] = o.Note
	}
	if o.Customer != nil {
		out["customer"] = map[string]any{"id": short(o.Customer.ID), "name": o.Customer.DisplayName}
	}
	if a := o.ShippingAddress; a != nil {
		out["shippingAddress"] = map[string]any{"name": a.Name, "company": a.Company, "address1": a.Address1, "address2": a.Address2, "city": a.City,
			"province": a.ProvinceCode, "zip": a.Zip, "country": a.CountryCode, "phone": a.Phone}
	}
	items := []map[string]any{}
	for _, li := range o.LineItems.Nodes {
		items = append(items, map[string]any{"title": li.Title, "variant": li.VariantTitle, "sku": li.SKU, "quantity": li.Quantity, "currentQuantity": li.CurrentQuantity, "unitPrice": li.OriginalUnitPriceSet.String()})
	}
	out["lineItems"] = items
	fs := []map[string]any{}
	for _, f := range o.Fulfillments {
		row := map[string]any{"id": short(f.ID), "name": f.Name, "status": f.Status, "created": f.CreatedAt}
		var tr []map[string]any
		for _, t := range f.TrackingInfo {
			tr = append(tr, map[string]any{"company": t.Company, "number": t.Number, "url": t.URL})
		}
		if len(tr) > 0 {
			row["tracking"] = tr
		}
		fs = append(fs, row)
	}
	out["fulfillments"] = fs
	ts := []map[string]any{}
	for _, t := range o.Transactions {
		ts = append(ts, map[string]any{"kind": t.Kind, "status": t.Status, "gateway": t.Gateway, "amount": t.AmountSet.String(), "created": t.CreatedAt})
	}
	out["transactions"] = ts
	out["received"] = o.TotalReceivedSet.String()
	return sdk.JSON(out)
}

const productsQuery = `query Products($first: Int!, $after: String, $query: String) {
  products(first: $first, after: $after, query: $query, sortKey: UPDATED_AT, reverse: true) {
    nodes { id title handle status vendor productType totalInventory tracksInventory updatedAt
      variants(first: 20) { nodes { id title sku price inventoryQuantity } } }
    pageInfo { hasNextPage endCursor }
  }
}`

func (c *conn) products(ctx context.Context, p input) (sdk.Result, error) {
	var terms []string
	if s := strings.TrimSpace(p.Search); s != "" {
		if !searchRe.MatchString(s) {
			return sdk.Result{}, errors.New("search is a few plain words")
		}
		terms = append(terms, strconv.Quote(s))
	}
	if p.Status != "" {
		if !productStatus[p.Status] {
			return sdk.Result{}, fmt.Errorf("status %q isn't a product status", p.Status)
		}
		terms = append(terms, "status:"+p.Status)
	}
	vars := map[string]any{"first": limit(p.Limit, 20, 100)}
	if p.After != "" {
		vars["after"] = p.After
	}
	if len(terms) > 0 {
		vars["query"] = strings.Join(terms, " ")
	}
	var d struct {
		Products struct {
			Nodes []struct {
				ID              string `json:"id"`
				Title           string `json:"title"`
				Handle          string `json:"handle"`
				Status          string `json:"status"`
				Vendor          string `json:"vendor"`
				ProductType     string `json:"productType"`
				TotalInventory  int    `json:"totalInventory"`
				TracksInventory bool   `json:"tracksInventory"`
				UpdatedAt       string `json:"updatedAt"`
				Variants        struct {
					Nodes []struct {
						ID                string `json:"id"`
						Title             string `json:"title"`
						SKU               string `json:"sku"`
						Price             string `json:"price"`
						InventoryQuantity *int   `json:"inventoryQuantity"`
					} `json:"nodes"`
				} `json:"variants"`
			} `json:"nodes"`
			PageInfo pageInfo `json:"pageInfo"`
		} `json:"products"`
	}
	if err := c.gql(ctx, productsQuery, vars, &d); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, x := range d.Products.Nodes {
		vs := []map[string]any{}
		for _, v := range x.Variants.Nodes {
			row := map[string]any{"id": short(v.ID), "title": v.Title, "sku": v.SKU, "price": v.Price}
			if v.InventoryQuantity != nil {
				row["inventory"] = *v.InventoryQuantity
			}
			vs = append(vs, row)
		}
		row := map[string]any{"id": short(x.ID), "title": x.Title, "handle": x.Handle, "status": x.Status, "vendor": x.Vendor, "type": x.ProductType, "updated": x.UpdatedAt, "variants": vs}
		if x.TracksInventory {
			row["totalInventory"] = x.TotalInventory
		}
		out = append(out, row)
	}
	return sdk.JSON(pageOut(out, d.Products.PageInfo))
}

const levelFields = `id name isActive inventoryLevels(first: $first) { nodes { quantities(names: $names) { name quantity } item { id sku tracked variant { displayName } } } }`

var (
	locationsQuery = `query Locations($first: Int!, $names: [String!]!) { locations(first: 20) { nodes { ` + levelFields + ` } } }`
	locationQuery  = `query Location($id: ID!, $first: Int!, $names: [String!]!) { location(id: $id) { ` + levelFields + ` } }`
)

type location struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	IsActive        bool   `json:"isActive"`
	InventoryLevels struct {
		Nodes []struct {
			Quantities []struct {
				Name     string `json:"name"`
				Quantity int    `json:"quantity"`
			} `json:"quantities"`
			Item struct {
				ID      string `json:"id"`
				SKU     string `json:"sku"`
				Tracked bool   `json:"tracked"`
				Variant *struct {
					DisplayName string `json:"displayName"`
				} `json:"variant"`
			} `json:"item"`
		} `json:"nodes"`
	} `json:"inventoryLevels"`
}

func (c *conn) inventory(ctx context.Context, p input) (sdk.Result, error) {
	if p.Below < 0 {
		return sdk.Result{}, errors.New("below is a positive number")
	}
	vars := map[string]any{"first": limit(p.Limit, 50, 250), "names": []string{"available", "on_hand", "committed", "incoming"}}
	var locs []location
	if p.Location != "" {
		g, ok := gid("Location", string(p.Location))
		if !ok {
			return sdk.Result{}, errors.New("the location is its id (numeric or gid://shopify/Location/…)")
		}
		vars["id"] = g
		var d struct {
			Location *location `json:"location"`
		}
		if err := c.gql(ctx, locationQuery, vars, &d); err != nil {
			return sdk.Result{}, err
		}
		if d.Location == nil {
			return sdk.Result{}, fmt.Errorf("there's no location %s", short(g))
		}
		locs = append(locs, *d.Location)
	} else {
		var d struct {
			Locations struct {
				Nodes []location `json:"nodes"`
			} `json:"locations"`
		}
		if err := c.gql(ctx, locationsQuery, vars, &d); err != nil {
			return sdk.Result{}, err
		}
		for _, l := range d.Locations.Nodes {
			if l.IsActive {
				locs = append(locs, l)
			}
		}
	}
	out := []map[string]any{}
	for _, l := range locs {
		items := []map[string]any{}
		for _, lv := range l.InventoryLevels.Nodes {
			q := map[string]int{}
			for _, x := range lv.Quantities {
				q[x.Name] = x.Quantity
			}
			if p.Below > 0 && (!lv.Item.Tracked || q["available"] >= p.Below) {
				continue
			}
			row := map[string]any{"item": short(lv.Item.ID), "sku": lv.Item.SKU, "available": q["available"], "onHand": q["on_hand"], "committed": q["committed"], "incoming": q["incoming"]}
			if lv.Item.Variant != nil {
				row["name"] = lv.Item.Variant.DisplayName
			}
			if !lv.Item.Tracked {
				row["tracked"] = false
			}
			items = append(items, row)
		}
		out = append(out, map[string]any{"location": short(l.ID), "name": l.Name, "active": l.IsActive, "items": items})
	}
	return sdk.JSON(map[string]any{"locations": out})
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func newKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "conduit-" + hex.EncodeToString(b)
}

const fulfillMutation = `mutation Fulfill($fulfillment: FulfillmentInput!) {
  fulfillmentCreate(fulfillment: $fulfillment) { fulfillment { id name status } userErrors { field message } }
}`

func (c *conn) fulfill(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	var tracking map[string]any
	if n := strings.TrimSpace(p.TrackingNumber); n != "" {
		if !trackRe.MatchString(n) {
			return sdk.Result{}, errors.New("the tracking number is letters, digits and dashes")
		}
		tracking = map[string]any{"number": n}
	}
	if co := strings.TrimSpace(p.TrackingCompany); co != "" {
		if !trackRe.MatchString(co) {
			return sdk.Result{}, errors.New("the tracking company is a carrier's name, like UPS")
		}
		if tracking == nil {
			tracking = map[string]any{}
		}
		tracking["company"] = co
	}
	if u := strings.TrimSpace(p.TrackingURL); u != "" {
		pu, err := url.Parse(u)
		if err != nil || pu.Scheme != "https" || pu.Host == "" || pu.User != nil || len(u) > 500 {
			return sdk.Result{}, errors.New("the tracking link is an https address")
		}
		if tracking == nil {
			tracking = map[string]any{}
		}
		tracking["url"] = u
	}
	g, err := c.resolveOrder(ctx, string(p.Order))
	if err != nil {
		return sdk.Result{}, err
	}
	o, err := c.getOrder(ctx, g)
	if err != nil {
		return sdk.Result{}, err
	}
	if o.CancelledAt != nil {
		return sdk.Result{}, fmt.Errorf("order %s is cancelled", o.Name)
	}
	var open []map[string]any
	items, held := 0, 0
	for _, fo := range o.FulfillmentOrders.Nodes {
		switch fo.Status {
		case "OPEN", "IN_PROGRESS":
			open = append(open, map[string]any{"fulfillmentOrderId": fo.ID})
			for _, li := range fo.LineItems.Nodes {
				items += li.RemainingQuantity
			}
		case "ON_HOLD", "SCHEDULED":
			held++
		}
	}
	if len(open) == 0 {
		if held > 0 {
			return sdk.Result{}, fmt.Errorf("order %s's items are on hold or scheduled; release them in Shopify first", o.Name)
		}
		return sdk.JSON(map[string]any{"order": o.Name, "fulfillmentStatus": o.DisplayFulfillmentStatus, "note": "nothing to change: nothing is left to fulfil"})
	}
	notify := "the customer isn't notified"
	if p.NotifyCustomer {
		notify = "the customer is emailed"
	}
	if call.DryRun {
		mode := ""
		if o.Test {
			mode = ", test order"
		}
		before := map[string]any{"fulfillmentStatus": o.DisplayFulfillmentStatus, "financialStatus": o.DisplayFinancialStatus, "total": o.TotalPriceSet.String()}
		after := map[string]any{"fulfilledItems": items, "notifyCustomer": p.NotifyCustomer}
		if tracking != nil {
			after["tracking"] = tracking
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Fulfil %d items of order %s (%s%s)", items, o.Name, notify, mode),
			Changes: []sdk.Change{{Target: "order " + o.Name, Op: "fulfill", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	in := map[string]any{"lineItemsByFulfillmentOrder": open, "notifyCustomer": p.NotifyCustomer}
	if tracking != nil {
		in["trackingInfo"] = tracking
	}
	var d struct {
		FulfillmentCreate struct {
			Fulfillment *struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"fulfillment"`
			UserErrors []userError `json:"userErrors"`
		} `json:"fulfillmentCreate"`
	}
	if err := c.gql(ctx, fulfillMutation, map[string]any{"fulfillment": in}, &d); err != nil {
		return sdk.Result{}, err
	}
	if err := userErr(d.FulfillmentCreate.UserErrors); err != nil {
		return sdk.Result{}, err
	}
	f := d.FulfillmentCreate.Fulfillment
	if f == nil || f.ID == "" {
		return sdk.Result{}, errors.New("Shopify didn't create the fulfilment")
	}
	res, err := sdk.JSON(map[string]any{"order": o.Name, "fulfillment": short(f.ID), "name": f.Name, "status": f.Status, "items": items, "customerNotified": p.NotifyCustomer})
	res.Undo = sdk.UndoWith("cancel_fulfillment", map[string]string{"fulfillment": short(f.ID)}, "Cancel fulfilment "+f.Name+" of order "+o.Name)
	return res, err
}

const fulfillmentQuery = `query Fulfillment($id: ID!) { fulfillment(id: $id) { id name status order { name } } }`

const cancelFulfillmentMutation = `mutation CancelFulfillment($id: ID!) { fulfillmentCancel(id: $id) { fulfillment { id status } userErrors { field message } } }`

func (c *conn) cancelFulfillment(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	g, ok := gid("Fulfillment", string(p.Fulfillment))
	if !ok {
		return sdk.Result{}, errors.New("the fulfilment is its id (numeric or gid://shopify/Fulfillment/…, see order)")
	}
	var d struct {
		Fulfillment *struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
			Order  struct {
				Name string `json:"name"`
			} `json:"order"`
		} `json:"fulfillment"`
	}
	if err := c.gql(ctx, fulfillmentQuery, map[string]any{"id": g}, &d); err != nil {
		return sdk.Result{}, err
	}
	f := d.Fulfillment
	if f == nil || f.ID == "" {
		return sdk.Result{}, fmt.Errorf("there's no fulfilment %s", short(g))
	}
	if f.Status == "CANCELLED" {
		return sdk.JSON(map[string]any{"fulfillment": short(f.ID), "order": f.Order.Name, "note": "nothing to change: it's cancelled already"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Cancel fulfilment %s of order %s: its items are open to fulfil again", f.Name, f.Order.Name),
			Changes: []sdk.Change{{Target: "fulfillment " + f.Name, Op: "cancel", Before: mustJSON(map[string]string{"status": f.Status}), After: mustJSON(map[string]string{"status": "CANCELLED"})}}}}, nil
	}
	var r struct {
		FulfillmentCancel struct {
			Fulfillment *struct {
				Status string `json:"status"`
			} `json:"fulfillment"`
			UserErrors []userError `json:"userErrors"`
		} `json:"fulfillmentCancel"`
	}
	if err := c.gql(ctx, cancelFulfillmentMutation, map[string]any{"id": f.ID}, &r); err != nil {
		return sdk.Result{}, err
	}
	if err := userErr(r.FulfillmentCancel.UserErrors); err != nil {
		return sdk.Result{}, err
	}
	status := "CANCELLED"
	if r.FulfillmentCancel.Fulfillment != nil {
		status = r.FulfillmentCancel.Fulfillment.Status
	}
	return sdk.JSON(map[string]any{"fulfillment": short(f.ID), "order": f.Order.Name, "status": status})
}

const cancelOrderMutation = `mutation CancelOrder($orderId: ID!, $reason: OrderCancelReason!, $restock: Boolean!, $notifyCustomer: Boolean, $refundMethod: OrderCancelRefundMethodInput, $staffNote: String) {
  orderCancel(orderId: $orderId, reason: $reason, restock: $restock, notifyCustomer: $notifyCustomer, refundMethod: $refundMethod, staffNote: $staffNote) {
    job { id done } orderCancelUserErrors { field message code }
  }
}`

func (c *conn) cancelOrder(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	reason := strings.ToUpper(strings.TrimSpace(p.Reason))
	if reason == "" {
		reason = "OTHER"
	}
	if !cancelReasons[reason] {
		return sdk.Result{}, fmt.Errorf("reason %q isn't one of CUSTOMER, DECLINED, FRAUD, INVENTORY, STAFF, OTHER", p.Reason)
	}
	note := strings.TrimSpace(p.StaffNote)
	if len(note) > 255 || strings.ContainsAny(note, "\x00") {
		return sdk.Result{}, errors.New("the staff note is at most 255 characters")
	}
	restock := true
	if p.Restock != nil {
		restock = *p.Restock
	}
	g, err := c.resolveOrder(ctx, string(p.Order))
	if err != nil {
		return sdk.Result{}, err
	}
	o, err := c.getOrder(ctx, g)
	if err != nil {
		return sdk.Result{}, err
	}
	if o.CancelledAt != nil {
		return sdk.JSON(map[string]any{"order": o.Name, "cancelledAt": *o.CancelledAt, "note": "nothing to change: it's cancelled already"})
	}
	pay := "payments kept (authorised payments are voided)"
	if p.Refund {
		pay = "refunds " + o.TotalReceivedSet.String() + " to the original payment methods"
	}
	if call.DryRun {
		mode := ""
		if o.Test {
			mode = ", test order"
		}
		before := map[string]any{"financialStatus": o.DisplayFinancialStatus, "fulfillmentStatus": o.DisplayFulfillmentStatus, "total": o.TotalPriceSet.String(), "received": o.TotalReceivedSet.String()}
		after := map[string]any{"cancelled": true, "reason": reason, "refund": p.Refund, "restock": restock, "notifyCustomer": p.NotifyCustomer}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Cancel order %s (total %s): %s%s", o.Name, o.TotalPriceSet.String(), pay, mode),
			Changes: []sdk.Change{{Target: "order " + o.Name, Op: "cancel", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	vars := map[string]any{"orderId": o.ID, "reason": reason, "restock": restock, "notifyCustomer": p.NotifyCustomer}
	if p.Refund {
		vars["refundMethod"] = map[string]any{"originalPaymentMethodsRefund": true}
	}
	if note != "" {
		vars["staffNote"] = note
	}
	var d struct {
		OrderCancel struct {
			Job *struct {
				ID   string `json:"id"`
				Done bool   `json:"done"`
			} `json:"job"`
			UserErrors []userError `json:"orderCancelUserErrors"`
		} `json:"orderCancel"`
	}
	if err := c.gql(ctx, cancelOrderMutation, vars, &d); err != nil {
		return sdk.Result{}, err
	}
	if err := userErr(d.OrderCancel.UserErrors); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"order": o.Name, "cancelling": true, "refund": p.Refund, "restock": restock, "customerNotified": p.NotifyCustomer}
	if j := d.OrderCancel.Job; j != nil {
		out["done"] = j.Done
	}
	return sdk.JSON(out)
}

const refundMutation = `mutation Refund($input: RefundInput!, $idempotencyKey: String!) {
  refundCreate(input: $input) @idempotent(key: $idempotencyKey) {
    refund { id totalRefundedSet { shopMoney { amount currencyCode } } }
    order { displayFinancialStatus totalRefundedSet { shopMoney { amount currencyCode } } }
    userErrors { field message }
  }
}`

func (c *conn) refund(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
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
	note := strings.TrimSpace(p.Note)
	if len(note) > 255 {
		return sdk.Result{}, errors.New("the note is at most 255 characters")
	}
	if p.IdempotencyKey != "" && !idemRe.MatchString(p.IdempotencyKey) {
		return sdk.Result{}, errors.New("the idempotency key is 8 to 128 letters, digits, - or _")
	}
	g, err := c.resolveOrder(ctx, string(p.Order))
	if err != nil {
		return sdk.Result{}, err
	}
	o, err := c.getOrder(ctx, g)
	if err != nil {
		return sdk.Result{}, err
	}
	// What's left: successful payments minus successful refunds. The refund
	// goes to the largest payment, so it can't exceed that one.
	var paid, refunded int64
	var parent *transaction
	cur := o.TotalPriceSet.ShopMoney.CurrencyCode
	for i, t := range o.Transactions {
		if t.Status != "SUCCESS" {
			continue
		}
		switch t.Kind {
		case "SALE", "CAPTURE":
			paid += t.AmountSet.value()
			if parent == nil || t.AmountSet.value() > parent.AmountSet.value() {
				parent = &o.Transactions[i]
			}
		case "REFUND":
			refunded += t.AmountSet.value()
		}
	}
	left := paid - refunded
	if parent == nil || left <= 0 {
		return sdk.Result{}, fmt.Errorf("order %s has nothing left to refund", o.Name)
	}
	if parent.AmountSet.ShopMoney.CurrencyCode != "" {
		cur = parent.AmountSet.ShopMoney.CurrencyCode
	}
	var fromParent int64
	for _, t := range o.Transactions {
		if t.Status == "SUCCESS" && t.Kind == "REFUND" && t.ParentTransaction != nil && t.ParentTransaction.ID == parent.ID {
			fromParent += t.AmountSet.value()
		}
	}
	room := parent.AmountSet.value() - fromParent
	if room < left {
		left = room
	}
	if left <= 0 {
		return sdk.Result{}, fmt.Errorf("order %s's payment is fully refunded; refund its other payments in Shopify", o.Name)
	}
	amount := want
	if amount == 0 {
		amount = left
	}
	if amount > left {
		return sdk.Result{}, fmt.Errorf("only %s of %s is left to refund on this payment", money(left, cur), money(parent.AmountSet.value(), cur))
	}
	if step := int64(scale / pow10(digits(cur))); amount%step != 0 {
		return sdk.Result{}, fmt.Errorf("%s has %d decimals", cur, digits(cur))
	}
	kind := "Full refund"
	if amount < left || refunded > 0 {
		kind = "Partial refund"
	}
	if call.DryRun {
		mode := "LIVE"
		if o.Test || parent.Test {
			mode = "test order"
		}
		before := map[string]any{"total": o.TotalPriceSet.String(), "paid": money(paid, cur), "refunded": money(refunded, cur), "financialStatus": o.DisplayFinancialStatus}
		after := map[string]any{"refund": money(amount, cur), "gateway": parent.Gateway, "refundedAfter": money(refunded+amount, cur), "notifyCustomer": p.NotifyCustomer}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s of %s on order %s via %s (%s)", kind, money(amount, cur), o.Name, parent.Gateway, mode),
			Changes: []sdk.Change{{Target: "order " + o.Name, Op: "refund", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	key := p.IdempotencyKey
	if key == "" {
		key = newKey()
	}
	in := map[string]any{"orderId": o.ID, "notify": p.NotifyCustomer, "transactions": []map[string]any{{
		"orderId": o.ID, "parentId": parent.ID, "kind": "REFUND", "gateway": parent.Gateway, "amount": decimal(amount, cur)}}}
	if note != "" {
		in["note"] = note
	}
	var d struct {
		RefundCreate struct {
			Refund *struct {
				ID               string   `json:"id"`
				TotalRefundedSet moneySet `json:"totalRefundedSet"`
			} `json:"refund"`
			Order *struct {
				DisplayFinancialStatus string   `json:"displayFinancialStatus"`
				TotalRefundedSet       moneySet `json:"totalRefundedSet"`
			} `json:"order"`
			UserErrors []userError `json:"userErrors"`
		} `json:"refundCreate"`
	}
	if err := c.gql(ctx, refundMutation, map[string]any{"input": in, "idempotencyKey": key}, &d); err != nil {
		return sdk.Result{}, err
	}
	if err := userErr(d.RefundCreate.UserErrors); err != nil {
		return sdk.Result{}, err
	}
	if d.RefundCreate.Refund == nil {
		return sdk.Result{}, errors.New("Shopify didn't create the refund")
	}
	out := map[string]any{"order": o.Name, "refund": short(d.RefundCreate.Refund.ID), "amount": money(amount, cur), "idempotencyKey": key}
	if ro := d.RefundCreate.Order; ro != nil {
		out["financialStatus"] = ro.DisplayFinancialStatus
		out["refundedTotal"] = ro.TotalRefundedSet.String()
	}
	return sdk.JSON(out)
}
