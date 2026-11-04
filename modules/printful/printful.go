// Package printful works with a Printful store through its API and a
// private token: the store, orders and their fulfilment status, shipping
// rates, and confirming a draft order for fulfilment.
//
// Confirming an order charges the card on the Printful account, so it's
// destructive and its preview shows the exact cost in the order's currency.
// Recipients' names, emails, phones and addresses appear only in order,
// which is sensitive.
package printful

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

// Config is one Printful store (or account).
type Config struct {
	Token string `json:"token"` // secret:// private token
	Store string `json:"store"` // store id, for an account-level token
}

const defaultBase = "https://api.printful.com"

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.printful.com (tests).
	Base string
}

// New returns the Printful module.
func New() *Module { return &Module{} }

var (
	tokenRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{20,128}$`)
	storeRe    = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	idRe       = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	externalRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	countryRe  = regexp.MustCompile(`^[A-Z]{2}$`)
	stateRe    = regexp.MustCompile(`^[A-Z0-9]{1,3}$`)
	zipRe      = regexp.MustCompile(`^[A-Za-z0-9 -]{1,12}$`)
	cityRe     = regexp.MustCompile(`^[\p{L}\p{N} '.-]{1,64}$`)
	curRe      = regexp.MustCompile(`^[A-Z]{3}$`)
	amountRe   = regexp.MustCompile(`^[0-9]{1,12}(\.[0-9]{1,4})?$`)
	emailRe    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	phoneRe    = regexp.MustCompile(`\+?[0-9][0-9 ().-]{6,}[0-9]`)
	statuses   = map[string]bool{"draft": true, "pending": true, "failed": true, "canceled": true, "inprocess": true, "onhold": true, "partial": true, "fulfilled": true, "archived": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	order := `{"type":"object","required":["order"],"properties":{"order":{"type":"string","description":"Order id, or @ and your external id (like @1001)"}}}`
	return sdk.Manifest{
		ID: "printful", Name: "Printful", Version: "0.1.0", Category: "Productivity", Icon: "package",
		Description: "A Printful store: orders, their status and tracking, shipping rates; confirm a draft order (which charges your card) with a preview.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A private token from the Printful Developers portal, with only the scopes you need (orders, stores)"},
			"store":{"type":"string","description":"Store id, needed when the token is for the whole account rather than one store"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "store", Title: "Store", Description: "The stores the token reaches: id, name and type.", Risk: sdk.RiskRead},
			{Name: "orders", Title: "Orders", Description: "Recent orders: id, external id, status, created, item count, cost and retail total, shipments. No recipient details.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["","draft","pending","failed","canceled","inprocess","onhold","partial","fulfilled","archived"]},"limit":{"type":"integer","default":20,"minimum":1,"maximum":100},"offset":{"type":"integer","minimum":0}}}`)},
			{Name: "order_status", Title: "Order status", Description: "Where an order is: status, costs, and each shipment's carrier, tracking number and dates. No recipient details.", Risk: sdk.RiskRead, Input: sdk.Schema(order)},
			{Name: "order", Title: "Order details", Description: "One order with its items, costs, shipments, and the recipient's name, email, phone and address.", Risk: sdk.RiskRead, Sensitive: true, Input: sdk.Schema(order)},
			{Name: "shipping_rates", Title: "Shipping rates", Description: "What shipping would cost and how long it takes for some variants to a country (and state, city, zip). Nothing is ordered.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["country","items"],"properties":{"country":{"type":"string","description":"Two-letter country code, like US or DE"},"state":{"type":"string","description":"State code, required for US, CA and AU"},"city":{"type":"string"},"zip":{"type":"string"},"currency":{"type":"string","description":"Three-letter currency code; the store's when empty"},"items":{"type":"array","minItems":1,"maxItems":50,"items":{"type":"object","required":["variant","quantity"],"properties":{"variant":{"type":"integer","minimum":1,"description":"Printful catalog variant id"},"quantity":{"type":"integer","minimum":1,"maximum":1000}}}}}}`)},
			{Name: "confirm_order", Title: "Confirm a draft order", Description: "Sends a draft order to fulfilment. Printful charges the card on your account the order's cost; the preview shows the exact amount, which the run must give as expectedCost (refused if the cost changed since). Can't be undone from here.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["order"],"properties":{"order":{"type":"string","description":"Order id, or @ and your external id (like @1001)"},"expectedCost":{"type":"string","description":"The charge the preview shows, like 25.22 EUR; needed to confirm, refused if the order's cost changed since"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the token in the vault and enter its secret:// reference")
	}
	store := strings.TrimSpace(c.Store)
	if store != "" && !storeRe.MatchString(store) {
		return errors.New("the store is its numeric id")
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
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if !tokenRe.MatchString(t) {
			return errors.New("the stored token doesn't look like a Printful private token")
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	if store != "" {
		api.Header.Set("X-PF-Store-Id", store)
	}
	api.HTTP = rest.SameHostOnly(hc)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// scrub keeps credentials, emails and phone numbers, and any of the
// recipient details in hide, out of error text, then shortens it.
func scrub(s string, hide ...string) string {
	s = rest.Redact(s)
	for _, v := range hide {
		if v = strings.TrimSpace(v); len(v) >= 3 {
			s = strings.ReplaceAll(s, v, "[recipient]")
		}
	}
	s = emailRe.ReplaceAllString(s, "[email]")
	s = phoneRe.ReplaceAllString(s, "[number]")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func friendly(err error, hide ...string) error {
	if err == nil {
		return nil
	}
	var e *rest.Error
	if !errors.As(err, &e) {
		return errors.New(scrub(err.Error(), hide...))
	}
	msg := "Printful: " + scrub(e.Message, hide...)
	switch e.Status {
	case http.StatusUnauthorized:
		msg = "Printful refused the token"
	case http.StatusForbidden:
		msg = "the token isn't allowed to do this in Printful (check its scopes)"
	case http.StatusNotFound:
		msg = "Printful didn't find it"
	case http.StatusTooManyRequests:
		msg = "Printful is limiting requests; try again in a moment"
	}
	return &rest.Error{Status: e.Status, Message: msg}
}

// do sends a request and unwraps Printful's {"code","result"} envelope.
// Error text is kept free of the details in hide.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any, hide ...string) (*paging, error) {
	var env struct {
		Code   int             `json:"code"`
		Result json.RawMessage `json:"result"`
		Paging *paging         `json:"paging"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if _, err := c.api.Do(ctx, method, path, q, body, &env); err != nil {
		return nil, friendly(err, hide...)
	}
	if env.Code >= 300 {
		msg := "the request failed"
		if env.Error != nil && env.Error.Message != "" {
			msg = env.Error.Message
		}
		return nil, friendly(&rest.Error{Status: env.Code, Message: msg}, hide...)
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return nil, errors.New("unexpected answer from Printful")
		}
	}
	return env.Paging, nil
}

type paging struct {
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

// Money: Printful sends decimal strings; they're checked and normalised,
// never turned into floats.
func normal(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !amountRe.MatchString(s) {
		return "", false
	}
	whole, frac, _ := strings.Cut(s, ".")
	frac = (frac + "00")[:max(2, len(frac))]
	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return "", false
	}
	return strconv.FormatInt(w, 10) + "." + frac, true
}

// units reads a decimal string in ten-thousandths, to compare amounts.
func units(s string) (int64, bool) {
	n, ok := normal(s)
	if !ok {
		return 0, false
	}
	whole, frac, _ := strings.Cut(n, ".")
	if len(frac) > 4 {
		return 0, false
	}
	w, _ := strconv.ParseInt(whole, 10, 64)
	f, _ := strconv.ParseInt((frac + "0000")[:4], 10, 64)
	return w*10000 + f, true
}

// expectCost checks the charge the preview showed (like 25.22 or
// 25.22 EUR) against the order now: a draft's items, shipping or address,
// and so its cost, can change between a preview and its approval.
func expectCost(given string, c costs) error {
	now := money(c.Total, c.Currency)
	g := strings.TrimSpace(given)
	if g == "" {
		return fmt.Errorf("give expectedCost %q, the charge the preview showed", now)
	}
	n, cur, _ := strings.Cut(g, " ")
	v, ok := units(n)
	w, _ := units(c.Total)
	if !ok || (cur != "" && !strings.EqualFold(strings.TrimSpace(cur), c.Currency)) {
		return fmt.Errorf("expectedCost is an amount like %q, as the preview showed it", now)
	}
	if v != w {
		return fmt.Errorf("the order changed since the preview: it costs %s now, not %s; preview it again", now, g)
	}
	return nil
}

func money(s, cur string) string {
	if n, ok := normal(s); ok {
		return n + " " + cur
	}
	return "? " + cur
}

type costs struct {
	Currency string `json:"currency"`
	Subtotal string `json:"subtotal"`
	Discount string `json:"discount"`
	Shipping string `json:"shipping"`
	Tax      string `json:"tax"`
	VAT      string `json:"vat"`
	Total    string `json:"total"`
}

func (c costs) out() map[string]any {
	m := map[string]any{"total": money(c.Total, c.Currency), "subtotal": money(c.Subtotal, c.Currency), "shipping": money(c.Shipping, c.Currency)}
	for k, v := range map[string]string{"discount": c.Discount, "tax": c.Tax, "vat": c.VAT} {
		if n, ok := normal(v); ok && strings.Trim(n, "0.") != "" {
			m[k] = n + " " + c.Currency
		}
	}
	return m
}

type shipment struct {
	Carrier        string `json:"carrier"`
	Service        string `json:"service"`
	TrackingNumber any    `json:"tracking_number"`
	ShipDate       string `json:"ship_date"`
	ShippedAt      int64  `json:"shipped_at"`
	Reshipment     bool   `json:"reshipment"`
}

func (s shipment) out() map[string]any {
	m := map[string]any{"carrier": s.Carrier, "service": s.Service, "shipDate": s.ShipDate}
	switch t := s.TrackingNumber.(type) {
	case string:
		m["trackingNumber"] = t
	case float64:
		m["trackingNumber"] = strconv.FormatFloat(t, 'f', -1, 64)
	}
	if s.ShippedAt > 0 {
		m["shipped"] = time.Unix(s.ShippedAt, 0).UTC().Format(time.RFC3339)
	}
	if s.Reshipment {
		m["reshipment"] = true
	}
	return m
}

// orderRow holds only what isn't personal; orderFull adds the recipient.
type orderRow struct {
	ID          int64      `json:"id"`
	ExternalID  string     `json:"external_id"`
	Status      string     `json:"status"`
	Created     int64      `json:"created"`
	Updated     int64      `json:"updated"`
	Shipping    string     `json:"shipping"`
	ShipService string     `json:"shipping_service_name"`
	Costs       costs      `json:"costs"`
	RetailCosts costs      `json:"retail_costs"`
	Shipments   []shipment `json:"shipments"`
	Items       []struct {
		Name      string `json:"name"`
		Quantity  int    `json:"quantity"`
		VariantID int64  `json:"variant_id"`
		SKU       string `json:"sku"`
	} `json:"items"`
}

func (o orderRow) label() string {
	if o.ExternalID != "" {
		return fmt.Sprintf("%d (%s)", o.ID, o.ExternalID)
	}
	return strconv.FormatInt(o.ID, 10)
}

func ts(v int64) string {
	if v <= 0 {
		return ""
	}
	return time.Unix(v, 0).UTC().Format(time.RFC3339)
}

func orderOut(o orderRow) map[string]any {
	items := 0
	for _, it := range o.Items {
		items += it.Quantity
	}
	out := map[string]any{"id": o.ID, "externalId": o.ExternalID, "status": o.Status, "created": ts(o.Created), "updated": ts(o.Updated), "items": items,
		"cost": money(o.Costs.Total, o.Costs.Currency), "shipping": o.ShipService, "shipments": len(o.Shipments)}
	if o.RetailCosts.Currency != "" && o.RetailCosts.Total != "" {
		out["retailTotal"] = money(o.RetailCosts.Total, o.RetailCosts.Currency)
	}
	return out
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ss, err := c.stores(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if len(ss) == 1 {
		return sdk.Health{Status: "ok", Message: "connected to " + ss[0].Name}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("connected, %d stores", len(ss))}
}

type store struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

func (c *conn) stores(ctx context.Context) ([]store, error) {
	var ss []store
	_, err := c.do(ctx, http.MethodGet, "/stores", nil, nil, &ss)
	return ss, err
}

type item struct {
	Variant  int64 `json:"variant"`
	Quantity int   `json:"quantity"`
}

type input struct {
	Status   string `json:"status"`
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
	Order    any    `json:"order"`
	Country  string `json:"country"`
	State    string `json:"state"`
	City     string `json:"city"`
	Zip      string `json:"zip"`
	Currency string `json:"currency"`
	Items    []item `json:"items"`
	// The charge the preview showed, checked again when the order is confirmed.
	ExpectedCost string `json:"expectedCost"`
}

// orderPath turns an order id or @external id into its path.
func orderPath(v any) (string, error) {
	var s string
	switch x := v.(type) {
	case string:
		s = strings.TrimSpace(x)
	case float64:
		s = strconv.FormatFloat(x, 'f', -1, 64)
	}
	switch {
	case idRe.MatchString(s):
		return "/orders/" + s, nil
	case strings.HasPrefix(s, "@") && externalRe.MatchString(s[1:]):
		return "/orders/" + url.PathEscape(s), nil
	}
	return "", errors.New("the order is its Printful id, or @ and your external id (like @1001)")
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
	case "store":
		ss, err := c.stores(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range ss {
			out = append(out, map[string]any{"id": s.ID, "name": s.Name, "type": s.Type})
		}
		return sdk.JSON(out)
	case "orders":
		return c.orders(ctx, p)
	case "order", "order_status", "confirm_order":
		path, err := orderPath(p.Order)
		if err != nil {
			return sdk.Result{}, err
		}
		switch call.Action {
		case "order":
			return c.orderDetail(ctx, path)
		case "order_status":
			o, err := c.getOrder(ctx, path)
			if err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(statusOut(o.orderRow))
		}
		return c.confirm(ctx, call, path, p.ExpectedCost)
	case "shipping_rates":
		return c.rates(ctx, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) orders(ctx context.Context, p input) (sdk.Result, error) {
	if p.Offset < 0 || p.Offset > 1000000 {
		return sdk.Result{}, errors.New("offset is a number from 0")
	}
	lim := p.Limit
	if lim <= 0 || lim > 100 {
		lim = 20
	}
	q := url.Values{"limit": {strconv.Itoa(lim)}, "offset": {strconv.Itoa(p.Offset)}}
	if p.Status != "" {
		if !statuses[p.Status] {
			return sdk.Result{}, fmt.Errorf("status %q isn't an order status", p.Status)
		}
		q.Set("status", p.Status)
	}
	var os []orderRow
	pg, err := c.do(ctx, http.MethodGet, "/orders", q, nil, &os)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, o := range os {
		out = append(out, orderOut(o))
	}
	res := map[string]any{"items": out}
	if pg != nil {
		res["total"] = pg.Total
		if next := p.Offset + len(os); next < pg.Total && len(os) > 0 {
			res["nextOffset"] = next
		}
	}
	return sdk.JSON(res)
}

type orderFull struct {
	orderRow
	Recipient struct {
		Name        string `json:"name"`
		Company     string `json:"company"`
		Address1    string `json:"address1"`
		Address2    string `json:"address2"`
		City        string `json:"city"`
		StateCode   string `json:"state_code"`
		CountryCode string `json:"country_code"`
		Zip         string `json:"zip"`
		Phone       string `json:"phone"`
		Email       string `json:"email"`
	} `json:"recipient"`
}

func (c *conn) getOrder(ctx context.Context, path string) (orderFull, error) {
	var o orderFull
	if _, err := c.do(ctx, http.MethodGet, path, nil, nil, &o); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return o, fmt.Errorf("there's no order %s", strings.TrimPrefix(path, "/orders/"))
		}
		return o, err
	}
	asked := strings.TrimPrefix(path, "/orders/")
	if o.ID == 0 {
		return o, fmt.Errorf("there's no order %s", asked)
	}
	// The id goes into the confirmation's path: it must be the order asked for.
	if ext, ok := strings.CutPrefix(asked, "@"); ok {
		if o.ExternalID != ext {
			return o, fmt.Errorf("Printful answered with another order for @%s", ext)
		}
	} else if strconv.FormatInt(o.ID, 10) != asked {
		return o, fmt.Errorf("Printful answered with another order for %s", asked)
	}
	return o, nil
}

func statusOut(o orderRow) map[string]any {
	out := orderOut(o)
	out["costs"] = o.Costs.out()
	ss := []map[string]any{}
	for _, s := range o.Shipments {
		ss = append(ss, s.out())
	}
	out["shipments"] = ss
	return out
}

func (c *conn) orderDetail(ctx context.Context, path string) (sdk.Result, error) {
	o, err := c.getOrder(ctx, path)
	if err != nil {
		return sdk.Result{}, err
	}
	out := statusOut(o.orderRow)
	r := o.Recipient
	out["recipient"] = map[string]any{"name": r.Name, "company": r.Company, "address1": r.Address1, "address2": r.Address2, "city": r.City, "state": r.StateCode,
		"country": r.CountryCode, "zip": r.Zip, "phone": r.Phone, "email": r.Email}
	items := []map[string]any{}
	for _, it := range o.Items {
		items = append(items, map[string]any{"name": it.Name, "quantity": it.Quantity, "variant": it.VariantID, "sku": it.SKU})
	}
	out["lineItems"] = items
	return sdk.JSON(out)
}

func (c *conn) confirm(ctx context.Context, call sdk.Call, path, expected string) (sdk.Result, error) {
	o, err := c.getOrder(ctx, path)
	if err != nil {
		return sdk.Result{}, err
	}
	switch o.Status {
	case "draft":
	case "failed":
		return sdk.Result{}, fmt.Errorf("order %s failed; fix it in Printful (often the address or the card), then confirm it", o.label())
	case "canceled", "archived":
		return sdk.Result{}, fmt.Errorf("order %s is %s", o.label(), o.Status)
	default:
		return sdk.JSON(map[string]any{"order": o.ID, "status": o.Status, "note": "nothing to change: it's confirmed already"})
	}
	charge := money(o.Costs.Total, o.Costs.Currency)
	if _, ok := units(o.Costs.Total); !ok || !curRe.MatchString(o.Costs.Currency) {
		return sdk.Result{}, fmt.Errorf("Printful hasn't worked out order %s's cost yet; try again in a moment", o.label())
	}
	expect := expectCost(expected, o.Costs)
	if call.DryRun {
		items := 0
		for _, it := range o.Items {
			items += it.Quantity
		}
		note := ""
		if expected == "" {
			note = fmt.Sprintf(" To run it, give expectedCost %q; it's refused if the cost changed.", charge)
		} else if expect != nil {
			note = " Running this call will be refused: " + expect.Error() + "."
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Confirm order %s (%d items, %s): Printful charges your card %s and starts fulfilment. It can't be undone.%s", o.label(), items, o.ShipService, charge, note),
			Changes: []sdk.Change{{Target: "order " + o.label(), Op: "confirm", Before: mustJSON(map[string]any{"status": o.Status}),
				After: mustJSON(map[string]any{"status": "pending", "charge": charge, "costs": o.Costs.out()})}}}}, nil
	}
	if expect != nil {
		return sdk.Result{}, expect
	}
	r := o.Recipient
	var after orderRow
	if _, err := c.do(ctx, http.MethodPost, "/orders/"+strconv.FormatInt(o.ID, 10)+"/confirm", nil, nil, &after,
		r.Name, r.Company, r.Address1, r.Address2, r.City, r.Zip, r.Email, r.Phone); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"order": o.ID, "status": after.Status, "charged": charge}
	if after.Costs.Total != "" {
		out["charged"] = money(after.Costs.Total, after.Costs.Currency)
	}
	return sdk.JSON(out)
}

func (c *conn) rates(ctx context.Context, p input) (sdk.Result, error) {
	country := strings.ToUpper(strings.TrimSpace(p.Country))
	if !countryRe.MatchString(country) {
		return sdk.Result{}, errors.New("country is a two-letter code, like US or DE")
	}
	rcp := map[string]any{"country_code": country}
	if s := strings.ToUpper(strings.TrimSpace(p.State)); s != "" {
		if !stateRe.MatchString(s) {
			return sdk.Result{}, errors.New("state is a state code, like CA")
		}
		rcp["state_code"] = s
	} else if country == "US" || country == "CA" || country == "AU" {
		return sdk.Result{}, errors.New("a state code is needed for " + country)
	}
	if s := strings.TrimSpace(p.City); s != "" {
		if !cityRe.MatchString(s) {
			return sdk.Result{}, errors.New("city is a city's name")
		}
		rcp["city"] = s
	}
	if s := strings.TrimSpace(p.Zip); s != "" {
		if !zipRe.MatchString(s) {
			return sdk.Result{}, errors.New("zip is a postal code")
		}
		rcp["zip"] = s
	}
	if len(p.Items) == 0 || len(p.Items) > 50 {
		return sdk.Result{}, errors.New("items lists 1 to 50 variants with quantities")
	}
	var items []map[string]any
	for _, it := range p.Items {
		if it.Variant <= 0 || it.Quantity <= 0 || it.Quantity > 1000 {
			return sdk.Result{}, errors.New("each item is a variant id and a quantity from 1 to 1000")
		}
		items = append(items, map[string]any{"variant_id": strconv.FormatInt(it.Variant, 10), "quantity": it.Quantity})
	}
	body := map[string]any{"recipient": rcp, "items": items}
	if s := strings.ToUpper(strings.TrimSpace(p.Currency)); s != "" {
		if !curRe.MatchString(s) {
			return sdk.Result{}, errors.New("currency is a three-letter code, like USD")
		}
		body["currency"] = s
	}
	var rs []struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Rate            string `json:"rate"`
		Currency        string `json:"currency"`
		MinDeliveryDays int    `json:"minDeliveryDays"`
		MaxDeliveryDays int    `json:"maxDeliveryDays"`
	}
	if _, err := c.do(ctx, http.MethodPost, "/shipping/rates", nil, body, &rs); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, r := range rs {
		row := map[string]any{"id": r.ID, "name": r.Name, "rate": money(r.Rate, r.Currency)}
		if r.MaxDeliveryDays > 0 {
			row["days"] = fmt.Sprintf("%d-%d", r.MinDeliveryDays, r.MaxDeliveryDays)
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
