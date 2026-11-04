// Package gumroad works with a Gumroad account through its API and an
// access token: the products, recent sales and subscriber counts, and
// turning a product's sales on or off.
//
// Disabling a product stops people buying it, so it's destructive and its
// preview shows the price and what the product has sold. Sales are returned
// without buyers' emails or names, and subscribers only as counts.
package gumroad

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Gumroad account.
type Config struct {
	Token string `json:"token"` // secret:// access token
}

const defaultBase = "https://api.gumroad.com"

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.gumroad.com (tests).
	Base string
}

// New returns the Gumroad module.
func New() *Module { return &Module{} }

var (
	tokenRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{20,128}$`)
	productRe = regexp.MustCompile(`^[A-Za-z0-9_=+-]{1,64}$`)
	pageKeyRe = regexp.MustCompile(`^[A-Za-z0-9_=+.:-]{1,200}$`)
	dateRe    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	emailRe   = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	zeroDigs  = map[string]bool{"JPY": true, "KRW": true, "CLP": true, "ISK": true, "VND": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	product := `{"type":"object","required":["product"],"properties":{"product":{"type":"string","description":"Product id (see products)"}}}`
	return sdk.Manifest{
		ID: "gumroad", Name: "Gumroad", Version: "0.1.0", Category: "Productivity", Icon: "credit-card",
		Description: "A Gumroad account: products, recent sales and subscriber counts; turn a product's sales on or off with a preview.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An access token from Settings, Advanced, Applications (create an application, then Generate access token)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "products", Title: "Products", Description: "Every product: name, published, price, sales count and revenue, and whether it's a membership.", Risk: sdk.RiskRead},
			{Name: "sales", Title: "Sales", Description: "Recent sales: product, price, date, and whether it was refunded or disputed. No buyer emails or names.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"product":{"type":"string","description":"Only this product's sales"},"after":{"type":"string","description":"Only sales on or after this date (YYYY-MM-DD)"},"before":{"type":"string","description":"Only sales on or before this date (YYYY-MM-DD)"},"pageKey":{"type":"string","description":"nextPageKey of the previous page"}}}`)},
			{Name: "subscribers", Title: "Subscriber count", Description: "How many subscribers a membership product has, by status (active, cancelling, failed payment, ended). Counts only, never who.", Risk: sdk.RiskRead, Input: sdk.Schema(product)},
			{Name: "enable_product", Title: "Enable a product", Description: "Publishes a product so people can buy it again. Undo disables it.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Input: sdk.Schema(product)},
			{Name: "disable_product", Title: "Disable a product", Description: "Unpublishes a product so nobody can buy it; existing buyers keep access. The preview shows its price and sales. Undo enables it again.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true, Input: sdk.Schema(product)},
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
	api := rest.New(base+"/v2", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if !tokenRe.MatchString(t) {
			return errors.New("the stored token doesn't look like a Gumroad access token")
		}
		r.Header.Set("Authorization", "Bearer "+t)
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
	msg := "Gumroad: " + scrub(e.Message)
	switch e.Status {
	case http.StatusUnauthorized:
		msg = "Gumroad refused the access token"
	case http.StatusForbidden:
		msg = "the access token isn't allowed to do this in Gumroad (check its scopes)"
	case http.StatusNotFound:
		msg = "Gumroad didn't find it"
	case http.StatusTooManyRequests:
		msg = "Gumroad is limiting requests; try again in a moment"
	}
	return &rest.Error{Status: e.Status, Message: msg}
}

// call sends a request and checks Gumroad's success flag, which some
// failures carry with a 200.
func (c *conn) call(ctx context.Context, method, path string, q url.Values, out any) error {
	var raw json.RawMessage
	if _, err := c.api.Do(ctx, method, path, q, nil, &raw); err != nil {
		return friendly(err)
	}
	var env struct {
		Success *bool  `json:"success"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return errors.New("unexpected answer from Gumroad")
	}
	if env.Success != nil && !*env.Success {
		if env.Message == "" {
			env.Message = "the request failed"
		}
		return errors.New("Gumroad: " + scrub(env.Message))
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return errors.New("unexpected answer from Gumroad")
	}
	return nil
}

type product struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Published          bool   `json:"published"`
	Deleted            bool   `json:"deleted"`
	Price              int64  `json:"price"`
	Currency           string `json:"currency"`
	SalesCount         any    `json:"sales_count"`
	SalesUSDCents      any    `json:"sales_usd_cents"`
	ShortURL           string `json:"short_url"`
	IsTieredMembership bool   `json:"is_tiered_membership"`
	SubscriptionDur    string `json:"subscription_duration"`
}

// num reads Gumroad's counts, which come as numbers or strings.
func num(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	}
	return 0
}

// cents renders an amount in a currency's smallest unit as a decimal string.
func cents(v int64, cur string) string {
	cur = strings.ToUpper(cur)
	if zeroDigs[cur] {
		return strconv.FormatInt(v, 10) + " " + cur
	}
	sign := ""
	if v < 0 {
		sign, v = "-", -v
	}
	return fmt.Sprintf("%s%d.%02d %s", sign, v/100, v%100, cur)
}

func (p product) out() map[string]any {
	row := map[string]any{"id": p.ID, "name": p.Name, "published": p.Published, "price": cents(p.Price, p.Currency), "sales": num(p.SalesCount),
		"revenue": cents(num(p.SalesUSDCents), "USD"), "url": p.ShortURL}
	if p.IsTieredMembership || p.SubscriptionDur != "" {
		row["membership"] = true
		if p.SubscriptionDur != "" {
			row["billing"] = p.SubscriptionDur
		}
	}
	return row
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	// Only the name is decoded: the user record also has the email.
	var u struct {
		User struct {
			Name string `json:"name"`
		} `json:"user"`
	}
	if err := c.call(ctx, http.MethodGet, "/user", nil, &u); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "connected"
	if u.User.Name != "" {
		msg += " as " + u.User.Name
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Product string `json:"product"`
	After   string `json:"after"`
	Before  string `json:"before"`
	PageKey string `json:"pageKey"`
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
	p.Product = strings.TrimSpace(p.Product)
	if p.Product != "" && !productRe.MatchString(p.Product) {
		return sdk.Result{}, errors.New("a product is its id from products")
	}
	switch call.Action {
	case "products":
		var d struct {
			Products []product `json:"products"`
		}
		if err := c.call(ctx, http.MethodGet, "/products", nil, &d); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range d.Products {
			if !x.Deleted {
				out = append(out, x.out())
			}
		}
		return sdk.JSON(out)
	case "sales":
		return c.sales(ctx, p)
	case "subscribers":
		if p.Product == "" {
			return sdk.Result{}, errors.New("a product is its id from products")
		}
		return c.subscribers(ctx, p.Product)
	case "enable_product", "disable_product":
		if p.Product == "" {
			return sdk.Result{}, errors.New("a product is its id from products")
		}
		return c.setPublished(ctx, call, p.Product)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func validDate(s string) bool {
	if !dateRe.MatchString(s) {
		return false
	}
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

func (c *conn) sales(ctx context.Context, p input) (sdk.Result, error) {
	q := url.Values{}
	if p.After != "" {
		if !validDate(p.After) {
			return sdk.Result{}, errors.New("after is a date like 2026-11-01")
		}
		q.Set("after", p.After)
	}
	if p.Before != "" {
		if !validDate(p.Before) {
			return sdk.Result{}, errors.New("before is a date like 2026-11-30")
		}
		q.Set("before", p.Before)
	}
	if p.PageKey != "" {
		if !pageKeyRe.MatchString(p.PageKey) {
			return sdk.Result{}, errors.New("pageKey is the nextPageKey of the previous page")
		}
		q.Set("page_key", p.PageKey)
	}
	if p.Product != "" {
		q.Set("product_id", p.Product)
	}
	// Decoded field by field: a sale also carries the buyer's email, name,
	// IP country and custom fields, which stay out of the audit log.
	var d struct {
		NextPageKey string `json:"next_page_key"`
		Sales       []struct {
			ID                string `json:"id"`
			ProductID         string `json:"product_id"`
			ProductName       string `json:"product_name"`
			Price             int64  `json:"price"`
			Currency          string `json:"currency"`
			Quantity          int    `json:"quantity"`
			CreatedAt         string `json:"created_at"`
			Refunded          bool   `json:"refunded"`
			PartiallyRefunded bool   `json:"partially_refunded"`
			Chargedback       bool   `json:"chargedback"`
			DisputeWon        bool   `json:"dispute_won"`
			SubscriptionID    string `json:"subscription_id"`
		} `json:"sales"`
	}
	if err := c.call(ctx, http.MethodGet, "/sales", q, &d); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, s := range d.Sales {
		cur := s.Currency
		if cur == "" {
			cur = "usd"
		}
		row := map[string]any{"id": s.ID, "product": s.ProductName, "productId": s.ProductID, "price": cents(s.Price, cur), "created": s.CreatedAt}
		if s.Quantity > 1 {
			row["quantity"] = s.Quantity
		}
		if s.Refunded {
			row["refunded"] = true
		}
		if s.PartiallyRefunded {
			row["partiallyRefunded"] = true
		}
		if s.Chargedback {
			row["disputed"] = true
			row["disputeWon"] = s.DisputeWon
		}
		if s.SubscriptionID != "" {
			row["subscription"] = true
		}
		out = append(out, row)
	}
	res := map[string]any{"items": out}
	if d.NextPageKey != "" {
		res["nextPageKey"] = d.NextPageKey
	}
	return sdk.JSON(res)
}

// maxSubscriberPages bounds the count for very large memberships.
const maxSubscriberPages = 50

func (c *conn) subscribers(ctx context.Context, id string) (sdk.Result, error) {
	pr, err := c.product(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	counts := map[string]int{}
	total := 0
	key := ""
	complete := true
	for page := 0; ; page++ {
		if page == maxSubscriberPages {
			complete = false
			break
		}
		q := url.Values{"paginated": {"true"}}
		if key != "" {
			q.Set("page_key", key)
		}
		// Only the status is decoded; never who subscribed.
		var d struct {
			NextPageKey string `json:"next_page_key"`
			Subscribers []struct {
				Status string `json:"status"`
			} `json:"subscribers"`
		}
		if err := c.call(ctx, http.MethodGet, "/products/"+url.PathEscape(pr.ID)+"/subscribers", q, &d); err != nil {
			return sdk.Result{}, err
		}
		for _, s := range d.Subscribers {
			counts[s.Status]++
			total++
		}
		if d.NextPageKey == "" || d.NextPageKey == key || !pageKeyRe.MatchString(d.NextPageKey) {
			break
		}
		key = d.NextPageKey
	}
	labels := map[string]string{"alive": "active", "pending_cancellation": "cancelling", "pending_failure": "paymentFailing", "failed_payment": "failedPayment",
		"fixed_subscription_period_ended": "ended", "cancelled": "cancelled"}
	by := map[string]int{}
	var other []string
	for s, n := range counts {
		if l, ok := labels[s]; ok {
			by[l] += n
		} else {
			by["other"] += n
			other = append(other, s)
		}
	}
	sort.Strings(other)
	out := map[string]any{"product": pr.ID, "name": pr.Name, "total": total, "active": by["active"] + by["cancelling"] + by["paymentFailing"], "byStatus": by}
	if !complete {
		out["note"] = fmt.Sprintf("counted the first %d pages only", maxSubscriberPages)
	}
	return sdk.JSON(out)
}

func (c *conn) product(ctx context.Context, id string) (product, error) {
	var d struct {
		Product product `json:"product"`
	}
	if err := c.call(ctx, http.MethodGet, "/products/"+url.PathEscape(id), nil, &d); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return product{}, fmt.Errorf("there's no product %s", id)
		}
		return product{}, err
	}
	if d.Product.ID == "" {
		return product{}, fmt.Errorf("there's no product %s", id)
	}
	if d.Product.ID != id {
		// The id goes into the change's path and the undo.
		return product{}, fmt.Errorf("Gumroad answered with another product for %s", id)
	}
	return d.Product, nil
}

func (c *conn) setPublished(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	enable := call.Action == "enable_product"
	pr, err := c.product(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	if pr.Deleted {
		return sdk.Result{}, fmt.Errorf("product %s was deleted", pr.Name)
	}
	if pr.Published == enable {
		return sdk.JSON(map[string]any{"product": pr.ID, "name": pr.Name, "published": pr.Published, "note": "nothing to change"})
	}
	verb, path, back := "Disable", "/disable", "enable_product"
	if enable {
		verb, path, back = "Enable", "/enable", "disable_product"
	}
	price := cents(pr.Price, pr.Currency)
	if call.DryRun {
		summary := fmt.Sprintf("Disable %s (%s, %d sales, %s revenue): nobody can buy it until it's enabled again", pr.Name, price, num(pr.SalesCount), cents(num(pr.SalesUSDCents), "USD"))
		if enable {
			summary = fmt.Sprintf("Enable %s: people can buy it again for %s", pr.Name, price)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "product " + pr.Name, Op: strings.ToLower(verb),
			Before: mustJSON(map[string]any{"published": pr.Published, "price": price}), After: mustJSON(map[string]any{"published": enable})}}}}, nil
	}
	var d struct {
		Product product `json:"product"`
	}
	if err := c.call(ctx, http.MethodPut, "/products/"+url.PathEscape(pr.ID)+path, nil, &d); err != nil {
		return sdk.Result{}, err
	}
	if d.Product.ID != "" && d.Product.Published != enable {
		return sdk.Result{}, fmt.Errorf("Gumroad kept %s as it was", pr.Name)
	}
	res, err := sdk.JSON(map[string]any{"product": pr.ID, "name": pr.Name, "published": enable})
	undo := "Enable " + pr.Name + " again"
	if enable {
		undo = "Disable " + pr.Name + " again"
	}
	res.Undo = sdk.UndoWith(back, map[string]string{"product": pr.ID}, undo)
	return res, err
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
