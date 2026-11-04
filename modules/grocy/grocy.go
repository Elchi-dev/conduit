// Package grocy works with a Grocy household server through its REST API and
// an API key: stock (what's expiring, what's below its minimum), the
// shopping list, consuming and adding stock, and chores.
package grocy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Grocy server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://grocy.example.com
	Token              string `json:"token"` // secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string
	now    func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces the clock (tests).
	Now func() time.Time
}

// New returns the Grocy module.
func New() *Module { return &Module{} }

const (
	maxAmount = 100000
	maxName   = 200
	maxNote   = 500
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// Grocy's transaction ids are PHP uniqid() values.
	txRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	digits = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	product := `"product":{"type":["string","integer"],"description":"Product id or exact name (see stock)"}`
	amount := `"amount":{"type":"number","exclusiveMinimum":0,"maximum":100000,"description":"In the product's stock unit"}`
	list := `"list":{"type":"integer","minimum":1,"default":1,"description":"Shopping list id (1 is the default list)"}`
	chore := `"chore":{"type":["string","integer"],"description":"Chore id or exact name (see chores_due)"}`
	return sdk.Manifest{
		ID: "grocy", Name: "Grocy", Version: "0.1.0", Category: "Productivity", Icon: "cart",
		Description: "Grocy stock, shopping list and chores: what's expiring or running low, add to the shopping list, use up stock, mark chores done.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Grocy's address, e.g. https://grocy.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API key from the user menu → Manage API keys"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "stock", Title: "Stock", Description: "Products in stock with their amount, unit and next due date.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":1000,"default":200}}}`)},
			{Name: "expiring", Title: "Expiring soon", Description: "Products due within some days, overdue or expired.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":90,"default":5}}}`)},
			{Name: "below_minimum", Title: "Below minimum", Description: "Products with less in stock than their minimum, and how much is missing.", Risk: sdk.RiskRead},
			{Name: "shopping_list", Title: "Shopping list", Description: "A shopping list's items with product, amount and note.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + list + `,"done":{"type":"boolean","default":true,"description":"Include items marked done"}}}`)},
			{Name: "add_to_shopping_list", Title: "Add to the shopping list", Description: "Adds a product (Grocy adds the amount to its line if it's on the list already) or a free-text note. Undo takes it off again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + product + `,"amount":{"type":"number","exclusiveMinimum":0,"maximum":100000,"default":1},"note":{"type":"string","maxLength":500},` + list + `}}`)},
			{Name: "remove_from_shopping_list", Title: "Remove from the shopping list", Description: "Removes a line by its id, or takes an amount of a product off the list (the line goes when nothing's left). Undo adds it back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"item":{"type":"integer","minimum":1,"description":"Shopping list line id (see shopping_list)"},` + product + `,` + amount + `,` + list + `}}`)},
			{Name: "consume_product", Title: "Consume a product", Description: "Takes an amount of a product out of stock, as used or spoiled. Undo reverts the booking, putting the same stock entries back (through undo_stock_transaction, so it's destructive).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["product","amount"],"properties":{` + product + `,` + amount + `,"spoiled":{"type":"boolean","default":false}}}`)},
			{Name: "add_stock", Title: "Add stock", Description: "Books a purchase of a product, with an optional due date. Undo reverts the booking (through undo_stock_transaction, so it's destructive).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["product","amount"],"properties":{` + product + `,` + amount + `,"bestBefore":{"type":"string","format":"date"}}}`)},
			{Name: "undo_stock_transaction", Title: "Revert a stock booking", Description: "Reverts a purchase or consume booking by its transaction id, as Grocy's own undo does. It can revert any past booking and can't be taken back, so it's destructive.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Transaction id"}}}`)},
			{Name: "chores_due", Title: "Chores due", Description: "Chores due within some days, overdue first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","minimum":0,"maximum":365,"default":7}}}`)},
			{Name: "complete_chore", Title: "Mark a chore done", Description: "Tracks a chore as done now. Undo reverts that execution (through undo_chore_execution, so it's destructive).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["chore"],"properties":{` + chore + `}}`)},
			{Name: "undo_chore_execution", Title: "Revert a chore execution", Description: "Reverts one tracked chore execution by its id. It can revert any past execution and can't be taken back, so it's destructive.", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://grocy.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	ref := c.Token
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(origin+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("GROCY-API-KEY", strings.TrimSpace(t))
		return nil
	})
	// The key is a custom header, which Go would forward on any redirect.
	api.HTTP = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, origin: origin, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Grocy refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Grocy refused the request: %v", err)
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var lists []struct {
		ID int `json:"id"`
	}
	if err := c.do(ctx, http.MethodGet, "/objects/shopping_lists", nil, nil, &lists); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Grocy API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var info struct {
		Version struct {
			Version string `json:"Version"`
		} `json:"grocy_version"`
	}
	if c.do(ctx, http.MethodGet, "/system/info", nil, nil, &info) == nil && info.Version.Version != "" {
		return sdk.Health{Status: "ok", Message: "Grocy " + info.Version.Version}
	}
	return sdk.Health{Status: "ok"}
}

// ref is an id or a name, as agents give either.
type ref string

func (r *ref) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err == nil {
		*r = ref(n.String())
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("give an id or a name")
	}
	*r = ref(s)
	return nil
}

// flt reads Grocy's numbers, which some versions send as strings.
type flt float64

func (f *flt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	*f = flt(v)
	return nil
}

// num reads Grocy's ids, also sometimes strings.
type num int

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	*n = num(v)
	return nil
}

type product struct {
	ID          num    `json:"id"`
	Name        string `json:"name"`
	QuStock     num    `json:"qu_id_stock"`
	QuPurchase  num    `json:"qu_id_purchase"`
	MinStock    flt    `json:"min_stock_amount"`
	Active      *num   `json:"active"`
	Description string `json:"description"`
}

type input struct {
	Limit      int     `json:"limit"`
	Days       *int    `json:"days"`
	List       int     `json:"list"`
	Done       *bool   `json:"done"`
	Product    ref     `json:"product"`
	Amount     float64 `json:"amount"`
	Note       string  `json:"note"`
	Item       int     `json:"item"`
	Spoiled    bool    `json:"spoiled"`
	BestBefore string  `json:"bestBefore"`
	Chore      ref     `json:"chore"`
	ID         ref     `json:"id"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func fmtAmount(a float64) string { return strconv.FormatFloat(a, 'f', -1, 64) }

func validAmount(a float64) error {
	if a <= 0 || a > maxAmount || math.IsNaN(a) || math.IsInf(a, 0) {
		return fmt.Errorf("the amount is more than 0 and at most %d", maxAmount)
	}
	return nil
}

func plainText(s string, max int) bool {
	if len([]rune(s)) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' {
			return false
		}
	}
	return true
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
	if p.List < 0 {
		return sdk.Result{}, errors.New("the list is a shopping list id")
	}
	if p.List == 0 {
		p.List = 1
	}
	switch call.Action {
	case "stock":
		return c.stock(ctx, p)
	case "expiring":
		days := 5
		if p.Days != nil {
			days = *p.Days
		}
		if days < 1 || days > 90 {
			return sdk.Result{}, errors.New("days is 1 to 90")
		}
		return c.expiring(ctx, days)
	case "below_minimum":
		var v volatile
		if err := c.do(ctx, http.MethodGet, "/stock/volatile", nil, nil, &v); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range v.Missing {
			r := map[string]any{"product": int(x.ID), "name": x.Name, "missing": float64(x.AmountMissing)}
			if x.PartlyInStock.bool() {
				r["partlyInStock"] = true
			}
			out = append(out, r)
		}
		return sdk.JSON(map[string]any{"belowMinimum": out})
	case "shopping_list":
		return c.shoppingList(ctx, p)
	case "add_to_shopping_list":
		return c.addToList(ctx, call, p)
	case "remove_from_shopping_list":
		return c.removeFromList(ctx, call, p)
	case "consume_product", "add_stock":
		return c.book(ctx, call, p)
	case "undo_stock_transaction":
		return c.undoTransaction(ctx, call, p)
	case "chores_due":
		days := 7
		if p.Days != nil {
			days = *p.Days
		}
		if days < 0 || days > 365 {
			return sdk.Result{}, errors.New("days is 0 to 365")
		}
		return c.choresDue(ctx, days)
	case "complete_chore":
		return c.completeChore(ctx, call, p)
	case "undo_chore_execution":
		id := string(p.ID)
		if !digits.MatchString(id) {
			return sdk.Result{}, errors.New("the id is a chore execution id")
		}
		if err := c.do(ctx, http.MethodPost, "/chores/executions/"+id+"/undo", nil, map[string]any{}, nil); err != nil {
			if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("Grocy couldn't revert chore execution %s (it may be reverted already): %v", id, err)
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"reverted": id})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type bit bool

func (b *bit) UnmarshalJSON(raw []byte) error {
	s := strings.Trim(string(raw), `"`)
	*b = bit(s == "1" || s == "true")
	return nil
}

func (b bit) bool() bool { return bool(b) }

type stockRow struct {
	ProductID  num     `json:"product_id"`
	Amount     flt     `json:"amount"`
	Opened     flt     `json:"amount_opened"`
	BestBefore string  `json:"best_before_date"`
	Product    product `json:"product"`
}

type volatile struct {
	DueSoon []stockRow `json:"due_products"`
	Overdue []stockRow `json:"overdue_products"`
	Expired []stockRow `json:"expired_products"`
	Missing []struct {
		ID            num    `json:"id"`
		Name          string `json:"name"`
		AmountMissing flt    `json:"amount_missing"`
		PartlyInStock bit    `json:"is_partly_in_stock"`
	} `json:"missing_products"`
}

// never is the date Grocy uses for "doesn't expire".
const never = "2999-12-31"

func (c *conn) units(ctx context.Context) map[int]string {
	var us []struct {
		ID         num    `json:"id"`
		Name       string `json:"name"`
		NamePlural string `json:"name_plural"`
	}
	out := map[int]string{}
	if c.do(ctx, http.MethodGet, "/objects/quantity_units", nil, nil, &us) != nil {
		return out
	}
	for _, u := range us {
		out[int(u.ID)] = u.Name
	}
	return out
}

func (c *conn) stockLine(r stockRow, units map[int]string) map[string]any {
	out := map[string]any{"product": int(r.ProductID), "name": r.Product.Name, "amount": float64(r.Amount)}
	if u := units[int(r.Product.QuStock)]; u != "" {
		out["unit"] = u
	}
	if r.BestBefore != "" && r.BestBefore != never {
		out["due"] = r.BestBefore
	}
	if r.Opened > 0 {
		out["opened"] = float64(r.Opened)
	}
	return out
}

func (c *conn) stock(ctx context.Context, p input) (sdk.Result, error) {
	limit := p.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var rows []stockRow
	if err := c.do(ctx, http.MethodGet, "/stock", nil, nil, &rows); err != nil {
		return sdk.Result{}, err
	}
	sort.Slice(rows, func(i, j int) bool {
		return strings.ToLower(rows[i].Product.Name) < strings.ToLower(rows[j].Product.Name)
	})
	units := c.units(ctx)
	out := []map[string]any{}
	for i, r := range rows {
		if i == limit {
			break
		}
		out = append(out, c.stockLine(r, units))
	}
	return sdk.JSON(map[string]any{"stock": out, "total": len(rows)})
}

func (c *conn) expiring(ctx context.Context, days int) (sdk.Result, error) {
	var v volatile
	if err := c.do(ctx, http.MethodGet, "/stock/volatile", url.Values{"due_soon_days": {strconv.Itoa(days)}}, nil, &v); err != nil {
		return sdk.Result{}, err
	}
	units := c.units(ctx)
	lines := func(rs []stockRow) []map[string]any {
		sort.Slice(rs, func(i, j int) bool { return rs[i].BestBefore < rs[j].BestBefore })
		out := []map[string]any{}
		for _, r := range rs {
			out = append(out, c.stockLine(r, units))
		}
		return out
	}
	return sdk.JSON(map[string]any{"days": days, "expired": lines(v.Expired), "overdue": lines(v.Overdue), "dueSoon": lines(v.DueSoon)})
}

func (c *conn) products(ctx context.Context) ([]product, error) {
	var ps []product
	err := c.do(ctx, http.MethodGet, "/objects/products", nil, nil, &ps)
	return ps, err
}

// product finds a product by id or exact name (case doesn't matter).
func (c *conn) product(ctx context.Context, r ref) (product, error) {
	s := strings.TrimSpace(string(r))
	if s == "" {
		return product{}, errors.New("name the product (an id or its exact name, see stock)")
	}
	if !plainText(s, maxName) {
		return product{}, errors.New("the product name is too long or has control characters")
	}
	if digits.MatchString(s) {
		var p product
		if err := c.do(ctx, http.MethodGet, "/objects/products/"+s, nil, nil, &p); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
				return product{}, fmt.Errorf("there's no product %s", s)
			}
			return product{}, err
		}
		if p.ID == 0 {
			return product{}, fmt.Errorf("there's no product %s", s)
		}
		return p, nil
	}
	ps, err := c.products(ctx)
	if err != nil {
		return product{}, err
	}
	for _, p := range ps {
		if strings.EqualFold(strings.TrimSpace(p.Name), s) {
			return p, nil
		}
	}
	return product{}, fmt.Errorf("there's no product named %q; see stock for names", s)
}

type listRow struct {
	ID      num    `json:"id"`
	Product *num   `json:"product_id"`
	Note    string `json:"note"`
	Amount  flt    `json:"amount"`
	List    num    `json:"shopping_list_id"`
	Done    bit    `json:"done"`
	QuID    *num   `json:"qu_id"`
}

func (c *conn) listRows(ctx context.Context, list int) ([]listRow, error) {
	var rows []listRow
	if err := c.do(ctx, http.MethodGet, "/objects/shopping_list", url.Values{"query[]": {"shopping_list_id=" + strconv.Itoa(list)}}, nil, &rows); err != nil {
		return nil, err
	}
	// Older versions ignore the filter.
	out := rows[:0]
	for _, r := range rows {
		if int(r.List) == list {
			out = append(out, r)
		}
	}
	return out, nil
}

func (c *conn) shoppingList(ctx context.Context, p input) (sdk.Result, error) {
	rows, err := c.listRows(ctx, p.List)
	if err != nil {
		return sdk.Result{}, err
	}
	ps, err := c.products(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	names := map[int]product{}
	for _, x := range ps {
		names[int(x.ID)] = x
	}
	units := c.units(ctx)
	out := []map[string]any{}
	for _, r := range rows {
		if r.Done.bool() && p.Done != nil && !*p.Done {
			continue
		}
		line := map[string]any{"item": int(r.ID), "amount": float64(r.Amount)}
		if r.Product != nil && *r.Product > 0 {
			pr := names[int(*r.Product)]
			line["product"], line["name"] = int(*r.Product), pr.Name
			qu := int(pr.QuPurchase)
			if r.QuID != nil && *r.QuID > 0 {
				qu = int(*r.QuID)
			}
			if u := units[qu]; u != "" {
				line["unit"] = u
			}
		}
		if r.Note != "" {
			line["note"] = r.Note
		}
		if r.Done.bool() {
			line["done"] = true
		}
		out = append(out, line)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i]["done"] == nil && out[j]["done"] != nil })
	return sdk.JSON(map[string]any{"list": p.List, "items": out})
}

func (c *conn) addToList(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	amount := p.Amount
	if amount == 0 {
		amount = 1
	}
	if err := validAmount(amount); err != nil {
		return sdk.Result{}, err
	}
	note := strings.TrimSpace(p.Note)
	if !plainText(note, maxNote) {
		return sdk.Result{}, fmt.Errorf("the note is at most %d characters, without control characters", maxNote)
	}
	if strings.TrimSpace(string(p.Product)) == "" {
		// A free-text line.
		if note == "" {
			return sdk.Result{}, errors.New("name a product or write a note")
		}
		body := map[string]any{"note": note, "amount": amount, "shopping_list_id": p.List}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add %q to shopping list %d", note, p.List),
				Changes: []sdk.Change{{Target: fmt.Sprintf("shopping list %d", p.List), Op: "create", After: mustJSON(body)}}}}, nil
		}
		var res struct {
			ID num `json:"created_object_id"`
		}
		if err := c.do(ctx, http.MethodPost, "/objects/shopping_list", nil, body, &res); err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"added": note, "amount": amount, "list": p.List, "item": int(res.ID)})
		if res.ID > 0 {
			r.Undo = sdk.UndoWith("remove_from_shopping_list", map[string]any{"item": int(res.ID)}, fmt.Sprintf("Remove %q from the shopping list", note))
		}
		return r, err
	}
	pr, err := c.product(ctx, p.Product)
	if err != nil {
		return sdk.Result{}, err
	}
	rows, err := c.listRows(ctx, p.List)
	if err != nil {
		return sdk.Result{}, err
	}
	var had *listRow
	for i, r := range rows {
		if r.Product != nil && *r.Product == pr.ID {
			had = &rows[i]
			break
		}
	}
	if call.DryRun {
		ch := sdk.Change{Target: fmt.Sprintf("%s on shopping list %d", pr.Name, p.List), Op: "create", After: mustJSON(map[string]any{"amount": amount, "note": note})}
		if had != nil {
			ch.Op = "update"
			ch.Before = mustJSON(map[string]any{"amount": float64(had.Amount)})
			ch.After = mustJSON(map[string]any{"amount": float64(had.Amount) + amount})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add %s %s to shopping list %d", fmtAmount(amount), pr.Name, p.List), Changes: []sdk.Change{ch}}}, nil
	}
	body := map[string]any{"product_id": int(pr.ID), "list_id": p.List, "product_amount": amount}
	if note != "" {
		body["note"] = note
	}
	if err := c.do(ctx, http.MethodPost, "/stock/shoppinglist/add-product", nil, body, nil); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"added": pr.Name, "product": int(pr.ID), "amount": amount, "list": p.List}
	if had != nil {
		out["note"] = fmt.Sprintf("it was on the list already; the amount went from %s to %s", fmtAmount(float64(had.Amount)), fmtAmount(float64(had.Amount)+amount))
	}
	r, err := sdk.JSON(out)
	r.Undo = sdk.UndoWith("remove_from_shopping_list", map[string]any{"product": int(pr.ID), "amount": amount, "list": p.List},
		fmt.Sprintf("Take %s %s off the shopping list", fmtAmount(amount), pr.Name))
	return r, err
}

func (c *conn) removeFromList(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	hasProduct := strings.TrimSpace(string(p.Product)) != ""
	switch {
	case p.Item < 0:
		return sdk.Result{}, errors.New("the item is a shopping list line id")
	case p.Item > 0 && hasProduct:
		return sdk.Result{}, errors.New("give a line id or a product, not both")
	case p.Item == 0 && !hasProduct:
		return sdk.Result{}, errors.New("give the line id (see shopping_list) or a product and amount")
	}
	if p.Item > 0 {
		var row listRow
		if err := c.do(ctx, http.MethodGet, "/objects/shopping_list/"+strconv.Itoa(p.Item), nil, nil, &row); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
				return sdk.Result{}, fmt.Errorf("there's no shopping list line %d", p.Item)
			}
			return sdk.Result{}, err
		}
		if row.ID == 0 {
			return sdk.Result{}, fmt.Errorf("there's no shopping list line %d", p.Item)
		}
		what := row.Note
		var pr product
		if row.Product != nil && *row.Product > 0 {
			if x, err := c.product(ctx, ref(strconv.Itoa(int(*row.Product)))); err == nil {
				pr = x
				what = pr.Name
			}
		}
		before := map[string]any{"amount": float64(row.Amount), "note": row.Note}
		if pr.ID > 0 {
			before["product"] = pr.Name
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Remove %q from shopping list %d", what, int(row.List)),
				Changes: []sdk.Change{{Target: fmt.Sprintf("shopping list line %d", p.Item), Op: "delete", Before: mustJSON(before)}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/objects/shopping_list/"+strconv.Itoa(p.Item), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"removed": what, "item": p.Item})
		undo := map[string]any{"amount": float64(row.Amount), "list": int(row.List)}
		if row.Note != "" {
			undo["note"] = row.Note
		}
		if pr.ID > 0 {
			undo["product"] = int(pr.ID)
		}
		if pr.ID > 0 || row.Note != "" {
			r.Undo = sdk.UndoWith("add_to_shopping_list", undo, fmt.Sprintf("Add %q back to the shopping list", what))
		}
		return r, err
	}
	if err := validAmount(p.Amount); err != nil {
		return sdk.Result{}, err
	}
	pr, err := c.product(ctx, p.Product)
	if err != nil {
		return sdk.Result{}, err
	}
	rows, err := c.listRows(ctx, p.List)
	if err != nil {
		return sdk.Result{}, err
	}
	var had *listRow
	for i, r := range rows {
		if r.Product != nil && *r.Product == pr.ID {
			had = &rows[i]
			break
		}
	}
	if had == nil {
		return sdk.Result{}, fmt.Errorf("%s isn't on shopping list %d", pr.Name, p.List)
	}
	taken := math.Min(p.Amount, float64(had.Amount))
	left := float64(had.Amount) - taken
	if call.DryRun {
		ch := sdk.Change{Target: fmt.Sprintf("%s on shopping list %d", pr.Name, p.List), Op: "update",
			Before: mustJSON(map[string]any{"amount": float64(had.Amount)}), After: mustJSON(map[string]any{"amount": left})}
		if left <= 0 {
			ch.Op, ch.After = "delete", nil
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Take %s %s off shopping list %d", fmtAmount(taken), pr.Name, p.List), Changes: []sdk.Change{ch}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, "/stock/shoppinglist/remove-product", nil, map[string]any{"product_id": int(pr.ID), "list_id": p.List, "product_amount": taken}, nil); err != nil {
		return sdk.Result{}, err
	}
	r, err := sdk.JSON(map[string]any{"removed": pr.Name, "product": int(pr.ID), "amount": taken, "left": left, "list": p.List})
	undo := map[string]any{"product": int(pr.ID), "amount": taken, "list": p.List}
	if left <= 0 && had.Note != "" {
		undo["note"] = had.Note
	}
	r.Undo = sdk.UndoWith("add_to_shopping_list", undo, fmt.Sprintf("Add %s %s back to the shopping list", fmtAmount(taken), pr.Name))
	return r, err
}

type stockLog struct {
	ID            num    `json:"id"`
	ProductID     num    `json:"product_id"`
	Amount        flt    `json:"amount"`
	TransactionID string `json:"transaction_id"`
	Type          string `json:"transaction_type"`
	Undone        bit    `json:"undone"`
}

func (c *conn) book(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	consume := call.Action == "consume_product"
	if err := validAmount(p.Amount); err != nil {
		return sdk.Result{}, err
	}
	bb := strings.TrimSpace(p.BestBefore)
	if bb != "" {
		if consume {
			return sdk.Result{}, errors.New("bestBefore is for add_stock")
		}
		if _, err := time.Parse("2006-01-02", bb); err != nil {
			return sdk.Result{}, errors.New("bestBefore is a date like 2026-12-31")
		}
	}
	pr, err := c.product(ctx, p.Product)
	if err != nil {
		return sdk.Result{}, err
	}
	var st struct {
		Amount flt `json:"stock_amount"`
		Unit   struct {
			Name string `json:"name"`
		} `json:"quantity_unit_stock"`
	}
	if err := c.do(ctx, http.MethodGet, "/stock/products/"+strconv.Itoa(int(pr.ID)), nil, nil, &st); err != nil {
		return sdk.Result{}, err
	}
	have := float64(st.Amount)
	unit := strings.TrimSpace(" " + st.Unit.Name)
	if consume && p.Amount > have {
		return sdk.Result{}, fmt.Errorf("only %s %s of %s is in stock", fmtAmount(have), unit, pr.Name)
	}
	after := have + p.Amount
	verb := "Add"
	if consume {
		after = have - p.Amount
		verb = "Consume"
		if p.Spoiled {
			verb = "Throw away (spoiled)"
		}
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %s %s of %s", verb, fmtAmount(p.Amount), unit, pr.Name),
			Changes: []sdk.Change{{Target: pr.Name + " stock", Op: "update", Before: mustJSON(map[string]float64{"amount": have}), After: mustJSON(map[string]float64{"amount": after})}}}}, nil
	}
	var logs []stockLog
	if consume {
		err = c.do(ctx, http.MethodPost, "/stock/products/"+strconv.Itoa(int(pr.ID))+"/consume", nil,
			map[string]any{"amount": p.Amount, "transaction_type": "consume", "spoiled": p.Spoiled}, &logs)
	} else {
		body := map[string]any{"amount": p.Amount, "transaction_type": "purchase"}
		if bb != "" {
			body["best_before_date"] = bb
		}
		err = c.do(ctx, http.MethodPost, "/stock/products/"+strconv.Itoa(int(pr.ID))+"/add", nil, body, &logs)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	tx := ""
	for _, l := range logs {
		if l.TransactionID != "" {
			tx = l.TransactionID
			break
		}
	}
	out := map[string]any{"product": int(pr.ID), "name": pr.Name, "amount": p.Amount, "stock": after}
	if tx != "" {
		out["transaction"] = tx
	}
	r, err := sdk.JSON(out)
	switch {
	case txRe.MatchString(tx):
		r.Undo = sdk.UndoWith("undo_stock_transaction", map[string]any{"id": tx}, fmt.Sprintf("Revert: %s %s %s of %s", strings.ToLower(verb), fmtAmount(p.Amount), unit, pr.Name))
	case consume:
		// Grocy before 3.0 answers without the transaction: put the same
		// amount back as a purchase.
		r.Undo = sdk.UndoWith("add_stock", map[string]any{"product": int(pr.ID), "amount": p.Amount}, fmt.Sprintf("Add %s %s of %s back to stock", fmtAmount(p.Amount), unit, pr.Name))
	}
	return r, err
}

func (c *conn) undoTransaction(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	id := strings.TrimSpace(string(p.ID))
	if !txRe.MatchString(id) {
		return sdk.Result{}, errors.New("the id is a stock transaction id")
	}
	var logs []stockLog
	if err := c.do(ctx, http.MethodGet, "/stock/transactions/"+id, nil, nil, &logs); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
			return sdk.Result{}, fmt.Errorf("there's no stock transaction %s", id)
		}
		return sdk.Result{}, err
	}
	if len(logs) == 0 {
		return sdk.Result{}, fmt.Errorf("there's no stock transaction %s", id)
	}
	total, kind := 0.0, logs[0].Type
	for _, l := range logs {
		if l.Undone.bool() {
			return sdk.Result{}, fmt.Errorf("stock transaction %s is reverted already", id)
		}
		total += math.Abs(float64(l.Amount))
	}
	name := ""
	if pr, err := c.product(ctx, ref(strconv.Itoa(int(logs[0].ProductID)))); err == nil {
		name = pr.Name
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Revert the %s of %s %s", kind, fmtAmount(total), name),
			Changes: []sdk.Change{{Target: "stock transaction " + id, Op: "undo", Before: mustJSON(map[string]any{"type": kind, "amount": total, "product": name})}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, "/stock/transactions/"+id+"/undo", nil, map[string]any{}, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"reverted": id, "type": kind, "amount": total, "product": name})
}

type chore struct {
	ID       num    `json:"chore_id"`
	Name     string `json:"chore_name"`
	Next     string `json:"next_estimated_execution_time"`
	Last     string `json:"last_tracked_time"`
	DateOnly bit    `json:"track_date_only"`
	Assigned *num   `json:"next_execution_assigned_to_user_id"`
}

func (c *conn) chores(ctx context.Context) ([]chore, error) {
	var cs []chore
	err := c.do(ctx, http.MethodGet, "/chores", nil, nil, &cs)
	return cs, err
}

func (c *conn) choresDue(ctx context.Context, days int) (sdk.Result, error) {
	cs, err := c.chores(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	now := c.now()
	today := now.Format("2006-01-02")
	until := now.AddDate(0, 0, days).Format("2006-01-02")
	sort.Slice(cs, func(i, j int) bool { return cs[i].Next < cs[j].Next })
	out := []map[string]any{}
	for _, ch := range cs {
		if len(ch.Next) < 10 || ch.Next[:10] >= never || ch.Next[:10] > until {
			continue
		}
		r := map[string]any{"chore": int(ch.ID), "name": ch.Name, "due": ch.Next}
		if ch.DateOnly.bool() {
			r["due"] = ch.Next[:10]
		}
		if ch.Next[:10] < today {
			r["overdue"] = true
		}
		if ch.Last != "" {
			r["last"] = ch.Last
		}
		out = append(out, r)
	}
	return sdk.JSON(map[string]any{"days": days, "chores": out})
}

func (c *conn) completeChore(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	s := strings.TrimSpace(string(p.Chore))
	if s == "" || !plainText(s, maxName) {
		return sdk.Result{}, errors.New("name the chore (an id or its exact name, see chores_due)")
	}
	cs, err := c.chores(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	var ch *chore
	for i := range cs {
		if strconv.Itoa(int(cs[i].ID)) == s || strings.EqualFold(strings.TrimSpace(cs[i].Name), s) {
			ch = &cs[i]
			break
		}
	}
	if ch == nil {
		return sdk.Result{}, fmt.Errorf("there's no chore %q; see chores_due", s)
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Mark %q done now", ch.Name),
			Changes: []sdk.Change{{Target: "chore " + ch.Name, Op: "track", Before: mustJSON(map[string]string{"last": ch.Last, "next": ch.Next})}}}}, nil
	}
	var log struct {
		ID num `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/chores/"+strconv.Itoa(int(ch.ID))+"/execute", nil, map[string]any{}, &log); err != nil {
		return sdk.Result{}, err
	}
	r, err := sdk.JSON(map[string]any{"done": ch.Name, "chore": int(ch.ID), "execution": int(log.ID)})
	if log.ID > 0 {
		r.Undo = sdk.UndoWith("undo_chore_execution", map[string]any{"id": int(log.ID)}, fmt.Sprintf("Revert %q being done", ch.Name))
	}
	return r, err
}
