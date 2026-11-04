// Package mealie works with a Mealie recipe server through its REST API and
// an API token: searching recipes, a recipe's ingredients and steps, the
// meal plan for today or this week, and shopping lists (reading them,
// adding, changing and removing items).
package mealie

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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Mealie server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://mealie.example.com
	Token              string `json:"token"` // secret:// API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client

	mu sync.Mutex
	// scope is where meal plans and shopping lists live: /households in
	// Mealie 2, /groups in Mealie 1.
	scope string
	now   func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Mealie module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	slugRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,250}$`)
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$`)
	dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	list := `"list":{"type":"string","description":"Shopping list name or id"}`
	item := `"item":{"type":"string","description":"Item id (see shopping_list)"}`
	return sdk.Manifest{
		ID: "mealie", Name: "Mealie", Version: "0.1.0", Category: "Home", Icon: "list",
		Description: "Mealie recipes, the meal plan and shopping lists: search recipes, read one, see today's or this week's meals, add to a shopping list.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Mealie's address, e.g. https://mealie.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API token from your user profile → API Tokens"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "search_recipes", Title: "Search recipes", Description: "Recipes matching words in their name, description or ingredients, with times, rating, tags and categories.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":50,"default":20}}}`)},
			{Name: "recipe", Title: "Recipe", Description: "One recipe: servings, times, ingredients, steps, notes and nutrition.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["slug"],"properties":{"slug":{"type":"string","description":"The recipe's slug (see search_recipes)"}}}`)},
			{Name: "meal_plan", Title: "Meal plan", Description: "Planned meals for today, this week (Monday to Sunday) or a date range.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"range":{"type":"string","enum":["today","week"],"default":"today"},"start":{"type":"string","format":"date"},"end":{"type":"string","format":"date"}}}`)},
			{Name: "shopping_lists", Title: "Shopping lists", Description: "The shopping lists.", Risk: sdk.RiskRead},
			{Name: "shopping_list", Title: "Shopping list", Description: "A list's items, unchecked first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["list"],"properties":{` + list + `,"checked":{"type":"boolean","description":"Include checked items (default true)"}}}`)},
			{Name: "add_shopping_item", Title: "Add to a shopping list", Description: "Adds an item (Mealie merges it into a matching unchecked item). Undo removes it, or restores the merged item.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["list","note"],"properties":{` + list + `,"note":{"type":"string","description":"What to buy, e.g. 2 lemons"},"quantity":{"type":"number","minimum":0,"default":1},"foodId":{"type":"string"},"unitId":{"type":"string"},"labelId":{"type":"string"}}}`)},
			{Name: "update_shopping_item", Title: "Change a shopping item", Description: "Checks or unchecks an item, or changes its text or quantity. Undo restores it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["item"],"properties":{` + item + `,"checked":{"type":"boolean"},"note":{"type":"string"},"quantity":{"type":"number","minimum":0}}}`)},
			{Name: "remove_shopping_item", Title: "Remove a shopping item", Description: "Deletes an item from its list. Undo adds it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["item"],"properties":{` + item + `}}`)},
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
		return errors.New("the address is like https://mealie.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, now: time.Now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		return errors.New("Mealie refused the API token")
	}
	if rest.IsStatus(err, http.StatusForbidden) {
		return errors.New("Mealie refused the request: the token's user lacks the permission for it")
	}
	return err
}

// where returns the API prefix for meal plans and shopping lists.
func (c *conn) where(ctx context.Context) (string, error) {
	c.mu.Lock()
	s := c.scope
	c.mu.Unlock()
	if s != "" {
		return s, nil
	}
	var about struct {
		Version string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "/app/about", nil, nil, &about); err != nil {
		return "", err
	}
	s = "/households"
	if v := strings.TrimPrefix(about.Version, "v"); strings.HasPrefix(v, "1.") || strings.HasPrefix(v, "0.") {
		s = "/groups"
	}
	c.mu.Lock()
	c.scope = s
	c.mu.Unlock()
	return s, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		Username string `json:"username"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/self", nil, nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Mealie API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + me.Username
	var about struct {
		Version string `json:"version"`
	}
	if c.do(ctx, http.MethodGet, "/app/about", nil, nil, &about) == nil && about.Version != "" {
		msg += " · Mealie " + about.Version
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type named struct {
	Name string `json:"name"`
}

func names(l []named) []string {
	out := []string{}
	for _, n := range l {
		out = append(out, n.Name)
	}
	return out
}

type recipeSummary struct {
	ID          string   `json:"id"`
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	TotalTime   *string  `json:"totalTime"`
	PrepTime    *string  `json:"prepTime"`
	PerformTime *string  `json:"performTime"`
	RecipeYield *string  `json:"recipeYield"`
	Rating      *float64 `json:"rating"`
	Tags        []named  `json:"tags"`
	Categories  []named  `json:"recipeCategory"`
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func opt(e map[string]any, k string, v *string) {
	if v != nil && *v != "" {
		e[k] = *v
	}
}

func summaryOut(r recipeSummary) map[string]any {
	e := map[string]any{"slug": r.Slug, "name": r.Name, "tags": names(r.Tags), "categories": names(r.Categories)}
	if r.Description != "" {
		e["description"] = clip(r.Description, 300)
	}
	opt(e, "totalTime", r.TotalTime)
	opt(e, "prepTime", r.PrepTime)
	opt(e, "cookTime", r.PerformTime)
	opt(e, "yield", r.RecipeYield)
	if r.Rating != nil && *r.Rating > 0 {
		e["rating"] = *r.Rating
	}
	return e
}

type shoppingItem struct {
	ID             string  `json:"id"`
	ShoppingListID string  `json:"shoppingListId"`
	Checked        bool    `json:"checked"`
	Position       int     `json:"position"`
	IsFood         bool    `json:"isFood"`
	Note           string  `json:"note"`
	Quantity       float64 `json:"quantity"`
	Display        string  `json:"display"`
	FoodID         *string `json:"foodId"`
	UnitID         *string `json:"unitId"`
	LabelID        *string `json:"labelId"`
	Food           *named  `json:"food"`
	Unit           *named  `json:"unit"`
	Label          *named  `json:"label"`
}

func (it shoppingItem) text() string {
	if it.Display != "" {
		return it.Display
	}
	s := it.Note
	if it.Food != nil && it.Food.Name != "" {
		s = strings.TrimSpace(it.Food.Name + " " + it.Note)
	}
	return s
}

func itemOut(it shoppingItem) map[string]any {
	e := map[string]any{"id": it.ID, "text": it.text(), "quantity": it.Quantity, "checked": it.Checked}
	if it.Label != nil && it.Label.Name != "" {
		e["label"] = it.Label.Name
	}
	return e
}

// update is what PUT /shopping/items/{id} takes.
func (it shoppingItem) update() map[string]any {
	return map[string]any{"id": it.ID, "shoppingListId": it.ShoppingListID, "checked": it.Checked, "position": it.Position, "isFood": it.IsFood,
		"note": it.Note, "quantity": it.Quantity, "foodId": it.FoodID, "unitId": it.UnitID, "labelId": it.LabelID}
}

type shoppingList struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	ListItems []shoppingItem `json:"listItems"`
}

// changes is Mealie's answer to item writes.
type changes struct {
	Created []shoppingItem `json:"createdItems"`
	Updated []shoppingItem `json:"updatedItems"`
	Deleted []shoppingItem `json:"deletedItems"`
}

type input struct {
	Query    string   `json:"query"`
	Limit    int      `json:"limit"`
	Slug     string   `json:"slug"`
	Range    string   `json:"range"`
	Start    string   `json:"start"`
	End      string   `json:"end"`
	List     string   `json:"list"`
	Checked  *bool    `json:"checked"`
	Note     *string  `json:"note"`
	Quantity *float64 `json:"quantity"`
	Item     string   `json:"item"`
	FoodID   string   `json:"foodId"`
	UnitID   string   `json:"unitId"`
	LabelID  string   `json:"labelId"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
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
	case "search_recipes":
		n := p.Limit
		if n == 0 {
			n = 20
		}
		if n < 1 || n > 50 {
			return sdk.Result{}, errors.New("limit is between 1 and 50")
		}
		q := url.Values{"page": {"1"}, "perPage": {strconv.Itoa(n)}, "orderBy": {"name"}, "orderDirection": {"asc"}}
		if s := strings.TrimSpace(p.Query); s != "" {
			if len(s) > 200 {
				return sdk.Result{}, errors.New("the search is too long")
			}
			q.Set("search", s)
			q.Del("orderBy") // keep Mealie's relevance order
			q.Del("orderDirection")
		}
		var out struct {
			Items []recipeSummary `json:"items"`
			Total int             `json:"total"`
		}
		if err := c.do(ctx, http.MethodGet, "/recipes", q, nil, &out); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, r := range out.Items {
			list = append(list, summaryOut(r))
		}
		return sdk.JSON(map[string]any{"total": out.Total, "recipes": list})

	case "recipe":
		return c.recipe(ctx, p.Slug)

	case "meal_plan":
		return c.mealPlan(ctx, p)

	case "shopping_lists":
		scope, err := c.where(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		lists, err := c.lists(ctx, scope)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, l := range lists {
			out = append(out, map[string]any{"id": l.ID, "name": l.Name})
		}
		return sdk.JSON(out)

	case "shopping_list":
		l, err := c.findList(ctx, p.List)
		if err != nil {
			return sdk.Result{}, err
		}
		items := l.ListItems
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].Checked != items[j].Checked {
				return !items[i].Checked
			}
			return items[i].Position < items[j].Position
		})
		out := []map[string]any{}
		open := 0
		for _, it := range items {
			if !it.Checked {
				open++
			}
			if it.Checked && p.Checked != nil && !*p.Checked {
				continue
			}
			out = append(out, itemOut(it))
		}
		return sdk.JSON(map[string]any{"id": l.ID, "name": l.Name, "open": open, "items": out})

	case "add_shopping_item":
		return c.addItem(ctx, call, p)

	case "update_shopping_item":
		return c.updateItem(ctx, call, p)

	case "remove_shopping_item":
		scope, it, err := c.item(ctx, p.Item)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Remove %q from the shopping list", it.text()),
				Changes: []sdk.Change{{Target: "shopping item " + it.text(), Op: "delete", Before: mustJSON(itemOut(it))}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, scope+"/shopping/items/"+it.ID, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"removed": it.text()})
		undo := map[string]any{"list": it.ShoppingListID, "note": it.Note, "quantity": it.Quantity}
		if it.FoodID != nil {
			undo["foodId"] = *it.FoodID
		}
		if it.UnitID != nil {
			undo["unitId"] = *it.UnitID
		}
		if it.LabelID != nil {
			undo["labelId"] = *it.LabelID
		}
		res.Undo = sdk.UndoWith("add_shopping_item", undo, "Add "+it.text()+" back")
		return res, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) recipe(ctx context.Context, slug string) (sdk.Result, error) {
	slug = strings.TrimSpace(slug)
	if !slugRe.MatchString(slug) || strings.Contains(slug, "..") {
		return sdk.Result{}, errors.New("enter the recipe's slug (see search_recipes)")
	}
	var r struct {
		recipeSummary
		RecipeServings float64 `json:"recipeServings"`
		OrgURL         *string `json:"orgURL"`
		Ingredients    []struct {
			Display      string   `json:"display"`
			Note         string   `json:"note"`
			OriginalText string   `json:"originalText"`
			Quantity     *float64 `json:"quantity"`
			Title        *string  `json:"title"`
			Food         *named   `json:"food"`
			Unit         *named   `json:"unit"`
		} `json:"recipeIngredient"`
		Instructions []struct {
			Title *string `json:"title"`
			Text  string  `json:"text"`
		} `json:"recipeInstructions"`
		Notes []struct {
			Title string `json:"title"`
			Text  string `json:"text"`
		} `json:"notes"`
		Nutrition map[string]any `json:"nutrition"`
	}
	if err := c.do(ctx, http.MethodGet, "/recipes/"+url.PathEscape(slug), nil, nil, &r); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no recipe %s", slug)
		}
		return sdk.Result{}, err
	}
	e := summaryOut(r.recipeSummary)
	if r.Description != "" {
		e["description"] = clip(r.Description, 2000)
	}
	if r.RecipeServings > 0 {
		e["servings"] = r.RecipeServings
	}
	opt(e, "source", r.OrgURL)
	ings := []string{}
	for _, in := range r.Ingredients {
		s := in.Display
		if s == "" {
			s = in.OriginalText
		}
		if s == "" {
			parts := []string{}
			if in.Quantity != nil && *in.Quantity > 0 {
				parts = append(parts, strconv.FormatFloat(*in.Quantity, 'f', -1, 64))
			}
			if in.Unit != nil {
				parts = append(parts, in.Unit.Name)
			}
			if in.Food != nil {
				parts = append(parts, in.Food.Name)
			}
			if in.Note != "" {
				parts = append(parts, in.Note)
			}
			s = strings.Join(parts, " ")
		}
		if in.Title != nil && *in.Title != "" {
			ings = append(ings, "## "+*in.Title)
		}
		ings = append(ings, clip(s, 300))
	}
	steps := []string{}
	for _, st := range r.Instructions {
		s := st.Text
		if st.Title != nil && *st.Title != "" {
			s = *st.Title + ": " + s
		}
		steps = append(steps, clip(s, 3000))
	}
	notes := []string{}
	for _, n := range r.Notes {
		notes = append(notes, clip(strings.TrimSpace(n.Title+" "+n.Text), 1000))
	}
	nut := map[string]any{}
	for k, v := range r.Nutrition {
		if s, ok := v.(string); ok && s != "" {
			nut[k] = s
		}
	}
	e["ingredients"], e["steps"], e["notes"], e["nutrition"] = ings, steps, notes, nut
	return sdk.JSON(e)
}

type mealEntry struct {
	Date      string `json:"date"`
	EntryType string `json:"entryType"`
	Title     string `json:"title"`
	Text      string `json:"text"`
	Recipe    *struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	} `json:"recipe"`
}

var mealOrder = map[string]int{"breakfast": 0, "lunch": 1, "dinner": 2, "side": 3, "snack": 4, "drink": 5, "dessert": 6}

func (c *conn) mealPlan(ctx context.Context, p input) (sdk.Result, error) {
	scope, err := c.where(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	now := c.now()
	today := now.Format("2006-01-02")
	start, end := today, today
	switch {
	case p.Start != "" || p.End != "":
		if !dateRe.MatchString(p.Start) || !dateRe.MatchString(p.End) {
			return sdk.Result{}, errors.New("start and end are dates like 2026-11-04")
		}
		a, e1 := time.Parse("2006-01-02", p.Start)
		b, e2 := time.Parse("2006-01-02", p.End)
		if e1 != nil || e2 != nil || b.Before(a) || b.Sub(a) > 62*24*time.Hour {
			return sdk.Result{}, errors.New("end is on or after start, at most two months later")
		}
		start, end = p.Start, p.End
	case p.Range == "week":
		wd := (int(now.Weekday()) + 6) % 7 // Monday is 0
		mon := now.AddDate(0, 0, -wd)
		start, end = mon.Format("2006-01-02"), mon.AddDate(0, 0, 6).Format("2006-01-02")
	case p.Range == "" || p.Range == "today":
	default:
		return sdk.Result{}, errors.New("range is today or week")
	}
	var out struct {
		Items []mealEntry `json:"items"`
	}
	q := url.Values{"start_date": {start}, "end_date": {end}, "page": {"1"}, "perPage": {"200"}, "orderBy": {"date"}, "orderDirection": {"asc"}}
	if err := c.do(ctx, http.MethodGet, scope+"/mealplans", q, nil, &out); err != nil {
		return sdk.Result{}, err
	}
	items := out.Items
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Date != items[j].Date {
			return items[i].Date < items[j].Date
		}
		return mealOrder[items[i].EntryType] < mealOrder[items[j].EntryType]
	})
	days := []map[string]any{}
	var cur map[string]any
	for _, it := range items {
		if it.Date < start || it.Date > end {
			continue
		}
		if cur == nil || cur["date"] != it.Date {
			cur = map[string]any{"date": it.Date, "meals": []map[string]any{}}
			days = append(days, cur)
		}
		e := map[string]any{"type": it.EntryType}
		if it.Recipe != nil {
			e["recipe"], e["slug"] = it.Recipe.Name, it.Recipe.Slug
		}
		if it.Title != "" {
			e["title"] = it.Title
		}
		if it.Text != "" {
			e["note"] = clip(it.Text, 500)
		}
		cur["meals"] = append(cur["meals"].([]map[string]any), e)
	}
	return sdk.JSON(map[string]any{"start": start, "end": end, "days": days})
}

func (c *conn) lists(ctx context.Context, scope string) ([]shoppingList, error) {
	var out struct {
		Items []shoppingList `json:"items"`
	}
	err := c.do(ctx, http.MethodGet, scope+"/shopping/lists", url.Values{"page": {"1"}, "perPage": {"100"}, "orderBy": {"name"}, "orderDirection": {"asc"}}, nil, &out)
	return out.Items, err
}

// findList resolves a list's name or id and reads it with its items.
func (c *conn) findList(ctx context.Context, ref string) (shoppingList, error) {
	var l shoppingList
	ref = strings.TrimSpace(ref)
	if ref == "" || len(ref) > 200 {
		return l, errors.New("enter the shopping list's name or id")
	}
	scope, err := c.where(ctx)
	if err != nil {
		return l, err
	}
	id := ""
	if uuidRe.MatchString(ref) {
		id = ref
	} else {
		lists, err := c.lists(ctx, scope)
		if err != nil {
			return l, err
		}
		for _, x := range lists {
			if strings.EqualFold(x.Name, ref) {
				id = x.ID
				break
			}
		}
		if id == "" {
			var have []string
			for _, x := range lists {
				have = append(have, x.Name)
			}
			return l, fmt.Errorf("there's no shopping list %s (lists: %s)", ref, strings.Join(have, ", "))
		}
		if !uuidRe.MatchString(id) {
			return l, errors.New("unexpected list id from Mealie")
		}
	}
	if err := c.do(ctx, http.MethodGet, scope+"/shopping/lists/"+id, nil, nil, &l); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return l, fmt.Errorf("there's no shopping list %s", ref)
		}
		return l, err
	}
	return l, nil
}

func (c *conn) item(ctx context.Context, id string) (string, shoppingItem, error) {
	var it shoppingItem
	id = strings.TrimSpace(id)
	if !uuidRe.MatchString(id) {
		return "", it, errors.New("enter the item's id (see shopping_list)")
	}
	scope, err := c.where(ctx)
	if err != nil {
		return "", it, err
	}
	if err := c.do(ctx, http.MethodGet, scope+"/shopping/items/"+id, nil, nil, &it); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return "", it, fmt.Errorf("there's no shopping item %s", id)
		}
		return "", it, err
	}
	if !uuidRe.MatchString(it.ID) {
		return "", it, errors.New("unexpected item from Mealie")
	}
	return scope, it, nil
}

func optID(s string) (*string, error) {
	if s == "" {
		return nil, nil
	}
	if !uuidRe.MatchString(s) {
		return nil, errors.New("food, unit and label ids are UUIDs")
	}
	return &s, nil
}

func (c *conn) addItem(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	note := ""
	if p.Note != nil {
		note = strings.TrimSpace(*p.Note)
	}
	if note == "" && p.FoodID == "" {
		return sdk.Result{}, errors.New("enter what to add")
	}
	if len(note) > 500 {
		return sdk.Result{}, errors.New("the item is too long")
	}
	qty := 1.0
	if p.Quantity != nil {
		qty = *p.Quantity
	}
	if qty < 0 || qty > 1e6 {
		return sdk.Result{}, errors.New("the quantity is a positive number")
	}
	food, err := optID(p.FoodID)
	if err != nil {
		return sdk.Result{}, err
	}
	unit, err := optID(p.UnitID)
	if err != nil {
		return sdk.Result{}, err
	}
	label, err := optID(p.LabelID)
	if err != nil {
		return sdk.Result{}, err
	}
	l, err := c.findList(ctx, p.List)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add %q to %s", note, l.Name),
			Changes: []sdk.Change{{Target: "shopping list " + l.Name, Op: "create", After: mustJSON(map[string]any{"text": note, "quantity": qty})}}}}, nil
	}
	before := map[string]shoppingItem{}
	for _, it := range l.ListItems {
		before[it.ID] = it
	}
	scope, _ := c.where(ctx)
	body := map[string]any{"shoppingListId": l.ID, "note": note, "quantity": qty, "checked": false, "isFood": food != nil, "foodId": food, "unitId": unit, "labelId": label}
	var ch changes
	if err := c.do(ctx, http.MethodPost, scope+"/shopping/items", nil, body, &ch); err != nil {
		return sdk.Result{}, err
	}
	switch {
	case len(ch.Created) > 0 && uuidRe.MatchString(ch.Created[0].ID):
		it := ch.Created[0]
		res, err := sdk.JSON(map[string]any{"list": l.Name, "added": itemOut(it)})
		res.Undo = sdk.UndoWith("remove_shopping_item", map[string]string{"item": it.ID}, fmt.Sprintf("Remove %s from %s", it.text(), l.Name))
		return res, err
	case len(ch.Updated) > 0:
		// Mealie merged it into a matching item: undo puts that item back.
		it := ch.Updated[0]
		res, err := sdk.JSON(map[string]any{"list": l.Name, "mergedInto": itemOut(it)})
		if old, ok := before[it.ID]; ok && uuidRe.MatchString(it.ID) {
			res.Undo = sdk.UndoWith("update_shopping_item", map[string]any{"item": it.ID, "quantity": old.Quantity, "note": old.Note, "checked": old.Checked},
				fmt.Sprintf("Set %s back to %s", old.text(), strconv.FormatFloat(old.Quantity, 'f', -1, 64)))
		}
		return res, err
	}
	return sdk.JSON(map[string]any{"list": l.Name, "added": note})
}

func (c *conn) updateItem(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Checked == nil && p.Note == nil && p.Quantity == nil {
		return sdk.Result{}, errors.New("say what to change: checked, note or quantity")
	}
	if p.Note != nil && len(*p.Note) > 500 {
		return sdk.Result{}, errors.New("the item is too long")
	}
	if p.Quantity != nil && (*p.Quantity < 0 || *p.Quantity > 1e6) {
		return sdk.Result{}, errors.New("the quantity is a positive number")
	}
	scope, it, err := c.item(ctx, p.Item)
	if err != nil {
		return sdk.Result{}, err
	}
	old := it
	if p.Checked != nil {
		it.Checked = *p.Checked
	}
	if p.Note != nil {
		it.Note = strings.TrimSpace(*p.Note)
	}
	if p.Quantity != nil {
		it.Quantity = *p.Quantity
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Change %q on the shopping list", old.text()),
			Changes: []sdk.Change{{Target: "shopping item " + old.text(), Op: "update",
				Before: mustJSON(map[string]any{"note": old.Note, "quantity": old.Quantity, "checked": old.Checked}),
				After:  mustJSON(map[string]any{"note": it.Note, "quantity": it.Quantity, "checked": it.Checked})}}}}, nil
	}
	if err := c.do(ctx, http.MethodPut, scope+"/shopping/items/"+it.ID, nil, it.update(), nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"item": it.ID, "note": it.Note, "quantity": it.Quantity, "checked": it.Checked})
	res.Undo = sdk.UndoWith("update_shopping_item", map[string]any{"item": it.ID, "note": old.Note, "quantity": old.Quantity, "checked": old.Checked}, "Restore "+old.text())
	return res, err
}
