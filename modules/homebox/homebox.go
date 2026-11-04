// Package homebox works with a Homebox home inventory through its REST API:
// searching items, locations, warranties running out, adding an item,
// changing how many there are and deleting one. It signs in with a user's
// email and password (Homebox's session login) or uses an API key on
// versions that have them.
package homebox

import (
	"bytes"
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
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Homebox server. Give either a token (an API key) or a
// username with a password.
type Config struct {
	URL                string `json:"url"`      // e.g. https://homebox.example.com
	Username           string `json:"username"` // the account's email
	Password           string `json:"password"` // secret://
	Token              string `json:"token"`    // secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string
	now    func() time.Time

	// Session login (when no API key is set).
	login    *rest.Client
	user     string
	password string // secret:// reference
	host     sdk.Host
	mu       sync.Mutex
	session  string
	expires  time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces the clock (tests).
	Now func() time.Time
}

// New returns the Homebox module.
func New() *Module { return &Module{} }

const (
	maxName        = 255
	maxDescription = 1000
	maxQuantity    = 1000000
	// maxScan is how many items warranty_soon reads in full at most.
	maxScan = 500
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	item := `"item":{"type":"string","description":"Item id (see search_items)"}`
	location := `"location":{"type":"string","description":"Location id or exact name (see locations)"}`
	return sdk.Manifest{
		ID: "homebox", Name: "Homebox", Version: "0.1.0", Category: "Productivity", Icon: "package",
		Description: "Your Homebox inventory: find items and where they are, see warranties running out, add items and change how many you have.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Homebox's address, e.g. https://homebox.example.com"},
			"username":{"type":"string","description":"The email you sign in with (with password)"},
			"password":{"type":"string","x-secret":true,"description":"That account's password"},
			"token":{"type":"string","x-secret":true,"description":"Or an API key, on Homebox versions that have them (instead of username and password)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "search_items", Title: "Search items", Description: "Items matching words in their name or description, everywhere or in one location, with quantity, location and labels.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string"},` + location + `,"archived":{"type":"boolean","default":false,"description":"Include archived items"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "item", Title: "Item", Description: "One item: description, quantity, location, labels, manufacturer and model, purchase and warranty. Notes and serial numbers are left out.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["item"],"properties":{` + item + `}}`)},
			{Name: "locations", Title: "Locations", Description: "Locations with how many items each holds.", Risk: sdk.RiskRead},
			{Name: "warranty_soon", Title: "Warranties ending soon", Description: "Items whose warranty ends within some days (or ended recently). Reads up to 500 items in full.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":730,"default":60},"includeExpired":{"type":"integer","minimum":0,"maximum":365,"default":0,"description":"Also list warranties that ended up to this many days ago"}}}`)},
			{Name: "add_item", Title: "Add an item", Description: "Adds an item to a location. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["name","location"],"properties":{"name":{"type":"string","maxLength":255},` + location + `,"quantity":{"type":"integer","minimum":0,"maximum":1000000,"default":1},"description":{"type":"string","maxLength":1000}}}`)},
			{Name: "update_quantity", Title: "Change the quantity", Description: "Sets how many of an item you have. Undo sets it back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["item","quantity"],"properties":{` + item + `,"quantity":{"type":"integer","minimum":0,"maximum":1000000}}}`)},
			{Name: "delete_item", Title: "Delete an item", Description: "Deletes an item with its attachments and maintenance log. Homebox can't bring it back.", Risk: sdk.RiskDestructive, DryRun: true,
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
		return errors.New("the address is like https://homebox.example.com")
	}
	user := strings.TrimSpace(c.Username)
	switch {
	case c.Token != "" && (user != "" || c.Password != ""):
		return errors.New("give an API key or a username and password, not both")
	case c.Token != "":
		if !strings.HasPrefix(c.Token, "secret://") {
			return errors.New("store the API key in the vault and enter its secret:// reference")
		}
	case user == "" || c.Password == "":
		return errors.New("enter the username (your email) and password, or an API key")
	case !strings.HasPrefix(c.Password, "secret://"):
		return errors.New("store the password in the vault and enter its secret:// reference")
	case len(user) > 255 || strings.ContainsAny(user, "\r\n"):
		return errors.New("the username is your Homebox email")
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
	client = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1"), "/api")
	cn := &conn{origin: origin, now: now, user: user, password: c.Password, host: h}
	tokenRef := c.Token
	cn.api = rest.New(origin+"/api/v1", func(ctx context.Context, r *http.Request) error {
		if tokenRef != "" {
			t, err := h.Secret(ctx, tokenRef)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+strings.TrimPrefix(strings.TrimSpace(t), "Bearer "))
			return nil
		}
		t, err := cn.sessionToken(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", t)
		return nil
	})
	cn.api.HTTP = client
	if tokenRef == "" {
		cn.login = rest.New(origin+"/api/v1", nil)
		cn.login.HTTP = client
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errLogin = errors.New("Homebox refused the username or password")

// sessionToken signs in when there's no session or it's about to end.
func (c *conn) sessionToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != "" && c.now().Add(time.Minute).Before(c.expires) {
		return c.session, nil
	}
	pw, err := c.host.Secret(ctx, c.password)
	if err != nil {
		return "", err
	}
	var res struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	_, err = c.login.Do(ctx, http.MethodPost, "/users/login", nil, map[string]any{"username": c.user, "password": pw, "stayLoggedIn": false}, &res)
	if err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusForbidden) {
			return "", errLogin
		}
		return "", fmt.Errorf("couldn't sign in to Homebox: %w", err)
	}
	t := strings.TrimSpace(res.Token)
	if t == "" || strings.ContainsAny(t, "\r\n") {
		return "", errors.New("Homebox's sign-in gave no session token")
	}
	if !strings.HasPrefix(t, "Bearer ") {
		t = "Bearer " + t
	}
	c.session = t
	c.expires = res.ExpiresAt
	if c.expires.IsZero() {
		c.expires = c.now().Add(time.Hour)
	}
	return t, nil
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if c.login != nil && rest.IsStatus(err, http.StatusUnauthorized) {
		// The session ended early (signed out elsewhere, server restart):
		// sign in again once.
		c.mu.Lock()
		c.session = ""
		c.mu.Unlock()
		_, err = c.api.Do(ctx, method, path, q, body, out)
	}
	switch {
	case errors.Is(err, errLogin):
		return err
	case rest.IsStatus(err, http.StatusUnauthorized):
		if c.login != nil {
			return errors.New("Homebox refused the session")
		}
		return errors.New("Homebox refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Homebox refused the request: %v", err)
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		Item struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"item"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/self", nil, nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Homebox API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in"
	if me.Item.Name != "" {
		msg += " as " + me.Item.Name
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type named struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type itemSummary struct {
	ID          string  `json:"id"`
	AssetID     string  `json:"assetId"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Quantity    int     `json:"quantity"`
	Archived    bool    `json:"archived"`
	Insured     bool    `json:"insured"`
	Location    *named  `json:"location"`
	Labels      []named `json:"labels"`
	UpdatedAt   string  `json:"updatedAt"`
}

type itemOut struct {
	itemSummary
	Manufacturer     string  `json:"manufacturer"`
	ModelNumber      string  `json:"modelNumber"`
	PurchaseTime     string  `json:"purchaseTime"`
	PurchaseFrom     string  `json:"purchaseFrom"`
	PurchasePrice    float64 `json:"purchasePrice"`
	LifetimeWarranty bool    `json:"lifetimeWarranty"`
	WarrantyExpires  string  `json:"warrantyExpires"`
	WarrantyDetails  string  `json:"warrantyDetails"`
}

// date reads Homebox's dates, which are zero ("0001-01-01") when unset.
func date(s string) string {
	if !dateRe.MatchString(s) || strings.HasPrefix(s, "0001-") {
		return ""
	}
	return s[:10]
}

func (c *conn) summary(it itemSummary) map[string]any {
	labels := []string{}
	for _, l := range it.Labels {
		labels = append(labels, l.Name)
	}
	out := map[string]any{"id": it.ID, "name": it.Name, "quantity": it.Quantity, "labels": labels,
		"open": c.origin + "/item/" + url.PathEscape(it.ID)}
	if it.Location != nil {
		out["location"] = it.Location.Name
	}
	if it.AssetID != "" && it.AssetID != "0" && it.AssetID != "000-000" {
		out["assetId"] = it.AssetID
	}
	if it.Archived {
		out["archived"] = true
	}
	return out
}

func (c *conn) get(ctx context.Context, id string) (itemOut, error) {
	id = strings.TrimSpace(id)
	if !uuidRe.MatchString(id) {
		return itemOut{}, errors.New("the item is an item id (see search_items)")
	}
	var it itemOut
	if err := c.do(ctx, http.MethodGet, "/items/"+id, nil, nil, &it); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
			return itemOut{}, fmt.Errorf("there's no item %s", id)
		}
		return itemOut{}, err
	}
	if it.ID == "" {
		return itemOut{}, fmt.Errorf("there's no item %s", id)
	}
	return it, nil
}

type location struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ItemCount   int    `json:"itemCount"`
}

func (c *conn) locations(ctx context.Context) ([]location, error) {
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/locations", nil, nil, &raw); err != nil {
		return nil, err
	}
	var ls []location
	if t := bytes.TrimSpace(raw); len(t) > 0 && t[0] == '[' {
		if err := json.Unmarshal(t, &ls); err != nil {
			return nil, fmt.Errorf("unexpected answer from Homebox: %w", err)
		}
		return ls, nil
	}
	// Older versions wrap lists.
	var w struct {
		Items []location `json:"items"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("unexpected answer from Homebox: %w", err)
	}
	return w.Items, nil
}

// location finds a location by id or exact name (case doesn't matter).
func (c *conn) location(ctx context.Context, s string) (location, error) {
	s = strings.TrimSpace(s)
	if s == "" || !plain(s, maxName) {
		return location{}, errors.New("the location is a location id or name (see locations)")
	}
	ls, err := c.locations(ctx)
	if err != nil {
		return location{}, err
	}
	for _, l := range ls {
		if strings.EqualFold(l.ID, s) {
			return l, nil
		}
	}
	var found []location
	for _, l := range ls {
		if strings.EqualFold(strings.TrimSpace(l.Name), s) {
			found = append(found, l)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return location{}, fmt.Errorf("there's no location %q; see locations", s)
	}
	return location{}, fmt.Errorf("%d locations are named %q; give its id", len(found), s)
}

func plain(s string, max int) bool {
	if len([]rune(s)) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}

type input struct {
	Query          string `json:"query"`
	Location       string `json:"location"`
	Archived       bool   `json:"archived"`
	Limit          int    `json:"limit"`
	Item           string `json:"item"`
	Days           int    `json:"days"`
	IncludeExpired int    `json:"includeExpired"`
	Name           string `json:"name"`
	Quantity       *int   `json:"quantity"`
	Description    string `json:"description"`
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
	case "search_items":
		q := strings.TrimSpace(p.Query)
		if !plain(q, 500) {
			return sdk.Result{}, errors.New("the query is too long")
		}
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 25
		}
		v := url.Values{"page": {"1"}, "pageSize": {strconv.Itoa(limit)}}
		if q != "" {
			v.Set("q", q)
		}
		if p.Archived {
			v.Set("includeArchived", "true")
		}
		var loc location
		if strings.TrimSpace(p.Location) != "" {
			if loc, err = c.location(ctx, p.Location); err != nil {
				return sdk.Result{}, err
			}
			v.Set("locations", loc.ID)
		}
		var res struct {
			Total int           `json:"total"`
			Items []itemSummary `json:"items"`
		}
		if err := c.do(ctx, http.MethodGet, "/items", v, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, it := range res.Items {
			out = append(out, c.summary(it))
		}
		return sdk.JSON(map[string]any{"items": out, "total": res.Total})

	case "item":
		it, err := c.get(ctx, p.Item)
		if err != nil {
			return sdk.Result{}, err
		}
		out := c.summary(it.itemSummary)
		for k, v := range map[string]string{"description": it.Description, "manufacturer": it.Manufacturer, "model": it.ModelNumber,
			"purchased": date(it.PurchaseTime), "purchasedFrom": it.PurchaseFrom, "warrantyExpires": date(it.WarrantyExpires), "warrantyDetails": it.WarrantyDetails} {
			if v != "" {
				out[k] = v
			}
		}
		if it.PurchasePrice > 0 {
			out["purchasePrice"] = it.PurchasePrice
		}
		if it.LifetimeWarranty {
			out["lifetimeWarranty"] = true
		}
		if it.Insured {
			out["insured"] = true
		}
		return sdk.JSON(out)

	case "locations":
		ls, err := c.locations(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.Slice(ls, func(i, j int) bool { return strings.ToLower(ls[i].Name) < strings.ToLower(ls[j].Name) })
		out := []map[string]any{}
		for _, l := range ls {
			r := map[string]any{"id": l.ID, "name": l.Name, "items": l.ItemCount}
			if l.Description != "" {
				r["description"] = l.Description
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "warranty_soon":
		return c.warrantySoon(ctx, p)
	case "add_item":
		return c.add(ctx, call, p)

	case "update_quantity":
		if p.Quantity == nil || *p.Quantity < 0 || *p.Quantity > maxQuantity {
			return sdk.Result{}, fmt.Errorf("the quantity is 0 to %d", maxQuantity)
		}
		it, err := c.get(ctx, p.Item)
		if err != nil {
			return sdk.Result{}, err
		}
		q := *p.Quantity
		if it.Quantity == q {
			return sdk.JSON(map[string]any{"item": it.ID, "name": it.Name, "quantity": q, "note": "nothing to change"})
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Set the quantity of %q from %d to %d", it.Name, it.Quantity, q),
				Changes: []sdk.Change{{Target: "item " + it.Name, Op: "update", Before: mustJSON(map[string]int{"quantity": it.Quantity}), After: mustJSON(map[string]int{"quantity": q})}}}}, nil
		}
		if err := c.do(ctx, http.MethodPatch, "/items/"+it.ID, nil, map[string]any{"id": it.ID, "quantity": q}, nil); err != nil {
			if rest.IsStatus(err, http.StatusMethodNotAllowed) {
				return sdk.Result{}, errors.New("this Homebox can't change a quantity on its own; update Homebox")
			}
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"item": it.ID, "name": it.Name, "quantity": q, "was": it.Quantity})
		res.Undo = sdk.UndoWith("update_quantity", map[string]any{"item": it.ID, "quantity": it.Quantity}, fmt.Sprintf("Set %q back to %d", it.Name, it.Quantity))
		return res, err

	case "delete_item":
		it, err := c.get(ctx, p.Item)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete item %q", it.Name),
				Changes: []sdk.Change{{Target: "item " + it.ID, Op: "delete", Before: mustJSON(c.summary(it.itemSummary))}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/items/"+it.ID, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": it.ID, "name": it.Name})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) add(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" || !plain(name, maxName) || strings.Contains(name, "\n") {
		return sdk.Result{}, fmt.Errorf("the name is one line of 1 to %d characters", maxName)
	}
	desc := strings.TrimSpace(p.Description)
	if !plain(desc, maxDescription) {
		return sdk.Result{}, fmt.Errorf("the description is at most %d characters", maxDescription)
	}
	q := 1
	if p.Quantity != nil {
		q = *p.Quantity
	}
	if q < 0 || q > maxQuantity {
		return sdk.Result{}, fmt.Errorf("the quantity is 0 to %d", maxQuantity)
	}
	if strings.TrimSpace(p.Location) == "" {
		return sdk.Result{}, errors.New("give the location (see locations)")
	}
	loc, err := c.location(ctx, p.Location)
	if err != nil {
		return sdk.Result{}, err
	}
	body := map[string]any{"name": name, "quantity": q, "locationId": loc.ID, "labelIds": []string{}}
	if desc != "" {
		body["description"] = desc
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add %d × %q to %s", q, name, loc.Name),
			Changes: []sdk.Change{{Target: "location " + loc.Name, Op: "create", After: mustJSON(map[string]any{"name": name, "quantity": q, "description": desc})}}}}, nil
	}
	var it itemSummary
	if err := c.do(ctx, http.MethodPost, "/items", nil, body, &it); err != nil {
		return sdk.Result{}, err
	}
	if !uuidRe.MatchString(it.ID) {
		return sdk.Result{}, errors.New("Homebox didn't say which item it made")
	}
	// Versions that ignore the quantity on create make one.
	if it.Quantity != q {
		if err := c.do(ctx, http.MethodPatch, "/items/"+it.ID, nil, map[string]any{"id": it.ID, "quantity": q}, nil); err == nil {
			it.Quantity = q
		}
	}
	if it.Location == nil {
		it.Location = &named{ID: loc.ID, Name: loc.Name}
	}
	r, err := sdk.JSON(c.summary(it))
	r.Undo = sdk.UndoWith("delete_item", map[string]any{"item": it.ID}, fmt.Sprintf("Delete %q", name))
	return r, err
}

func (c *conn) warrantySoon(ctx context.Context, p input) (sdk.Result, error) {
	days := p.Days
	if days == 0 {
		days = 60
	}
	if days < 1 || days > 730 || p.IncludeExpired < 0 || p.IncludeExpired > 365 {
		return sdk.Result{}, errors.New("days is 1 to 730 and includeExpired 0 to 365")
	}
	now := c.now()
	from := now.AddDate(0, 0, -p.IncludeExpired).Format("2006-01-02")
	until := now.AddDate(0, 0, days).Format("2006-01-02")
	today := now.Format("2006-01-02")

	// Listings don't carry warranties: read each item, a page at a time.
	var ids []string
	total := 0
	for page := 1; len(ids) < maxScan; page++ {
		var res struct {
			Total int           `json:"total"`
			Items []itemSummary `json:"items"`
		}
		if err := c.do(ctx, http.MethodGet, "/items", url.Values{"page": {strconv.Itoa(page)}, "pageSize": {"100"}}, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		total = res.Total
		for _, it := range res.Items {
			if len(ids) < maxScan && uuidRe.MatchString(it.ID) {
				ids = append(ids, it.ID)
			}
		}
		if len(res.Items) < 100 || page*100 >= res.Total {
			break
		}
	}
	type hit struct {
		row     map[string]any
		expires string
	}
	var (
		mu    sync.Mutex
		hits  []hit
		first error
		wg    sync.WaitGroup
		sem   = make(chan struct{}, 4)
	)
	for _, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			it, err := c.get(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if first == nil {
					first = err
				}
				return
			}
			exp := date(it.WarrantyExpires)
			if it.LifetimeWarranty || exp == "" || exp < from || exp > until {
				return
			}
			r := c.summary(it.itemSummary)
			r["warrantyExpires"] = exp
			if exp < today {
				r["expired"] = true
			}
			hits = append(hits, hit{r, exp})
		}(id)
	}
	wg.Wait()
	if first != nil {
		return sdk.Result{}, first
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].expires < hits[j].expires })
	out := []map[string]any{}
	for _, h := range hits {
		out = append(out, h.row)
	}
	res := map[string]any{"days": days, "items": out, "checked": len(ids)}
	if total > len(ids) {
		res["note"] = fmt.Sprintf("only the first %d of %d items were checked", len(ids), total)
	}
	return sdk.JSON(res)
}
