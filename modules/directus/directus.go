// Package directus works with a Directus project through its REST API and a
// static token: collections and their fields, listing, reading, creating,
// updating and deleting items, and running flows that have a webhook or
// manual trigger.
//
// System collections (directus_users, directus_sessions, directus_settings
// and every other directus_ one) are refused for every item action, so
// users' e-mails, password hashes and tokens are never read. Hash and
// concealed fields of the project's own collections are left out of every
// item and can't be filtered on or set.
package directus

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
	"github.com/elchi-dev/conduit/modules/internal/records"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Directus project.
type Config struct {
	URL                string `json:"url"`   // e.g. https://directus.example.com
	Token              string `json:"token"` // secret:// static token
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

// New returns the Directus module.
func New() *Module { return &Module{} }

var (
	pathRe  = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	nameRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)
	idRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	fieldRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	uuidRe  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	coll := `"collection":{"type":"string","description":"Collection name (from collections)"}`
	item := `"id":{"type":["string","integer"],"description":"The item's primary key"}`
	one := sdk.Schema(`{"type":"object","required":["collection","id"],"properties":{` + coll + `,` + item + `}}`)
	return sdk.Manifest{
		ID: "directus", Name: "Directus", Version: "0.1.0", Category: "Development", Icon: "database",
		Description: "Directus: collections and fields; list, read, create, update and delete items; run webhook and manual flows.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Your Directus project, e.g. https://directus.example.com or https://example.directus.app"},
			"token":{"type":"string","x-secret":true,"description":"A user's static token (User Directory, a user, Token); it acts with that user's role and permissions"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "collections", Title: "Collections", Description: "The project's own collections (not directus_ system ones): name, note, singleton, hidden, folder.", Risk: sdk.RiskRead},
			{Name: "fields", Title: "Collection fields", Description: "A collection's fields: name, type, primary key, required, read only, and whether it's a hash or concealed field (left out of items).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["collection"],"properties":{` + coll + `}}`)},
			{Name: "list_items", Title: "List items", Description: "Items of a collection, with conditions, a sort and pages (at most 100 a page). Items can hold personal data, so they're kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["collection"],"properties":{` + coll + `,` + records.WhereSchema + `,` + records.SortSchema + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":25},"page":{"type":"integer","minimum":1,"default":1}}}`)},
			{Name: "get_item", Title: "Read an item", Description: "One item by primary key. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true, Input: one},
			{Name: "create_item", Title: "Create an item", Description: "Adds an item to a collection. Undo deletes it.", Risk: sdk.RiskWrite, Sensitive: true, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["collection","data"],"properties":{` + coll + `,` + records.DataSchema + `}}`)},
			{Name: "update_item", Title: "Update an item", Description: "Sets some fields of an item; the others stay as they are. The preview shows the values before and after.", Risk: sdk.RiskWrite, Sensitive: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["collection","id","data"],"properties":{` + coll + `,` + item + `,` + records.DataSchema + `}}`)},
			{Name: "delete_item", Title: "Delete an item", Description: "Deletes an item for good.", Risk: sdk.RiskDestructive, DryRun: true, Input: one},
			{Name: "flows", Title: "Flows", Description: "Flows: id, name, status, trigger (event, schedule, webhook, manual, operation) and, for webhooks, the method.", Risk: sdk.RiskRead},
			{Name: "trigger_flow", Title: "Run a flow", Description: "Runs an active flow with a webhook or manual trigger, which can do whatever its operations do (send mail, call APIs, change data). Its answer is kept out of logs.", Risk: sdk.RiskDestructive, Sensitive: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["flow"],"properties":{"flow":{"type":"string","description":"Flow id (a UUID, from flows)"},"payload":{"type":"object","description":"The body sent to a POST webhook flow; for a manual flow, {\"collection\":…,\"keys\":[…]}"}}}`)},
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
		return errors.New("the address is like https://directus.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the static token in the vault and enter its secret:// reference")
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
	ref := c.Token
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Directus refused the token")
	case rest.IsStatus(err, http.StatusForbidden):
		// Directus answers 403 for anything the role can't see, missing
		// or not.
		return errors.New("the token's role can't do this in Directus (or it doesn't exist)")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

type field struct {
	Field string `json:"field"`
	Type  string `json:"type"`
	Meta  *struct {
		Special   []string       `json:"special"`
		Interface string         `json:"interface"`
		Required  bool           `json:"required"`
		Readonly  bool           `json:"readonly"`
		Hidden    bool           `json:"hidden"`
		Options   map[string]any `json:"options"`
	} `json:"meta"`
	Schema *struct {
		PrimaryKey    bool `json:"is_primary_key"`
		AutoIncrement bool `json:"has_auto_increment"`
	} `json:"schema"`
}

func (f field) special(s string) bool {
	if f.Meta == nil {
		return false
	}
	for _, x := range f.Meta.Special {
		if x == s {
			return true
		}
	}
	return false
}

// secret says whether a field holds a secret: a hash (passwords) or a
// concealed or masked value.
func (f field) secret() bool {
	if f.Type == "hash" || f.special("hash") || f.special("conceal") {
		return true
	}
	if f.Meta != nil {
		if f.Meta.Interface == "input-hash" {
			return true
		}
		if m, _ := f.Meta.Options["masked"].(bool); m {
			return true
		}
	}
	return false
}

func (f field) pk() bool { return f.Schema != nil && f.Schema.PrimaryKey }

type collection struct {
	Name   string
	Fields []field
}

func (c collection) field(name string) (field, bool) {
	for _, f := range c.Fields {
		if f.Field == name {
			return f, true
		}
	}
	return field{}, false
}

func (c collection) readable(name string) bool {
	f, ok := c.field(name)
	return fieldRe.MatchString(name) && ok && !f.secret() && f.Type != "alias"
}

// writable says why a field can't be set, or nil.
func (c collection) writable(create bool) func(string) error {
	return func(name string) error {
		f, ok := c.field(name)
		switch {
		case !fieldRe.MatchString(name) || !ok:
			return fmt.Errorf("%s has no field %q", c.Name, records.Short(name))
		case f.secret():
			return fmt.Errorf("%s is a hash or concealed field, which isn't set here", name)
		case f.Type == "alias":
			return fmt.Errorf("%s is a relation or presentation field; set the related items' own fields", name)
		case f.pk() && (!create || f.Schema.AutoIncrement):
			return fmt.Errorf("%s is the primary key", name)
		case f.special("date-created") || f.special("date-updated") || f.special("user-created") || f.special("user-updated"):
			return fmt.Errorf("%s is set by Directus", name)
		}
		return nil
	}
}

func (c collection) pk() string {
	for _, f := range c.Fields {
		if f.pk() {
			return f.Field
		}
	}
	return "id"
}

// clean drops secret fields from an item and shortens long values.
func (c collection) clean(r map[string]any) map[string]any {
	for _, f := range c.Fields {
		if f.secret() {
			delete(r, f.Field)
		}
	}
	records.Clip(r)
	return r
}

func checkName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !nameRe.MatchString(s) {
		return "", errors.New("a collection is its name (letters, digits, _ and -)")
	}
	if strings.HasPrefix(strings.ToLower(s), "directus_") {
		return "", fmt.Errorf("%s is a Directus system collection (users, sessions, settings…); its items aren't read or changed here", s)
	}
	return s, nil
}

func (c *conn) collection(ctx context.Context, name string) (collection, error) {
	var out struct {
		Data []field `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/fields/"+url.PathEscape(name), nil, nil, &out); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return collection{}, fmt.Errorf("there's no collection %s", name)
		}
		return collection{}, err
	}
	if len(out.Data) == 0 {
		return collection{}, fmt.Errorf("there's no collection %s (or the token can't see its fields)", name)
	}
	return collection{Name: name, Fields: out.Data}, nil
}

// itemID reads a primary key: a string or a whole number.
func itemID(raw json.RawMessage) (string, error) {
	var s string
	var n json.Number
	switch {
	case json.Unmarshal(raw, &s) == nil:
	case json.Unmarshal(raw, &n) == nil:
		s = n.String()
	default:
		return "", errors.New("an item is its primary key (letters, digits, _ and -)")
	}
	s = strings.TrimSpace(s)
	if !idRe.MatchString(s) {
		return "", errors.New("an item is its primary key (letters, digits, _ and -)")
	}
	return s, nil
}

// idText writes a primary key from an answer as text.
func idText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	cs, err := c.collections(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Directus API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d collections", len(cs))}
}

type input struct {
	Collection string                     `json:"collection"`
	ID         json.RawMessage            `json:"id"`
	Where      []records.Cond             `json:"where"`
	Sort       string                     `json:"sort"`
	Limit      int                        `json:"limit"`
	Page       int                        `json:"page"`
	Data       map[string]json.RawMessage `json:"data"`
	Flow       string                     `json:"flow"`
	Payload    map[string]any             `json:"payload"`
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
	case "collections":
		cs, err := c.collections(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(cs)
	case "flows":
		return c.flows(ctx)
	case "trigger_flow":
		return c.trigger(ctx, call, p)
	case "fields", "list_items", "get_item", "create_item", "update_item", "delete_item":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	name, err := checkName(p.Collection)
	if err != nil {
		return sdk.Result{}, err
	}
	var id string
	switch call.Action {
	case "get_item", "update_item", "delete_item":
		if id, err = itemID(p.ID); err != nil {
			return sdk.Result{}, err
		}
	}
	if (call.Action == "create_item" || call.Action == "update_item") && len(p.Data) == 0 {
		return sdk.Result{}, errors.New("give the fields to set in data")
	}
	if err := records.Check(p.Where, fieldRe.MatchString, ""); err != nil {
		return sdk.Result{}, err
	}
	col, err := c.collection(ctx, name)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "fields":
		out := []map[string]any{}
		for _, f := range col.Fields {
			row := map[string]any{"field": f.Field, "type": f.Type, "primaryKey": f.pk(), "secret": f.secret()}
			if f.Meta != nil {
				row["required"], row["readonly"], row["hidden"] = f.Meta.Required, f.Meta.Readonly, f.Meta.Hidden
				if f.Meta.Interface != "" {
					row["interface"] = f.Meta.Interface
				}
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	case "list_items":
		return c.list(ctx, col, p)
	case "get_item":
		r, err := c.item(ctx, col, id)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(col.clean(r))
	case "create_item":
		return c.create(ctx, call, col, p.Data)
	case "update_item":
		return c.update(ctx, call, col, id, p.Data)
	}
	return c.remove(ctx, call, col, id)
}

func (c *conn) collections(ctx context.Context) ([]map[string]any, error) {
	var out struct {
		Data []struct {
			Collection string `json:"collection"`
			Meta       *struct {
				Note      string `json:"note"`
				Singleton bool   `json:"singleton"`
				Hidden    bool   `json:"hidden"`
			} `json:"meta"`
			Schema *struct{} `json:"schema"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/collections", nil, nil, &out); err != nil {
		return nil, err
	}
	cs := []map[string]any{}
	for _, x := range out.Data {
		if strings.HasPrefix(x.Collection, "directus_") {
			continue
		}
		row := map[string]any{"name": x.Collection, "folder": x.Schema == nil}
		if x.Meta != nil {
			row["singleton"], row["hidden"] = x.Meta.Singleton, x.Meta.Hidden
			if x.Meta.Note != "" {
				row["note"] = x.Meta.Note
			}
		}
		cs = append(cs, row)
	}
	return cs, nil
}

var dxOps = map[string]string{"eq": "_eq", "ne": "_neq", "gt": "_gt", "gte": "_gte", "lt": "_lt", "lte": "_lte", "contains": "_contains"}

// Filter renders checked conditions as a Directus filter object (JSON, so
// values are never spliced into an expression).
func Filter(cs []records.Cond) map[string]any {
	and := []any{}
	for _, c := range cs {
		switch c.Op {
		case "empty":
			and = append(and, map[string]any{c.Field: map[string]any{"_null": true}})
		case "notempty":
			and = append(and, map[string]any{c.Field: map[string]any{"_nnull": true}})
		default:
			and = append(and, map[string]any{c.Field: map[string]any{dxOps[c.Op]: c.Value}})
		}
	}
	return map[string]any{"_and": and}
}

func (c *conn) list(ctx context.Context, col collection, p input) (sdk.Result, error) {
	if err := records.Check(p.Where, col.readable, ""); err != nil {
		return sdk.Result{}, err
	}
	sortBy, desc, err := records.Sort(p.Sort, col.readable)
	if err != nil {
		return sdk.Result{}, err
	}
	q := url.Values{"limit": {strconv.Itoa(records.Limit(p.Limit, 25, 100))}, "page": {strconv.Itoa(records.Page(p.Page))}, "meta": {"filter_count"}}
	if len(p.Where) > 0 {
		q.Set("filter", string(records.Raw(Filter(p.Where))))
	}
	if sortBy != "" {
		if desc {
			sortBy = "-" + sortBy
		}
		q.Set("sort", sortBy)
	}
	var out struct {
		Data []map[string]any `json:"data"`
		Meta struct {
			FilterCount *int `json:"filter_count"`
		} `json:"meta"`
	}
	if err := c.do(ctx, http.MethodGet, "/items/"+url.PathEscape(col.Name), q, nil, &out); err != nil {
		return sdk.Result{}, err
	}
	rows := []map[string]any{}
	for _, r := range out.Data {
		rows = append(rows, col.clean(r))
	}
	rows, cut := records.Fit(rows)
	res := map[string]any{"collection": col.Name, "page": records.Page(p.Page), "items": rows}
	if out.Meta.FilterCount != nil {
		res["total"] = *out.Meta.FilterCount
	}
	if cut {
		res["truncated"] = true
	}
	return sdk.JSON(res)
}

func (c *conn) item(ctx context.Context, col collection, id string) (map[string]any, error) {
	var out struct {
		Data map[string]any `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, "/items/"+url.PathEscape(col.Name)+"/"+url.PathEscape(id), nil, nil, &out)
	if rest.IsStatus(err, http.StatusNotFound) || (err == nil && out.Data == nil) {
		return nil, fmt.Errorf("there's no item %s in %s", id, col.Name)
	}
	if err != nil {
		return nil, err
	}
	if got := idText(out.Data[col.pk()]); got != "" && got != id {
		return nil, fmt.Errorf("Directus answered with another item for %s", id)
	}
	return out.Data, nil
}

func (c *conn) create(ctx context.Context, call sdk.Call, col collection, data map[string]json.RawMessage) (sdk.Result, error) {
	if err := records.Data(data, col.writable(true)); err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create an item in %s (%s)", col.Name, strings.Join(records.Keys(data), ", ")),
			Changes: []sdk.Change{{Target: "collection " + col.Name, Op: "create", After: records.Raw(data)}}}}, nil
	}
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, "/items/"+url.PathEscape(col.Name), nil, data, &out); err != nil {
		return sdk.Result{}, err
	}
	id := idText(out.Data[col.pk()])
	res, err := sdk.JSON(map[string]any{"collection": col.Name, "created": col.clean(out.Data)})
	if idRe.MatchString(id) {
		res.Undo = sdk.UndoWith("delete_item", map[string]string{"collection": col.Name, "id": id}, "Delete the new item "+id)
	}
	return res, err
}

func (c *conn) update(ctx context.Context, call sdk.Call, col collection, id string, data map[string]json.RawMessage) (sdk.Result, error) {
	if err := records.Data(data, col.writable(false)); err != nil {
		return sdk.Result{}, err
	}
	cur, err := c.item(ctx, col, id)
	if err != nil {
		return sdk.Result{}, err
	}
	before, after := map[string]any{}, map[string]json.RawMessage{}
	for k, v := range data {
		if !records.Same(cur[k], v) {
			before[k], after[k] = cur[k], v
		}
	}
	if len(after) == 0 {
		return sdk.JSON(map[string]any{"collection": col.Name, "id": id, "note": "nothing to change"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Update item %s in %s (%s)", id, col.Name, strings.Join(records.Keys(after), ", ")),
			Changes: []sdk.Change{{Target: "item " + id + " in " + col.Name, Op: "update", Before: records.Raw(before), After: records.Raw(after)}}}}, nil
	}
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := c.do(ctx, http.MethodPatch, "/items/"+url.PathEscape(col.Name)+"/"+url.PathEscape(id), nil, after, &out); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"collection": col.Name, "updated": col.clean(out.Data), "changed": records.Keys(after)})
}

func (c *conn) remove(ctx context.Context, call sdk.Call, col collection, id string) (sdk.Result, error) {
	if _, err := c.item(ctx, col, id); err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		// Only the key: this action isn't sensitive, so its plan is logged.
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete item %s from %s for good", id, col.Name),
			Changes: []sdk.Change{{Target: "item " + id + " in " + col.Name, Op: "delete"}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, "/items/"+url.PathEscape(col.Name)+"/"+url.PathEscape(id), nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"collection": col.Name, "deleted": id})
}

type flow struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Status      string         `json:"status"`
	Trigger     string         `json:"trigger"`
	Description string         `json:"description"`
	Options     map[string]any `json:"options"`
}

func (f flow) method() string {
	if f.Trigger == "manual" {
		return http.MethodPost
	}
	if m, _ := f.Options["method"].(string); strings.EqualFold(m, "POST") {
		return http.MethodPost
	}
	return http.MethodGet
}

func (c *conn) flows(ctx context.Context) (sdk.Result, error) {
	var out struct {
		Data []flow `json:"data"`
	}
	q := url.Values{"limit": {"-1"}, "fields": {"id,name,status,trigger,description,options"}, "sort": {"name"}}
	if err := c.do(ctx, http.MethodGet, "/flows", q, nil, &out); err != nil {
		return sdk.Result{}, err
	}
	rows := []map[string]any{}
	for _, f := range out.Data {
		row := map[string]any{"id": f.ID, "name": f.Name, "status": f.Status, "trigger": f.Trigger}
		if f.Description != "" {
			row["description"] = f.Description
		}
		if f.Trigger == "webhook" || f.Trigger == "manual" {
			row["method"] = f.method()
		}
		rows = append(rows, row)
	}
	return sdk.JSON(rows)
}

func (c *conn) trigger(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	id := strings.TrimSpace(p.Flow)
	if !uuidRe.MatchString(id) {
		return sdk.Result{}, errors.New("a flow is its id, a UUID (from flows)")
	}
	if b := records.Raw(p.Payload); len(b) > records.MaxBody {
		return sdk.Result{}, fmt.Errorf("the payload is larger than %d KB", records.MaxBody>>10)
	}
	var out struct {
		Data flow `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/flows/"+id, url.Values{"fields": {"id,name,status,trigger,options"}}, nil, &out); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no flow %s", id)
		}
		return sdk.Result{}, err
	}
	f := out.Data
	if !strings.EqualFold(f.ID, id) {
		return sdk.Result{}, fmt.Errorf("there's no flow %s", id)
	}
	if f.Trigger != "webhook" && f.Trigger != "manual" {
		return sdk.Result{}, fmt.Errorf("%s runs on its %s trigger; only webhook and manual flows are run from here", f.Name, f.Trigger)
	}
	if f.Status != "active" {
		return sdk.Result{}, fmt.Errorf("%s is %s; turn it on in Directus first", f.Name, f.Status)
	}
	method := f.method()
	if method == http.MethodGet && len(p.Payload) > 0 {
		return sdk.Result{}, fmt.Errorf("%s is a GET webhook, which takes no payload", f.Name)
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Run flow %s (%s trigger, %s): it does whatever its operations do", f.Name, f.Trigger, method),
			Changes: []sdk.Change{{Target: "flow " + f.Name, Op: "run", After: records.Raw(p.Payload)}}}}, nil
	}
	var body any
	if method == http.MethodPost {
		body = p.Payload
		if p.Payload == nil {
			body = map[string]any{}
		}
	}
	var res any
	if err := c.do(ctx, method, "/flows/trigger/"+f.ID, nil, body, &res); err != nil {
		return sdk.Result{}, err
	}
	answer := records.Clip(res)
	if len(records.Raw(answer)) > records.MaxOutput {
		answer = "(the answer was too large to show)"
	}
	return sdk.JSON(map[string]any{"flow": f.ID, "name": f.Name, "ran": true, "answer": answer})
}
