// Package strapi works with a Strapi project (5, or 4) through its REST API
// and an API token: content types and their fields, listing, reading,
// creating, updating and deleting entries, and publishing and unpublishing
// them.
//
// Only the project's own collection types (api::) are reached: plugin and
// admin types such as plugin::users-permissions.user, which hold e-mails and
// password hashes, are refused for every entry action. Private and password
// fields are left out of every entry and can't be filtered on or set.
package strapi

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
	"github.com/elchi-dev/conduit/modules/internal/records"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Strapi project.
type Config struct {
	URL                string `json:"url"`     // e.g. https://cms.example.com
	Token              string `json:"token"`   // secret:// API token
	Version            int    `json:"version"` // 5 (default) or 4
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
	v4  bool
	now func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Strapi module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	pluralRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	idRe     = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
	fieldRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
)

// system are the fields Strapi keeps itself.
var system = map[string]bool{"id": true, "documentId": true, "createdAt": true, "updatedAt": true, "publishedAt": true, "locale": true, "createdBy": true, "updatedBy": true, "localizations": true}

// nested are attribute types a condition can't compare.
var nested = map[string]bool{"relation": true, "media": true, "component": true, "dynamiczone": true, "json": true, "blocks": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	typ := `"type":{"type":"string","description":"The content type's plural API id, e.g. articles (from content_types)"}`
	entry := `"id":{"type":"string","description":"The entry's documentId (Strapi 5) or id (Strapi 4)"}`
	status := `"status":{"type":"string","enum":["draft","published"],"description":"Strapi 5, types with drafts: the draft or the published version (Strapi's default is published)"}`
	one := sdk.Schema(`{"type":"object","required":["type","id"],"properties":{` + typ + `,` + entry + `}}`)
	return sdk.Manifest{
		ID: "strapi", Name: "Strapi", Version: "0.1.0", Category: "Development", Icon: "document",
		Description: "Strapi: content types; list, read, create, update and delete entries; publish and unpublish them.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Your Strapi project, e.g. https://cms.example.com (without /api)"},
			"token":{"type":"string","x-secret":true,"description":"An API token (Settings, API Tokens): full access, or custom with find, findOne, create, update and delete on your types and Content-type-builder read"},
			"version":{"type":"integer","enum":[5,4],"default":5,"description":"Strapi's major version"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "content_types", Title: "Content types", Description: "The project's collection types: plural API id, name, whether drafts are on, and their fields (name, type, required, private).", Risk: sdk.RiskRead},
			{Name: "list_entries", Title: "List entries", Description: "Entries of a collection type, with conditions, a sort and pages (at most 100 a page). Entries can hold personal data, so they're kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["type"],"properties":{` + typ + `,` + records.WhereSchema + `,` + records.SortSchema + `,` + status + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":25},"page":{"type":"integer","minimum":1,"default":1}}}`)},
			{Name: "get_entry", Title: "Read an entry", Description: "One entry. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["type","id"],"properties":{` + typ + `,` + entry + `,` + status + `}}`)},
			{Name: "create_entry", Title: "Create an entry", Description: "Adds an entry; on a type with drafts it's a draft until published. Undo deletes it.", Risk: sdk.RiskWrite, Sensitive: true, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["type","data"],"properties":{` + typ + `,` + records.DataSchema + `}}`)},
			{Name: "update_entry", Title: "Update an entry", Description: "Sets some fields of an entry (on Strapi 5, of its draft). The preview shows the values before and after.", Risk: sdk.RiskWrite, Sensitive: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["type","id","data"],"properties":{` + typ + `,` + entry + `,` + records.DataSchema + `}}`)},
			{Name: "delete_entry", Title: "Delete an entry", Description: "Deletes an entry for good, draft and published versions.", Risk: sdk.RiskDestructive, DryRun: true, Input: one},
			{Name: "publish_entry", Title: "Publish an entry", Description: "Makes an entry (its current draft, on Strapi 5) public. On Strapi 4, undo unpublishes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: one},
			{Name: "unpublish_entry", Title: "Unpublish an entry", Description: "Takes an entry off the public API, back to a draft (Strapi 4; Strapi 5's REST API can't unpublish). Undo publishes it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: one},
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
		return errors.New("the address is like https://cms.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	if c.Version == 0 {
		c.Version = 5
	}
	if c.Version != 4 && c.Version != 5 {
		return errors.New("version is 5 or 4")
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
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, v4: c.Version == 4, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Strapi refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API token isn't allowed to do this in Strapi")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

type attr struct {
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Private  bool   `json:"private"`
}

type ctype struct {
	UID    string
	Plural string
	Name   string
	Drafts bool
	Attrs  map[string]attr
}

func (t ctype) readable(name string) bool {
	if !fieldRe.MatchString(name) {
		return false
	}
	if name == "id" || name == "documentId" || name == "createdAt" || name == "updatedAt" || name == "publishedAt" || name == "locale" {
		return true
	}
	a, ok := t.Attrs[name]
	return ok && !a.Private && a.Type != "password" && !nested[a.Type]
}

func (t ctype) writable(name string) error {
	a, ok := t.Attrs[name]
	switch {
	case system[name] && name != "locale":
		return fmt.Errorf("%s is set by Strapi (publish with publish_entry)", name)
	case !fieldRe.MatchString(name) || !ok:
		return fmt.Errorf("%s has no field %q", t.Plural, records.Short(name))
	case a.Private || a.Type == "password":
		return fmt.Errorf("%s is a private or password field, which isn't set here", name)
	}
	return nil
}

// clean flattens a Strapi 4 entry, drops private and password fields and
// who created or changed it, and shortens long values.
func (t ctype) clean(e map[string]any) map[string]any {
	if a, ok := e["attributes"].(map[string]any); ok {
		a["id"] = e["id"]
		e = a
	}
	for k, a := range t.Attrs {
		if a.Private || a.Type == "password" {
			delete(e, k)
		}
	}
	delete(e, "createdBy")
	delete(e, "updatedBy")
	records.Clip(e)
	return e
}

func (c *conn) types(ctx context.Context) ([]ctype, error) {
	var out struct {
		Data []struct {
			UID    string `json:"uid"`
			Schema struct {
				Kind        string          `json:"kind"`
				PluralName  string          `json:"pluralName"`
				DisplayName string          `json:"displayName"`
				Drafts      bool            `json:"draftAndPublish"`
				Attributes  map[string]attr `json:"attributes"`
			} `json:"schema"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/content-type-builder/content-types", nil, nil, &out); err != nil {
		return nil, err
	}
	ts := []ctype{}
	for _, d := range out.Data {
		// Only the project's own collection types; plugin:: and admin::
		// types (users, roles, API tokens) never.
		if !strings.HasPrefix(d.UID, "api::") || d.Schema.Kind != "collectionType" || !pluralRe.MatchString(d.Schema.PluralName) {
			continue
		}
		ts = append(ts, ctype{UID: d.UID, Plural: d.Schema.PluralName, Name: d.Schema.DisplayName, Drafts: d.Schema.Drafts, Attrs: d.Schema.Attributes})
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Plural < ts[j].Plural })
	return ts, nil
}

func (c *conn) ctype(ctx context.Context, plural string) (ctype, error) {
	ts, err := c.types(ctx)
	if err != nil {
		return ctype{}, err
	}
	for _, t := range ts {
		if t.Plural == plural {
			return t, nil
		}
	}
	return ctype{}, fmt.Errorf("there's no collection type %s of the project's own (plugin types such as users aren't reached here)", plural)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ts, err := c.types(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Strapi API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d content types", len(ts))}
}

type input struct {
	Type   string                     `json:"type"`
	ID     string                     `json:"id"`
	Where  []records.Cond             `json:"where"`
	Sort   string                     `json:"sort"`
	Status string                     `json:"status"`
	Limit  int                        `json:"limit"`
	Page   int                        `json:"page"`
	Data   map[string]json.RawMessage `json:"data"`
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
	if call.Action == "content_types" {
		ts, err := c.types(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range ts {
			fields := []map[string]any{}
			for _, k := range records.Keys(t.Attrs) {
				a := t.Attrs[k]
				fields = append(fields, map[string]any{"name": k, "type": a.Type, "required": a.Required, "private": a.Private})
			}
			out = append(out, map[string]any{"type": t.Plural, "uid": t.UID, "name": t.Name, "drafts": t.Drafts, "fields": fields})
		}
		return sdk.JSON(out)
	}
	switch call.Action {
	case "list_entries", "create_entry":
	case "get_entry", "update_entry", "delete_entry", "publish_entry", "unpublish_entry":
		p.ID = strings.TrimSpace(p.ID)
		if !idRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("an entry is its documentId (Strapi 5) or id (Strapi 4)")
		}
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	p.Type = strings.TrimSpace(p.Type)
	if !pluralRe.MatchString(p.Type) {
		return sdk.Result{}, errors.New("a type is its plural API id, like articles (from content_types)")
	}
	if p.Status != "" && p.Status != "draft" && p.Status != "published" {
		return sdk.Result{}, errors.New("status is draft or published")
	}
	if (call.Action == "create_entry" || call.Action == "update_entry") && len(p.Data) == 0 {
		return sdk.Result{}, errors.New("give the fields to set in data")
	}
	if call.Action == "unpublish_entry" && !c.v4 {
		return sdk.Result{}, errors.New("Strapi 5's REST API can't unpublish an entry; unpublish it in the admin panel")
	}
	if err := records.Check(p.Where, fieldRe.MatchString, ""); err != nil {
		return sdk.Result{}, err
	}
	t, err := c.ctype(ctx, p.Type)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "list_entries":
		return c.list(ctx, t, p)
	case "get_entry":
		e, err := c.entry(ctx, t, p.ID, p.Status)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(t.clean(e))
	case "create_entry":
		return c.create(ctx, call, t, p.Data)
	case "update_entry":
		return c.update(ctx, call, t, p.ID, p.Data)
	case "delete_entry":
		return c.remove(ctx, call, t, p.ID)
	}
	return c.publish(ctx, call, t, p.ID)
}

var stOps = map[string]string{"eq": "$eq", "ne": "$ne", "gt": "$gt", "gte": "$gte", "lt": "$lt", "lte": "$lte", "contains": "$containsi"}

// Filters adds checked conditions to a query in Strapi's filters[...]
// syntax; each value is its own query parameter.
func Filters(q url.Values, cs []records.Cond) {
	for i, c := range cs {
		key := fmt.Sprintf("filters[$and][%d][%s]", i, c.Field)
		switch c.Op {
		case "empty":
			q.Set(key+"[$null]", "true")
		case "notempty":
			q.Set(key+"[$notNull]", "true")
		default:
			var v string
			switch x := c.Value.(type) {
			case string:
				v = x
			case float64:
				v = records.Number(x)
			case bool:
				v = strconv.FormatBool(x)
			}
			q.Set(key+"["+stOps[c.Op]+"]", v)
		}
	}
}

// versionQuery asks for a draft or published version: status on Strapi 5,
// publicationState on Strapi 4 (where an entry has one version).
func (c *conn) versionQuery(t ctype, status string) url.Values {
	q := url.Values{}
	if !t.Drafts {
		return q
	}
	if c.v4 {
		q.Set("publicationState", "preview")
	} else if status != "" {
		q.Set("status", status)
	}
	return q
}

func (c *conn) list(ctx context.Context, t ctype, p input) (sdk.Result, error) {
	if err := records.Check(p.Where, t.readable, ""); err != nil {
		return sdk.Result{}, err
	}
	sortBy, desc, err := records.Sort(p.Sort, t.readable)
	if err != nil {
		return sdk.Result{}, err
	}
	q := c.versionQuery(t, p.Status)
	q.Set("pagination[page]", strconv.Itoa(records.Page(p.Page)))
	q.Set("pagination[pageSize]", strconv.Itoa(records.Limit(p.Limit, 25, 100)))
	Filters(q, p.Where)
	if sortBy != "" {
		if desc {
			sortBy += ":desc"
		}
		q.Set("sort", sortBy)
	}
	var out struct {
		Data []map[string]any `json:"data"`
		Meta struct {
			Pagination struct {
				Page      int `json:"page"`
				PageCount int `json:"pageCount"`
				Total     int `json:"total"`
			} `json:"pagination"`
		} `json:"meta"`
	}
	if err := c.do(ctx, http.MethodGet, "/"+t.Plural, q, nil, &out); err != nil {
		return sdk.Result{}, err
	}
	rows := []map[string]any{}
	for _, e := range out.Data {
		rows = append(rows, t.clean(e))
	}
	rows, cut := records.Fit(rows)
	pg := out.Meta.Pagination
	res := map[string]any{"type": t.Plural, "page": pg.Page, "pages": pg.PageCount, "total": pg.Total, "entries": rows}
	if cut {
		res["truncated"] = true
	}
	return sdk.JSON(res)
}

var errMissing = errors.New("missing")

// entry reads one entry, raw (a Strapi 4 entry has its attributes nested).
func (c *conn) entry(ctx context.Context, t ctype, id, status string) (map[string]any, error) {
	var out struct {
		Data map[string]any `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, "/"+t.Plural+"/"+url.PathEscape(id), c.versionQuery(t, status), nil, &out)
	if rest.IsStatus(err, http.StatusNotFound) || (err == nil && out.Data == nil) {
		return nil, fmt.Errorf("there's no entry %s in %s: %w", id, t.Plural, errMissing)
	}
	if err != nil {
		return nil, err
	}
	if entryID(out.Data) != id {
		return nil, fmt.Errorf("Strapi answered with another entry for %s", id)
	}
	return out.Data, nil
}

func entryID(e map[string]any) string {
	if s, ok := e["documentId"].(string); ok && s != "" {
		return s
	}
	switch x := e["id"].(type) {
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case string:
		return x
	}
	return ""
}

func (c *conn) create(ctx context.Context, call sdk.Call, t ctype, data map[string]json.RawMessage) (sdk.Result, error) {
	if err := records.Data(data, t.writable); err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		sum := fmt.Sprintf("Create an entry in %s (%s)", t.Plural, strings.Join(records.Keys(data), ", "))
		if t.Drafts {
			sum += " as a draft"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "type " + t.Plural, Op: "create", After: records.Raw(data)}}}}, nil
	}
	body := map[string]any{}
	for k, v := range data {
		body[k] = v
	}
	q := url.Values{}
	if t.Drafts {
		// New entries stay drafts until published: Strapi 5 publishes on
		// create unless asked not to, and Strapi 4 does unless publishedAt
		// is null.
		if c.v4 {
			body["publishedAt"] = nil
		} else {
			q.Set("status", "draft")
		}
	}
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, "/"+t.Plural, q, map[string]any{"data": body}, &out); err != nil {
		return sdk.Result{}, err
	}
	id := entryID(out.Data)
	res, err := sdk.JSON(map[string]any{"type": t.Plural, "created": t.clean(out.Data)})
	if idRe.MatchString(id) {
		res.Undo = sdk.UndoWith("delete_entry", map[string]string{"type": t.Plural, "id": id}, "Delete the new entry "+id)
	}
	return res, err
}

func (c *conn) update(ctx context.Context, call sdk.Call, t ctype, id string, data map[string]json.RawMessage) (sdk.Result, error) {
	if err := records.Data(data, t.writable); err != nil {
		return sdk.Result{}, err
	}
	raw, err := c.entry(ctx, t, id, "draft")
	if err != nil {
		return sdk.Result{}, err
	}
	cur := t.clean(raw)
	before, after := map[string]any{}, map[string]json.RawMessage{}
	for k, v := range data {
		if !records.Same(cur[k], v) {
			before[k], after[k] = cur[k], v
		}
	}
	if len(after) == 0 {
		return sdk.JSON(map[string]any{"type": t.Plural, "id": id, "note": "nothing to change"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Update entry %s in %s (%s)", id, t.Plural, strings.Join(records.Keys(after), ", ")),
			Changes: []sdk.Change{{Target: "entry " + id + " in " + t.Plural, Op: "update", Before: records.Raw(before), After: records.Raw(after)}}}}, nil
	}
	q := url.Values{}
	if t.Drafts && !c.v4 {
		q.Set("status", "draft") // Strapi 5 publishes an update unless asked not to
	}
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := c.do(ctx, http.MethodPut, "/"+t.Plural+"/"+url.PathEscape(id), q, map[string]any{"data": after}, &out); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"type": t.Plural, "updated": t.clean(out.Data), "changed": records.Keys(after)})
}

func (c *conn) remove(ctx context.Context, call sdk.Call, t ctype, id string) (sdk.Result, error) {
	if _, err := c.entry(ctx, t, id, "draft"); err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		// Only the id: this action isn't sensitive, so its plan is logged.
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete entry %s from %s for good", id, t.Plural),
			Changes: []sdk.Change{{Target: "entry " + id + " in " + t.Plural, Op: "delete"}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, "/"+t.Plural+"/"+url.PathEscape(id), nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"type": t.Plural, "deleted": id})
}

// content is an entry without what Strapi keeps itself, to compare a draft
// with its published version.
func content(t ctype, e map[string]any) string {
	e = t.clean(e)
	for k := range system {
		delete(e, k)
	}
	return string(records.Raw(e))
}

func (c *conn) publish(ctx context.Context, call sdk.Call, t ctype, id string) (sdk.Result, error) {
	publishing := call.Action == "publish_entry"
	if !t.Drafts {
		return sdk.Result{}, fmt.Errorf("%s doesn't use drafts: its entries are public as soon as they're saved", t.Plural)
	}
	raw, err := c.entry(ctx, t, id, "draft")
	if err != nil {
		return sdk.Result{}, err
	}
	target := "entry " + id + " in " + t.Plural
	var before, after any
	if c.v4 {
		attrs := raw
		if a, ok := raw["attributes"].(map[string]any); ok {
			attrs = a
		}
		published := attrs["publishedAt"] != nil
		if published == publishing {
			return sdk.JSON(map[string]any{"type": t.Plural, "id": id, "published": published, "note": "nothing to change"})
		}
		before, after = map[string]any{"published": published}, map[string]any{"published": publishing}
	} else {
		pub, err := c.entry(ctx, t, id, "published")
		if err != nil && !errors.Is(err, errMissing) {
			return sdk.Result{}, err
		}
		if pub != nil && content(t, pub) == content(t, raw) {
			return sdk.JSON(map[string]any{"type": t.Plural, "id": id, "published": true, "note": "nothing to change"})
		}
		before, after = map[string]any{"published": pub != nil}, map[string]any{"published": true, "draftPublished": true}
	}
	if call.DryRun {
		sum := fmt.Sprintf("Publish %s: it becomes public", target)
		if !publishing {
			sum = fmt.Sprintf("Unpublish %s: it leaves the public API", target)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: strings.TrimSuffix(call.Action, "_entry"), Before: records.Raw(before), After: records.Raw(after)}}}}, nil
	}
	q, data := url.Values{}, map[string]any{}
	switch {
	case !c.v4:
		q.Set("status", "published")
	case publishing:
		data["publishedAt"] = c.now().UTC().Format(time.RFC3339)
	default:
		data["publishedAt"] = nil
	}
	if err := c.do(ctx, http.MethodPut, "/"+t.Plural+"/"+url.PathEscape(id), q, map[string]any{"data": data}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"type": t.Plural, "id": id, "published": publishing})
	if c.v4 {
		if publishing {
			res.Undo = sdk.UndoWith("unpublish_entry", map[string]string{"type": t.Plural, "id": id}, "Unpublish "+id+" again")
		} else {
			res.Undo = sdk.UndoWith("publish_entry", map[string]string{"type": t.Plural, "id": id}, "Publish "+id+" again")
		}
	}
	return res, err
}
