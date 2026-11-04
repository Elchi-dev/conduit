// Package nocodb works with NocoDB (NocoDB Cloud or self-hosted) through its
// v2 REST API and an API token: bases, tables and their fields, and listing,
// creating, updating and deleting records.
//
// User fields (User, Created by, Last modified by) are returned as display
// names only, never e-mail addresses, and can't be filtered on or set.
package nocodb

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

// Config is one NocoDB workspace or server.
type Config struct {
	URL                string `json:"url"`   // default https://app.nocodb.com
	Token              string `json:"token"` // secret:// API token (xc-token)
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://app.nocodb.com as the default address.
	Base string
}

// New returns the NocoDB module.
func New() *Module { return &Module{} }

const defaultBase = "https://app.nocodb.com"

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	metaRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	// A field is its title: anything but control characters and the
	// characters of the where syntax.
	titleRe = regexp.MustCompile(`^[^(),~\\\x00-\x1f\x7f]{1,100}$`)
)

// whereChars are refused in condition values: the where syntax's own
// characters, and a backslash, which some NocoDB versions read as an escape.
const whereChars = `(),~\`

// people are the field types that hold users (with their e-mails).
var people = map[string]bool{"User": true, "CreatedBy": true, "LastModifiedBy": true}

// computed are the field types NocoDB fills in itself.
var computed = map[string]bool{"Formula": true, "Rollup": true, "Lookup": true, "Links": true, "LinkToAnotherRecord": true, "CreatedTime": true,
	"LastModifiedTime": true, "AutoNumber": true, "ID": true, "Button": true, "Barcode": true, "QrCode": true, "Count": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	table := `"table":{"type":"string","description":"Table id (from tables), e.g. m1a2b3c4d5"}`
	rec := `"id":{"type":["string","integer"],"description":"The record's primary key"}`
	return sdk.Manifest{
		ID: "nocodb", Name: "NocoDB", Version: "0.1.0", Category: "Development", Icon: "layout",
		Description: "NocoDB: bases, tables and fields; list, create, update and delete records.",
		Presets:     []string{"developer", "team", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"url":{"type":"string","default":"https://app.nocodb.com","description":"NocoDB Cloud, or your server, e.g. https://nocodb.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API token (Account settings, Tokens); it acts with its user's roles"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "bases", Title: "Bases", Description: "The bases the token can see: id and title.", Risk: sdk.RiskRead},
			{Name: "tables", Title: "Tables", Description: "A base's tables: id, title and whether it's a view of an external database.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["base"],"properties":{"base":{"type":"string","description":"Base id (from bases)"}}}`)},
			{Name: "fields", Title: "Table fields", Description: "A table's fields: title, type, primary key, required, and whether NocoDB fills it in.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["table"],"properties":{` + table + `}}`)},
			{Name: "list_records", Title: "List records", Description: "Records of a table, with conditions, a sort and pages (at most 100 a page). Records can hold personal data, so they're kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["table"],"properties":{` + table + `,` + records.WhereSchema + `,` + records.SortSchema + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":25},"page":{"type":"integer","minimum":1,"default":1}}}`)},
			{Name: "create_record", Title: "Create a record", Description: "Adds a record to a table, fields by title. Undo deletes it.", Risk: sdk.RiskWrite, Sensitive: true, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["table","data"],"properties":{` + table + `,` + records.DataSchema + `}}`)},
			{Name: "update_record", Title: "Update a record", Description: "Sets some fields of a record; the others stay as they are. The preview shows the values before and after.", Risk: sdk.RiskWrite, Sensitive: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["table","id","data"],"properties":{` + table + `,` + rec + `,` + records.DataSchema + `}}`)},
			{Name: "delete_record", Title: "Delete a record", Description: "Deletes a record for good.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["table","id"],"properties":{` + table + `,` + rec + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = defaultBase
		if m.Base != "" {
			c.URL = m.Base
		}
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://nocodb.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v2")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api/v2", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("xc-token", strings.TrimSpace(t))
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
		return errors.New("NocoDB refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token's user isn't allowed to do this in NocoDB")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

type column struct {
	Title    string `json:"title"`
	Type     string `json:"uidt"`
	PK       bool   `json:"pk"`
	AI       bool   `json:"ai"`
	System   bool   `json:"system"`
	Required bool   `json:"rqd"`
}

type table struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Columns []column `json:"columns"`
}

func (t table) column(title string) (column, bool) {
	for _, c := range t.Columns {
		if c.Title == title {
			return c, true
		}
	}
	return column{}, false
}

// readable says whether a field may be filtered and sorted on. Lookups are
// left out: one can show a linked table's user field, and a condition on it
// would find users' e-mails one guess at a time.
func (t table) readable(title string) bool {
	c, ok := t.column(title)
	return titleRe.MatchString(title) && ok && !people[c.Type] && c.Type != "Lookup" && c.Type != "Links" && c.Type != "LinkToAnotherRecord" && c.Type != "Button" && c.Type != "Attachment"
}

func (t table) writable(create bool) func(string) error {
	return func(title string) error {
		c, ok := t.column(title)
		switch {
		case !titleRe.MatchString(title) || !ok:
			return fmt.Errorf("%s has no field %q", t.Title, records.Short(title))
		case c.PK && (!create || c.AI):
			return fmt.Errorf("%s is the primary key", title)
		case c.System || computed[c.Type]:
			return fmt.Errorf("%s is filled in by NocoDB", title)
		case people[c.Type]:
			return fmt.Errorf("%s is a user field; set people in NocoDB", title)
		case c.Type == "Attachment":
			return fmt.Errorf("%s is an attachment field; upload files in NocoDB", title)
		}
		return nil
	}
}

func (t table) pk() column {
	for _, c := range t.Columns {
		if c.PK {
			return c
		}
	}
	return column{Title: "Id", Type: "ID", AI: true}
}

// key is a primary key as NocoDB takes it in a body: a number for numeric
// keys.
func (t table) key(id string) any {
	pk := t.pk()
	if pk.AI || pk.Type == "ID" || pk.Type == "AutoNumber" || pk.Type == "Number" {
		if _, err := strconv.ParseInt(id, 10, 64); err == nil {
			return json.Number(id)
		}
	}
	return id
}

// person is a user as returned: the display name, else the id. Never the
// e-mail.
func person(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if n, _ := x["display_name"].(string); n != "" {
			return n
		}
		return x["id"]
	case []any:
		out := []any{}
		for _, e := range x {
			out = append(out, person(e))
		}
		return out
	case string:
		if strings.Contains(x, "@") {
			return "(a user)"
		}
	}
	return v
}

// users replaces, at any depth, the users a lookup shows (objects with an
// e-mail) by their names.
func users(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if _, ok := x["email"]; ok {
			return person(x)
		}
		for k, e := range x {
			x[k] = users(e)
		}
	case []any:
		for i, e := range x {
			x[i] = users(e)
		}
	}
	return v
}

// clean replaces users by their names and shortens long values.
func (t table) clean(r map[string]any) map[string]any {
	for _, c := range t.Columns {
		v, ok := r[c.Title]
		switch {
		case !ok:
		case people[c.Type]:
			r[c.Title] = person(v)
		case c.Type == "Lookup" || c.Type == "Rollup" || c.Type == "Formula":
			r[c.Title] = users(v)
		}
	}
	records.Clip(r)
	return r
}

func (c *conn) table(ctx context.Context, raw string) (table, error) {
	var t table
	id := strings.TrimSpace(raw)
	if !metaRe.MatchString(id) {
		return t, errors.New("a table is its id (from tables)")
	}
	if err := c.do(ctx, http.MethodGet, "/meta/tables/"+id, nil, nil, &t); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
			return t, fmt.Errorf("there's no table %s", id)
		}
		return t, err
	}
	if t.ID != id {
		return t, fmt.Errorf("NocoDB answered with another table for %s", id)
	}
	return t, nil
}

func recordID(raw json.RawMessage) (string, error) {
	var s string
	var n json.Number
	switch {
	case json.Unmarshal(raw, &s) == nil:
	case json.Unmarshal(raw, &n) == nil:
		s = n.String()
	default:
		return "", errors.New("a record is its primary key (letters, digits, _ and -)")
	}
	s = strings.TrimSpace(s)
	if !idRe.MatchString(s) {
		return "", errors.New("a record is its primary key (letters, digits, _ and -)")
	}
	return s, nil
}

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
	var out struct {
		List []struct{} `json:"list"`
	}
	if err := c.do(ctx, http.MethodGet, "/meta/bases/", nil, nil, &out); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no NocoDB API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d bases", len(out.List))}
}

type input struct {
	Base  string                     `json:"base"`
	Table string                     `json:"table"`
	ID    json.RawMessage            `json:"id"`
	Where []records.Cond             `json:"where"`
	Sort  string                     `json:"sort"`
	Limit int                        `json:"limit"`
	Page  int                        `json:"page"`
	Data  map[string]json.RawMessage `json:"data"`
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
	case "bases":
		var out struct {
			List []struct {
				ID     string `json:"id"`
				Title  string `json:"title"`
				Status string `json:"status"`
			} `json:"list"`
		}
		if err := c.do(ctx, http.MethodGet, "/meta/bases/", nil, nil, &out); err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for _, b := range out.List {
			rows = append(rows, map[string]any{"id": b.ID, "title": b.Title})
		}
		return sdk.JSON(rows)
	case "tables":
		b := strings.TrimSpace(p.Base)
		if !metaRe.MatchString(b) {
			return sdk.Result{}, errors.New("a base is its id (from bases)")
		}
		var out struct {
			List []struct {
				ID    string `json:"id"`
				Title string `json:"title"`
				Type  string `json:"type"`
				MM    bool   `json:"mm"`
			} `json:"list"`
		}
		if err := c.do(ctx, http.MethodGet, "/meta/bases/"+b+"/tables", nil, nil, &out); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no base %s", b)
			}
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for _, t := range out.List {
			if t.MM {
				continue // link tables NocoDB keeps for many-to-many fields
			}
			rows = append(rows, map[string]any{"id": t.ID, "title": t.Title, "view": t.Type == "view"})
		}
		return sdk.JSON(rows)
	case "fields", "list_records", "create_record", "update_record", "delete_record":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	if !metaRe.MatchString(strings.TrimSpace(p.Table)) {
		return sdk.Result{}, errors.New("a table is its id (from tables)")
	}
	var id string
	if call.Action == "update_record" || call.Action == "delete_record" {
		if id, err = recordID(p.ID); err != nil {
			return sdk.Result{}, err
		}
	}
	if (call.Action == "create_record" || call.Action == "update_record") && len(p.Data) == 0 {
		return sdk.Result{}, errors.New("give the fields to set in data")
	}
	if err := records.Check(p.Where, titleRe.MatchString, whereChars); err != nil {
		return sdk.Result{}, err
	}
	t, err := c.table(ctx, p.Table)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "fields":
		rows := []map[string]any{}
		for _, col := range t.Columns {
			rows = append(rows, map[string]any{"title": col.Title, "type": col.Type, "primaryKey": col.PK, "required": col.Required, "automatic": col.System || computed[col.Type] || (col.PK && col.AI)})
		}
		return sdk.JSON(map[string]any{"table": t.ID, "title": t.Title, "fields": rows})
	case "list_records":
		return c.list(ctx, t, p)
	case "create_record":
		return c.create(ctx, call, t, p.Data)
	case "update_record":
		return c.update(ctx, call, t, id, p.Data)
	}
	return c.remove(ctx, call, t, id)
}

var ncOps = map[string]string{"eq": "eq", "ne": "neq", "gt": "gt", "gte": "ge", "lt": "lt", "lte": "le"}

// Where renders checked conditions in NocoDB's where syntax. Titles and
// values were checked to hold none of its characters ( ) , ~ (nor values a
// backslash).
func Where(cs []records.Cond) string {
	parts := []string{}
	for _, c := range cs {
		var v string
		switch x := c.Value.(type) {
		case string:
			v = x
		case float64:
			v = records.Number(x)
		case bool:
			v = strconv.FormatBool(x)
		}
		switch c.Op {
		case "empty":
			parts = append(parts, "("+c.Field+",blank)")
		case "notempty":
			parts = append(parts, "("+c.Field+",notblank)")
		case "contains":
			parts = append(parts, "("+c.Field+",like,%"+v+"%)")
		default:
			parts = append(parts, "("+c.Field+","+ncOps[c.Op]+","+v+")")
		}
	}
	return strings.Join(parts, "~and")
}

func (c *conn) list(ctx context.Context, t table, p input) (sdk.Result, error) {
	if err := records.Check(p.Where, t.readable, whereChars); err != nil {
		return sdk.Result{}, err
	}
	sortBy, desc, err := records.Sort(p.Sort, t.readable)
	if err != nil {
		return sdk.Result{}, err
	}
	limit := records.Limit(p.Limit, 25, 100)
	q := url.Values{"limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa((records.Page(p.Page) - 1) * limit)}}
	if w := Where(p.Where); w != "" {
		q.Set("where", w)
	}
	if sortBy != "" {
		if desc {
			sortBy = "-" + sortBy
		}
		q.Set("sort", sortBy)
	}
	var out struct {
		List     []map[string]any `json:"list"`
		PageInfo struct {
			TotalRows  int  `json:"totalRows"`
			IsLastPage bool `json:"isLastPage"`
		} `json:"pageInfo"`
	}
	if err := c.do(ctx, http.MethodGet, "/tables/"+t.ID+"/records", q, nil, &out); err != nil {
		return sdk.Result{}, err
	}
	rows := []map[string]any{}
	for _, r := range out.List {
		rows = append(rows, t.clean(r))
	}
	rows, cut := records.Fit(rows)
	res := map[string]any{"table": t.ID, "page": records.Page(p.Page), "total": out.PageInfo.TotalRows, "lastPage": out.PageInfo.IsLastPage, "records": rows}
	if cut {
		res["truncated"] = true
	}
	return sdk.JSON(res)
}

func (c *conn) record(ctx context.Context, t table, id string) (map[string]any, error) {
	var r map[string]any
	err := c.do(ctx, http.MethodGet, "/tables/"+t.ID+"/records/"+url.PathEscape(id), nil, nil, &r)
	if rest.IsStatus(err, http.StatusNotFound) || (err == nil && len(r) == 0) {
		return nil, fmt.Errorf("there's no record %s in %s", id, t.Title)
	}
	if err != nil {
		return nil, err
	}
	if got := idText(r[t.pk().Title]); got != "" && got != id {
		return nil, fmt.Errorf("NocoDB answered with another record for %s", id)
	}
	return r, nil
}

func (c *conn) create(ctx context.Context, call sdk.Call, t table, data map[string]json.RawMessage) (sdk.Result, error) {
	if err := records.Data(data, t.writable(true)); err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create a record in %s (%s)", t.Title, strings.Join(records.Keys(data), ", ")),
			Changes: []sdk.Change{{Target: "table " + t.Title, Op: "create", After: records.Raw(data)}}}}, nil
	}
	var out map[string]any
	if err := c.do(ctx, http.MethodPost, "/tables/"+t.ID+"/records", nil, data, &out); err != nil {
		return sdk.Result{}, err
	}
	id := idText(out[t.pk().Title])
	res, err := sdk.JSON(map[string]any{"table": t.ID, "created": id})
	if idRe.MatchString(id) {
		res.Undo = sdk.UndoWith("delete_record", map[string]string{"table": t.ID, "id": id}, "Delete the new record "+id)
	}
	return res, err
}

func (c *conn) update(ctx context.Context, call sdk.Call, t table, id string, data map[string]json.RawMessage) (sdk.Result, error) {
	if err := records.Data(data, t.writable(false)); err != nil {
		return sdk.Result{}, err
	}
	cur, err := c.record(ctx, t, id)
	if err != nil {
		return sdk.Result{}, err
	}
	before, after := map[string]any{}, map[string]any{}
	for k, v := range data {
		if !records.Same(cur[k], v) {
			before[k], after[k] = cur[k], v
		}
	}
	if len(after) == 0 {
		return sdk.JSON(map[string]any{"table": t.ID, "id": id, "note": "nothing to change"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Update record %s in %s (%s)", id, t.Title, strings.Join(records.Keys(after), ", ")),
			Changes: []sdk.Change{{Target: "record " + id + " in " + t.Title, Op: "update", Before: records.Raw(before), After: records.Raw(after)}}}}, nil
	}
	changed := records.Keys(after)
	after[t.pk().Title] = t.key(id)
	if err := c.do(ctx, http.MethodPatch, "/tables/"+t.ID+"/records", nil, []any{after}, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"table": t.ID, "updated": id, "changed": changed})
}

func (c *conn) remove(ctx context.Context, call sdk.Call, t table, id string) (sdk.Result, error) {
	if _, err := c.record(ctx, t, id); err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		// Only the key: this action isn't sensitive, so its plan is logged.
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete record %s from %s for good", id, t.Title),
			Changes: []sdk.Change{{Target: "record " + id + " in " + t.Title, Op: "delete"}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, "/tables/"+t.ID+"/records", nil, []any{map[string]any{t.pk().Title: t.key(id)}}, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"table": t.ID, "deleted": id})
}
