// Package pocketbase works with a PocketBase server (0.23 or later) as a
// superuser: collections and their fields, and listing, reading, creating,
// updating and deleting records.
//
// Auth and system collections (_superusers, users and every other auth
// collection, _mfas, _otps, _externalAuths, _authOrigins) are refused for
// every record action, so e-mail addresses, password hashes and token keys
// are never read. Hidden fields are left out of every record and can't be
// filtered on or set.
package pocketbase

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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/records"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one PocketBase server.
type Config struct {
	URL                string `json:"url"`      // e.g. https://pb.example.com
	Email              string `json:"email"`    // a superuser's e-mail
	Password           string `json:"password"` // secret:// reference to its password
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api   *rest.Client
	login *rest.Client // signs in; carries no credentials itself
	host  sdk.Host
	email string
	pass  string // secret:// reference

	mu    sync.Mutex
	token string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the PocketBase module.
func New() *Module { return &Module{} }

var (
	pathRe  = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	nameRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,99}$`)
	idRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	fieldRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,99}$`)
	emailRe = regexp.MustCompile(`^[^\s@]{1,128}@[^\s@]{1,253}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	coll := `"collection":{"type":"string","description":"Collection name (from collections)"}`
	rec := `"id":{"type":"string","description":"Record id"}`
	one := sdk.Schema(`{"type":"object","required":["collection","id"],"properties":{` + coll + `,` + rec + `}}`)
	return sdk.Manifest{
		ID: "pocketbase", Name: "PocketBase", Version: "0.1.0", Category: "Development", Icon: "database",
		Description: "PocketBase: collections and their fields; list, read, create, update and delete records (auth and system collections excluded).",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","email","password"],"properties":{
			"url":{"type":"string","description":"Your PocketBase server, e.g. https://pb.example.com"},
			"email":{"type":"string","description":"A superuser's e-mail address (Dashboard, System, Superusers); a dedicated one is best"},
			"password":{"type":"string","x-secret":true,"description":"That superuser's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "collections", Title: "Collections", Description: "Every collection: name, type (base, view, auth), whether it's a system one, and its field count.", Risk: sdk.RiskRead},
			{Name: "schema", Title: "Collection fields", Description: "A collection's fields (name, type, required, hidden) and its API rules, to build filters and records.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["collection"],"properties":{` + coll + `}}`)},
			{Name: "list_records", Title: "List records", Description: "Records of a base or view collection, with conditions, a sort and pages (at most 100 a page). Records can hold personal data, so they're kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["collection"],"properties":{` + coll + `,` + records.WhereSchema + `,` + records.SortSchema + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":25},"page":{"type":"integer","minimum":1,"default":1}}}`)},
			{Name: "get_record", Title: "Read a record", Description: "One record by id. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true, Input: one},
			{Name: "create_record", Title: "Create a record", Description: "Adds a record to a base collection. Undo deletes it.", Risk: sdk.RiskWrite, Sensitive: true, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["collection","data"],"properties":{` + coll + `,` + records.DataSchema + `}}`)},
			{Name: "update_record", Title: "Update a record", Description: "Sets some fields of a record; the others stay as they are. The preview shows the values before and after.", Risk: sdk.RiskWrite, Sensitive: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["collection","id","data"],"properties":{` + coll + `,` + rec + `,` + records.DataSchema + `}}`)},
			{Name: "delete_record", Title: "Delete a record", Description: "Deletes a record for good (and, as the collection's relations say, records that depend on it).", Risk: sdk.RiskDestructive, DryRun: true, Input: one},
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
		return errors.New("the address is like https://pb.example.com")
	}
	c.Email = strings.TrimSpace(c.Email)
	if !emailRe.MatchString(c.Email) {
		return errors.New("enter the superuser's e-mail address")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the superuser's password in the vault and enter its secret:// reference")
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
	client = rest.SameHostOnly(client)
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/_")
	cn := &conn{host: h, email: c.Email, pass: c.Password}
	cn.login = rest.New(base, nil)
	cn.login.HTTP = client
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := cn.session(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", t)
		return nil
	})
	cn.api.HTTP = client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errLogin = errors.New("PocketBase refused the superuser e-mail or password")

// session returns the superuser token, signing in when there's none.
func (c *conn) session(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		return c.token, nil
	}
	pw, err := c.host.Secret(ctx, c.pass)
	if err != nil {
		return "", err
	}
	var out struct {
		Token string `json:"token"`
	}
	_, err = c.login.Do(ctx, http.MethodPost, "/api/collections/_superusers/auth-with-password", nil, map[string]string{"identity": c.email, "password": pw}, &out)
	switch {
	case rest.IsStatus(err, http.StatusBadRequest), rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return "", errLogin
	case rest.IsStatus(err, http.StatusNotFound):
		return "", errors.New("no PocketBase 0.23 or later at this address (no _superusers collection)")
	case err != nil:
		return "", err
	case out.Token == "":
		return "", errors.New("PocketBase didn't return a session")
	}
	c.token = out.Token
	return c.token, nil
}

// do calls the API, signing in again once when the session has expired.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		_, err = c.api.Do(ctx, method, path, q, body, out)
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return errLogin
		}
	}
	if rest.IsStatus(err, http.StatusForbidden) {
		return errors.New("PocketBase refused this (is the account a superuser?)")
	}
	return err
}

type field struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Hidden   bool   `json:"hidden"`
	System   bool   `json:"system"`
}

type collection struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Type       string  `json:"type"`
	System     bool    `json:"system"`
	Fields     []field `json:"fields"`
	ListRule   *string `json:"listRule"`
	ViewRule   *string `json:"viewRule"`
	CreateRule *string `json:"createRule"`
	UpdateRule *string `json:"updateRule"`
	DeleteRule *string `json:"deleteRule"`
	ViewQuery  string  `json:"viewQuery"`
}

// private says whether a collection's records are never read or written:
// auth collections hold e-mails, password hashes and token keys, and system
// ones hold sign-in secrets (one-time passwords, MFA, OAuth2 links).
func (c collection) private() bool {
	return c.Type == "auth" || c.System || strings.HasPrefix(c.Name, "_")
}

func (c collection) field(name string) (field, bool) {
	for _, f := range c.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return field{}, false
}

// readable says whether a field may be filtered and sorted on.
func (c collection) readable(name string) bool {
	if !fieldRe.MatchString(name) {
		return false
	}
	f, ok := c.field(name)
	return ok && !f.Hidden && f.Type != "password"
}

// writable says why a field can't be set, or nil.
func (c collection) writable(name string) error {
	f, ok := c.field(name)
	switch {
	case !fieldRe.MatchString(name) || !ok:
		return fmt.Errorf("%s has no field %q", c.Name, records.Short(name))
	case f.Hidden || f.Type == "password":
		return fmt.Errorf("%s is a hidden field, which isn't set here", name)
	case f.Name == "id" || f.Type == "autodate":
		return fmt.Errorf("%s is set by PocketBase", name)
	case f.Type == "file":
		return fmt.Errorf("%s is a file field; upload files in the dashboard", name)
	}
	return nil
}

// clean drops hidden fields from a record and shortens long values.
func (c collection) clean(r map[string]any) map[string]any {
	for _, f := range c.Fields {
		if f.Hidden || f.Type == "password" {
			delete(r, f.Name)
		}
	}
	delete(r, "expand")
	records.Clip(r)
	return r
}

func (c *conn) collection(ctx context.Context, name string) (collection, error) {
	var col collection
	name = strings.TrimSpace(name)
	if !nameRe.MatchString(name) {
		return col, errors.New("a collection is its name (letters, digits and _)")
	}
	if strings.HasPrefix(name, "_") {
		return col, fmt.Errorf("%s is a system collection; its records aren't read or changed here", name)
	}
	if err := c.do(ctx, http.MethodGet, "/api/collections/"+url.PathEscape(name), nil, nil, &col); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return col, fmt.Errorf("there's no collection %s", name)
		}
		return col, err
	}
	if col.Name != name && col.ID != name {
		return col, fmt.Errorf("PocketBase answered with another collection for %s", name)
	}
	if col.private() {
		return col, fmt.Errorf("%s is an auth or system collection; its records hold sign-in details and aren't read or changed here", col.Name)
	}
	if col.Type == "view" {
		if err := c.viewOK(ctx, col); err != nil {
			return col, err
		}
	}
	return col, nil
}

// viewOK refuses a view collection whose query reads an auth or system
// collection: it would show users' e-mails (or more) as plain fields.
func (c *conn) viewOK(ctx context.Context, view collection) error {
	var page struct {
		Items []collection `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/collections", url.Values{"perPage": {"500"}, "fields": {"id,name,type,system"}}, nil, &page); err != nil {
		return err
	}
	q := strings.ToLower(view.ViewQuery)
	for _, col := range page.Items {
		if !col.private() {
			continue
		}
		for _, n := range []string{col.Name, col.ID} {
			if n != "" && regexp.MustCompile(`(^|[^a-z0-9_])`+regexp.QuoteMeta(strings.ToLower(n))+`($|[^a-z0-9_])`).MatchString(q) {
				return fmt.Errorf("%s is a view of the auth or system collection %s; its records aren't read here", view.Name, col.Name)
			}
		}
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var page struct {
		TotalItems int `json:"totalItems"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/collections", url.Values{"perPage": {"1"}}, nil, &page); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d collections", page.TotalItems)}
}

type input struct {
	Collection string                     `json:"collection"`
	ID         string                     `json:"id"`
	Where      []records.Cond             `json:"where"`
	Sort       string                     `json:"sort"`
	Limit      int                        `json:"limit"`
	Page       int                        `json:"page"`
	Data       map[string]json.RawMessage `json:"data"`
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
	p.ID = strings.TrimSpace(p.ID)
	switch call.Action {
	case "collections":
		return c.collections(ctx)
	case "schema":
		return c.schema(ctx, p.Collection)
	case "list_records":
		return c.list(ctx, p)
	case "get_record", "update_record", "delete_record":
		if !idRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("a record is its id (letters, digits, _ and -)")
		}
	case "create_record":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	if call.Action == "create_record" || call.Action == "update_record" {
		if len(p.Data) == 0 {
			return sdk.Result{}, errors.New("give the fields to set in data")
		}
	}
	if !nameRe.MatchString(strings.TrimSpace(p.Collection)) {
		return sdk.Result{}, errors.New("a collection is its name (letters, digits and _)")
	}
	col, err := c.collection(ctx, p.Collection)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "get_record":
		r, err := c.record(ctx, col, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(col.clean(r))
	case "create_record":
		return c.create(ctx, call, col, p.Data)
	case "update_record":
		return c.update(ctx, call, col, p.ID, p.Data)
	default:
		return c.remove(ctx, call, col, p.ID)
	}
}

func (c *conn) collections(ctx context.Context) (sdk.Result, error) {
	var page struct {
		Items []collection `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/collections", url.Values{"perPage": {"500"}, "sort": {"name"}}, nil, &page); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, col := range page.Items {
		row := map[string]any{"name": col.Name, "id": col.ID, "type": col.Type, "system": col.System, "fields": len(col.Fields)}
		if col.private() {
			row["records"] = "not available here (auth or system collection)"
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

func rule(r *string) any {
	if r == nil {
		return "superusers only"
	}
	if *r == "" {
		return "anyone"
	}
	return *r
}

func (c *conn) schema(ctx context.Context, name string) (sdk.Result, error) {
	name = strings.TrimSpace(name)
	if !nameRe.MatchString(name) {
		return sdk.Result{}, errors.New("a collection is its name (letters, digits and _)")
	}
	var col collection
	if err := c.do(ctx, http.MethodGet, "/api/collections/"+url.PathEscape(name), nil, nil, &col); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no collection %s", name)
		}
		return sdk.Result{}, err
	}
	fields := []map[string]any{}
	for _, f := range col.Fields {
		fields = append(fields, map[string]any{"name": f.Name, "type": f.Type, "required": f.Required, "hidden": f.Hidden, "system": f.System})
	}
	return sdk.JSON(map[string]any{"name": col.Name, "type": col.Type, "system": col.System, "fields": fields,
		"rules":            map[string]any{"list": rule(col.ListRule), "view": rule(col.ViewRule), "create": rule(col.CreateRule), "update": rule(col.UpdateRule), "delete": rule(col.DeleteRule)},
		"recordsAvailable": !col.private()})
}

// quote writes a string as a PocketBase filter literal. Values were checked
// by records.Check: no control characters and no backslash, so escaping the
// quote is all there is to it.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `\'`) + "'" }

var pbOps = map[string]string{"eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "contains": "~"}

// Filter renders checked conditions as a PocketBase filter expression.
func Filter(cs []records.Cond) string {
	parts := []string{}
	for _, c := range cs {
		var v string
		switch x := c.Value.(type) {
		case string:
			v = quote(x)
		case float64:
			v = records.Number(x)
		case bool:
			v = strconv.FormatBool(x)
		}
		switch c.Op {
		case "empty":
			parts = append(parts, c.Field+" = null")
		case "notempty":
			parts = append(parts, c.Field+" != null")
		default:
			parts = append(parts, c.Field+" "+pbOps[c.Op]+" "+v)
		}
	}
	return strings.Join(parts, " && ")
}

func (c *conn) list(ctx context.Context, p input) (sdk.Result, error) {
	if !nameRe.MatchString(strings.TrimSpace(p.Collection)) {
		return sdk.Result{}, errors.New("a collection is its name (letters, digits and _)")
	}
	// The field names are checked against the collection, so they're
	// fetched first; the shape of the conditions is checked before that.
	if err := records.Check(p.Where, fieldRe.MatchString, `\`); err != nil {
		return sdk.Result{}, err
	}
	col, err := c.collection(ctx, p.Collection)
	if err != nil {
		return sdk.Result{}, err
	}
	if err := records.Check(p.Where, col.readable, `\`); err != nil {
		return sdk.Result{}, err
	}
	sortBy, desc, err := records.Sort(p.Sort, func(s string) bool { return col.readable(s) })
	if err != nil {
		return sdk.Result{}, err
	}
	q := url.Values{"perPage": {strconv.Itoa(records.Limit(p.Limit, 25, 100))}, "page": {strconv.Itoa(records.Page(p.Page))}}
	if f := Filter(p.Where); f != "" {
		q.Set("filter", f)
	}
	if sortBy != "" {
		if desc {
			sortBy = "-" + sortBy
		}
		q.Set("sort", sortBy)
	}
	var page struct {
		Page       int              `json:"page"`
		TotalItems int              `json:"totalItems"`
		TotalPages int              `json:"totalPages"`
		Items      []map[string]any `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/collections/"+url.PathEscape(col.Name)+"/records", q, nil, &page); err != nil {
		return sdk.Result{}, err
	}
	rows := []map[string]any{}
	for _, r := range page.Items {
		rows = append(rows, col.clean(r))
	}
	rows, cut := records.Fit(rows)
	out := map[string]any{"collection": col.Name, "page": page.Page, "pages": page.TotalPages, "total": page.TotalItems, "records": rows}
	if cut {
		out["truncated"] = true
	}
	return sdk.JSON(out)
}

func (c *conn) record(ctx context.Context, col collection, id string) (map[string]any, error) {
	var r map[string]any
	if err := c.do(ctx, http.MethodGet, "/api/collections/"+url.PathEscape(col.Name)+"/records/"+url.PathEscape(id), nil, nil, &r); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return nil, fmt.Errorf("there's no record %s in %s", id, col.Name)
		}
		return nil, err
	}
	if got, _ := r["id"].(string); got != id {
		return nil, fmt.Errorf("PocketBase answered with another record for %s", id)
	}
	return r, nil
}

func (c *conn) create(ctx context.Context, call sdk.Call, col collection, data map[string]json.RawMessage) (sdk.Result, error) {
	if col.Type == "view" {
		return sdk.Result{}, fmt.Errorf("%s is a view collection, which is read only", col.Name)
	}
	if err := records.Data(data, col.writable); err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create a record in %s (%s)", col.Name, strings.Join(records.Keys(data), ", ")),
			Changes: []sdk.Change{{Target: "collection " + col.Name, Op: "create", After: records.Raw(data)}}}}, nil
	}
	var r map[string]any
	if err := c.do(ctx, http.MethodPost, "/api/collections/"+url.PathEscape(col.Name)+"/records", nil, data, &r); err != nil {
		return sdk.Result{}, err
	}
	id, _ := r["id"].(string)
	res, err := sdk.JSON(map[string]any{"collection": col.Name, "created": col.clean(r)})
	if idRe.MatchString(id) {
		res.Undo = sdk.UndoWith("delete_record", map[string]string{"collection": col.Name, "id": id}, "Delete the new record "+id)
	}
	return res, err
}

func (c *conn) update(ctx context.Context, call sdk.Call, col collection, id string, data map[string]json.RawMessage) (sdk.Result, error) {
	if col.Type == "view" {
		return sdk.Result{}, fmt.Errorf("%s is a view collection, which is read only", col.Name)
	}
	if err := records.Data(data, col.writable); err != nil {
		return sdk.Result{}, err
	}
	cur, err := c.record(ctx, col, id)
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
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Update record %s in %s (%s)", id, col.Name, strings.Join(records.Keys(after), ", ")),
			Changes: []sdk.Change{{Target: "record " + id + " in " + col.Name, Op: "update", Before: records.Raw(before), After: records.Raw(after)}}}}, nil
	}
	var r map[string]any
	if err := c.do(ctx, http.MethodPatch, "/api/collections/"+url.PathEscape(col.Name)+"/records/"+url.PathEscape(id), nil, after, &r); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"collection": col.Name, "updated": col.clean(r), "changed": records.Keys(after)})
}

func (c *conn) remove(ctx context.Context, call sdk.Call, col collection, id string) (sdk.Result, error) {
	if col.Type == "view" {
		return sdk.Result{}, fmt.Errorf("%s is a view collection, which is read only", col.Name)
	}
	cur, err := c.record(ctx, col, id)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		// The preview names the record, never its values: this action isn't
		// sensitive, so its plan is logged.
		before := map[string]any{"id": id, "created": cur["created"], "updated": cur["updated"]}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete record %s from %s for good", id, col.Name),
			Changes: []sdk.Change{{Target: "record " + id + " in " + col.Name, Op: "delete", Before: records.Raw(before)}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, "/api/collections/"+url.PathEscape(col.Name)+"/records/"+url.PathEscape(id), nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"collection": col.Name, "deleted": id})
}
