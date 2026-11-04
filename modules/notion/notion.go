// Package notion works with a Notion workspace through an internal
// integration token: search pages and databases, read a page as Markdown,
// query a database, create pages in it, append blocks, and move pages to the
// trash and back.
package notion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Notion integration.
type Config struct {
	Token string `json:"token"` // secret:// internal integration secret
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.notion.com/v1 (tests).
	Base string
}

// New returns the Notion module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://api.notion.com/v1"
	// Version is the Notion-Version this module is written against: data
	// sources (2025-09-03) and in_trash instead of archived (2026-03-11).
	Version = "2026-03-11"

	maxBlocksPerCall = 100
	maxPageRequests  = 60 // block-children requests for one read_page
)

var (
	hexID   = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	uuidID  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	idInURL = regexp.MustCompile(`([0-9a-fA-F]{32})$`)
)

// normID accepts a Notion id with or without dashes, or a notion.so /
// notion.site link, and returns the dashed form. Nothing else reaches a path.
func normID(s, what string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "https://") {
		u, err := url.Parse(s)
		if err == nil {
			h := strings.ToLower(u.Hostname())
			if h == "notion.so" || strings.HasSuffix(h, ".notion.so") || strings.HasSuffix(h, ".notion.site") {
				seg := u.Path[strings.LastIndex(u.Path, "/")+1:]
				if m := idInURL.FindStringSubmatch(seg); m != nil {
					s = m[1]
				}
			}
		}
	}
	if uuidID.MatchString(s) {
		s = strings.ReplaceAll(s, "-", "")
	}
	if !hexID.MatchString(s) {
		return "", fmt.Errorf("the %s is a Notion id (32 hex characters) or a link to it", what)
	}
	s = strings.ToLower(s)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	page := `"page":{"type":"string","description":"Page id or link"}`
	db := `"database":{"type":"string","description":"Database id or link"},"dataSource":{"type":"string","description":"Data source id or name, when the database has more than one"}`
	content := `"content":{"type":"string","description":"Text as simple Markdown: # headings, - bullets, 1. numbers, - [ ] to-dos, > quotes, --- and code fences"}`
	return sdk.Manifest{
		ID: "notion", Name: "Notion", Version: "0.1.0", Category: "Knowledge", Icon: "document",
		Description: "Search Notion, read pages as Markdown, query databases, add pages and blocks, and trash pages.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"Internal integration secret (notion.so/profile/integrations). It sees only the pages and databases shared with the integration"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "search", Title: "Search", Description: "Pages and databases shared with the integration whose title matches.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string"},"type":{"type":"string","enum":["page","database"]},"limit":{"type":"integer","default":20,"maximum":100}}}`)},
			{Name: "read_page", Title: "Read a page", Description: "A page's properties and content as Markdown, nested blocks included (bounded). Page content is private, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["page"],"properties":{` + page + `,"maxChars":{"type":"integer","default":20000,"maximum":200000},"depth":{"type":"integer","default":3,"minimum":1,"maximum":5}}}`)},
			{Name: "database", Title: "Database details", Description: "A database's data sources and their properties (names and types), to build filters and new pages.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["database"],"properties":{` + db + `}}`)},
			{Name: "query_database", Title: "Query a database", Description: "Rows (pages) of a database, with a Notion filter and sorts, and their property values as text.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["database"],"properties":{` + db + `,"filter":{"type":"object","description":"A Notion filter object, e.g. {\"property\":\"Status\",\"status\":{\"equals\":\"Doing\"}}"},"sorts":{"type":"array","items":{"type":"object"}},"limit":{"type":"integer","default":50,"maximum":500}}}`)},
			{Name: "create_page", Title: "Create a page in a database", Description: "Adds a row: title and property values by name (converted to the property's type), and optional content. Undo moves it to the trash.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["database"],"properties":{` + db + `,"title":{"type":"string"},"properties":{"type":"object","description":"Property name to value: text, number, true/false, a select or status name, a list for multi-select, a date (2026-11-04 or {start,end}), page ids for relations"},` + content + `}}`)},
			{Name: "append_blocks", Title: "Append to a page", Description: "Adds content at the end of a page (or block). Undo moves the new blocks to the trash.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["page","content"],"properties":{` + page + `,` + content + `}}`)},
			{Name: "trash_blocks", Title: "Trash blocks", Description: "Moves blocks to the trash (not child pages or databases: use archive_page for a page). Undo restores them.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["blocks"],"properties":{"blocks":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"string"}}}}`)},
			{Name: "restore_blocks", Title: "Restore blocks", Description: "Brings trashed blocks back. Undo trashes them again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["blocks"],"properties":{"blocks":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"string"}}}}`)},
			{Name: "archive_page", Title: "Move a page to the trash", Description: "Trashes a page (Notion keeps it for 30 days). Undo restores it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["page"],"properties":{` + page + `}}`)},
			{Name: "unarchive_page", Title: "Restore a page", Description: "Brings a page back from the trash. Undo trashes it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["page"],"properties":{` + page + `}}`)},
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
		return errors.New("store the integration secret in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	tok := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.Header.Set("Notion-Version", Version)
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u struct {
		Name string `json:"name"`
		Bot  struct {
			Workspace string `json:"workspace_name"`
		} `json:"bot"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/users/me", nil, nil, &u); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "Notion refused the integration secret"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "integration " + u.Name
	if u.Bot.Workspace != "" {
		msg += " in " + u.Bot.Workspace
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type richText struct {
	PlainText   string `json:"plain_text"`
	Href        string `json:"href"`
	Annotations struct {
		Bold          bool `json:"bold"`
		Italic        bool `json:"italic"`
		Strikethrough bool `json:"strikethrough"`
		Code          bool `json:"code"`
	} `json:"annotations"`
}

func plain(rt []richText) string {
	var b strings.Builder
	for _, r := range rt {
		b.WriteString(r.PlainText)
	}
	return b.String()
}

type pageObj struct {
	Object     string                     `json:"object"`
	ID         string                     `json:"id"`
	URL        string                     `json:"url"`
	InTrash    bool                       `json:"in_trash"`
	LastEdited string                     `json:"last_edited_time"`
	Properties map[string]json.RawMessage `json:"properties"`
	Title      []richText                 `json:"title"` // data sources and databases
	Parent     struct {
		Type       string `json:"type"`
		DatabaseID string `json:"database_id"`
	} `json:"parent"`
}

func (p pageObj) title() string {
	if p.Object != "page" {
		return plain(p.Title)
	}
	for _, raw := range p.Properties {
		var v struct {
			Type  string     `json:"type"`
			Title []richText `json:"title"`
		}
		if json.Unmarshal(raw, &v) == nil && v.Type == "title" {
			return plain(v.Title)
		}
	}
	return ""
}

// propText flattens a property value to text.
func propText(raw json.RawMessage) any {
	var v map[string]json.RawMessage
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	var typ string
	json.Unmarshal(v["type"], &typ)
	val := v[typ]
	name := func(r json.RawMessage) string {
		var n struct {
			Name string `json:"name"`
		}
		json.Unmarshal(r, &n)
		return n.Name
	}
	switch typ {
	case "title", "rich_text":
		var rt []richText
		json.Unmarshal(val, &rt)
		return plain(rt)
	case "number", "checkbox", "url", "email", "phone_number", "created_time", "last_edited_time":
		var x any
		json.Unmarshal(val, &x)
		return x
	case "select", "status":
		if string(val) == "null" {
			return nil
		}
		return name(val)
	case "multi_select", "people":
		var xs []json.RawMessage
		json.Unmarshal(val, &xs)
		out := []string{}
		for _, x := range xs {
			out = append(out, name(x))
		}
		return out
	case "date":
		var d *struct {
			Start string  `json:"start"`
			End   *string `json:"end"`
		}
		json.Unmarshal(val, &d)
		if d == nil {
			return nil
		}
		if d.End != nil {
			return d.Start + " → " + *d.End
		}
		return d.Start
	case "relation":
		var xs []struct {
			ID string `json:"id"`
		}
		json.Unmarshal(val, &xs)
		out := []string{}
		for _, x := range xs {
			out = append(out, x.ID)
		}
		return out
	case "unique_id":
		var u struct {
			Prefix *string `json:"prefix"`
			Number int     `json:"number"`
		}
		json.Unmarshal(val, &u)
		if u.Prefix != nil {
			return fmt.Sprintf("%s-%d", *u.Prefix, u.Number)
		}
		return u.Number
	case "formula":
		var f map[string]json.RawMessage
		json.Unmarshal(val, &f)
		var ft string
		json.Unmarshal(f["type"], &ft)
		var x any
		json.Unmarshal(f[ft], &x)
		return x
	case "rollup":
		var f map[string]json.RawMessage
		json.Unmarshal(val, &f)
		var ft string
		json.Unmarshal(f["type"], &ft)
		if ft == "array" {
			var xs []json.RawMessage
			json.Unmarshal(f["array"], &xs)
			out := []any{}
			for _, x := range xs {
				out = append(out, propText(x))
			}
			return out
		}
		var x any
		json.Unmarshal(f[ft], &x)
		return x
	case "files":
		var xs []json.RawMessage
		json.Unmarshal(val, &xs)
		out := []string{}
		for _, x := range xs {
			out = append(out, name(x))
		}
		return out
	case "created_by", "last_edited_by":
		return name(val)
	}
	return nil
}

func pageSummary(p pageObj, withProps bool) map[string]any {
	out := map[string]any{"id": p.ID, "title": p.title(), "url": p.URL, "lastEdited": p.LastEdited}
	if p.Object != "page" {
		out["type"] = "database"
		if p.Object == "data_source" {
			out["dataSource"] = p.ID
			if p.Parent.DatabaseID != "" {
				out["id"] = p.Parent.DatabaseID
			}
		}
	} else {
		out["type"] = "page"
	}
	if p.InTrash {
		out["inTrash"] = true
	}
	if withProps {
		props := map[string]any{}
		for k, raw := range p.Properties {
			props[k] = propText(raw)
		}
		out["properties"] = props
	}
	return out
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

type input struct {
	Query      string          `json:"query"`
	Type       string          `json:"type"`
	Limit      int             `json:"limit"`
	Page       string          `json:"page"`
	MaxChars   int             `json:"maxChars"`
	Depth      int             `json:"depth"`
	Database   string          `json:"database"`
	DataSource string          `json:"dataSource"`
	Filter     json.RawMessage `json:"filter"`
	Sorts      json.RawMessage `json:"sorts"`
	Title      *string         `json:"title"`
	Properties map[string]any  `json:"properties"`
	Content    string          `json:"content"`
	Blocks     []string        `json:"blocks"`
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
	case "search":
		return c.search(ctx, p)
	case "read_page":
		return c.readPage(ctx, p)
	case "database":
		db, srcs, err := c.dataSources(ctx, p.Database)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range srcs {
			schema, err := c.schema(ctx, s.ID)
			if err != nil {
				return sdk.Result{}, err
			}
			props := map[string]string{}
			for k, v := range schema {
				props[k] = v.Type
			}
			out = append(out, map[string]any{"id": s.ID, "name": s.Name, "properties": props})
		}
		return sdk.JSON(map[string]any{"id": db.ID, "title": plain(db.Title), "url": db.URL, "dataSources": out})
	case "query_database":
		return c.query(ctx, p)
	case "create_page":
		return c.createPage(ctx, call, p)
	case "append_blocks":
		return c.appendBlocks(ctx, call, p)
	case "trash_blocks", "restore_blocks":
		return c.trashBlocks(ctx, call, p.Blocks)
	case "archive_page", "unarchive_page":
		return c.trashPage(ctx, call, p.Page)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) search(ctx context.Context, p input) (sdk.Result, error) {
	limit := p.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	body := map[string]any{"page_size": limit, "sort": map[string]any{"direction": "descending", "timestamp": "last_edited_time"}}
	if q := strings.TrimSpace(p.Query); q != "" {
		body["query"] = q
	}
	switch p.Type {
	case "":
	case "page":
		body["filter"] = map[string]any{"property": "object", "value": "page"}
	case "database":
		body["filter"] = map[string]any{"property": "object", "value": "data_source"}
	default:
		return sdk.Result{}, errors.New("the type is page or database")
	}
	var res struct {
		Results []pageObj `json:"results"`
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/search", nil, body, &res); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, r := range res.Results {
		out = append(out, pageSummary(r, false))
	}
	return sdk.JSON(out)
}

type database struct {
	ID          string     `json:"id"`
	URL         string     `json:"url"`
	Title       []richText `json:"title"`
	DataSources []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"data_sources"`
}

type source struct{ ID, Name string }

func (c *conn) dataSources(ctx context.Context, raw string) (database, []source, error) {
	var db database
	id, err := normID(raw, "database")
	if err != nil {
		return db, nil, err
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/databases/"+id, nil, nil, &db); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return db, nil, fmt.Errorf("there's no database %s shared with the integration (share it from the database's ••• menu, Connections)", id)
		}
		return db, nil, err
	}
	var out []source
	for _, s := range db.DataSources {
		out = append(out, source{s.ID, s.Name})
	}
	if len(out) == 0 {
		return db, nil, errors.New("this database has no data sources the integration can use")
	}
	return db, out, nil
}

// pickSource resolves the data source to query or write: the only one, or
// the one named or given by id.
func (c *conn) pickSource(ctx context.Context, p input) (database, source, error) {
	db, srcs, err := c.dataSources(ctx, p.Database)
	if err != nil {
		return db, source{}, err
	}
	want := strings.TrimSpace(p.DataSource)
	if want == "" {
		if len(srcs) > 1 {
			names := []string{}
			for _, s := range srcs {
				names = append(names, s.Name)
			}
			return db, source{}, fmt.Errorf("this database has %d data sources (%s); say which in dataSource", len(srcs), strings.Join(names, ", "))
		}
		return db, srcs[0], nil
	}
	wantID, _ := normID(want, "data source")
	for _, s := range srcs {
		if s.ID == wantID || strings.EqualFold(s.Name, want) {
			return db, s, nil
		}
	}
	return db, source{}, fmt.Errorf("the database has no data source %q", want)
}

type propSchema struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

func (c *conn) schema(ctx context.Context, sourceID string) (map[string]propSchema, error) {
	if _, err := normID(sourceID, "data source"); err != nil {
		return nil, err
	}
	var ds struct {
		Properties map[string]propSchema `json:"properties"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/data_sources/"+sourceID, nil, nil, &ds); err != nil {
		return nil, err
	}
	return ds.Properties, nil
}

func (c *conn) query(ctx context.Context, p input) (sdk.Result, error) {
	limit := p.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	body := map[string]any{}
	if len(p.Filter) > 0 && string(p.Filter) != "null" {
		var f map[string]any
		if json.Unmarshal(p.Filter, &f) != nil || len(f) == 0 {
			return sdk.Result{}, errors.New("the filter is a Notion filter object")
		}
		body["filter"] = f
	}
	if len(p.Sorts) > 0 && string(p.Sorts) != "null" {
		var s []map[string]any
		if json.Unmarshal(p.Sorts, &s) != nil {
			return sdk.Result{}, errors.New("sorts is a list of Notion sort objects")
		}
		body["sorts"] = s
	}
	db, src, err := c.pickSource(ctx, p)
	if err != nil {
		return sdk.Result{}, err
	}
	if _, err := normID(src.ID, "data source"); err != nil {
		return sdk.Result{}, err
	}
	var rows []map[string]any
	more := false
	for len(rows) < limit {
		body["page_size"] = min(100, limit-len(rows))
		var res struct {
			Results    []pageObj `json:"results"`
			HasMore    bool      `json:"has_more"`
			NextCursor *string   `json:"next_cursor"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/data_sources/"+src.ID+"/query", nil, body, &res); err != nil {
			return sdk.Result{}, err
		}
		for _, r := range res.Results {
			rows = append(rows, pageSummary(r, true))
		}
		more = res.HasMore
		if !res.HasMore || res.NextCursor == nil || len(res.Results) == 0 {
			break
		}
		body["start_cursor"] = *res.NextCursor
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	return sdk.JSON(map[string]any{"database": plain(db.Title), "dataSource": src.Name, "count": len(rows), "more": more, "rows": rows})
}

func (c *conn) getPage(ctx context.Context, raw string) (pageObj, error) {
	var pg pageObj
	id, err := normID(raw, "page")
	if err != nil {
		return pg, err
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/pages/"+id, nil, nil, &pg); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return pg, fmt.Errorf("there's no page %s shared with the integration", id)
		}
		return pg, err
	}
	return pg, nil
}

// trashPage moves a page to the trash or back (archive_page / unarchive_page).
func (c *conn) trashPage(ctx context.Context, call sdk.Call, raw string) (sdk.Result, error) {
	trash := call.Action == "archive_page"
	pg, err := c.getPage(ctx, raw)
	if err != nil {
		return sdk.Result{}, err
	}
	title := pg.title()
	if pg.InTrash == trash {
		state := "in the trash"
		if !pg.InTrash {
			state = "not in the trash"
		}
		return sdk.JSON(map[string]any{"page": pg.ID, "note": "the page is already " + state})
	}
	verb, back, backDesc := "Move %q to the trash", "unarchive_page", "Restore %q"
	if !trash {
		verb, back, backDesc = "Restore %q from the trash", "archive_page", "Move %q to the trash again"
	}
	if call.DryRun {
		op := "trash"
		if !trash {
			op = "restore"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf(verb, title), Changes: []sdk.Change{{Target: fmt.Sprintf("page %q", title), Op: op}}}}, nil
	}
	if _, err := c.api.Do(ctx, http.MethodPatch, "/pages/"+pg.ID, nil, map[string]any{"in_trash": trash}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"page": pg.ID, "title": title, "inTrash": trash})
	res.Undo = sdk.UndoWith(back, map[string]any{"page": pg.ID}, fmt.Sprintf(backDesc, title))
	return res, err
}

func (c *conn) trashBlocks(ctx context.Context, call sdk.Call, raw []string) (sdk.Result, error) {
	trash := call.Action == "trash_blocks"
	if len(raw) == 0 || len(raw) > maxBlocksPerCall {
		return sdk.Result{}, fmt.Errorf("pick 1 to %d blocks", maxBlocksPerCall)
	}
	var ids []string
	seen := map[string]bool{}
	for _, r := range raw {
		id, err := normID(r, "block")
		if err != nil {
			return sdk.Result{}, err
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	op, back, desc := "trash", "restore_blocks", "Restore %d blocks"
	if !trash {
		op, back, desc = "restore", "trash_blocks", "Trash %d blocks again"
	}
	// A child_page or child_database block is a whole page or database:
	// trashing it takes everything inside along, so it's not done here.
	blocks := map[string]block{}
	if call.DryRun || trash {
		for _, id := range ids {
			var b block
			if _, err := c.api.Do(ctx, http.MethodGet, "/blocks/"+id, nil, nil, &b); err != nil {
				return sdk.Result{}, fmt.Errorf("block %s: %w", id, err)
			}
			if trash && (b.Type == "child_page" || b.Type == "child_database") {
				return sdk.Result{}, fmt.Errorf("block %s is a whole %s, with everything in it; trash_blocks doesn't remove pages or databases (move a page to the trash with archive_page)", id, strings.TrimPrefix(b.Type, "child_"))
			}
			blocks[id] = b
		}
	}
	if call.DryRun {
		var changes []sdk.Change
		for _, id := range ids {
			b := blocks[id]
			text := []rune(b.text())
			if len(text) > 80 {
				text = append(text[:80], '…')
			}
			changes = append(changes, sdk.Change{Target: fmt.Sprintf("%s block %s %q", b.Type, id, string(text)), Op: op})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %d blocks", strings.ToUpper(op[:1])+op[1:], len(ids)), Changes: changes}}, nil
	}
	var done []string
	for _, id := range ids {
		if _, err := c.api.Do(ctx, http.MethodPatch, "/blocks/"+id, nil, map[string]any{"in_trash": trash}, nil); err != nil {
			res, _ := sdk.JSON(map[string]any{"done": done, "failed": id, "error": err.Error()})
			if len(done) > 0 {
				res.Undo = sdk.UndoWith(back, map[string]any{"blocks": done}, fmt.Sprintf(desc, len(done)))
			}
			return res, fmt.Errorf("block %s: %w", id, err)
		}
		done = append(done, id)
	}
	res, err := sdk.JSON(map[string]any{"blocks": done, "inTrash": trash})
	res.Undo = sdk.UndoWith(back, map[string]any{"blocks": done}, fmt.Sprintf(desc, len(done)))
	return res, err
}

// text builds Notion rich text from a string, in the 2000-character pieces
// the API allows.
func text(s string) []map[string]any {
	out := []map[string]any{}
	r := []rune(s)
	for len(r) > 0 {
		n := min(len(r), 2000)
		out = append(out, map[string]any{"type": "text", "text": map[string]any{"content": string(r[:n])}})
		r = r[n:]
	}
	return out
}

var (
	numberedRe = regexp.MustCompile(`^\d+[.)] `)
	codeLangs  = map[string]bool{"bash": true, "c": true, "c#": true, "c++": true, "css": true, "diff": true, "docker": true, "go": true, "graphql": true,
		"html": true, "java": true, "javascript": true, "json": true, "kotlin": true, "markdown": true, "php": true, "plain text": true, "powershell": true,
		"python": true, "ruby": true, "rust": true, "shell": true, "sql": true, "swift": true, "typescript": true, "xml": true, "yaml": true}
	langAlias = map[string]string{"sh": "shell", "js": "javascript", "ts": "typescript", "py": "python", "yml": "yaml", "md": "markdown", "golang": "go", "dockerfile": "docker", "cpp": "c++", "csharp": "c#", "text": "plain text", "txt": "plain text"}
)

func blk(typ string, body map[string]any) map[string]any {
	return map[string]any{"object": "block", "type": typ, typ: body}
}

// blocks turns simple Markdown into Notion blocks.
func blocks(md string) ([]map[string]any, error) {
	var out []map[string]any
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		switch {
		case t == "":
			continue
		case strings.HasPrefix(t, "```"):
			lang := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(t, "```")))
			if a, ok := langAlias[lang]; ok {
				lang = a
			}
			if !codeLangs[lang] {
				lang = "plain text"
			}
			var code []string
			for i++; i < len(lines) && strings.TrimSpace(lines[i]) != "```"; i++ {
				code = append(code, lines[i])
			}
			out = append(out, blk("code", map[string]any{"rich_text": text(strings.Join(code, "\n")), "language": lang}))
		case t == "---" || t == "***":
			out = append(out, blk("divider", map[string]any{}))
		case strings.HasPrefix(t, "### "):
			out = append(out, blk("heading_3", map[string]any{"rich_text": text(t[4:])}))
		case strings.HasPrefix(t, "## "):
			out = append(out, blk("heading_2", map[string]any{"rich_text": text(t[3:])}))
		case strings.HasPrefix(t, "# "):
			out = append(out, blk("heading_1", map[string]any{"rich_text": text(t[2:])}))
		case strings.HasPrefix(t, "- [ ] ") || strings.HasPrefix(t, "- [x] ") || strings.HasPrefix(t, "- [X] "):
			out = append(out, blk("to_do", map[string]any{"rich_text": text(t[6:]), "checked": t[3] != ' '}))
		case strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "* "):
			out = append(out, blk("bulleted_list_item", map[string]any{"rich_text": text(t[2:])}))
		case numberedRe.MatchString(t):
			out = append(out, blk("numbered_list_item", map[string]any{"rich_text": text(numberedRe.ReplaceAllString(t, ""))}))
		case strings.HasPrefix(t, "> "):
			out = append(out, blk("quote", map[string]any{"rich_text": text(t[2:])}))
		default:
			out = append(out, blk("paragraph", map[string]any{"rich_text": text(l)}))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("there's no content to add")
	}
	if len(out) > maxBlocksPerCall {
		return nil, fmt.Errorf("up to %d blocks at a time (this is %d)", maxBlocksPerCall, len(out))
	}
	return out, nil
}

func (c *conn) appendBlocks(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	id, err := normID(p.Page, "page")
	if err != nil {
		return sdk.Result{}, err
	}
	bs, err := blocks(p.Content)
	if err != nil {
		return sdk.Result{}, err
	}
	target := "block " + id
	var pg pageObj
	if _, err := c.api.Do(ctx, http.MethodGet, "/pages/"+id, nil, nil, &pg); err == nil {
		target = fmt.Sprintf("page %q", pg.title())
	} else if !rest.IsStatus(err, http.StatusNotFound) && !rest.IsStatus(err, http.StatusBadRequest) {
		return sdk.Result{}, err
	}
	if call.DryRun {
		var changes []sdk.Change
		for _, b := range bs {
			changes = append(changes, sdk.Change{Target: target, Op: "append " + b["type"].(string), After: mustJSON(b)})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Append %d blocks to %s", len(bs), target), Changes: changes}}, nil
	}
	var res struct {
		Results []struct {
			ID string `json:"id"`
		} `json:"results"`
	}
	if _, err := c.api.Do(ctx, http.MethodPatch, "/blocks/"+id+"/children", nil, map[string]any{"children": bs}, &res); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no page or block %s shared with the integration", id)
		}
		return sdk.Result{}, err
	}
	var ids []string
	for _, r := range res.Results {
		ids = append(ids, r.ID)
	}
	out, err := sdk.JSON(map[string]any{"page": id, "added": len(ids), "blocks": ids})
	if len(ids) > 0 {
		out.Undo = sdk.UndoWith("trash_blocks", map[string]any{"blocks": ids}, fmt.Sprintf("Remove the %d added blocks", len(ids)))
	}
	return out, err
}

// propValue converts a simple value to a Notion property value of a type.
func propValue(name, typ string, v any) (any, error) {
	str := func() (string, error) {
		switch x := v.(type) {
		case string:
			return x, nil
		case float64, bool:
			return fmt.Sprint(x), nil
		}
		return "", fmt.Errorf("%s takes text", name)
	}
	switch typ {
	case "title", "rich_text":
		s, err := str()
		if err != nil {
			return nil, err
		}
		return map[string]any{typ: text(s)}, nil
	case "number":
		if _, ok := v.(float64); !ok && v != nil {
			return nil, fmt.Errorf("%s takes a number", name)
		}
		return map[string]any{"number": v}, nil
	case "checkbox":
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("%s takes true or false", name)
		}
		return map[string]any{"checkbox": b}, nil
	case "select", "status":
		if v == nil {
			return map[string]any{typ: nil}, nil
		}
		s, err := str()
		if err != nil {
			return nil, err
		}
		return map[string]any{typ: map[string]any{"name": s}}, nil
	case "multi_select":
		var names []any
		switch x := v.(type) {
		case string:
			names = []any{x}
		case []any:
			names = x
		default:
			return nil, fmt.Errorf("%s takes a list of names", name)
		}
		opts := []map[string]any{}
		for _, n := range names {
			s, ok := n.(string)
			if !ok || strings.Contains(s, ",") {
				return nil, fmt.Errorf("%s takes names without commas", name)
			}
			opts = append(opts, map[string]any{"name": s})
		}
		return map[string]any{"multi_select": opts}, nil
	case "date":
		switch x := v.(type) {
		case nil:
			return map[string]any{"date": nil}, nil
		case string:
			return map[string]any{"date": map[string]any{"start": x}}, nil
		case map[string]any:
			if _, ok := x["start"].(string); !ok {
				return nil, fmt.Errorf("%s takes a date or {start, end}", name)
			}
			d := map[string]any{"start": x["start"]}
			if e, ok := x["end"].(string); ok {
				d["end"] = e
			}
			return map[string]any{"date": d}, nil
		}
		return nil, fmt.Errorf("%s takes a date", name)
	case "url", "email", "phone_number":
		s, err := str()
		if err != nil {
			return nil, err
		}
		return map[string]any{typ: s}, nil
	case "relation":
		var list []any
		switch x := v.(type) {
		case string:
			list = []any{x}
		case []any:
			list = x
		default:
			return nil, fmt.Errorf("%s takes page ids", name)
		}
		rel := []map[string]any{}
		for _, r := range list {
			s, _ := r.(string)
			id, err := normID(s, name+" page")
			if err != nil {
				return nil, err
			}
			rel = append(rel, map[string]any{"id": id})
		}
		return map[string]any{"relation": rel}, nil
	}
	return nil, fmt.Errorf("%s is a %s property, which this module can't set", name, typ)
}

func (c *conn) createPage(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Title == nil && len(p.Properties) == 0 {
		return sdk.Result{}, errors.New("give the page a title or property values")
	}
	if len(p.Properties) > 100 {
		return sdk.Result{}, errors.New("too many properties")
	}
	var children []map[string]any
	if strings.TrimSpace(p.Content) != "" {
		var err error
		if children, err = blocks(p.Content); err != nil {
			return sdk.Result{}, err
		}
	}
	db, src, err := c.pickSource(ctx, p)
	if err != nil {
		return sdk.Result{}, err
	}
	schema, err := c.schema(ctx, src.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	props := map[string]any{}
	titleName := ""
	for name, s := range schema {
		if s.Type == "title" {
			titleName = name
		}
	}
	for name, v := range p.Properties {
		s, ok := schema[name]
		if !ok {
			return sdk.Result{}, fmt.Errorf("the database has no property %q (see database)", name)
		}
		pv, err := propValue(name, s.Type, v)
		if err != nil {
			return sdk.Result{}, err
		}
		props[name] = pv
	}
	title := ""
	if p.Title != nil {
		if titleName == "" {
			return sdk.Result{}, errors.New("the database has no title property")
		}
		title = strings.TrimSpace(*p.Title)
		props[titleName] = map[string]any{"title": text(title)}
	} else if tv, ok := p.Properties[titleName].(string); ok {
		title = tv
	}
	body := map[string]any{"parent": map[string]any{"type": "data_source_id", "data_source_id": src.ID}, "properties": props}
	if len(children) > 0 {
		body["children"] = children
	}
	where := plain(db.Title)
	if call.DryRun {
		after := map[string]any{"properties": p.Properties, "title": title, "blocks": len(children)}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create %q in %s", title, where),
			Changes: []sdk.Change{{Target: "database " + where, Op: "create", After: mustJSON(after)}}}}, nil
	}
	var pg pageObj
	if _, err := c.api.Do(ctx, http.MethodPost, "/pages", nil, body, &pg); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"id": pg.ID, "url": pg.URL, "title": title, "database": where})
	if pg.ID != "" {
		res.Undo = sdk.UndoWith("archive_page", map[string]any{"page": pg.ID}, fmt.Sprintf("Move %q to the trash", title))
	}
	return res, err
}
