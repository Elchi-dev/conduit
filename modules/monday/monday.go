// Package monday works with monday.com through its GraphQL API and a personal
// API token: boards, items and their column values, creating items, changing
// a column's value, and posting updates on items.
package monday

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/mention"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one monday.com account.
type Config struct {
	Token string `json:"token"` // secret:// personal API token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.monday.com/v2 (tests).
	Base string
}

// New returns the monday.com module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://api.monday.com/v2"
	maxName     = 255
	maxValue    = 2000
	maxUpdate   = 20000
)

var (
	idRe     = regexp.MustCompile(`^\d{1,20}$`)
	columnRe = regexp.MustCompile(`^[a-z0-9_]{1,100}$`)
	dateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// personal column types hold someone's contact details: they're left out
// of answers and not changed from here.
var personal = map[string]bool{"email": true, "phone": true}

// readOnly column types are computed or need more than a simple value.
var readOnly = map[string]bool{
	"auto_number": true, "board_relation": true, "button": true, "creation_log": true, "dependency": true, "doc": true,
	"file": true, "formula": true, "integration": true, "item_id": true, "last_updated": true, "mirror": true,
	"progress": true, "subtasks": true, "time_tracking": true, "vote": true, "subitems": true,
}

// roundTrip column types take back the text they show, so a change to one
// can be undone by setting the old text again.
var roundTrip = map[string]bool{"text": true, "long_text": true, "numbers": true, "status": true, "dropdown": true, "date": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	item := `"item":{"type":"string","description":"Item id (from items)"}`
	return sdk.Manifest{
		ID: "monday", Name: "monday.com", Version: "0.1.0", Category: "Productivity", Icon: "layout",
		Description: "monday.com: boards and items with their column values; create items, change a column's value and post updates.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A personal API token (your avatar, Developers, My access tokens). It acts as you"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "boards", Title: "Boards", Description: "Active boards you can see, with their workspace and item count.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":50,"maximum":200}}}`)},
			{Name: "items", Title: "Items", Description: "Items on a board with their group and column values; pass the cursor from one page to get the next.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"board":{"type":"string","description":"Board id"},"cursor":{"type":"string","description":"From the previous page"},"limit":{"type":"integer","default":50,"maximum":100}}}`)},
			{Name: "item", Title: "Item details", Description: "Every column (with its id, for change_column_value) and the latest updates.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["item"],"properties":{` + item + `}}`)},
			{Name: "create_item", Title: "Create an item", Description: "Adds an item to a board, optionally in a group and with column values. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["board","name"],"properties":{"board":{"type":"string","description":"Board id"},"name":{"type":"string","maxLength":255},
					"group":{"type":"string","description":"Group id; the board's first group when empty"},
					"columns":{"type":"object","additionalProperties":{"type":"string"},"description":"Column id to value, as you'd type it: {\"status\":\"Working on it\",\"date4\":\"2026-12-01\"}"}}}`)},
			{Name: "change_column_value", Title: "Change a column's value", Description: "Sets one column of an item to a value as you'd type it (a status label, a date, a number, text). Undo puts the old value back for text, number, status, dropdown and date columns.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["item","column","value"],"properties":{` + item + `,"column":{"type":"string","description":"Column id (from item)"},"value":{"type":"string","description":"The new value; empty clears it"}}}`)},
			{Name: "add_update", Title: "Post an update", Description: "Posts an update (a comment) on an item; its subscribers are notified as usual. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["item","text"],"properties":{` + item + `,"text":{"type":"string","x-multiline":true}}}`)},
			{Name: "delete_update", Title: "Delete an update", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["update"],"properties":{"update":{"type":"string","description":"Update id"}}}`)},
			{Name: "delete_item", Title: "Delete an item", Description: "Moves the item to monday.com's trash.", Risk: sdk.RiskDestructive, DryRun: true,
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
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
		r.Header.Set("Authorization", strings.TrimSpace(t))
		return nil
	})
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

// gql runs one GraphQL operation. Values only ever travel in vars.
func (c *conn) gql(ctx context.Context, query string, vars map[string]any, out any) error {
	var res struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
		ErrorMessage string `json:"error_message"`
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "", nil, map[string]any{"query": query, "variables": vars}, &res); err != nil {
		switch {
		case rest.IsStatus(err, http.StatusUnauthorized):
			return errors.New("monday.com refused the API token")
		case rest.IsStatus(err, http.StatusForbidden):
			return errors.New("your monday.com account isn't allowed to do this")
		case rest.IsStatus(err, http.StatusTooManyRequests):
			return errors.New("monday.com's rate limit was reached; try again in a minute")
		}
		return err
	}
	if len(res.Errors) > 0 {
		return errors.New("monday.com: " + rest.Redact(res.Errors[0].Message))
	}
	if res.ErrorMessage != "" {
		if strings.Contains(strings.ToLower(res.ErrorMessage), "not authenticated") {
			return errors.New("monday.com refused the API token")
		}
		return errors.New("monday.com: " + rest.Redact(res.ErrorMessage))
	}
	if out != nil && len(res.Data) > 0 {
		if err := json.Unmarshal(res.Data, out); err != nil {
			return errors.New("unexpected answer from monday.com")
		}
	}
	return nil
}

type column struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Text   string `json:"text"`
	Column struct {
		Title string `json:"title"`
	} `json:"column"`
}

type item struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	State     string   `json:"state"`
	URL       string   `json:"url"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
	Board     *named   `json:"board"`
	Group     *grp     `json:"group"`
	Columns   []column `json:"column_values"`
	Updates   []struct {
		ID        string `json:"id"`
		TextBody  string `json:"text_body"`
		CreatedAt string `json:"created_at"`
		Creator   *named `json:"creator"`
	} `json:"updates"`
}

type named struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type grp struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

const columnFields = `column_values { id type text column { title } }`
const itemFields = `id name state url updated_at group { id title } ` + columnFields

func summary(i item) map[string]any {
	cols := map[string]string{}
	for _, c := range i.Columns {
		if personal[c.Type] || c.Text == "" {
			continue
		}
		cols[c.Column.Title] = c.Text
	}
	out := map[string]any{"id": i.ID, "name": i.Name, "columns": cols, "url": i.URL}
	if i.Group != nil {
		out["group"] = i.Group.Title
	}
	if i.State != "" && i.State != "active" {
		out["state"] = i.State
	}
	if i.UpdatedAt != "" {
		out["updated"] = i.UpdatedAt
	}
	return out
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var d struct {
		Me struct {
			Name    string `json:"name"`
			Account struct {
				Name string `json:"name"`
			} `json:"account"`
		} `json:"me"`
	}
	if err := c.gql(ctx, `query { me { name account { name } } }`, nil, &d); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + d.Me.Name + " in " + d.Me.Account.Name}
}

type input struct {
	Board   string            `json:"board"`
	Cursor  string            `json:"cursor"`
	Limit   int               `json:"limit"`
	Item    string            `json:"item"`
	Name    string            `json:"name"`
	Group   string            `json:"group"`
	Columns map[string]string `json:"columns"`
	Column  string            `json:"column"`
	Value   *string           `json:"value"`
	Text    string            `json:"text"`
	Update  string            `json:"update"`
}

func need(id, what string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("the %s is its numeric id", what)
	}
	return nil
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
	p.Board, p.Item, p.Update, p.Column, p.Group = strings.TrimSpace(p.Board), strings.TrimSpace(p.Item), strings.TrimSpace(p.Update), strings.TrimSpace(p.Column), strings.TrimSpace(p.Group)
	switch call.Action {
	case "boards":
		limit := p.Limit
		if limit <= 0 || limit > 200 {
			limit = 50
		}
		var d struct {
			Boards []struct {
				named
				Kind       string `json:"board_kind"`
				ItemsCount int    `json:"items_count"`
				URL        string `json:"url"`
				Workspace  *named `json:"workspace"`
			} `json:"boards"`
		}
		q := `query($limit: Int!) { boards(limit: $limit, state: active, order_by: used_at) { id name board_kind items_count url workspace { id name } } }`
		if err := c.gql(ctx, q, map[string]any{"limit": limit}, &d); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, b := range d.Boards {
			r := map[string]any{"id": b.ID, "name": b.Name, "kind": b.Kind, "items": b.ItemsCount, "url": b.URL}
			if b.Workspace != nil {
				r["workspace"] = b.Workspace.Name
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "items":
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 50
		}
		type page struct {
			Cursor *string `json:"cursor"`
			Items  []item  `json:"items"`
		}
		var pg page
		board := ""
		if p.Cursor != "" {
			if len(p.Cursor) > 2000 || strings.ContainsAny(p.Cursor, " \r\n\t") {
				return sdk.Result{}, errors.New("the cursor is the one the previous page returned")
			}
			var d struct {
				Next page `json:"next_items_page"`
			}
			q := `query($cursor: String!, $limit: Int!) { next_items_page(cursor: $cursor, limit: $limit) { cursor items { ` + itemFields + ` } } }`
			if err := c.gql(ctx, q, map[string]any{"cursor": p.Cursor, "limit": limit}, &d); err != nil {
				return sdk.Result{}, err
			}
			pg = d.Next
		} else {
			if err := need(p.Board, "board"); err != nil {
				return sdk.Result{}, err
			}
			var d struct {
				Boards []struct {
					Name  string `json:"name"`
					Items page   `json:"items_page"`
				} `json:"boards"`
			}
			q := `query($board: [ID!], $limit: Int!) { boards(ids: $board) { name items_page(limit: $limit) { cursor items { ` + itemFields + ` } } } }`
			if err := c.gql(ctx, q, map[string]any{"board": []string{p.Board}, "limit": limit}, &d); err != nil {
				return sdk.Result{}, err
			}
			if len(d.Boards) == 0 {
				return sdk.Result{}, fmt.Errorf("there's no board %s", p.Board)
			}
			pg, board = d.Boards[0].Items, d.Boards[0].Name
		}
		out := []map[string]any{}
		for _, i := range pg.Items {
			out = append(out, summary(i))
		}
		res := map[string]any{"count": len(out), "items": out}
		if board != "" {
			res["board"] = board
		}
		if pg.Cursor != nil && *pg.Cursor != "" {
			res["cursor"] = *pg.Cursor
		}
		return sdk.JSON(res)

	case "item":
		i, err := c.item(ctx, p.Item, true)
		if err != nil {
			return sdk.Result{}, err
		}
		out := summary(i)
		cols := []map[string]string{}
		for _, x := range i.Columns {
			r := map[string]string{"id": x.ID, "title": x.Column.Title, "type": x.Type}
			if !personal[x.Type] {
				r["text"] = x.Text
			}
			cols = append(cols, r)
		}
		out["columns"] = cols
		if i.Board != nil {
			out["board"] = i.Board.Name
			out["boardId"] = i.Board.ID
		}
		out["created"] = i.CreatedAt
		ups := []map[string]any{}
		for _, u := range i.Updates {
			r := map[string]any{"id": u.ID, "at": u.CreatedAt, "text": u.TextBody}
			if u.Creator != nil {
				r["by"] = u.Creator.Name
			}
			ups = append(ups, r)
		}
		out["updates"] = ups
		return sdk.JSON(out)

	case "create_item":
		return c.create(ctx, call, p)
	case "change_column_value":
		return c.change(ctx, call, p)
	case "add_update":
		return c.addUpdate(ctx, call, p)

	case "delete_update":
		if err := need(p.Update, "update"); err != nil {
			return sdk.Result{}, err
		}
		var d struct {
			Delete *named `json:"delete_update"`
		}
		if err := c.gql(ctx, `mutation($id: ID!) { delete_update(id: $id) { id } }`, map[string]any{"id": p.Update}, &d); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.Update})

	case "delete_item":
		i, err := c.item(ctx, p.Item, false)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete item %q", i.Name),
				Changes: []sdk.Change{{Target: target(i), Op: "delete", Before: mustJSON(summary(i))}}}}, nil
		}
		if err := c.gql(ctx, `mutation($id: ID!) { delete_item(item_id: $id) { id } }`, map[string]any{"id": i.ID}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": i.ID, "name": i.Name})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func target(i item) string {
	t := fmt.Sprintf("item %s %q", i.ID, i.Name)
	if i.Board != nil {
		t += " on " + i.Board.Name
	}
	return t
}

func (c *conn) item(ctx context.Context, id string, updates bool) (item, error) {
	if err := need(id, "item"); err != nil {
		return item{}, err
	}
	q := `query($ids: [ID!]) { items(ids: $ids) { ` + itemFields + ` created_at board { id name } } }`
	if updates {
		q = `query($ids: [ID!]) { items(ids: $ids) { ` + itemFields + ` created_at board { id name } updates(limit: 20) { id text_body created_at creator { id name } } } }`
	}
	var d struct {
		Items []item `json:"items"`
	}
	if err := c.gql(ctx, q, map[string]any{"ids": []string{id}}, &d); err != nil {
		return item{}, err
	}
	if len(d.Items) == 0 {
		return item{}, fmt.Errorf("there's no item %s", id)
	}
	if d.Items[0].ID != id {
		// The id goes into the change and its undo.
		return item{}, fmt.Errorf("monday.com answered with another item for %s", id)
	}
	return d.Items[0], nil
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if err := need(p.Board, "board"); err != nil {
		return sdk.Result{}, err
	}
	name := strings.TrimSpace(p.Name)
	if name == "" || len(name) > maxName {
		return sdk.Result{}, fmt.Errorf("an item name is 1 to %d characters", maxName)
	}
	if p.Group != "" && !columnRe.MatchString(p.Group) {
		return sdk.Result{}, errors.New("the group is its id, like topics or new_group12345")
	}
	if len(p.Columns) > 50 {
		return sdk.Result{}, errors.New("up to 50 columns")
	}
	for k, v := range p.Columns {
		if !columnRe.MatchString(k) {
			return sdk.Result{}, fmt.Errorf("%q isn't a column id (see item)", k)
		}
		if len(v) > maxValue {
			return sdk.Result{}, fmt.Errorf("the value for %s is too long", k)
		}
	}
	var d struct {
		Boards []struct {
			Name    string `json:"name"`
			Columns []struct {
				ID    string `json:"id"`
				Title string `json:"title"`
				Type  string `json:"type"`
			} `json:"columns"`
			Groups []grp `json:"groups"`
		} `json:"boards"`
	}
	if err := c.gql(ctx, `query($board: [ID!]) { boards(ids: $board) { name columns { id title type } groups { id title } } }`, map[string]any{"board": []string{p.Board}}, &d); err != nil {
		return sdk.Result{}, err
	}
	if len(d.Boards) == 0 {
		return sdk.Result{}, fmt.Errorf("there's no board %s", p.Board)
	}
	b := d.Boards[0]
	where := b.Name
	if p.Group != "" {
		found := false
		for _, g := range b.Groups {
			if g.ID == p.Group {
				found, where = true, b.Name+", "+g.Title
			}
		}
		if !found {
			return sdk.Result{}, fmt.Errorf("board %s has no group %s", b.Name, p.Group)
		}
	}
	types := map[string]string{}
	for _, col := range b.Columns {
		types[col.ID] = col.Type
	}
	for k := range p.Columns {
		t, ok := types[k]
		switch {
		case !ok:
			return sdk.Result{}, fmt.Errorf("board %s has no column %s", b.Name, k)
		case personal[t]:
			return sdk.Result{}, fmt.Errorf("%s is a %s column; Conduit doesn't fill in contact details", k, t)
		case readOnly[t]:
			return sdk.Result{}, fmt.Errorf("%s is a %s column, which can't be set with a simple value", k, t)
		}
	}
	vars := map[string]any{"board": p.Board, "name": name, "group": nil, "values": nil}
	if p.Group != "" {
		vars["group"] = p.Group
	}
	if len(p.Columns) > 0 {
		vars["values"] = string(mustJSON(p.Columns))
	}
	if call.DryRun {
		after := map[string]any{"name": name}
		if len(p.Columns) > 0 {
			after["columns"] = p.Columns
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create item %q on %s", name, where),
			Changes: []sdk.Change{{Target: "item on " + where, Op: "create", After: mustJSON(after)}}}}, nil
	}
	var r struct {
		Create named `json:"create_item"`
	}
	q := `mutation($board: ID!, $name: String!, $group: String, $values: JSON) { create_item(board_id: $board, item_name: $name, group_id: $group, column_values: $values) { id name } }`
	if err := c.gql(ctx, q, vars, &r); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]string{"item": r.Create.ID, "name": r.Create.Name, "board": b.Name})
	if idRe.MatchString(r.Create.ID) {
		res.Undo = sdk.UndoWith("delete_item", map[string]string{"item": r.Create.ID}, fmt.Sprintf("Delete item %q", name))
	}
	return res, err
}

func (c *conn) change(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if err := need(p.Item, "item"); err != nil {
		return sdk.Result{}, err
	}
	if !columnRe.MatchString(p.Column) {
		return sdk.Result{}, errors.New("the column is its id (see item)")
	}
	if p.Value == nil {
		return sdk.Result{}, errors.New("give the new value (empty clears it)")
	}
	value := strings.TrimSpace(*p.Value)
	if len(value) > maxValue {
		return sdk.Result{}, errors.New("the value is too long")
	}
	i, err := c.item(ctx, p.Item, false)
	if err != nil {
		return sdk.Result{}, err
	}
	var col *column
	for k := range i.Columns {
		if i.Columns[k].ID == p.Column {
			col = &i.Columns[k]
		}
	}
	switch {
	case col == nil:
		return sdk.Result{}, fmt.Errorf("item %s has no column %s", i.ID, p.Column)
	case personal[col.Type]:
		return sdk.Result{}, fmt.Errorf("%s is a %s column; Conduit doesn't change contact details", col.Column.Title, col.Type)
	case readOnly[col.Type]:
		return sdk.Result{}, fmt.Errorf("%s is a %s column, which can't be set with a simple value", col.Column.Title, col.Type)
	case i.Board == nil || !idRe.MatchString(i.Board.ID):
		return sdk.Result{}, errors.New("monday.com didn't say which board the item is on")
	}
	if col.Text == value {
		return sdk.JSON(map[string]any{"item": i.ID, "column": col.Column.Title, "value": value, "note": "nothing to change"})
	}
	tgt := fmt.Sprintf("%s of %s", col.Column.Title, target(i))
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Set %s of %q to %q", col.Column.Title, i.Name, value),
			Changes: []sdk.Change{{Target: tgt, Op: "update", Before: mustJSON(col.Text), After: mustJSON(value)}}}}, nil
	}
	q := `mutation($board: ID!, $item: ID!, $column: String!, $value: String!) { change_simple_column_value(board_id: $board, item_id: $item, column_id: $column, value: $value) { id } }`
	if err := c.gql(ctx, q, map[string]any{"board": i.Board.ID, "item": i.ID, "column": col.ID, "value": value}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"item": i.ID, "column": col.Column.Title, "from": col.Text, "to": value})
	if roundTrip[col.Type] && (col.Type != "date" || col.Text == "" || dateRe.MatchString(col.Text)) {
		res.Undo = sdk.UndoWith("change_column_value", map[string]string{"item": i.ID, "column": col.ID, "value": col.Text},
			fmt.Sprintf("Set %s back to %q", col.Column.Title, col.Text))
	}
	return res, err
}

func (c *conn) addUpdate(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if err := need(p.Item, "item"); err != nil {
		return sdk.Result{}, err
	}
	text := strings.TrimSpace(p.Text)
	if text == "" || len(text) > maxUpdate {
		return sdk.Result{}, fmt.Errorf("an update is 1 to %d characters", maxUpdate)
	}
	if f := mention.Find(text); f.Wildcard != "" {
		return sdk.Result{}, fmt.Errorf("%s would reach everyone; wildcard mentions aren't sent from Conduit", f.Wildcard)
	}
	i, err := c.item(ctx, p.Item, false)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Post an update on %q", i.Name),
			Changes: []sdk.Change{{Target: target(i), Op: "create", After: mustJSON(map[string]string{"text": text})}}}}, nil
	}
	// The body is HTML: the text is escaped, so it can't carry markup or
	// mention tags.
	body := strings.ReplaceAll(html.EscapeString(text), "\n", "<br>")
	var r struct {
		Create named `json:"create_update"`
	}
	if err := c.gql(ctx, `mutation($item: ID!, $body: String!) { create_update(item_id: $item, body: $body) { id } }`, map[string]any{"item": i.ID, "body": body}, &r); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]string{"item": i.ID, "update": r.Create.ID})
	if idRe.MatchString(r.Create.ID) {
		res.Undo = sdk.UndoWith("delete_update", map[string]string{"update": r.Create.ID}, "Delete the update")
	}
	return res, err
}
