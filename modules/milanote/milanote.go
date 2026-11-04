// Package milanote reads and edits Milanote boards (notes, to-do lists,
// links, columns, nested boards) through Milanote's private web API, signed
// in like a browser. Milanote has no public API; everything that depends on
// its wire format lives in client.go.
package milanote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const moduleVersion = "0.1.0"

// Config is one Milanote account.
type Config struct {
	URL           string `json:"url"`           // default https://app.milanote.com
	Email         string `json:"email"`         // with password
	Password      string `json:"password"`      // secret://
	SessionCookie string `json:"sessionCookie"` // secret://, for Google/Apple sign-in accounts
	Timezone      string `json:"timezone"`      // IANA name for exports, default UTC
}

type conn struct{ c *client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP, when set, replaces the client built from the host (tests).
	HTTP *http.Client
	// MinInterval is the least time between two requests to Milanote
	// (default 400 ms: about as fast as a person clicks).
	MinInterval time.Duration
}

// New returns the Milanote module.
func New() *Module { return &Module{} }

var (
	idRe     = regexp.MustCompile(`^[0-9A-Za-z]{8,32}$`)
	emailRe  = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	maxItems = 50
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	board := `"board":{"type":"string","description":"Board id or board URL (app.milanote.com/1Xiq…/name)"}`
	id := `"id":{"type":"string","description":"Card id, from the board action"}`
	ids := `"ids":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":50,"description":"Card ids"}`
	return sdk.Manifest{
		ID: "milanote", Name: "Milanote", Version: moduleVersion, Category: "Productivity", Icon: "layout",
		Description: "Your Milanote boards: read them as data or Markdown, search, add notes, to-dos and links, move, archive and export. Uses Milanote's private web API.",
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"url":{"type":"string","default":"https://app.milanote.com","description":"Leave as is unless you know otherwise"},
			"email":{"type":"string","description":"Your Milanote sign-in email (with a password)"},
			"password":{"type":"string","x-secret":true,"description":"Your Milanote password, from the vault"},
			"sessionCookie":{"type":"string","x-secret":true,"description":"Instead of a password (needed for Google or Apple sign-in): the value of the __Secure-milanote.session_token cookie, from the vault"},
			"timezone":{"type":"string","description":"Time zone for exports, e.g. Europe/Berlin (default UTC)"}}}`),
		Resources: []sdk.ResourceSpec{{Kind: "board", Title: "Boards", ListAction: "boards", GetAction: "board", ViewHint: "detail"}},
		Actions: []sdk.ActionSpec{
			{Name: "boards", Title: "Boards", Description: "Your boards as a tree, from Home or from a board.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"parent":{"type":"string","description":"Board id or URL (default: Home)"},"depth":{"type":"integer","minimum":1,"maximum":4,"default":2}}}`)},
			{Name: "board", Title: "Read a board", Description: "Every card on a board as structured data and as Markdown.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["board"],"properties":{` + board + `,"format":{"type":"string","enum":["both","json","markdown"],"default":"both"}}}`)},
			{Name: "search", Title: "Search", Description: "Boards and cards matching words.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},"sort":{"type":"string","enum":["viewed","modified"],"default":"viewed"}}}`)},
			{Name: "add_note", Title: "Add a note", Description: "A note card on top of the board's Unsorted panel, or of a column.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["board","text"],"properties":{` + board + `,"text":{"type":"string","description":"Plain text; each line is a paragraph"},"column":{"type":"string","description":"Column id on that board"}}}`)},
			{Name: "add_todo", Title: "Add a to-do list", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["board","tasks"],"properties":{` + board + `,"title":{"type":"string"},"tasks":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"string"}},"column":{"type":"string"}}}`)},
			{Name: "check_todo", Title: "Tick a task", Description: "Ticks or unticks one task of a to-do list.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["board","id","task"],"properties":{` + board + `,` + id + `,"task":{"type":"string","description":"Task id or its exact text"},"done":{"type":"boolean","default":true}}}`)},
			{Name: "add_link", Title: "Add a link", Description: "A link card with Milanote's preview of the page.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["board","url"],"properties":{` + board + `,"url":{"type":"string","format":"uri"},"column":{"type":"string"}}}`)},
			{Name: "update_note", Title: "Edit a note", Description: "Replaces a note's text. Undo restores the text with its formatting.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["board","id"],"properties":{` + board + `,` + id + `,"text":{"type":"string"},"textContent":{"type":"object","description":"Milanote's rich-text document (used by undo)"}}}`)},
			{Name: "move", Title: "Move a card", Description: "To another board or into a column; lands on top of Unsorted or the column.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["board","id"],"properties":{` + board + `,` + id + `,"toBoard":{"type":"string","description":"Board id or URL (default: the same board)"},"toColumn":{"type":"string","description":"Column id on the target board"},"location":{"type":"object","description":"Exact location (used by undo)"}}}`)},
			{Name: "archive", Title: "Move to trash", Description: "What the Delete key does in Milanote: the cards go to the board's trash and can be restored.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["board","ids"],"properties":{` + board + `,` + ids + `}}`)},
			{Name: "restore", Title: "Restore from trash", Description: "Puts trashed cards back where they were.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["ids"],"properties":{` + ids + `}}`)},
			{Name: "delete", Title: "Delete for good", Description: "Removes cards that are already in the trash, permanently. Archive them first. Can't be undone.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["ids"],"properties":{` + ids + `}}`)},
			{Name: "export", Title: "Export as Markdown", Description: "A board as Markdown, rendered by Conduit or by Milanote's own export.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["board"],"properties":{` + board + `,"via":{"type":"string","enum":["conduit","milanote"],"default":"conduit"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.URL == "" {
		c.URL = defaultBase
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.URL), "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Path != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname()))) {
		return errors.New("the address is like https://app.milanote.com")
	}
	hasPW := c.Email != "" || c.Password != ""
	if c.SessionCookie == "" && !hasPW {
		return errors.New("enter your email and password, or a session cookie (for Google or Apple sign-in)")
	}
	if hasPW {
		if !emailRe.MatchString(strings.TrimSpace(c.Email)) {
			return errors.New("enter the email you sign in to Milanote with")
		}
		if !strings.HasPrefix(c.Password, "secret://") {
			return errors.New("store the password in the vault and enter its secret:// reference")
		}
	}
	if c.SessionCookie != "" && !strings.HasPrefix(c.SessionCookie, "secret://") {
		return errors.New("store the session cookie in the vault and enter its secret:// reference")
	}
	tz := "UTC"
	if c.Timezone != "" {
		if _, err := time.LoadLocation(c.Timezone); err != nil {
			return errors.New("the time zone is like Europe/Berlin")
		}
		tz = c.Timezone
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 40*time.Second) // a long poll is held up to ~25 s
	}
	cp := *hc
	cp.Jar = nil // cookies are kept in memory by the client, for this host only
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	gap := m.MinInterval
	if gap == 0 {
		gap = 400 * time.Millisecond
	}
	cl := &client{base: u, http: &cp, gap: gap, tz: tz}
	if hasPW {
		email, ref := strings.TrimSpace(c.Email), c.Password
		cl.creds = func(ctx context.Context) (string, string, error) {
			pw, err := h.Secret(ctx, ref)
			return email, pw, err
		}
	}
	if c.SessionCookie != "" {
		ref := c.SessionCookie
		cl.cookie = func(ctx context.Context) (string, error) { return h.Secret(ctx, ref) }
	}
	m.set.Put(id, &conn{c: cl})
	return nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	cn, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	u, err := cn.c.me(ctx)
	switch {
	case err == nil:
		who := u.Name
		if who == "" {
			who = u.Email
		}
		return sdk.Health{Status: "ok", Message: "Signed in as " + who + " (Milanote web API " + WireVersion + ")"}
	case errors.Is(err, errLimited):
		return sdk.Health{Status: "degraded", Message: err.Error()}
	}
	// errSignIn, errCookieDead, errBlocked and errChanged all say what to do.
	return sdk.Health{Status: "down", Message: err.Error()}
}

// input is every action's parameters.
type input struct {
	Board       string          `json:"board"`
	Parent      string          `json:"parent"`
	Depth       int             `json:"depth"`
	Format      string          `json:"format"`
	Query       string          `json:"query"`
	Sort        string          `json:"sort"`
	ID          string          `json:"id"`
	IDs         []string        `json:"ids"`
	Text        *string         `json:"text"`
	TextContent json.RawMessage `json:"textContent"`
	Title       string          `json:"title"`
	Tasks       []string        `json:"tasks"`
	Task        string          `json:"task"`
	Done        *bool           `json:"done"`
	URL         string          `json:"url"`
	Column      string          `json:"column"`
	ToBoard     string          `json:"toBoard"`
	ToColumn    string          `json:"toColumn"`
	Location    json.RawMessage `json:"location"`
	Via         string          `json:"via"`
}

// boardID accepts a board id or a board URL.
func boardID(v, field string) (string, error) {
	v = strings.TrimSpace(v)
	if idRe.MatchString(v) {
		return v, nil
	}
	if u, err := url.Parse(v); err == nil && strings.HasSuffix(strings.ToLower(u.Hostname()), "milanote.com") {
		for _, seg := range strings.Split(strings.Trim(u.Path, "/"), "/") {
			if idRe.MatchString(seg) && len(seg) >= 12 {
				return seg, nil
			}
		}
	}
	return "", fmt.Errorf("%s must be a board id or a Milanote board URL", field)
}

func cardID(v string) (string, error) {
	v = strings.TrimSpace(v)
	if !idRe.MatchString(v) {
		return "", errors.New("give the card's id, from the board action")
	}
	return v, nil
}

func cardIDs(vs []string) ([]string, error) {
	if len(vs) == 0 || len(vs) > maxItems {
		return nil, fmt.Errorf("give 1 to %d card ids", maxItems)
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range vs {
		id, err := cardID(v)
		if err != nil {
			return nil, err
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

func find(b *Board, id string) (Element, error) {
	for _, e := range b.Children {
		if e.ID == id {
			return e, nil
		}
	}
	return Element{}, fmt.Errorf("%s isn't a card on %q", id, b.Self.Title)
}

// destination is the top of Unsorted, or of a column on that board.
func destination(b *Board, column string) (json.RawMessage, error) {
	if column == "" {
		return topOf(b, b.Self.ID), nil
	}
	col, err := find(b, strings.TrimSpace(column))
	if err != nil || col.Kind != "column" {
		return nil, fmt.Errorf("%s isn't a column on %q", column, b.Self.Title)
	}
	return topOf(b, col.ID), nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	cn, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	c := cn.c
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	loadArg := func() (*Board, error) {
		id, err := boardID(p.Board, "board")
		if err != nil {
			return nil, err
		}
		return c.loadBoard(ctx, id)
	}

	switch call.Action {
	case "boards":
		return m.boards(ctx, c, p)

	case "board":
		b, err := loadArg()
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"id": b.Self.ID, "title": b.Self.Title, "url": c.boardURL(b.Self.ID)}
		if p.Format != "markdown" {
			out["elements"] = elementsOut(c, b.Children)
		}
		if p.Format != "json" {
			out["markdown"] = renderMarkdown(c, b)
		}
		return sdk.JSON(out)

	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" || len(q) > 200 {
			return sdk.Result{}, errors.New("give some words to search for")
		}
		sortBy := p.Sort
		if sortBy == "" {
			sortBy = "viewed"
		}
		if sortBy != "viewed" && sortBy != "modified" {
			return sdk.Result{}, errors.New("sort is viewed or modified")
		}
		total, hits, err := c.search(ctx, q, sortBy)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"total": total, "results": hits})

	case "add_note", "add_todo", "add_link":
		b, err := loadArg()
		if err != nil {
			return sdk.Result{}, err
		}
		loc, err := destination(b, p.Column)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"board": b.Self.ID, "url": c.boardURL(b.Self.ID)}
		var made string
		switch call.Action {
		case "add_note":
			if p.Text == nil || strings.TrimSpace(*p.Text) == "" {
				return sdk.Result{}, errors.New("the note needs text")
			}
			err = c.write(ctx, func(s *syncConn) (err error) {
				made, err = s.create(ctx, "CARD", loc, noteContent(*p.Text))
				return err
			})
			out["text"] = *p.Text
		case "add_todo":
			var items []string
			for _, t := range p.Tasks {
				if t = strings.TrimSpace(t); t != "" {
					items = append(items, t)
				}
			}
			if len(items) == 0 || len(items) > 100 {
				return sdk.Result{}, errors.New("give 1 to 100 tasks")
			}
			content, tasks := todoContent(strings.TrimSpace(p.Title), items)
			err = c.write(ctx, func(s *syncConn) (err error) {
				made, err = s.create(ctx, "TASK_LIST", loc, content)
				return err
			})
			out["title"], out["tasks"] = p.Title, tasks
		case "add_link":
			lu, perr := url.Parse(strings.TrimSpace(p.URL))
			if perr != nil || (lu.Scheme != "http" && lu.Scheme != "https") || lu.Host == "" {
				return sdk.Result{}, errors.New("the link starts with http:// or https://")
			}
			var title string
			err = c.write(ctx, func(s *syncConn) (err error) {
				made, title, err = s.addLink(ctx, b.Self.ID, loc, lu.String())
				return err
			})
			out["link"], out["title"] = lu.String(), title
		}
		if made != "" {
			out["id"] = made
		}
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(out)
		r.Undo = sdk.UndoWith("archive", map[string]any{"board": b.Self.ID, "ids": []string{made}}, "Move the new card to the trash")
		return r, nil

	case "check_todo":
		b, err := loadArg()
		if err != nil {
			return sdk.Result{}, err
		}
		id, err := cardID(p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		e, err := find(b, id)
		if err != nil {
			return sdk.Result{}, err
		}
		task := strings.TrimSpace(p.Task)
		if task == "" {
			return sdk.Result{}, errors.New("give the task's id or its text")
		}
		done := p.Done == nil || *p.Done
		changes, was, err := checkTask(e, task, done)
		if err != nil {
			return sdk.Result{}, err
		}
		if err := c.write(ctx, func(s *syncConn) error { return s.update(ctx, b.Self.ID, e.ID, changes) }); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"board": b.Self.ID, "id": e.ID, "task": was.ID, "text": was.Text, "done": done})
		ref := was.ID
		if ref == "" {
			ref = was.Text
		}
		r.Undo = sdk.UndoWith("check_todo", map[string]any{"board": b.Self.ID, "id": e.ID, "task": ref, "done": was.Done}, "Set "+quote(was.Text)+" back")
		return r, nil

	case "update_note":
		b, err := loadArg()
		if err != nil {
			return sdk.Result{}, err
		}
		id, err := cardID(p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		e, err := find(b, id)
		if err != nil {
			return sdk.Result{}, err
		}
		if e.WireType != "CARD" {
			return sdk.Result{}, errors.New("that card isn't a note")
		}
		var changes map[string]any
		after := ""
		switch {
		case len(p.TextContent) > 0:
			var probe struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(p.TextContent, &probe) != nil || probe.Type != "doc" {
				return sdk.Result{}, errors.New("textContent must be a Milanote document")
			}
			changes, after = noteChanges("", p.TextContent), renderRich(p.TextContent, false)
		case p.Text != nil && strings.TrimSpace(*p.Text) != "":
			changes, after = noteChanges(*p.Text, nil), *p.Text
		default:
			return sdk.Result{}, errors.New("give the note's new text")
		}
		if call.DryRun {
			bj, _ := json.Marshal(e.Text)
			aj, _ := json.Marshal(after)
			return sdk.Result{Plan: &sdk.Plan{Summary: "Edit a note on " + quote(b.Self.Title),
				Changes: []sdk.Change{{Target: e.ID, Op: "update", Before: bj, After: aj}}}}, nil
		}
		old := noteDoc(e)
		if err := c.write(ctx, func(s *syncConn) error { return s.update(ctx, b.Self.ID, e.ID, changes) }); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"board": b.Self.ID, "id": e.ID, "text": after})
		undo := map[string]any{"board": b.Self.ID, "id": e.ID}
		if len(old) > 0 && string(old) != "null" {
			undo["textContent"] = old
		} else {
			undo["text"] = e.Text
		}
		r.Undo = sdk.UndoWith("update_note", undo, "Restore the note's earlier text")
		return r, nil

	case "move":
		b, err := loadArg()
		if err != nil {
			return sdk.Result{}, err
		}
		id, err := cardID(p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		e, err := find(b, id)
		if err != nil {
			return sdk.Result{}, err
		}
		var to json.RawMessage
		target := b
		if len(p.Location) > 0 {
			parent := locationParent(p.Location)
			if !idRe.MatchString(parent) {
				return sdk.Result{}, errors.New("location needs a parentId")
			}
			if parent == e.ID {
				return sdk.Result{}, errors.New("a card can't move into itself")
			}
			to = p.Location
		} else {
			if p.ToBoard != "" {
				tid, err := boardID(p.ToBoard, "toBoard")
				if err != nil {
					return sdk.Result{}, err
				}
				if tid == e.ID {
					return sdk.Result{}, errors.New("a board can't move into itself")
				}
				if tid != b.Self.ID {
					if target, err = c.loadBoard(ctx, tid); err != nil {
						return sdk.Result{}, err
					}
				}
			}
			if p.ToColumn == e.ID {
				return sdk.Result{}, errors.New("a column can't move into itself")
			}
			if to, err = destination(target, p.ToColumn); err != nil {
				return sdk.Result{}, err
			}
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]string{"board": b.Self.Title, "column": columnTitle(b, e.Column)})
			after, _ := json.Marshal(map[string]string{"board": target.Self.Title, "column": columnTitle(target, p.ToColumn)})
			return sdk.Result{Plan: &sdk.Plan{Summary: "Move " + describe(e) + " to " + quote(target.Self.Title),
				Changes: []sdk.Change{{Target: e.ID, Op: "move", Before: before, After: after}}}}, nil
		}
		if err := c.write(ctx, func(s *syncConn) error { return s.move(ctx, []Move{fromHere(e, to)}, "DROP") }); err != nil {
			return sdk.Result{}, err
		}
		dest := strings.TrimSuffix(locationParent(to), "-trash")
		r, _ := sdk.JSON(map[string]any{"id": e.ID, "from": b.Self.ID, "to": dest})
		if len(p.Location) == 0 {
			// The card now sits on the target board (or one of its columns); undo finds it there
			// and puts it back at its exact old position.
			r.Undo = sdk.UndoWith("move", map[string]any{"board": target.Self.ID, "id": e.ID, "location": e.location}, "Move "+describe(e)+" back")
		}
		return r, nil

	case "archive":
		b, err := loadArg()
		if err != nil {
			return sdk.Result{}, err
		}
		ids, err := cardIDs(p.IDs)
		if err != nil {
			return sdk.Result{}, err
		}
		var els []Element
		var moves []Move
		var changes []sdk.Change
		for _, id := range ids {
			e, err := find(b, id)
			if err != nil {
				return sdk.Result{}, err
			}
			els = append(els, e)
			moves = append(moves, trashMove(e))
			before, _ := json.Marshal(elementOut(c, e))
			changes = append(changes, sdk.Change{Target: e.ID, Op: "trash", Before: before})
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Move %d card(s) on %s to the trash (restorable)", len(els), quote(b.Self.Title)), Changes: changes}}, nil
		}
		if err := c.write(ctx, func(s *syncConn) error { return s.move(ctx, moves, "TRASH") }); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"board": b.Self.ID, "trashed": ids})
		r.Undo = sdk.UndoWith("restore", map[string]any{"ids": ids}, fmt.Sprintf("Restore %d card(s)", len(ids)))
		return r, nil

	case "restore", "delete":
		ids, err := cardIDs(p.IDs)
		if err != nil {
			return sdk.Result{}, err
		}
		trash, err := c.trash(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var els []Element
		var changes []sdk.Change
		for _, id := range ids {
			e, ok := trash[id]
			if !ok {
				if call.Action == "delete" {
					return sdk.Result{}, fmt.Errorf("%s isn't in the trash; archive it first, then delete it", id)
				}
				return sdk.Result{}, fmt.Errorf("%s isn't in the trash", id)
			}
			els = append(els, e)
			before, _ := json.Marshal(elementOut(c, e))
			changes = append(changes, sdk.Change{Target: e.ID, Op: call.Action, Before: before})
		}
		if call.Action == "restore" {
			var moves []Move
			for _, e := range els {
				back, err := restoreTarget(e)
				if err != nil {
					return sdk.Result{}, err
				}
				moves = append(moves, fromHere(e, back))
			}
			if err := c.write(ctx, func(s *syncConn) error { return s.move(ctx, moves, "DROP") }); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"restored": ids})
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete %d card(s) from the trash for good", len(els)), Changes: changes}}, nil
		}
		var gone []string
		err = c.write(ctx, func(s *syncConn) error {
			for _, e := range els {
				if err := s.deleteForever(ctx, e); err != nil {
					return err
				}
				gone = append(gone, e.ID)
			}
			return nil
		})
		if err != nil {
			if len(gone) > 0 {
				return sdk.Result{}, fmt.Errorf("deleted %s, then: %w", strings.Join(gone, ", "), err)
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": gone})

	case "export":
		id, err := boardID(p.Board, "board")
		if err != nil {
			return sdk.Result{}, err
		}
		switch p.Via {
		case "", "conduit":
			b, err := c.loadBoard(ctx, id)
			if err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"board": id, "title": b.Self.Title, "via": "conduit", "markdown": renderMarkdown(c, b)})
		case "milanote":
			file, md, err := c.exportMarkdown(ctx, id)
			if err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"board": id, "via": "milanote", "markdown": md, "fileUrl": file})
		}
		return sdk.Result{}, errors.New("via is conduit or milanote")
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type boardNode struct {
	ID       string       `json:"id"`
	Title    string       `json:"title"`
	URL      string       `json:"url"`
	Section  string       `json:"section,omitempty"`
	Shortcut bool         `json:"shortcut,omitempty"`
	Boards   []*boardNode `json:"boards,omitempty"`
}

// maxLoads caps how many boards one tree walk opens, to stay polite.
const maxLoads = 40

func (m *Module) boards(ctx context.Context, c *client, p input) (sdk.Result, error) {
	root := ""
	if p.Parent != "" {
		var err error
		if root, err = boardID(p.Parent, "parent"); err != nil {
			return sdk.Result{}, err
		}
	} else {
		u, err := c.currentUser(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		root = u.RootBoard
	}
	depth := p.Depth
	if depth <= 0 {
		depth = 2
	}
	depth = min(depth, 4)
	loads, truncated := 0, false
	var walk func(id string, level int) (*boardNode, error)
	walk = func(id string, level int) (*boardNode, error) {
		loads++
		b, err := c.loadBoard(ctx, id)
		if err != nil {
			return nil, err
		}
		n := &boardNode{ID: id, Title: b.Self.Title, URL: c.boardURL(id)}
		for _, e := range b.Children {
			if e.Kind != "board" {
				continue
			}
			child := &boardNode{ID: e.ID, Title: e.Title, URL: c.boardURL(e.ID), Section: e.Section, Shortcut: e.WireType == "ALIAS"}
			if level+1 < depth && !child.Shortcut {
				if loads >= maxLoads {
					truncated = true
				} else if sub, err := walk(e.ID, level+1); err == nil {
					sub.Section = child.Section
					child = sub
				} else if !errors.Is(err, errNotFound) && !strings.Contains(err.Error(), "can't open") {
					return nil, err
				}
			}
			n.Boards = append(n.Boards, child)
		}
		return n, nil
	}
	tree, err := walk(root, 0)
	if err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"root": tree, "truncated": truncated})
}

type elementJSON struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Section string `json:"section"`
	Column  string `json:"column,omitempty"`
	Title   string `json:"title,omitempty"`
	Text    string `json:"text,omitempty"`
	URL     string `json:"url,omitempty"`
	Tasks   []Task `json:"tasks,omitempty"`
	Done    *bool  `json:"done,omitempty"`
	Updated string `json:"updated,omitempty"`
}

func elementOut(c *client, e Element) elementJSON {
	o := elementJSON{ID: e.ID, Type: e.Kind, Section: e.Section, Column: e.Column, Title: e.Title, Text: e.Text, URL: e.URL, Tasks: e.Tasks}
	if e.Column != "" {
		o.Section = "column"
	}
	if e.Kind == "board" && e.WireType == "BOARD" {
		o.URL = c.boardURL(e.ID)
	}
	if e.Kind == "task" {
		d := e.Done
		o.Done = &d
	}
	if !e.Modified.IsZero() {
		o.Updated = e.Modified.Format(time.RFC3339)
	}
	return o
}

func elementsOut(c *client, es []Element) []elementJSON {
	out := make([]elementJSON, 0, len(es))
	for _, e := range es {
		out = append(out, elementOut(c, e))
	}
	return out
}

// renderMarkdown writes a board as Markdown: the canvas in reading order,
// then each column, then the Unsorted panel.
func renderMarkdown(c *client, b *Board) string {
	var sb strings.Builder
	sb.WriteString("# " + oneLine(b.Self.Title) + "\n")
	var canvas, unsorted, columns []Element
	inCol := map[string][]Element{}
	for _, e := range b.Children {
		switch {
		case e.Column != "":
			inCol[e.Column] = append(inCol[e.Column], e)
		case e.Kind == "column":
			columns = append(columns, e)
		case e.Section == "unsorted":
			unsorted = append(unsorted, e)
		default:
			canvas = append(canvas, e)
		}
	}
	write := func(es []Element) {
		for _, e := range es {
			if t := mdElement(c, e); t != "" {
				sb.WriteString("\n" + t + "\n")
			}
		}
	}
	write(canvas)
	for _, col := range columns {
		title := col.Title
		if title == "" {
			title = "Column"
		}
		sb.WriteString("\n## " + oneLine(title) + "\n")
		write(inCol[col.ID])
	}
	if len(unsorted) > 0 {
		sb.WriteString("\n## Unsorted\n")
		write(unsorted)
	}
	return sb.String()
}

func mdElement(c *client, e Element) string {
	switch e.Kind {
	case "note", "document", "annotation":
		return e.Markdown
	case "link":
		t := e.Title
		if t == "" {
			t = e.URL
		}
		s := "- [" + oneLine(t) + "](" + e.URL + ")"
		if e.Text != "" {
			s += " — " + oneLine(e.Text)
		}
		return s
	case "todo":
		var lines []string
		if e.Title != "" {
			lines = append(lines, "**"+oneLine(e.Title)+"**", "")
		}
		for _, t := range e.Tasks {
			box := "[ ]"
			if t.Done {
				box = "[x]"
			}
			lines = append(lines, "- "+box+" "+oneLine(t.Text))
		}
		return strings.Join(lines, "\n")
	case "board":
		if e.WireType == "ALIAS" {
			return "- Board shortcut: " + oneLine(e.Title)
		}
		return "- Board: [" + oneLine(e.Title) + "](" + c.boardURL(e.ID) + ")"
	case "image":
		return "![" + oneLine(e.Title) + "](" + e.URL + ")"
	case "file":
		if e.URL != "" {
			return "- File: [" + oneLine(e.Title) + "](" + e.URL + ")"
		}
		return "- File: " + oneLine(e.Title)
	case "comment", "column":
		return ""
	}
	return e.Markdown
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func quote(s string) string {
	s = oneLine(s)
	if len(s) > 60 {
		s = s[:57] + "..."
	}
	return "“" + s + "”"
}

func describe(e Element) string {
	label := e.Title
	if label == "" {
		label = e.Text
	}
	if label == "" {
		return "the " + e.Kind
	}
	return "the " + e.Kind + " " + quote(label)
}

func columnTitle(b *Board, col string) string {
	if col == "" {
		return ""
	}
	if e, ok := b.All[col]; ok {
		return e.Title
	}
	return col
}
