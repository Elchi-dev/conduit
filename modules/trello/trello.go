// Package trello works with Trello boards through an API key and token:
// boards, lists and cards (search, due soon), and adding, moving, commenting
// on and archiving cards.
package trello

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
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Trello account.
type Config struct {
	Key   string `json:"key"`   // API key, plain or secret://
	Token string `json:"token"` // secret:// API token
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.trello.com/1 (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Trello module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.trello.com/1"

var (
	// Boards and cards have a 24-hex id and an 8-character short link; lists
	// only the id.
	objRe  = regexp.MustCompile(`^(?:[0-9a-fA-F]{24}|[A-Za-z0-9]{8})$`)
	listRe = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)
	// https://trello.com/b/AbCd1234/name or /c/AbCd1234/12-name
	linkRe = regexp.MustCompile(`^https://trello\.com/[bc]/([A-Za-z0-9]{8})(?:/.*)?$`)
	keyRe  = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
)

// objID accepts an id, a short link or a Trello link to a board or card.
func objID(s, what string) (string, error) {
	s = strings.TrimSpace(s)
	if m := linkRe.FindStringSubmatch(s); m != nil {
		return m[1], nil
	}
	if !objRe.MatchString(s) {
		return "", fmt.Errorf("the %s is its id, short link or trello.com link", what)
	}
	return s, nil
}

func listID(s string) (string, error) {
	if !listRe.MatchString(strings.TrimSpace(s)) {
		return "", errors.New("the list is a list id (24 hex characters, see lists)")
	}
	return strings.TrimSpace(s), nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	card := `"card":{"type":"string","description":"Card id, short link or trello.com/c/… link"}`
	board := `"board":{"type":"string","description":"Board id, short link or trello.com/b/… link"}`
	list := `"list":{"type":"string","description":"List id (see lists)"}`
	pos := `"position":{"description":"top, bottom or a number","oneOf":[{"type":"string","enum":["top","bottom"]},{"type":"number","minimum":0}]}`
	return sdk.Manifest{
		ID: "trello", Name: "Trello", Version: "0.1.0", Category: "Productivity", Icon: "layout",
		Description: "Trello boards, lists and cards: search, see what's due, add, move, comment on and archive cards.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key","token"],"properties":{
			"key":{"type":"string","description":"API key of your Power-Up (trello.com/power-ups/admin, API key); it may be a secret:// reference"},
			"token":{"type":"string","x-secret":true,"description":"API token generated for that key; it acts as you on every board you can see"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "boards", Title: "Boards", Description: "Your open boards.", Risk: sdk.RiskRead},
			{Name: "lists", Title: "Lists", Description: "A board's open lists, in order.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["board"],"properties":{` + board + `}}`)},
			{Name: "cards", Title: "Cards", Description: "Open cards on a board or in a list.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + board + `,` + list + `,"limit":{"type":"integer","default":100,"maximum":500}}}`)},
			{Name: "search", Title: "Search cards", Description: "Trello search over cards (operators like board:, list:, label:, due:week work).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},"limit":{"type":"integer","default":25,"maximum":100}}}`)},
			{Name: "due_soon", Title: "Due soon", Description: "Unfinished cards due in the next days, overdue ones first, on one board or all open boards.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + board + `,"days":{"type":"integer","default":7,"minimum":1,"maximum":90}}}`)},
			{Name: "card", Title: "Card details", Description: "A card with its description, list, board, labels and due date.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["card"],"properties":{` + card + `}}`)},
			{Name: "add_card", Title: "Add a card", Description: "Adds a card to a list. Undo archives it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["list","name"],"properties":{` + list + `,"name":{"type":"string"},"description":{"type":"string"},"due":{"type":"string","description":"RFC 3339 time or YYYY-MM-DD"},` + pos + `}}`)},
			{Name: "move_card", Title: "Move a card", Description: "Moves a card to another list (on any board you can see). Undo moves it back where it was.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["card","list"],"properties":{` + card + `,` + list + `,` + pos + `}}`)},
			{Name: "comment", Title: "Comment on a card", Description: "Adds a comment as you; everyone on the board sees it.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["card","text"],"properties":{` + card + `,"text":{"type":"string","maxLength":16384}}}`)},
			{Name: "archive_card", Title: "Archive a card", Description: "Archives (closes) a card; it keeps its comments and can come back. Undo unarchives it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["card"],"properties":{` + card + `}}`)},
			{Name: "unarchive_card", Title: "Unarchive a card", Description: "Sends an archived card back to its list. Undo archives it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["card"],"properties":{` + card + `}}`)},
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
	key := strings.TrimSpace(c.Key)
	if !strings.HasPrefix(key, "secret://") && !keyRe.MatchString(key) {
		return errors.New("the API key is 32 hex characters (or a secret:// reference to it)")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	tok := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k := key
		if strings.HasPrefix(k, "secret://") {
			v, err := h.Secret(ctx, k)
			if err != nil {
				return err
			}
			k = strings.TrimSpace(v)
		}
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		// In a header rather than ?key=&token=, so neither ends up in
		// a proxy's or server's access log.
		r.Header.Set("Authorization", fmt.Sprintf(`OAuth oauth_consumer_key="%s", oauth_token="%s"`, k, strings.TrimSpace(t)))
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

func (m *Module) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
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
	if _, err := c.api.Do(ctx, http.MethodGet, "/members/me", url.Values{"fields": {"username,fullName"}}, nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "Trello refused the key or token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + me.Username}
}

type label struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

type card struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Desc        string  `json:"desc"`
	IDList      string  `json:"idList"`
	IDBoard     string  `json:"idBoard"`
	Due         *string `json:"due"`
	DueComplete bool    `json:"dueComplete"`
	Closed      bool    `json:"closed"`
	URL         string  `json:"shortUrl"`
	Pos         pos     `json:"pos"`
	Labels      []label `json:"labels"`
	LastActive  string  `json:"dateLastActivity"`
	List        *struct {
		Name string `json:"name"`
	} `json:"list"`
	Board *struct {
		Name string `json:"name"`
	} `json:"board"`
}

const cardFields = "name,idList,idBoard,due,dueComplete,closed,shortUrl,pos,labels,dateLastActivity"

type list struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IDBoard string `json:"idBoard"`
	Closed  bool   `json:"closed"`
	Pos     pos    `json:"pos"`
}

// pos is a card or list position; anything but a number reads as 0.
type pos float64

func (p *pos) UnmarshalJSON(b []byte) error {
	var f float64
	if json.Unmarshal(b, &f) == nil {
		*p = pos(f)
	}
	return nil
}

func cardOut(c card, lists map[string]string) map[string]any {
	ls := []string{}
	for _, l := range c.Labels {
		if l.Name != "" {
			ls = append(ls, l.Name)
		} else if l.Color != "" {
			ls = append(ls, l.Color)
		}
	}
	out := map[string]any{"id": c.ID, "name": c.Name, "listId": c.IDList, "labels": ls, "url": c.URL}
	if n, ok := lists[c.IDList]; ok {
		out["list"] = n
	}
	if c.Due != nil {
		out["due"], out["dueComplete"] = *c.Due, c.DueComplete
	}
	if c.Closed {
		out["archived"] = true
	}
	return out
}

func (c *conn) listNames(ctx context.Context, board string) (map[string]string, error) {
	var ls []list
	if _, err := c.api.Do(ctx, http.MethodGet, "/boards/"+board+"/lists", url.Values{"filter": {"all"}, "fields": {"name"}}, nil, &ls); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, l := range ls {
		out[l.ID] = l.Name
	}
	return out, nil
}

func (c *conn) getCard(ctx context.Context, raw string) (card, error) {
	var k card
	id, err := objID(raw, "card")
	if err != nil {
		return k, err
	}
	q := url.Values{"fields": {cardFields + ",desc"}, "list": {"true"}, "list_fields": {"name"}, "board": {"true"}, "board_fields": {"name"}}
	if _, err := c.api.Do(ctx, http.MethodGet, "/cards/"+id, q, nil, &k); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
			return k, fmt.Errorf("there's no card %s (or the token can't see it)", id)
		}
		return k, err
	}
	return k, nil
}

func (c *conn) getList(ctx context.Context, id string) (list, error) {
	var l list
	if _, err := c.api.Do(ctx, http.MethodGet, "/lists/"+id, url.Values{"fields": {"name,idBoard,closed"}}, nil, &l); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
			return l, fmt.Errorf("there's no list %s (or the token can't see it)", id)
		}
		return l, err
	}
	if l.Closed {
		return l, fmt.Errorf("the list %q is archived", l.Name)
	}
	return l, nil
}

type input struct {
	Board       string          `json:"board"`
	List        string          `json:"list"`
	Card        string          `json:"card"`
	Query       string          `json:"query"`
	Limit       int             `json:"limit"`
	Days        int             `json:"days"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Due         string          `json:"due"`
	Text        string          `json:"text"`
	Position    json.RawMessage `json:"position"`
}

// position checks top / bottom / a number; def when absent.
func position(raw json.RawMessage, def string) (any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return def, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s == "top" || s == "bottom" {
			return s, nil
		}
		return nil, errors.New("the position is top, bottom or a number")
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil || f < 0 {
		return nil, errors.New("the position is top, bottom or a number")
	}
	return f, nil
}

func dueTime(s string) (string, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.Add(12 * time.Hour).Format(time.RFC3339), nil
	}
	return "", errors.New("the due date is an RFC 3339 time (2026-11-10T17:00:00+01:00) or a date (2026-11-10)")
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
	case "boards":
		var bs []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			URL        string `json:"shortUrl"`
			LastActive string `json:"dateLastActivity"`
			Starred    bool   `json:"starred"`
		}
		q := url.Values{"filter": {"open"}, "fields": {"name,shortUrl,dateLastActivity,starred"}}
		if _, err := c.api.Do(ctx, http.MethodGet, "/members/me/boards", q, nil, &bs); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, b := range bs {
			out = append(out, map[string]any{"id": b.ID, "name": b.Name, "url": b.URL, "lastActivity": b.LastActive, "starred": b.Starred})
		}
		return sdk.JSON(out)

	case "lists":
		b, err := objID(p.Board, "board")
		if err != nil {
			return sdk.Result{}, err
		}
		var ls []list
		if _, err := c.api.Do(ctx, http.MethodGet, "/boards/"+b+"/lists", url.Values{"filter": {"open"}, "fields": {"name,pos"}}, nil, &ls); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, l := range ls {
			out = append(out, map[string]any{"id": l.ID, "name": l.Name})
		}
		return sdk.JSON(out)

	case "cards":
		limit := p.Limit
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		var cs []card
		var names map[string]string
		q := url.Values{"fields": {cardFields}}
		switch {
		case p.List != "":
			l, err := listID(p.List)
			if err != nil {
				return sdk.Result{}, err
			}
			if _, err := c.api.Do(ctx, http.MethodGet, "/lists/"+l+"/cards", q, nil, &cs); err != nil {
				return sdk.Result{}, err
			}
		case p.Board != "":
			b, err := objID(p.Board, "board")
			if err != nil {
				return sdk.Result{}, err
			}
			if _, err := c.api.Do(ctx, http.MethodGet, "/boards/"+b+"/cards/open", q, nil, &cs); err != nil {
				return sdk.Result{}, err
			}
			if names, err = c.listNames(ctx, b); err != nil {
				return sdk.Result{}, err
			}
		default:
			return sdk.Result{}, errors.New("pick a board or a list")
		}
		out := []map[string]any{}
		for _, k := range cs {
			if len(out) == limit {
				break
			}
			out = append(out, cardOut(k, names))
		}
		return sdk.JSON(map[string]any{"total": len(cs), "cards": out})

	case "search":
		qs := strings.TrimSpace(p.Query)
		if qs == "" || len(qs) > 16384 {
			return sdk.Result{}, errors.New("enter what to search for")
		}
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 25
		}
		var res struct {
			Cards []card `json:"cards"`
		}
		q := url.Values{"query": {qs}, "modelTypes": {"cards"}, "cards_limit": {strconv.Itoa(limit)}, "card_fields": {cardFields},
			"card_board": {"true"}, "board_fields": {"name"}, "card_list": {"true"}, "partial": {"true"}}
		if _, err := c.api.Do(ctx, http.MethodGet, "/search", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, k := range res.Cards {
			o := cardOut(k, nil)
			if k.Board != nil {
				o["board"] = k.Board.Name
			}
			if k.List != nil {
				o["list"] = k.List.Name
			}
			out = append(out, o)
		}
		return sdk.JSON(out)

	case "due_soon":
		return m.dueSoon(ctx, c, p)

	case "card":
		k, err := c.getCard(ctx, p.Card)
		if err != nil {
			return sdk.Result{}, err
		}
		out := cardOut(k, nil)
		out["description"] = k.Desc
		out["lastActivity"] = k.LastActive
		if k.List != nil {
			out["list"] = k.List.Name
		}
		if k.Board != nil {
			out["board"], out["boardId"] = k.Board.Name, k.IDBoard
		}
		return sdk.JSON(out)

	case "add_card":
		return c.addCard(ctx, call, p)
	case "move_card":
		return c.moveCard(ctx, call, p)
	case "comment":
		text := strings.TrimSpace(p.Text)
		if text == "" || len(p.Text) > 16384 {
			return sdk.Result{}, errors.New("the comment is 1 to 16384 characters")
		}
		k, err := c.getCard(ctx, p.Card)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Comment on %q", k.Name),
				Changes: []sdk.Change{{Target: fmt.Sprintf("card %q", k.Name), Op: "comment", After: mustJSON(text)}}}}, nil
		}
		var a struct {
			ID string `json:"id"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/cards/"+k.ID+"/actions/comments", nil, map[string]any{"text": text}, &a); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"card": k.ID, "comment": a.ID, "url": k.URL})
	case "archive_card", "unarchive_card":
		return c.archive(ctx, call, p.Card)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (m *Module) dueSoon(ctx context.Context, c *conn, p input) (sdk.Result, error) {
	days := p.Days
	if days <= 0 || days > 90 {
		days = 7
	}
	now := m.now()
	until := now.Add(time.Duration(days) * 24 * time.Hour)
	type withBoard struct {
		card
		board string
	}
	var found []withBoard
	if p.Board != "" {
		b, err := objID(p.Board, "board")
		if err != nil {
			return sdk.Result{}, err
		}
		var bd struct {
			Name  string `json:"name"`
			Cards []card `json:"cards"`
		}
		q := url.Values{"fields": {"name"}, "cards": {"open"}, "card_fields": {cardFields}}
		if _, err := c.api.Do(ctx, http.MethodGet, "/boards/"+b, q, nil, &bd); err != nil {
			return sdk.Result{}, err
		}
		for _, k := range bd.Cards {
			found = append(found, withBoard{k, bd.Name})
		}
	} else {
		var bs []struct {
			Name  string `json:"name"`
			Cards []card `json:"cards"`
		}
		q := url.Values{"filter": {"open"}, "fields": {"name"}, "cards": {"open"}, "card_fields": {cardFields}}
		if _, err := c.api.Do(ctx, http.MethodGet, "/members/me/boards", q, nil, &bs); err != nil {
			return sdk.Result{}, err
		}
		for _, b := range bs {
			for _, k := range b.Cards {
				found = append(found, withBoard{k, b.Name})
			}
		}
	}
	type hit struct {
		at  time.Time
		out map[string]any
	}
	var hits []hit
	for _, k := range found {
		if k.Due == nil || k.DueComplete || k.Closed {
			continue
		}
		at, err := time.Parse(time.RFC3339, *k.Due)
		if err != nil || at.After(until) {
			continue
		}
		o := cardOut(k.card, nil)
		o["board"] = k.board
		if at.Before(now) {
			o["overdue"] = true
		}
		hits = append(hits, hit{at, o})
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].at.Before(hits[j].at) })
	out := []map[string]any{}
	for _, h := range hits {
		if len(out) == 200 {
			break
		}
		out = append(out, h.out)
	}
	return sdk.JSON(map[string]any{"days": days, "cards": out})
}

func (c *conn) addCard(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	l, err := listID(p.List)
	if err != nil {
		return sdk.Result{}, err
	}
	name := strings.TrimSpace(p.Name)
	if name == "" || len(name) > 16384 {
		return sdk.Result{}, errors.New("the card needs a name")
	}
	if len(p.Description) > 16384 {
		return sdk.Result{}, errors.New("the description is up to 16384 characters")
	}
	pos, err := position(p.Position, "bottom")
	if err != nil {
		return sdk.Result{}, err
	}
	body := map[string]any{"idList": l, "name": name, "pos": pos}
	if p.Description != "" {
		body["desc"] = p.Description
	}
	if p.Due != "" {
		d, err := dueTime(p.Due)
		if err != nil {
			return sdk.Result{}, err
		}
		body["due"] = d
	}
	lst, err := c.getList(ctx, l)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add card %q to %s", name, lst.Name),
			Changes: []sdk.Change{{Target: "list " + lst.Name, Op: "create", After: mustJSON(body)}}}}, nil
	}
	var k card
	if _, err := c.api.Do(ctx, http.MethodPost, "/cards", nil, body, &k); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(cardOut(k, map[string]string{l: lst.Name}))
	if k.ID != "" {
		res.Undo = sdk.UndoWith("archive_card", map[string]any{"card": k.ID}, fmt.Sprintf("Archive card %q", name))
	}
	return res, err
}

func (c *conn) moveCard(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	l, err := listID(p.List)
	if err != nil {
		return sdk.Result{}, err
	}
	pos, err := position(p.Position, "top")
	if err != nil {
		return sdk.Result{}, err
	}
	k, err := c.getCard(ctx, p.Card)
	if err != nil {
		return sdk.Result{}, err
	}
	to, err := c.getList(ctx, l)
	if err != nil {
		return sdk.Result{}, err
	}
	from := k.IDList
	fromName := from
	if k.List != nil {
		fromName = k.List.Name
	}
	if from == l && len(p.Position) == 0 {
		return sdk.JSON(map[string]any{"card": k.ID, "note": "the card is already in " + to.Name})
	}
	body := map[string]any{"idList": l, "pos": pos}
	if to.IDBoard != "" && to.IDBoard != k.IDBoard {
		body["idBoard"] = to.IDBoard
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Move %q from %s to %s", k.Name, fromName, to.Name),
			Changes: []sdk.Change{{Target: fmt.Sprintf("card %q", k.Name), Op: "move", Before: mustJSON(map[string]any{"list": fromName, "board": boardName(k)}), After: mustJSON(map[string]any{"list": to.Name, "position": pos})}}}}, nil
	}
	var after card
	if _, err := c.api.Do(ctx, http.MethodPut, "/cards/"+k.ID, nil, body, &after); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"card": k.ID, "from": fromName, "to": to.Name, "url": k.URL})
	res.Undo = sdk.UndoWith("move_card", map[string]any{"card": k.ID, "list": from, "position": float64(k.Pos)}, fmt.Sprintf("Move %q back to %s", k.Name, fromName))
	return res, err
}

func boardName(k card) string {
	if k.Board != nil {
		return k.Board.Name
	}
	return k.IDBoard
}

func (c *conn) archive(ctx context.Context, call sdk.Call, raw string) (sdk.Result, error) {
	archiving := call.Action == "archive_card"
	k, err := c.getCard(ctx, raw)
	if err != nil {
		return sdk.Result{}, err
	}
	if k.Closed == archiving {
		state := "open"
		if k.Closed {
			state = "archived"
		}
		return sdk.JSON(map[string]any{"card": k.ID, "note": "the card is already " + state})
	}
	verb, back, backVerb := "Archive", "unarchive_card", "Unarchive"
	if !archiving {
		verb, back, backVerb = "Unarchive", "archive_card", "Archive"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s card %q", verb, k.Name),
			Changes: []sdk.Change{{Target: fmt.Sprintf("card %q on %s", k.Name, boardName(k)), Op: strings.ToLower(verb)}}}}, nil
	}
	if _, err := c.api.Do(ctx, http.MethodPut, "/cards/"+k.ID, nil, map[string]any{"closed": archiving}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"card": k.ID, "name": k.Name, "archived": archiving})
	res.Undo = sdk.UndoWith(back, map[string]any{"card": k.ID}, fmt.Sprintf("%s card %q", backVerb, k.Name))
	return res, err
}
