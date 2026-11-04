// Package freshdesk works with Freshdesk through its REST API v2 with an
// agent's API key: ticket lists and search, one ticket with its
// conversation, private notes (undo deletes them), public replies to the
// requester, status changes and assignment.
//
// A public reply emails the customer and can't be unsent, so it's
// destructive. Ticket contents (subjects, requesters, conversations) are
// personal data, so the actions that return them are sensitive.
package freshdesk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Freshdesk helpdesk.
type Config struct {
	Domain string `json:"domain"` // acme for acme.freshdesk.com
	APIKey string `json:"apiKey"` // secret:// the agent's API key
}

type conn struct {
	api  *rest.Client
	site string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://<domain>.freshdesk.com (tests).
	Base string
}

// New returns the Freshdesk module.
func New() *Module { return &Module{} }

var (
	subRe  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	idRe   = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	ctrlRe = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
)

const maxText = 20000

var (
	statusName = map[int]string{2: "open", 3: "pending", 4: "resolved", 5: "closed"}
	statusCode = map[string]int{"open": 2, "pending": 3, "resolved": 4, "closed": 5}
	priority   = map[int]string{1: "low", 2: "medium", 3: "high", 4: "urgent"}
)

func status(n int) string {
	if s, ok := statusName[n]; ok {
		return s
	}
	return "status " + strconv.Itoa(n) // a custom status
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	tk := `"ticket":{"type":["string","integer"],"description":"Ticket number, e.g. 1234"}`
	text := `"text":{"type":"string","format":"textarea","maxLength":20000}`
	return sdk.Manifest{
		ID: "freshdesk", Name: "Freshdesk", Version: "0.1.0", Category: "Communication", Icon: "headset",
		Description: "Freshdesk: ticket lists and search, a ticket with its conversation, private notes, public replies (destructive: they email the customer), status and assignment.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["domain","apiKey"],"properties":{
			"domain":{"type":"string","description":"Your Freshdesk domain: acme for acme.freshdesk.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"An agent's API key (Profile settings, View API key)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "tickets", Title: "Tickets", Description: "Unresolved tickets (open or pending), new and my open ones, watched ones, or the latest, most recently updated first: number, subject, status, priority, assignee.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"filter":{"type":"string","enum":["unresolved","new_and_my_open","watching","recent"],"default":"unresolved"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "search", Title: "Search tickets", Description: "Freshdesk's query language, e.g. priority:4 AND status:2, or tag:'billing'.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string","maxLength":500}}}`)},
			{Name: "ticket", Title: "Open a ticket", Description: "A ticket with requester, assignee, tags and its latest conversation entries, public and private.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket"],"properties":{` + tk + `,"conversations":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "agents", Title: "Agents", Description: "Agents with their id and name, to assign tickets to.", Risk: sdk.RiskRead},
			{Name: "add_note", Title: "Add a private note", Description: "A note only agents see; the requester isn't notified. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket","text"],"properties":{` + tk + `,` + text + `}}`)},
			{Name: "delete_note", Title: "Delete a private note", Description: "Deletes one private note, for good. Only private notes: replies and customer messages are refused. The preview quotes the note.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket","note"],"properties":{` + tk + `,"note":{"type":["string","integer"],"description":"The note's id"}}}`)},
			{Name: "reply", Title: "Reply to the requester", Description: "A public reply, emailed to the requester. It can't be unsent, so it's destructive. The preview shows who gets it and the text.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket","text"],"properties":{` + tk + `,` + text + `}}`)},
			{Name: "set_status", Title: "Set the status", Description: "Open or pending (also reopens a resolved or closed ticket). Resolving and closing are resolve. Undo sets the status it had.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket","status"],"properties":{` + tk + `,"status":{"type":"string","enum":["open","pending"]}}}`)},
			{Name: "resolve", Title: "Resolve or close a ticket", Description: "Sets a ticket resolved (default) or closed. Freshdesk's automations may email the requester (a satisfaction survey or a resolution notice), which can't be unsent, so it's destructive. Undo sets the status it had.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket"],"properties":{` + tk + `,"status":{"type":"string","enum":["resolved","closed"],"default":"resolved"}}}`)},
			{Name: "assign", Title: "Assign a ticket", Description: "To an agent (id from agents), or unassign it. Undo gives it back to whoever had it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket"],"properties":{` + tk + `,"assignee":{"type":["string","integer"],"description":"Agent id"},"unassign":{"type":"boolean"}}}`)},
		},
	}
}

// domain accepts acme, acme.freshdesk.com or https://acme.freshdesk.com.
func domain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".freshdesk.com")
	if !subRe.MatchString(s) {
		return "", errors.New("the domain is the first part of your Freshdesk address: acme for acme.freshdesk.com")
	}
	return s, nil
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	d, err := domain(c.Domain)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	site := "https://" + d + ".freshdesk.com"
	if m.Base != "" {
		site = strings.TrimRight(m.Base, "/")
	}
	ref := c.APIKey
	api := rest.New(site+"/api/v2", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(k)+":X")))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, site: site})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Freshdesk refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Freshdesk refused: this agent can't do that")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusBadRequest):
		return fmt.Errorf("Freshdesk refused the request: %v", err)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Freshdesk's rate limit was hit; try again in a minute")
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me agent
	if _, err := c.api.Do(ctx, http.MethodGet, "/agents/me", nil, nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "Freshdesk API here").Error()}
	}
	return sdk.Health{Status: "ok", Message: "Signed in as " + clip(me.Contact.Name, 80)}
}

type flexID string

func (f *flexID) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*f = flexID(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "#")))
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return errors.New("an id is a number")
	}
	*f = flexID(n.String())
	return nil
}

type input struct {
	Ticket        flexID `json:"ticket"`
	Note          flexID `json:"note"`
	Filter        string `json:"filter"`
	Limit         int    `json:"limit"`
	Conversations int    `json:"conversations"`
	Query         string `json:"query"`
	Text          string `json:"text"`
	Status        string `json:"status"`
	Assignee      flexID `json:"assignee"`
	Unassign      bool   `json:"unassign"`
}

type ticket struct {
	ID          int64    `json:"id"`
	Subject     string   `json:"subject"`
	Status      int      `json:"status"`
	Priority    int      `json:"priority"`
	Type        *string  `json:"type"`
	RequesterID int64    `json:"requester_id"`
	ResponderID *int64   `json:"responder_id"`
	GroupID     *int64   `json:"group_id"`
	Tags        []string `json:"tags"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	Description string   `json:"description_text"`
	Requester   *struct {
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"requester"`
}

type agent struct {
	ID      int64 `json:"id"`
	Contact struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"contact"`
}

type conversation struct {
	ID        int64  `json:"id"`
	BodyText  string `json:"body_text"`
	Incoming  bool   `json:"incoming"`
	Private   bool   `json:"private"`
	Source    int    `json:"source"` // 0 reply, 2 note, ...
	UserID    int64  `json:"user_id"`
	CreatedAt string `json:"created_at"`
	FromEmail string `json:"from_email"`
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func limit(n, def int) (int, error) {
	if n == 0 {
		return def, nil
	}
	if n < 1 || n > 100 {
		return 0, errors.New("the limit is 1 to 100")
	}
	return n, nil
}

func text(s string) (string, error) {
	t := strings.TrimSpace(s)
	switch {
	case t == "":
		return "", errors.New("the text is empty")
	case utf8.RuneCountInString(t) > maxText:
		return "", fmt.Errorf("the text is at most %d characters", maxText)
	case !utf8.ValidString(t) || ctrlRe.MatchString(t):
		return "", errors.New("the text has control characters")
	}
	return t, nil
}

// htmlBody turns plain text into the HTML body Freshdesk takes, escaped.
func htmlBody(t string) string {
	t = strings.ReplaceAll(t, "\r\n", "\n")
	return strings.ReplaceAll(html.EscapeString(t), "\n", "<br>")
}

func (c *conn) summary(t ticket) map[string]any {
	o := map[string]any{"ticket": t.ID, "subject": clip(t.Subject, 200), "status": status(t.Status), "updated": t.UpdatedAt, "url": c.site + "/a/tickets/" + strconv.FormatInt(t.ID, 10)}
	if p, ok := priority[t.Priority]; ok {
		o["priority"] = p
	}
	if t.ResponderID != nil {
		o["assigneeId"] = *t.ResponderID
	} else {
		o["assigneeId"] = nil
	}
	return o
}

func (c *conn) getTicket(ctx context.Context, id string) (ticket, error) {
	var t ticket
	if _, err := c.api.Do(ctx, http.MethodGet, "/tickets/"+id, url.Values{"include": {"requester"}}, nil, &t); err != nil {
		return ticket{}, friendly(err, "ticket #"+id)
	}
	return t, nil
}

func (c *conn) conversations(ctx context.Context, id string) ([]conversation, error) {
	var cs []conversation
	if _, err := c.api.Do(ctx, http.MethodGet, "/tickets/"+id+"/conversations", url.Values{"per_page": {"100"}}, nil, &cs); err != nil {
		return nil, friendly(err, "ticket #"+id)
	}
	return cs, nil
}

func (c *conn) agentName(ctx context.Context, id *int64) string {
	if id == nil {
		return "nobody"
	}
	var a agent
	if _, err := c.api.Do(ctx, http.MethodGet, "/agents/"+strconv.FormatInt(*id, 10), nil, nil, &a); err != nil || a.Contact.Name == "" {
		return "agent " + strconv.FormatInt(*id, 10)
	}
	return clip(a.Contact.Name, 80)
}

func (c *conn) update(ctx context.Context, id string, fields map[string]any) (ticket, error) {
	var t ticket
	if _, err := c.api.Do(ctx, http.MethodPut, "/tickets/"+id, nil, fields, &t); err != nil {
		return ticket{}, friendly(err, "ticket #"+id)
	}
	return t, nil
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
	tid := string(p.Ticket)
	switch call.Action {
	case "tickets", "search", "agents":
	default:
		if !idRe.MatchString(tid) {
			return sdk.Result{}, errors.New("the ticket is its number, e.g. 1234")
		}
	}
	switch call.Action {
	case "tickets", "search":
		n, err := limit(p.Limit, 25)
		if err != nil {
			return sdk.Result{}, err
		}
		var list []ticket
		query := ""
		switch {
		case call.Action == "search":
			query = strings.TrimSpace(p.Query)
			if query == "" || utf8.RuneCountInString(query) > 500 || ctrlRe.MatchString(query) || strings.ContainsAny(query, "\"\r\n\t") {
				return sdk.Result{}, errors.New("the query is 1 to 500 characters on one line, with 'single quotes' around text values")
			}
		case p.Filter == "" || p.Filter == "unresolved":
			query = "status:2 OR status:3"
		case p.Filter == "new_and_my_open" || p.Filter == "watching" || p.Filter == "recent":
		default:
			return sdk.Result{}, errors.New("the filter is unresolved, new_and_my_open, watching or recent")
		}
		if query != "" {
			var a struct {
				Results []ticket `json:"results"`
			}
			if _, err := c.api.Do(ctx, http.MethodGet, "/search/tickets", url.Values{"query": {`"` + query + `"`}}, nil, &a); err != nil {
				return sdk.Result{}, friendly(err, "search here")
			}
			list = a.Results
		} else {
			q := url.Values{"per_page": {strconv.Itoa(n)}, "order_by": {"updated_at"}, "order_type": {"desc"}}
			if p.Filter != "recent" {
				q.Set("filter", p.Filter)
			}
			if _, err := c.api.Do(ctx, http.MethodGet, "/tickets", q, nil, &list); err != nil {
				return sdk.Result{}, friendly(err, "ticket list")
			}
		}
		out := []map[string]any{}
		for i, t := range list {
			if i >= n {
				break
			}
			out = append(out, c.summary(t))
		}
		return sdk.JSON(out)

	case "ticket":
		n, err := limit(p.Conversations, 20)
		if err != nil {
			return sdk.Result{}, err
		}
		t, err := c.getTicket(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		cs, err := c.conversations(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		if len(cs) > n {
			cs = cs[len(cs)-n:]
		}
		list := []map[string]any{}
		for _, x := range cs {
			kind := "reply"
			switch {
			case x.Private:
				kind = "private note"
			case x.Source == 2:
				kind = "public note"
			case x.Incoming:
				kind = "customer"
			}
			e := map[string]any{"id": x.ID, "kind": kind, "at": x.CreatedAt, "text": clip(x.BodyText, 4000)}
			if x.FromEmail != "" {
				e["from"] = clip(x.FromEmail, 200)
			}
			list = append(list, e)
		}
		o := c.summary(t)
		o["created"], o["tags"], o["description"] = t.CreatedAt, t.Tags, clip(t.Description, 4000)
		if t.Type != nil {
			o["type"] = *t.Type
		}
		if t.Requester != nil {
			o["requester"] = map[string]any{"id": t.Requester.ID, "name": clip(t.Requester.Name, 80), "email": clip(t.Requester.Email, 200)}
		}
		o["assignee"] = c.agentName(ctx, t.ResponderID)
		o["conversations"] = list
		return sdk.JSON(o)

	case "agents":
		var as []agent
		if _, err := c.api.Do(ctx, http.MethodGet, "/agents", url.Values{"per_page": {"100"}}, nil, &as); err != nil {
			return sdk.Result{}, friendly(err, "agent list")
		}
		list := []map[string]any{}
		for _, a := range as {
			list = append(list, map[string]any{"id": a.ID, "name": clip(a.Contact.Name, 80)})
		}
		return sdk.JSON(list)

	case "add_note", "reply":
		body, err := text(p.Text)
		if err != nil {
			return sdk.Result{}, err
		}
		t, err := c.getTicket(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.Action == "add_note" {
			if call.DryRun {
				return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add a private note to ticket #%s; the requester isn't notified", tid),
					Changes: []sdk.Change{{Target: "ticket #" + tid, Op: "note", After: mustJSON(map[string]any{"text": clip(body, 2000)})}}}}, nil
			}
			var out conversation
			if _, err := c.api.Do(ctx, http.MethodPost, "/tickets/"+tid+"/notes", nil, map[string]any{"body": htmlBody(body), "private": true}, &out); err != nil {
				return sdk.Result{}, friendly(err, "ticket #"+tid)
			}
			r, err := sdk.JSON(map[string]any{"ticket": t.ID, "note": out.ID})
			if out.ID > 0 {
				r.Undo = sdk.UndoWith("delete_note", map[string]string{"ticket": tid, "note": strconv.FormatInt(out.ID, 10)}, "Delete the note on ticket #"+tid)
			}
			return r, err
		}
		to := "the requester"
		if t.Requester != nil {
			to = clip(t.Requester.Name, 80) + " <" + clip(t.Requester.Email, 200) + ">"
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Email a public reply on ticket #%s (%s) to %s; it can't be unsent", tid, clip(t.Subject, 100), to),
				Changes: []sdk.Change{{Target: "ticket #" + tid, Op: "reply", After: mustJSON(map[string]any{"to": to, "text": clip(body, 2000)})}}}}, nil
		}
		var out conversation
		if _, err := c.api.Do(ctx, http.MethodPost, "/tickets/"+tid+"/reply", nil, map[string]any{"body": htmlBody(body)}, &out); err != nil {
			return sdk.Result{}, friendly(err, "ticket #"+tid)
		}
		return sdk.JSON(map[string]any{"ticket": t.ID, "reply": out.ID})

	case "delete_note":
		nid := string(p.Note)
		if !idRe.MatchString(nid) {
			return sdk.Result{}, errors.New("the note is its id")
		}
		cs, err := c.conversations(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		var note *conversation
		for i := range cs {
			if strconv.FormatInt(cs[i].ID, 10) == nid {
				note = &cs[i]
			}
		}
		switch {
		case note == nil:
			return sdk.Result{}, fmt.Errorf("ticket #%s has no note %s", tid, nid)
		case !note.Private || note.Source != 2:
			return sdk.Result{}, fmt.Errorf("entry %s on ticket #%s isn't a private note; only private notes can be deleted here", nid, tid)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete private note %s on ticket #%s for good", nid, tid),
				Changes: []sdk.Change{{Target: "ticket #" + tid, Op: "delete", Before: mustJSON(map[string]any{"text": clip(note.BodyText, 500)})}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodDelete, "/conversations/"+nid, nil, nil, nil); err != nil {
			return sdk.Result{}, friendly(err, "note "+nid)
		}
		return sdk.JSON(map[string]any{"ticket": tid, "deleted": nid})

	case "set_status", "resolve":
		to := p.Status
		if call.Action == "resolve" {
			if to == "" {
				to = "resolved"
			}
			if to != "resolved" && to != "closed" {
				return sdk.Result{}, errors.New("resolve sets resolved or closed (set_status sets open or pending)")
			}
		} else if to == "resolved" || to == "closed" {
			return sdk.Result{}, errors.New("resolving or closing a ticket may email the requester; use resolve")
		} else if to != "open" && to != "pending" {
			return sdk.Result{}, errors.New("the status is open or pending (resolve resolves or closes it)")
		}
		code := statusCode[to]
		t, err := c.getTicket(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		before := status(t.Status)
		if t.Status == code {
			return sdk.JSON(map[string]any{"ticket": t.ID, "status": before, "note": "the ticket already has this status"})
		}
		if call.DryRun {
			// Ids and statuses only: this plan goes in the audit log as is.
			summary := fmt.Sprintf("Set ticket #%s from %s to %s", tid, before, to)
			if call.Action == "resolve" {
				summary = fmt.Sprintf("Set ticket #%s from %s to %s; it may email the requester (satisfaction survey or resolution notice)", tid, before, to)
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: summary,
				Changes: []sdk.Change{{Target: "ticket #" + tid, Op: "update", Before: mustJSON(map[string]any{"status": before}), After: mustJSON(map[string]any{"status": to})}}}}, nil
		}
		after, err := c.update(ctx, tid, map[string]any{"status": code})
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"ticket": t.ID, "from": before, "to": status(after.Status)})
		switch before {
		case "open", "pending":
			r.Undo = sdk.UndoWith("set_status", map[string]any{"ticket": tid, "status": before}, fmt.Sprintf("Set ticket #%s back to %s", tid, before))
		case "resolved", "closed":
			r.Undo = sdk.UndoWith("resolve", map[string]any{"ticket": tid, "status": before}, fmt.Sprintf("Set ticket #%s back to %s", tid, before))
		}
		return r, err

	case "assign":
		var to *int64
		switch {
		case p.Unassign && p.Assignee != "":
			return sdk.Result{}, errors.New("give an assignee or unassign, not both")
		case p.Unassign:
		case idRe.MatchString(string(p.Assignee)):
			n, _ := strconv.ParseInt(string(p.Assignee), 10, 64)
			to = &n
		default:
			return sdk.Result{}, errors.New("the assignee is an agent id from agents (or set unassign)")
		}
		t, err := c.getTicket(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		if (to == nil && t.ResponderID == nil) || (to != nil && t.ResponderID != nil && *to == *t.ResponderID) {
			return sdk.JSON(map[string]any{"ticket": t.ID, "note": "the ticket is already assigned that way"})
		}
		before, after := c.agentName(ctx, t.ResponderID), c.agentName(ctx, to)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Assign ticket #%s from %s to %s", tid, before, after),
				Changes: []sdk.Change{{Target: "ticket #" + tid, Op: "assign", Before: mustJSON(map[string]any{"assignee": before}), After: mustJSON(map[string]any{"assignee": after})}}}}, nil
		}
		if _, err := c.update(ctx, tid, map[string]any{"responder_id": to}); err != nil {
			return sdk.Result{}, err
		}
		undo := map[string]any{"ticket": tid, "unassign": true}
		if t.ResponderID != nil {
			undo = map[string]any{"ticket": tid, "assignee": strconv.FormatInt(*t.ResponderID, 10)}
		}
		r, err := sdk.JSON(map[string]any{"ticket": t.ID, "from": before, "to": after})
		r.Undo = sdk.UndoWith("assign", undo, fmt.Sprintf("Give ticket #%s back to %s", tid, before))
		return r, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
