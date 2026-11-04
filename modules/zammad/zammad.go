// Package zammad works with a Zammad helpdesk through its REST API with an
// access token: ticket lists and search, one ticket with its articles,
// internal notes (undo deletes them), email replies to the customer and
// state changes.
//
// A reply emails the customer and can't be unsent, so it's destructive.
// Tickets and articles are personal data, so the actions that return them
// are sensitive.
package zammad

import (
	"context"
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
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Zammad helpdesk.
type Config struct {
	Address            string `json:"address"` // https://support.example.com or https://acme.zammad.com
	Token              string `json:"token"`   // secret:// access token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
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
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Zammad module.
func New() *Module { return &Module{} }

const maxText = 20000

var (
	idRe     = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	prefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
	ctrlRe   = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
	tagRe    = regexp.MustCompile(`(?s)<[^>]*>`)
	breakRe  = regexp.MustCompile(`(?i)<br\s*/?>|</p>|</div>`)
	emailRe  = regexp.MustCompile(`^[^\s@<>,;"]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,63}$`)
)

// states are the ones set_state sets; pending ones need a time.
var states = map[string]bool{"open": false, "closed": false, "new": false, "pending reminder": true, "pending close": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	tk := `"ticket":{"type":["string","integer"],"description":"The ticket's id (from tickets), not its number"}`
	text := `"text":{"type":"string","format":"textarea","maxLength":20000}`
	return sdk.Manifest{
		ID: "zammad", Name: "Zammad", Version: "0.1.0", Category: "Communication", Icon: "headset",
		Description: "Zammad: open tickets and search, a ticket with its articles, internal notes, email replies (destructive: they email the customer) and state changes.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["address","token"],"properties":{
			"address":{"type":"string","description":"Your Zammad, e.g. https://support.example.com or https://acme.zammad.com"},
			"token":{"type":"string","x-secret":true,"description":"An access token (Profile, Token Access) with ticket.agent permission"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate, to trust it"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "tickets", Title: "Tickets", Description: "New and open tickets (only mine with mine), most recently updated first: id, number, title, state, priority, owner and customer.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"mine":{"type":"boolean","description":"Only tickets I own"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "search", Title: "Search tickets", Description: "Zammad search, e.g. printer, state.name:open AND priority_id:3, or customer.email:jane@example.com.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string","maxLength":500},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "ticket", Title: "Open a ticket", Description: "A ticket with customer, owner, group and its latest articles (emails, notes, calls), internal ones included.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket"],"properties":{` + tk + `,"articles":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "add_note", Title: "Add an internal note", Description: "A note only agents see; the customer isn't notified. Undo deletes it (Zammad lets agents delete their own notes for a few minutes).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket","text"],"properties":{` + tk + `,` + text + `}}`)},
			{Name: "delete_note", Title: "Delete an internal note", Description: "Deletes one internal note. Only internal notes: emails and customer articles are refused.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket","note"],"properties":{` + tk + `,"note":{"type":["string","integer"],"description":"The note's article id"}}}`)},
			{Name: "reply", Title: "Reply to the customer", Description: "An email to the ticket's customer. It can't be unsent, so it's destructive. The preview shows the address and the text.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket","text"],"properties":{` + tk + `,` + text + `}}`)},
			{Name: "set_state", Title: "Set the state", Description: "Open, closed, new, or pending reminder / pending close until a time. Undo sets the state it had.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket","state"],"properties":{` + tk + `,"state":{"type":"string","enum":["open","closed","new","pending reminder","pending close"]},"pendingUntil":{"type":"string","format":"date-time","description":"For a pending state, e.g. 2026-11-10T09:00:00Z"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.Address))
	prefix := ""
	if err == nil {
		prefix = strings.TrimRight(u.Path, "/")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return errors.New("the address is your Zammad, like https://support.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	site := u.Scheme + "://" + u.Host + prefix
	ref := c.Token
	api := rest.New(site+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Token token="+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, site: site})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Zammad refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Zammad refused: the token can't do that (it needs ticket.agent; notes can only be deleted for a few minutes)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusUnprocessableEntity):
		return fmt.Errorf("Zammad refused the change: %v", err)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Zammad's rate limit was hit; try again in a minute")
	}
	return err
}

type user struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Email     string `json:"email"`
}

func (u user) name() string {
	n := strings.TrimSpace(u.Firstname + " " + u.Lastname)
	if n == "" {
		n = u.Login
	}
	return clip(n, 80)
}

func (c *conn) me(ctx context.Context) (user, error) {
	var me user
	_, err := c.api.Do(ctx, http.MethodGet, "/users/me", nil, nil, &me)
	return me, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	me, err := c.me(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "Zammad API here").Error()}
	}
	return sdk.Health{Status: "ok", Message: "Signed in as " + me.name()}
}

type flexID string

func (f *flexID) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*f = flexID(strings.TrimSpace(s))
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
	Ticket       flexID `json:"ticket"`
	Note         flexID `json:"note"`
	Mine         bool   `json:"mine"`
	Limit        int    `json:"limit"`
	Articles     int    `json:"articles"`
	Query        string `json:"query"`
	Text         string `json:"text"`
	State        string `json:"state"`
	PendingUntil string `json:"pendingUntil"`
}

type ticket struct {
	ID          int64   `json:"id"`
	Number      string  `json:"number"`
	Title       string  `json:"title"`
	State       string  `json:"state"`
	Priority    string  `json:"priority"`
	Group       string  `json:"group"`
	Owner       string  `json:"owner"`
	OwnerID     int64   `json:"owner_id"`
	Customer    string  `json:"customer"`
	CustomerID  int64   `json:"customer_id"`
	PendingTime *string `json:"pending_time"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

type article struct {
	ID          int64  `json:"id"`
	TicketID    int64  `json:"ticket_id"`
	From        string `json:"from"`
	To          string `json:"to"`
	Subject     string `json:"subject"`
	Body        string `json:"body"`
	ContentType string `json:"content_type"`
	Internal    bool   `json:"internal"`
	Type        string `json:"type"`
	Sender      string `json:"sender"`
	CreatedAt   string `json:"created_at"`
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

// plain turns an HTML article body into text.
func plain(a article) string {
	if !strings.Contains(a.ContentType, "html") {
		return a.Body
	}
	s := breakRe.ReplaceAllString(a.Body, "\n")
	return html.UnescapeString(tagRe.ReplaceAllString(s, ""))
}

func (c *conn) summary(t ticket) map[string]any {
	o := map[string]any{"ticket": t.ID, "number": t.Number, "title": clip(t.Title, 200), "state": t.State, "priority": t.Priority, "owner": clip(t.Owner, 80),
		"customer": clip(t.Customer, 200), "updated": t.UpdatedAt, "url": c.site + "/#ticket/zoom/" + strconv.FormatInt(t.ID, 10)}
	if t.Group != "" {
		o["group"] = clip(t.Group, 80)
	}
	if t.PendingTime != nil && *t.PendingTime != "" {
		o["pendingUntil"] = *t.PendingTime
	}
	return o
}

func (c *conn) search(ctx context.Context, query string, n int) ([]ticket, error) {
	q := url.Values{"query": {query}, "limit": {strconv.Itoa(n)}, "expand": {"true"}, "sort_by": {"updated_at"}, "order_by": {"desc"}}
	var raw json.RawMessage
	if _, err := c.api.Do(ctx, http.MethodGet, "/tickets/search", q, nil, &raw); err != nil {
		return nil, friendly(err, "search here")
	}
	var list []ticket
	if json.Unmarshal(raw, &list) == nil {
		return list, nil
	}
	// Older servers answer with ids and assets.
	var a struct {
		Tickets []int64 `json:"tickets"`
		Assets  struct {
			Ticket map[string]ticket `json:"Ticket"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("unexpected answer from Zammad: %w", err)
	}
	for _, id := range a.Tickets {
		if t, ok := a.Assets.Ticket[strconv.FormatInt(id, 10)]; ok {
			list = append(list, t)
		}
	}
	return list, nil
}

func (c *conn) get(ctx context.Context, id string) (ticket, error) {
	var t ticket
	if _, err := c.api.Do(ctx, http.MethodGet, "/tickets/"+id, url.Values{"expand": {"true"}}, nil, &t); err != nil {
		return ticket{}, friendly(err, "ticket "+id)
	}
	return t, nil
}

func (c *conn) customer(ctx context.Context, t ticket) (user, error) {
	var u user
	if t.CustomerID <= 0 {
		return u, errors.New("the ticket has no customer")
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/users/"+strconv.FormatInt(t.CustomerID, 10), nil, nil, &u); err != nil {
		return u, friendly(err, "customer")
	}
	return u, nil
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
	if call.Action != "tickets" && call.Action != "search" && !idRe.MatchString(tid) {
		return sdk.Result{}, errors.New("the ticket is its id from tickets, e.g. 42")
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	switch call.Action {
	case "tickets", "search":
		n, err := limit(p.Limit, 25)
		if err != nil {
			return sdk.Result{}, err
		}
		query := "(state.name:new OR state.name:open)"
		if call.Action == "search" {
			query = strings.TrimSpace(p.Query)
			if query == "" || utf8.RuneCountInString(query) > 500 || ctrlRe.MatchString(query) || strings.ContainsAny(query, "\r\n\t") {
				return sdk.Result{}, errors.New("the query is 1 to 500 characters on one line")
			}
		} else if p.Mine {
			me, err := c.me(ctx)
			if err != nil {
				return sdk.Result{}, friendly(err, "user")
			}
			query += " AND owner_id:" + strconv.FormatInt(me.ID, 10)
		}
		list, err := c.search(ctx, query, n)
		if err != nil {
			return sdk.Result{}, err
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
		n, err := limit(p.Articles, 20)
		if err != nil {
			return sdk.Result{}, err
		}
		t, err := c.get(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		var as []article
		if _, err := c.api.Do(ctx, http.MethodGet, "/ticket_articles/by_ticket/"+tid, url.Values{"expand": {"true"}}, nil, &as); err != nil {
			return sdk.Result{}, friendly(err, "ticket "+tid)
		}
		if len(as) > n {
			as = as[len(as)-n:]
		}
		list := []map[string]any{}
		for _, a := range as {
			e := map[string]any{"id": a.ID, "type": a.Type, "sender": a.Sender, "internal": a.Internal, "at": a.CreatedAt, "from": clip(a.From, 200), "text": clip(plain(a), 4000)}
			if a.To != "" {
				e["to"] = clip(a.To, 200)
			}
			list = append(list, e)
		}
		o := c.summary(t)
		o["created"] = t.CreatedAt
		o["articles"] = list
		return sdk.JSON(o)

	case "add_note", "reply":
		body, err := text(p.Text)
		if err != nil {
			return sdk.Result{}, err
		}
		t, err := c.get(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		if t.State == "merged" || t.State == "removed" {
			return sdk.Result{}, fmt.Errorf("ticket %s is %s", tid, t.State)
		}
		n, _ := strconv.ParseInt(tid, 10, 64)
		if call.Action == "add_note" {
			if call.DryRun {
				return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add an internal note to ticket #%s (%s); the customer isn't notified", t.Number, clip(t.Title, 100)),
					Changes: []sdk.Change{{Target: "ticket #" + t.Number, Op: "note", After: mustJSON(map[string]any{"text": clip(body, 2000)})}}}}, nil
			}
			var out article
			in := map[string]any{"ticket_id": n, "body": body, "content_type": "text/plain", "type": "note", "internal": true}
			if _, err := c.api.Do(ctx, http.MethodPost, "/ticket_articles", nil, in, &out); err != nil {
				return sdk.Result{}, friendly(err, "ticket "+tid)
			}
			r, err := sdk.JSON(map[string]any{"ticket": t.ID, "note": out.ID})
			if out.ID > 0 {
				r.Undo = sdk.UndoWith("delete_note", map[string]string{"ticket": tid, "note": strconv.FormatInt(out.ID, 10)}, "Delete the note on ticket #"+t.Number)
			}
			return r, err
		}
		cu, err := c.customer(ctx, t)
		if err != nil {
			return sdk.Result{}, err
		}
		if !emailRe.MatchString(cu.Email) {
			return sdk.Result{}, fmt.Errorf("the customer of ticket %s has no usable email address", tid)
		}
		to := cu.name() + " <" + cu.Email + ">"
		subject := clip(t.Title, 200)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Email a reply on ticket #%s (%s) to %s; it can't be unsent", t.Number, clip(t.Title, 100), to),
				Changes: []sdk.Change{{Target: "ticket #" + t.Number, Op: "reply", After: mustJSON(map[string]any{"to": to, "subject": subject, "text": clip(body, 2000)})}}}}, nil
		}
		var out article
		in := map[string]any{"ticket_id": n, "to": cu.Email, "subject": subject, "body": body, "content_type": "text/plain", "type": "email", "internal": false}
		if _, err := c.api.Do(ctx, http.MethodPost, "/ticket_articles", nil, in, &out); err != nil {
			return sdk.Result{}, friendly(err, "ticket "+tid)
		}
		return sdk.JSON(map[string]any{"ticket": t.ID, "reply": out.ID})

	case "delete_note":
		nid := string(p.Note)
		if !idRe.MatchString(nid) {
			return sdk.Result{}, errors.New("the note is its article id")
		}
		var a article
		if _, err := c.api.Do(ctx, http.MethodGet, "/ticket_articles/"+nid, url.Values{"expand": {"true"}}, nil, &a); err != nil {
			return sdk.Result{}, friendly(err, "article "+nid)
		}
		switch {
		case strconv.FormatInt(a.TicketID, 10) != tid:
			return sdk.Result{}, fmt.Errorf("article %s isn't on ticket %s", nid, tid)
		case !a.Internal || a.Type != "note":
			return sdk.Result{}, fmt.Errorf("article %s isn't an internal note; only internal notes can be deleted here", nid)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete internal note %s on ticket %s", nid, tid),
				Changes: []sdk.Change{{Target: "ticket " + tid, Op: "delete", Before: mustJSON(map[string]any{"text": clip(plain(a), 500)})}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodDelete, "/ticket_articles/"+nid, nil, nil, nil); err != nil {
			return sdk.Result{}, friendly(err, "article "+nid)
		}
		return sdk.JSON(map[string]any{"ticket": tid, "deleted": nid})

	case "set_state":
		pending, ok := states[p.State]
		if !ok {
			return sdk.Result{}, errors.New("the state is open, closed, new, pending reminder or pending close")
		}
		var until string
		switch {
		case pending:
			at, err := time.Parse(time.RFC3339, strings.TrimSpace(p.PendingUntil))
			if err != nil {
				return sdk.Result{}, errors.New("a pending state needs pendingUntil, a time like 2026-11-10T09:00:00Z")
			}
			if at.After(now().AddDate(5, 0, 0)) {
				return sdk.Result{}, errors.New("pendingUntil is at most five years ahead")
			}
			until = at.UTC().Format(time.RFC3339)
		case p.PendingUntil != "":
			return sdk.Result{}, errors.New("pendingUntil goes with a pending state")
		}
		t, err := c.get(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		if t.State == "merged" || t.State == "removed" {
			return sdk.Result{}, fmt.Errorf("ticket %s is %s", tid, t.State)
		}
		prevUntil := ""
		if t.PendingTime != nil {
			prevUntil = *t.PendingTime
		}
		if t.State == p.State && (!pending || prevUntil == until) {
			return sdk.JSON(map[string]any{"ticket": t.ID, "state": t.State, "note": "the ticket already has this state"})
		}
		before := map[string]any{"state": t.State}
		after := map[string]any{"state": p.State}
		if prevUntil != "" {
			before["pendingUntil"] = prevUntil
		}
		if until != "" {
			after["pendingUntil"] = until
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Set ticket #%s (%s) from %s to %s", t.Number, clip(t.Title, 100), t.State, p.State),
				Changes: []sdk.Change{{Target: "ticket #" + t.Number, Op: "update", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
		}
		body := map[string]any{"state": p.State}
		if until != "" {
			body["pending_time"] = until
		}
		var got ticket
		if _, err := c.api.Do(ctx, http.MethodPut, "/tickets/"+tid, url.Values{"expand": {"true"}}, body, &got); err != nil {
			return sdk.Result{}, friendly(err, "ticket "+tid)
		}
		r, err := sdk.JSON(map[string]any{"ticket": t.ID, "from": t.State, "to": p.State})
		if back, ok := states[t.State]; ok {
			undo := map[string]any{"ticket": tid, "state": t.State}
			if back {
				if pt, err := time.Parse(time.RFC3339, prevUntil); err == nil {
					undo["pendingUntil"] = pt.UTC().Format(time.RFC3339)
				} else {
					undo = nil
				}
			}
			if undo != nil {
				r.Undo = sdk.UndoWith("set_state", undo, fmt.Sprintf("Set ticket #%s back to %s", t.Number, t.State))
			}
		}
		return r, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
