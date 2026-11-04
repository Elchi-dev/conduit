// Package zendesk works with Zendesk Support through its REST API v2, with an
// agent's email and API token or an OAuth access token: views and the
// tickets in them, search, one ticket with its conversation, internal notes,
// public replies to the requester, status changes and assignment.
//
// A public reply emails the customer and can't be unsent, so it's
// destructive. Ticket contents (subjects, requesters, comments) are personal
// data, so the actions that return them are sensitive.
package zendesk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// Config is one Zendesk account.
type Config struct {
	Subdomain  string `json:"subdomain"`  // acme for acme.zendesk.com
	Email      string `json:"email"`      // the agent the API token belongs to
	Token      string `json:"token"`      // secret:// API token
	OAuthToken string `json:"oauthToken"` // secret:// OAuth access token, instead of email and token
}

type conn struct {
	api  *rest.Client
	site string // https://acme.zendesk.com, for links
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://<subdomain>.zendesk.com (tests).
	Base string
}

// New returns the Zendesk module.
func New() *Module { return &Module{} }

var (
	subRe   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	emailRe = regexp.MustCompile(`^[^\s@/:]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,63}$`)
	idRe    = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	ctrlRe  = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
)

const maxText = 20000

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	tk := `"ticket":{"type":["string","integer"],"description":"Ticket number, e.g. 1234"}`
	text := `"text":{"type":"string","format":"textarea","maxLength":20000}`
	return sdk.Manifest{
		ID: "zendesk", Name: "Zendesk", Version: "0.1.0", Category: "Communication", Icon: "headset",
		Description: "Zendesk Support: views, ticket search, a ticket with its conversation, internal notes, public replies (destructive: they email the customer), status and assignment.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["subdomain"],"properties":{
			"subdomain":{"type":"string","description":"Your Zendesk subdomain: acme for acme.zendesk.com"},
			"email":{"type":"string","description":"The agent's email, with an API token"},
			"token":{"type":"string","x-secret":true,"description":"An API token (Admin Center, Apps and integrations, Zendesk API)"},
			"oauthToken":{"type":"string","x-secret":true,"description":"An OAuth access token, instead of email and API token"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "views", Title: "Views", Description: "The active views (id and title), to list tickets from.", Risk: sdk.RiskRead},
			{Name: "tickets", Title: "Tickets", Description: "Tickets in a view, or all unsolved tickets, most recently updated first: number, subject, status, priority, assignee.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"view":{"type":["string","integer"],"description":"View id from views (default: all unsolved tickets)"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "search", Title: "Search tickets", Description: "Zendesk search syntax, e.g. status:open requester:jane@example.com printer.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string","maxLength":500},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "ticket", Title: "Open a ticket", Description: "A ticket with requester, assignee, tags and its latest comments, public and internal.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket"],"properties":{` + tk + `,"comments":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "agents", Title: "Agents", Description: "Agents and admins with their id and name, to assign tickets to.", Risk: sdk.RiskRead},
			{Name: "add_note", Title: "Add an internal note", Description: "A private comment only agents see; the requester isn't notified. Zendesk can't delete comments, so there's no undo.", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket","text"],"properties":{` + tk + `,` + text + `}}`)},
			{Name: "reply", Title: "Reply to the requester", Description: "A public comment, emailed to the requester and CCs. It can't be unsent, so it's destructive. The preview shows who gets it and the text.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket","text"],"properties":{` + tk + `,` + text + `}}`)},
			{Name: "set_status", Title: "Set the status", Description: "Open, pending or on hold (also reopens a solved ticket). Solving is resolve. Undo sets the status it had.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket","status"],"properties":{` + tk + `,"status":{"type":"string","enum":["open","pending","hold"]}}}`)},
			{Name: "resolve", Title: "Solve a ticket", Description: "Sets a ticket solved. Zendesk's triggers may email the requester (a satisfaction survey or a resolution notice), which can't be unsent, so it's destructive. Undo reopens it with the status it had, until it closes.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket"],"properties":{` + tk + `}}`)},
			{Name: "assign", Title: "Assign a ticket", Description: "To an agent (id from agents), or unassign it. Undo gives it back to whoever had it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["ticket"],"properties":{` + tk + `,"assignee":{"type":["string","integer"],"description":"Agent id"},"unassign":{"type":"boolean"}}}`)},
		},
	}
}

// subdomain accepts acme, acme.zendesk.com or https://acme.zendesk.com.
func subdomain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".zendesk.com")
	if !subRe.MatchString(s) {
		return "", errors.New("the subdomain is the first part of your Zendesk address: acme for acme.zendesk.com")
	}
	return s, nil
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	sub, err := subdomain(c.Subdomain)
	if err != nil {
		return err
	}
	var auth func(context.Context, *http.Request) error
	switch {
	case c.OAuthToken != "" && c.Token != "":
		return errors.New("give an API token or an OAuth token, not both")
	case c.OAuthToken != "":
		if !strings.HasPrefix(c.OAuthToken, "secret://") {
			return errors.New("store the OAuth token in the vault and enter its secret:// reference")
		}
		ref := c.OAuthToken
		auth = func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, ref)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
			return nil
		}
	case c.Token != "":
		if !strings.HasPrefix(c.Token, "secret://") {
			return errors.New("store the API token in the vault and enter its secret:// reference")
		}
		email := strings.TrimSpace(c.Email)
		if !emailRe.MatchString(email) {
			return errors.New("an API token goes with the email of the agent it belongs to")
		}
		ref := c.Token
		auth = func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, ref)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(email+"/token:"+strings.TrimSpace(t))))
			return nil
		}
	default:
		return errors.New("add an agent's email and API token, or an OAuth token, stored in the vault")
	}
	site := "https://" + sub + ".zendesk.com"
	if m.Base != "" {
		site = strings.TrimRight(m.Base, "/")
	}
	api := rest.New(site+"/api/v2", auth)
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
		return errors.New("Zendesk refused the credentials (check the email and API token, or the OAuth token)")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Zendesk refused: this account can't do that")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusUnprocessableEntity):
		return fmt.Errorf("Zendesk refused the change: %v (a closed ticket can't be changed)", err)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Zendesk's rate limit was hit; try again in a minute")
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		User struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
			Role string `json:"role"`
		} `json:"user"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/users/me.json", nil, nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "Zendesk API here").Error()}
	}
	// Zendesk answers an unauthenticated /users/me with an anonymous user.
	if me.User.ID == 0 {
		return sdk.Health{Status: "down", Message: "Zendesk didn't accept the credentials"}
	}
	if me.User.Role != "agent" && me.User.Role != "admin" {
		return sdk.Health{Status: "degraded", Message: "signed in as an end user, not an agent"}
	}
	return sdk.Health{Status: "ok", Message: "Signed in as " + clip(me.User.Name, 80)}
}

// flexID takes an id given as a JSON string or number.
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
	Ticket   flexID `json:"ticket"`
	View     flexID `json:"view"`
	Limit    int    `json:"limit"`
	Comments int    `json:"comments"`
	Query    string `json:"query"`
	Text     string `json:"text"`
	Status   string `json:"status"`
	Assignee flexID `json:"assignee"`
	Unassign bool   `json:"unassign"`
}

type ticket struct {
	ID          int64    `json:"id"`
	Subject     string   `json:"subject"`
	Status      string   `json:"status"`
	Priority    *string  `json:"priority"`
	Type        *string  `json:"type"`
	RequesterID *int64   `json:"requester_id"`
	AssigneeID  *int64   `json:"assignee_id"`
	GroupID     *int64   `json:"group_id"`
	Tags        []string `json:"tags"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	Via         struct {
		Channel string `json:"channel"`
	} `json:"via"`
	ResultType string `json:"result_type"` // search results
}

type user struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
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

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
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

func (c *conn) summary(t ticket) map[string]any {
	o := map[string]any{"ticket": t.ID, "subject": clip(t.Subject, 200), "status": t.Status, "updated": t.UpdatedAt, "url": c.site + "/agent/tickets/" + strconv.FormatInt(t.ID, 10)}
	if p := str(t.Priority); p != "" {
		o["priority"] = p
	}
	if t.AssigneeID != nil {
		o["assigneeId"] = *t.AssigneeID
	} else {
		o["assigneeId"] = nil
	}
	return o
}

func (c *conn) getTicket(ctx context.Context, id string) (ticket, map[int64]user, error) {
	var a struct {
		Ticket ticket `json:"ticket"`
		Users  []user `json:"users"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/tickets/"+id+".json", url.Values{"include": {"users"}}, nil, &a); err != nil {
		return ticket{}, nil, friendly(err, "ticket #"+id)
	}
	users := map[int64]user{}
	for _, u := range a.Users {
		users[u.ID] = u
	}
	return a.Ticket, users, nil
}

func (c *conn) userName(ctx context.Context, id *int64, known map[int64]user) string {
	if id == nil {
		return "nobody"
	}
	if u, ok := known[*id]; ok {
		return clip(u.Name, 80)
	}
	var a struct {
		User user `json:"user"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/users/"+strconv.FormatInt(*id, 10)+".json", nil, nil, &a); err != nil || a.User.Name == "" {
		return "agent " + strconv.FormatInt(*id, 10)
	}
	return clip(a.User.Name, 80)
}

func (c *conn) update(ctx context.Context, id string, fields map[string]any) (ticket, error) {
	var a struct {
		Ticket ticket `json:"ticket"`
	}
	if _, err := c.api.Do(ctx, http.MethodPut, "/tickets/"+id+".json", nil, map[string]any{"ticket": fields}, &a); err != nil {
		return ticket{}, friendly(err, "ticket #"+id)
	}
	return a.Ticket, nil
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
	case "views", "tickets", "search", "agents":
	default:
		if !idRe.MatchString(tid) {
			return sdk.Result{}, errors.New("the ticket is its number, e.g. 1234")
		}
	}
	switch call.Action {
	case "views":
		var a struct {
			Views []struct {
				ID    int64  `json:"id"`
				Title string `json:"title"`
			} `json:"views"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/views/active.json", url.Values{"per_page": {"100"}}, nil, &a); err != nil {
			return sdk.Result{}, friendly(err, "views")
		}
		list := []map[string]any{}
		for _, v := range a.Views {
			list = append(list, map[string]any{"view": v.ID, "title": clip(v.Title, 200)})
		}
		return sdk.JSON(list)

	case "tickets", "search":
		n, err := limit(p.Limit, 25)
		if err != nil {
			return sdk.Result{}, err
		}
		var list []ticket
		if call.Action == "tickets" && p.View != "" {
			if !idRe.MatchString(string(p.View)) {
				return sdk.Result{}, errors.New("the view is its id from views")
			}
			var a struct {
				Tickets []ticket `json:"tickets"`
			}
			q := url.Values{"per_page": {strconv.Itoa(n)}, "sort_by": {"updated_at"}, "sort_order": {"desc"}}
			if _, err := c.api.Do(ctx, http.MethodGet, "/views/"+string(p.View)+"/tickets.json", q, nil, &a); err != nil {
				return sdk.Result{}, friendly(err, "view "+string(p.View))
			}
			list = a.Tickets
		} else {
			query := "status<solved"
			if call.Action == "search" {
				query = strings.TrimSpace(p.Query)
				if query == "" || utf8.RuneCountInString(query) > 500 || ctrlRe.MatchString(query) || strings.ContainsAny(query, "\r\n\t") {
					return sdk.Result{}, errors.New("the query is 1 to 500 characters on one line")
				}
			}
			var a struct {
				Results []ticket `json:"results"`
			}
			q := url.Values{"query": {"type:ticket " + query}, "per_page": {strconv.Itoa(n)}, "sort_by": {"updated_at"}, "sort_order": {"desc"}}
			if _, err := c.api.Do(ctx, http.MethodGet, "/search.json", q, nil, &a); err != nil {
				return sdk.Result{}, friendly(err, "search here")
			}
			for _, t := range a.Results {
				if t.ResultType == "" || t.ResultType == "ticket" {
					list = append(list, t)
				}
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
		n, err := limit(p.Comments, 20)
		if err != nil {
			return sdk.Result{}, err
		}
		t, users, err := c.getTicket(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		var cm struct {
			Comments []struct {
				ID        int64  `json:"id"`
				AuthorID  int64  `json:"author_id"`
				PlainBody string `json:"plain_body"`
				Body      string `json:"body"`
				Public    bool   `json:"public"`
				CreatedAt string `json:"created_at"`
			} `json:"comments"`
			Users []user `json:"users"`
		}
		q := url.Values{"include": {"users"}, "sort_order": {"desc"}, "per_page": {strconv.Itoa(n)}}
		if _, err := c.api.Do(ctx, http.MethodGet, "/tickets/"+tid+"/comments.json", q, nil, &cm); err != nil {
			return sdk.Result{}, friendly(err, "ticket #"+tid)
		}
		for _, u := range cm.Users {
			users[u.ID] = u
		}
		comments := []map[string]any{}
		for i := len(cm.Comments) - 1; i >= 0; i-- { // oldest of the latest first
			x := cm.Comments[i]
			b := x.PlainBody
			if b == "" {
				b = x.Body
			}
			kind := "internal note"
			if x.Public {
				kind = "public"
			}
			comments = append(comments, map[string]any{"id": x.ID, "author": clip(users[x.AuthorID].Name, 80), "kind": kind, "at": x.CreatedAt, "text": clip(b, 4000)})
		}
		o := c.summary(t)
		o["type"], o["channel"], o["created"], o["tags"] = str(t.Type), t.Via.Channel, t.CreatedAt, t.Tags
		if t.RequesterID != nil {
			u := users[*t.RequesterID]
			o["requester"] = map[string]any{"id": *t.RequesterID, "name": clip(u.Name, 80), "email": clip(u.Email, 200)}
		}
		o["assignee"] = c.userName(ctx, t.AssigneeID, users)
		o["comments"] = comments
		return sdk.JSON(o)

	case "agents":
		var a struct {
			Users []user `json:"users"`
		}
		q := url.Values{"role[]": {"agent", "admin"}, "per_page": {"100"}}
		if _, err := c.api.Do(ctx, http.MethodGet, "/users.json", q, nil, &a); err != nil {
			return sdk.Result{}, friendly(err, "agent list")
		}
		list := []map[string]any{}
		for _, u := range a.Users {
			list = append(list, map[string]any{"id": u.ID, "name": clip(u.Name, 80), "role": u.Role})
		}
		return sdk.JSON(list)

	case "add_note", "reply":
		body, err := text(p.Text)
		if err != nil {
			return sdk.Result{}, err
		}
		public := call.Action == "reply"
		t, users, err := c.getTicket(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		if t.Status == "closed" {
			return sdk.Result{}, fmt.Errorf("ticket #%s is closed; Zendesk doesn't take comments on closed tickets (open a follow-up)", tid)
		}
		if call.DryRun {
			if !public {
				return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add an internal note to ticket #%s; the requester isn't notified", tid),
					Changes: []sdk.Change{{Target: "ticket #" + tid, Op: "note", After: mustJSON(map[string]any{"text": clip(body, 2000)})}}}}, nil
			}
			to := "the requester"
			if t.RequesterID != nil {
				if u, ok := users[*t.RequesterID]; ok {
					to = clip(u.Name, 80) + " <" + clip(u.Email, 200) + ">"
				}
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Email a public reply on ticket #%s (%s) to %s and any CCs; it can't be unsent", tid, clip(t.Subject, 100), to),
				Changes: []sdk.Change{{Target: "ticket #" + tid, Op: "reply", After: mustJSON(map[string]any{"to": to, "text": clip(body, 2000)})}}}}, nil
		}
		if _, err := c.update(ctx, tid, map[string]any{"comment": map[string]any{"body": body, "public": public}}); err != nil {
			return sdk.Result{}, err
		}
		kind := "note"
		if public {
			kind = "reply"
		}
		return sdk.JSON(map[string]any{"ticket": t.ID, "added": kind})

	case "set_status", "resolve":
		to := p.Status
		if call.Action == "resolve" {
			to = "solved"
		} else {
			switch to {
			case "open", "pending", "hold":
			case "solved":
				return sdk.Result{}, errors.New("solving a ticket may email the requester; use resolve")
			default:
				return sdk.Result{}, errors.New("the status is open, pending or hold (resolve solves it)")
			}
		}
		t, _, err := c.getTicket(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		if t.Status == "closed" {
			return sdk.Result{}, fmt.Errorf("ticket #%s is closed and can't change any more", tid)
		}
		if t.Status == to {
			return sdk.JSON(map[string]any{"ticket": t.ID, "status": to, "note": "the ticket already has this status"})
		}
		back := t.Status
		if back == "new" { // a ticket can't be set back to new
			back = "open"
		}
		if call.DryRun {
			// Ids and statuses only: this plan goes in the audit log as is.
			summary := fmt.Sprintf("Set ticket #%s from %s to %s", tid, t.Status, to)
			if to == "solved" {
				summary = fmt.Sprintf("Solve ticket #%s (now %s); it may email the requester (satisfaction survey or resolution notice)", tid, t.Status)
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: summary,
				Changes: []sdk.Change{{Target: "ticket #" + tid, Op: "update", Before: mustJSON(map[string]any{"status": t.Status}), After: mustJSON(map[string]any{"status": to})}}}}, nil
		}
		after, err := c.update(ctx, tid, map[string]any{"status": to})
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"ticket": t.ID, "from": t.Status, "to": after.Status})
		if back == "solved" {
			r.Undo = sdk.UndoWith("resolve", map[string]any{"ticket": tid}, fmt.Sprintf("Solve ticket #%s again", tid))
		} else {
			r.Undo = sdk.UndoWith("set_status", map[string]any{"ticket": tid, "status": back}, fmt.Sprintf("Set ticket #%s back to %s", tid, back))
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
		t, users, err := c.getTicket(ctx, tid)
		if err != nil {
			return sdk.Result{}, err
		}
		if t.Status == "closed" {
			return sdk.Result{}, fmt.Errorf("ticket #%s is closed and can't change any more", tid)
		}
		if (to == nil && t.AssigneeID == nil) || (to != nil && t.AssigneeID != nil && *to == *t.AssigneeID) {
			return sdk.JSON(map[string]any{"ticket": t.ID, "note": "the ticket is already assigned that way"})
		}
		before, after := c.userName(ctx, t.AssigneeID, users), c.userName(ctx, to, users)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Assign ticket #%s from %s to %s", tid, before, after),
				Changes: []sdk.Change{{Target: "ticket #" + tid, Op: "assign", Before: mustJSON(map[string]any{"assignee": before}), After: mustJSON(map[string]any{"assignee": after})}}}}, nil
		}
		if _, err := c.update(ctx, tid, map[string]any{"assignee_id": to}); err != nil {
			return sdk.Result{}, err
		}
		undo := map[string]any{"ticket": tid, "unassign": true}
		if t.AssigneeID != nil {
			undo = map[string]any{"ticket": tid, "assignee": strconv.FormatInt(*t.AssigneeID, 10)}
		}
		r, err := sdk.JSON(map[string]any{"ticket": t.ID, "from": before, "to": after})
		r.Undo = sdk.UndoWith("assign", undo, fmt.Sprintf("Give ticket #%s back to %s", tid, before))
		return r, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
