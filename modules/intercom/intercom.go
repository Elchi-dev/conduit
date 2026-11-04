// Package intercom works with Intercom's inbox through its REST API and an
// access token: conversations by state, one conversation with its parts,
// replies to the customer as the token's admin, internal notes, closing,
// snoozing and reopening, and contact search.
//
// A reply reaches the customer (Messenger, email) and can't be unsent, so
// it's destructive; so is closing, which can send the customer a rating
// request. Conversations and contacts are personal data, so the actions
// that return them are sensitive.
package intercom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/mention"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Intercom workspace.
type Config struct {
	Region string `json:"region"` // us (default), eu or au
	Token  string `json:"token"`  // secret:// access token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.intercom.io (tests).
	Base string
}

// New returns the Intercom module.
func New() *Module { return &Module{} }

const (
	apiVersion = "2.11"
	maxText    = 20000
)

var (
	convRe = regexp.MustCompile(`^[0-9]{1,20}$`)
	idRe   = regexp.MustCompile(`^[0-9]{1,20}$`)
	ctrlRe = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
	tagRe  = regexp.MustCompile(`<[^>]*>`)

	regions = map[string]string{"us": "https://api.intercom.io", "eu": "https://api.eu.intercom.io", "au": "https://api.au.intercom.io"}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	cv := `"conversation":{"type":["string","integer"],"description":"Conversation id, e.g. 123456789"}`
	text := `"text":{"type":"string","format":"textarea","maxLength":20000}`
	return sdk.Manifest{
		ID: "intercom", Name: "Intercom", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "Intercom: conversations and their messages, replies to customers (destructive: they're sent), internal notes, closing, snoozing and reopening, and contact search.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"region":{"type":"string","enum":["us","eu","au"],"default":"us","description":"Where your workspace is hosted"},
			"token":{"type":"string","x-secret":true,"description":"An access token (Developer Hub, your app, Authentication); it acts as the admin who made the app"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "conversations", Title: "Conversations", Description: "Conversations by state (open by default, closed, snoozed or all), most recently updated first: id, title, state, priority, assignee, customer and the opening message.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"state":{"type":"string","enum":["open","closed","snoozed","all"],"default":"open"},"limit":{"type":"integer","minimum":1,"maximum":50,"default":20}}}`)},
			{Name: "conversation", Title: "Open a conversation", Description: "A conversation's customer, state and assignee with its messages, internal notes included.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation"],"properties":{` + cv + `}}`)},
			{Name: "contacts", Title: "Search contacts", Description: "Users and leads whose name or email contains the query: id, name, email, phone, role and last seen.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string","maxLength":200},"limit":{"type":"integer","minimum":1,"maximum":50,"default":20}}}`)},
			{Name: "add_note", Title: "Add an internal note", Description: "A note only teammates see; the customer isn't sent anything. Intercom can't delete conversation parts, so there's no undo.", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","text"],"properties":{` + cv + `,` + text + `}}`)},
			{Name: "reply", Title: "Reply to the customer", Description: "A public reply as the token's admin, delivered to the customer in Messenger or by email. It can't be unsent, so it's destructive. The preview shows who gets it and the text.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","text"],"properties":{` + cv + `,` + text + `}}`)},
			{Name: "open", Title: "Reopen a conversation", Description: "Opens a closed or snoozed conversation. Undo closes or snoozes it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation"],"properties":{` + cv + `}}`)},
			{Name: "snooze", Title: "Snooze a conversation", Description: "Snoozes a conversation until a time; it reopens by itself then. Undo sets the state it had.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","until"],"properties":{` + cv + `,"until":{"type":"string","format":"date-time","description":"A future time, e.g. 2026-11-10T09:00:00Z"}}}`)},
			{Name: "close", Title: "Close a conversation", Description: "Closes a conversation. Intercom may ask the customer to rate it, which can't be unsent, so it's destructive. Undo sets the state it had.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation"],"properties":{` + cv + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	region := strings.ToLower(strings.TrimSpace(c.Region))
	if region == "" {
		region = "us"
	}
	base, ok := regions[region]
	if !ok {
		return errors.New("the region is us, eu or au")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.Header.Set("Intercom-Version", apiVersion)
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Intercom refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Intercom refused: the token's app lacks the permission for this")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusUnprocessableEntity), rest.IsStatus(err, http.StatusBadRequest):
		return fmt.Errorf("Intercom refused the request: %v", err)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Intercom's rate limit was hit; try again in a minute")
	}
	return err
}

type admin struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
	App  struct {
		Name string `json:"name"`
	} `json:"app"`
}

func (c *conn) me(ctx context.Context) (admin, error) {
	var me admin
	if _, err := c.api.Do(ctx, http.MethodGet, "/me", nil, nil, &me); err != nil {
		return admin{}, friendly(err, "Intercom API here")
	}
	if me.Type != "admin" || !idRe.MatchString(me.ID) {
		return admin{}, errors.New("the token doesn't act as an Intercom admin")
	}
	return me, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	me, err := c.me(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "Signed in as " + clip(me.Name, 80)
	if me.App.Name != "" {
		msg += " in " + clip(me.App.Name, 80)
	}
	return sdk.Health{Status: "ok", Message: msg}
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
	Conversation flexID `json:"conversation"`
	State        string `json:"state"`
	Limit        int    `json:"limit"`
	Query        string `json:"query"`
	Text         string `json:"text"`
	Until        string `json:"until"`
}

type author struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type part struct {
	ID        string  `json:"id"`
	PartType  string  `json:"part_type"`
	Body      string  `json:"body"`
	CreatedAt int64   `json:"created_at"`
	Author    *author `json:"author"`
}

type conversation struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	State           string `json:"state"`
	Priority        string `json:"priority"`
	CreatedAt       int64  `json:"created_at"`
	UpdatedAt       int64  `json:"updated_at"`
	SnoozedUntil    int64  `json:"snoozed_until"`
	AdminAssigneeID any    `json:"admin_assignee_id"`
	Source          struct {
		Type    string  `json:"type"`
		Subject string  `json:"subject"`
		Body    string  `json:"body"`
		Author  *author `json:"author"`
	} `json:"source"`
	Parts struct {
		Parts []part `json:"conversation_parts"`
	} `json:"conversation_parts"`
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// plain turns Intercom's HTML bodies into text.
func plain(s string) string {
	s = strings.NewReplacer("<br>", "\n", "<br/>", "\n", "<br />", "\n", "</p>", "\n").Replace(s)
	return strings.TrimSpace(html.UnescapeString(tagRe.ReplaceAllString(s, "")))
}

// htmlBody makes the text an HTML body that shows exactly as written: Intercom's
// bodies are HTML, so markup an agent writes (a link, an image, hidden text)
// would otherwise reach the customer as markup.
func htmlBody(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	return "<p>" + strings.ReplaceAll(html.EscapeString(s), "\n", "<br>") + "</p>"
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func when(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func limit(n, def int) (int, error) {
	if n == 0 {
		return def, nil
	}
	if n < 1 || n > 50 {
		return 0, errors.New("the limit is 1 to 50")
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

func person(a *author) map[string]any {
	if a == nil {
		return nil
	}
	o := map[string]any{"name": clip(a.Name, 80), "type": a.Type}
	if a.Email != "" {
		o["email"] = clip(a.Email, 200)
	}
	return o
}

func assignee(v any) any {
	switch x := v.(type) {
	case string:
		if x != "" {
			return x
		}
	case float64:
		if x > 0 {
			return strconv.FormatInt(int64(x), 10)
		}
	}
	return nil
}

func summary(cv conversation) map[string]any {
	o := map[string]any{"conversation": cv.ID, "title": clip(cv.Title, 200), "state": cv.State, "assigneeId": assignee(cv.AdminAssigneeID),
		"customer": person(cv.Source.Author), "updated": when(cv.UpdatedAt), "message": clip(plain(cv.Source.Body), 300)}
	if cv.Priority != "" {
		o["priority"] = cv.Priority
	}
	if cv.State == "snoozed" {
		o["snoozedUntil"] = when(cv.SnoozedUntil)
	}
	return o
}

func (c *conn) get(ctx context.Context, id string) (conversation, error) {
	var cv conversation
	q := url.Values{"display_as": {"plaintext"}}
	if _, err := c.api.Do(ctx, http.MethodGet, "/conversations/"+url.PathEscape(id), q, nil, &cv); err != nil {
		return conversation{}, friendly(err, "conversation "+id)
	}
	return cv, nil
}

// undoTo is the undo that brings a conversation back to the state it had.
func undoTo(id string, cv conversation, now time.Time) *sdk.Undo {
	switch cv.State {
	case "open":
		return sdk.UndoWith("open", map[string]string{"conversation": id}, "Reopen conversation "+id)
	case "closed":
		return sdk.UndoWith("close", map[string]string{"conversation": id}, "Close conversation "+id+" again")
	case "snoozed":
		if time.Unix(cv.SnoozedUntil, 0).After(now.Add(time.Minute)) {
			return sdk.UndoWith("snooze", map[string]string{"conversation": id, "until": when(cv.SnoozedUntil)}, "Snooze conversation "+id+" again")
		}
		return sdk.UndoWith("open", map[string]string{"conversation": id}, "Reopen conversation "+id)
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
	cid := string(p.Conversation)
	switch call.Action {
	case "conversations", "contacts":
	default:
		if !convRe.MatchString(cid) {
			return sdk.Result{}, errors.New("the conversation is its id, a number like 123456789")
		}
	}
	switch call.Action {
	case "conversations":
		st := p.State
		if st == "" {
			st = "open"
		}
		var q map[string]any
		switch st {
		case "open", "closed", "snoozed":
			q = map[string]any{"field": "state", "operator": "=", "value": st}
		case "all":
			q = map[string]any{"field": "created_at", "operator": ">", "value": 0}
		default:
			return sdk.Result{}, errors.New("the state is open, closed, snoozed or all")
		}
		n, err := limit(p.Limit, 20)
		if err != nil {
			return sdk.Result{}, err
		}
		var a struct {
			Conversations []conversation `json:"conversations"`
		}
		body := map[string]any{"query": q, "pagination": map[string]any{"per_page": n}, "sort": map[string]any{"field": "updated_at", "order": "descending"}}
		if _, err := c.api.Do(ctx, http.MethodPost, "/conversations/search", nil, body, &a); err != nil {
			return sdk.Result{}, friendly(err, "conversation search here")
		}
		sort.SliceStable(a.Conversations, func(i, j int) bool { return a.Conversations[i].UpdatedAt > a.Conversations[j].UpdatedAt })
		out := []map[string]any{}
		for i, cv := range a.Conversations {
			if i >= n {
				break
			}
			out = append(out, summary(cv))
		}
		return sdk.JSON(out)

	case "conversation":
		cv, err := c.get(ctx, cid)
		if err != nil {
			return sdk.Result{}, err
		}
		msgs := []map[string]any{{"kind": "customer", "from": person(cv.Source.Author), "at": when(cv.CreatedAt), "text": clip(plain(cv.Source.Body), 4000)}}
		ps := cv.Parts.Parts
		if len(ps) > 50 {
			ps = ps[len(ps)-50:]
		}
		for _, x := range ps {
			kind := x.PartType
			switch {
			case x.PartType == "note":
				kind = "internal note"
			case x.PartType == "comment" && x.Author != nil && x.Author.Type == "admin":
				kind = "reply"
			case x.PartType == "comment" && x.Author != nil && x.Author.Type == "bot":
				kind = "bot"
			case x.PartType == "comment":
				kind = "customer"
			}
			e := map[string]any{"id": x.ID, "kind": kind, "at": when(x.CreatedAt)}
			if x.Author != nil {
				e["from"] = clip(x.Author.Name, 80)
			}
			if t := plain(x.Body); t != "" {
				e["text"] = clip(t, 4000)
			}
			msgs = append(msgs, e)
		}
		o := summary(cv)
		delete(o, "message")
		o["channel"] = cv.Source.Type
		if cv.Source.Subject != "" {
			o["subject"] = clip(plain(cv.Source.Subject), 200)
		}
		o["messages"] = msgs
		return sdk.JSON(o)

	case "contacts":
		query := strings.TrimSpace(p.Query)
		if query == "" || utf8.RuneCountInString(query) > 200 || ctrlRe.MatchString(query) || strings.ContainsAny(query, "\r\n\t") {
			return sdk.Result{}, errors.New("the query is 1 to 200 characters on one line")
		}
		n, err := limit(p.Limit, 20)
		if err != nil {
			return sdk.Result{}, err
		}
		var a struct {
			Data []struct {
				ID         string `json:"id"`
				Role       string `json:"role"`
				Name       string `json:"name"`
				Email      string `json:"email"`
				Phone      string `json:"phone"`
				LastSeenAt int64  `json:"last_seen_at"`
			} `json:"data"`
		}
		body := map[string]any{"query": map[string]any{"operator": "OR", "value": []any{
			map[string]any{"field": "name", "operator": "~", "value": query},
			map[string]any{"field": "email", "operator": "~", "value": query},
		}}, "pagination": map[string]any{"per_page": n}}
		if _, err := c.api.Do(ctx, http.MethodPost, "/contacts/search", nil, body, &a); err != nil {
			return sdk.Result{}, friendly(err, "contact search here")
		}
		out := []map[string]any{}
		for i, x := range a.Data {
			if i >= n {
				break
			}
			e := map[string]any{"id": x.ID, "name": clip(x.Name, 80), "email": clip(x.Email, 200), "role": x.Role, "lastSeen": when(x.LastSeenAt)}
			if x.Phone != "" {
				e["phone"] = clip(x.Phone, 40)
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "add_note", "reply":
		body, err := text(p.Text)
		if err != nil {
			return sdk.Result{}, err
		}
		note := call.Action == "add_note"
		if f := mention.Find(body); note && f.Wildcard != "" {
			return sdk.Result{}, fmt.Errorf("%s would notify the whole team; wildcard mentions aren't sent from Conduit", f.Wildcard)
		}
		cv, err := c.get(ctx, cid)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			if note {
				s := fmt.Sprintf("Add an internal note to conversation %s; the customer isn't sent anything", cid)
				if pv := mention.Find(body).Preview(); pv != "" {
					s += "; it " + pv
				}
				return sdk.Result{Plan: &sdk.Plan{Summary: s,
					Changes: []sdk.Change{{Target: "conversation " + cid, Op: "note", After: mustJSON(map[string]any{"text": clip(body, 2000)})}}}}, nil
			}
			to := "the customer"
			if a := cv.Source.Author; a != nil && a.Type != "admin" {
				to = clip(a.Name, 80)
				if a.Email != "" {
					to += " <" + clip(a.Email, 200) + ">"
				}
			}
			s := fmt.Sprintf("Send a reply on conversation %s to %s; it can't be unsent", cid, to)
			if cv.State != "open" {
				s += " (it also reopens the conversation)"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: s,
				Changes: []sdk.Change{{Target: "conversation " + cid, Op: "reply", After: mustJSON(map[string]any{"to": to, "text": clip(body, 2000)})}}}}, nil
		}
		me, err := c.me(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		kind := "comment"
		if note {
			kind = "note"
		}
		in := map[string]any{"message_type": kind, "type": "admin", "admin_id": me.ID, "body": htmlBody(body)}
		if _, err := c.api.Do(ctx, http.MethodPost, "/conversations/"+url.PathEscape(cid)+"/reply", nil, in, nil); err != nil {
			return sdk.Result{}, friendly(err, "conversation "+cid)
		}
		added := "reply"
		if note {
			added = "note"
		}
		return sdk.JSON(map[string]any{"conversation": cid, "added": added})

	case "open", "close", "snooze":
		to := map[string]string{"open": "open", "close": "closed", "snooze": "snoozed"}[call.Action]
		var until time.Time
		now := time.Now()
		if call.Action == "snooze" {
			until, err = time.Parse(time.RFC3339, strings.TrimSpace(p.Until))
			switch {
			case err != nil:
				return sdk.Result{}, errors.New("until is a time like 2026-11-10T09:00:00Z")
			case !until.After(now.Add(time.Minute)):
				return sdk.Result{}, errors.New("until is in the past; snooze to a future time")
			case until.After(now.AddDate(1, 0, 0)):
				return sdk.Result{}, errors.New("until is at most a year ahead")
			}
			until = until.UTC().Truncate(time.Second)
		} else if p.Until != "" {
			return sdk.Result{}, errors.New("until goes with snooze")
		}
		cv, err := c.get(ctx, cid)
		if err != nil {
			return sdk.Result{}, err
		}
		if cv.State == to && (to != "snoozed" || cv.SnoozedUntil == until.Unix()) {
			return sdk.JSON(map[string]any{"conversation": cid, "state": cv.State, "note": "nothing to change: the conversation is already " + to})
		}
		after := map[string]any{"state": to}
		if to == "snoozed" {
			after["until"] = when(until.Unix())
		}
		if call.DryRun {
			// Ids and states only: this plan goes in the audit log as is.
			s := fmt.Sprintf("Set conversation %s from %s to %s", cid, cv.State, to)
			switch to {
			case "closed":
				s = fmt.Sprintf("Close conversation %s (now %s); Intercom may ask the customer to rate it", cid, cv.State)
			case "snoozed":
				s = fmt.Sprintf("Snooze conversation %s (now %s) until %s", cid, cv.State, when(until.Unix()))
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: s,
				Changes: []sdk.Change{{Target: "conversation " + cid, Op: "update", Before: mustJSON(map[string]any{"state": cv.State}), After: mustJSON(after)}}}}, nil
		}
		me, err := c.me(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		// Intercom's message types are open, close and snoozed.
		in := map[string]any{"message_type": call.Action, "type": "admin", "admin_id": me.ID}
		if to == "snoozed" {
			in["message_type"] = "snoozed"
		}
		if to == "snoozed" {
			in["snoozed_until"] = until.Unix()
		}
		var got conversation
		if _, err := c.api.Do(ctx, http.MethodPost, "/conversations/"+url.PathEscape(cid)+"/parts", nil, in, &got); err != nil {
			return sdk.Result{}, friendly(err, "conversation "+cid)
		}
		state := got.State
		if state == "" {
			state = to
		}
		r, err := sdk.JSON(map[string]any{"conversation": cid, "from": cv.State, "to": state})
		r.Undo = undoTo(cid, cv, now)
		return r, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
