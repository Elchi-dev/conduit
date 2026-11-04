// Package chatwoot works with Chatwoot (app.chatwoot.com or self-hosted)
// through its application API with a user access token: conversations,
// their messages, private notes (undo deletes them), replies to the contact,
// resolving and reopening, and assignment.
//
// A reply goes out to the contact on the conversation's channel (email,
// website chat, WhatsApp, ...) and can't be unsent, so it's destructive.
// Conversations and messages are personal data, so the actions that return
// them are sensitive.
package chatwoot

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
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Chatwoot account.
type Config struct {
	Address   string          `json:"address"`   // https://app.chatwoot.com or a self-hosted server
	AccountID json.RawMessage `json:"accountId"` // the account's number, as a string or number
	Token     string          `json:"token"`     // secret:// user access token
}

type conn struct {
	api     *rest.Client
	site    string
	account string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Chatwoot module.
func New() *Module { return &Module{} }

const (
	defaultAddress = "https://app.chatwoot.com"
	maxText        = 20000
)

var (
	idRe     = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	prefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
	ctrlRe   = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	cv := `"conversation":{"type":["string","integer"],"description":"Conversation number, e.g. 42"}`
	text := `"text":{"type":"string","format":"textarea","maxLength":20000}`
	return sdk.Manifest{
		ID: "chatwoot", Name: "Chatwoot", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "Chatwoot: open and assigned conversations, their messages, private notes, replies to contacts (destructive: they're sent), resolving, reopening and assigning.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["accountId","token"],"properties":{
			"address":{"type":"string","default":"https://app.chatwoot.com","description":"https://app.chatwoot.com, or your server, e.g. https://chat.example.com"},
			"accountId":{"type":["string","integer"],"description":"The account's number, from the address bar: /app/accounts/<number>/..."},
			"token":{"type":"string","x-secret":true,"description":"Your access token (Profile settings, Access token)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "conversations", Title: "Conversations", Description: "Conversations by status (open by default) and assignee (mine, unassigned, assigned or all), most recent first: number, contact, inbox, assignee, unread count and the last message.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["open","pending","resolved","snoozed","all"],"default":"open"},"assignee":{"type":"string","enum":["me","unassigned","assigned","all"],"default":"all"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "messages", Title: "Open a conversation", Description: "A conversation's contact, status and assignee with its latest messages, including private notes.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation"],"properties":{` + cv + `}}`)},
			{Name: "agents", Title: "Agents", Description: "The account's agents with their id, name and availability, to assign conversations to.", Risk: sdk.RiskRead},
			{Name: "add_note", Title: "Add a private note", Description: "A note only agents see; the contact isn't sent anything. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","text"],"properties":{` + cv + `,` + text + `}}`)},
			{Name: "delete_note", Title: "Delete a private note", Description: "Deletes one private note. Only private notes: messages to or from the contact are refused. The preview quotes the note.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","note"],"properties":{` + cv + `,"note":{"type":["string","integer"],"description":"The note's message id"}}}`)},
			{Name: "reply", Title: "Reply to the contact", Description: "Sends a message to the contact on the conversation's channel. It can't be unsent, so it's destructive. The preview shows who gets it, how, and the text.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","text"],"properties":{` + cv + `,` + text + `}}`)},
			{Name: "set_status", Title: "Reopen or set pending", Description: "Sets a conversation open or pending (also reopens a resolved one). Resolving is resolve. Undo sets the status it had.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","status"],"properties":{` + cv + `,"status":{"type":"string","enum":["open","pending"]}}}`)},
			{Name: "resolve", Title: "Resolve a conversation", Description: "Sets a conversation resolved. Chatwoot may message the contact (a satisfaction survey, or the inbox's resolution message), which can't be unsent, so it's destructive. Undo sets the status it had.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation"],"properties":{` + cv + `}}`)},
			{Name: "assign", Title: "Assign a conversation", Description: "To an agent (id from agents), or unassign it. Undo gives it back to whoever had it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation"],"properties":{` + cv + `,"assignee":{"type":["string","integer"],"description":"Agent id"},"unassign":{"type":"boolean"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	addr := strings.TrimSpace(c.Address)
	if addr == "" {
		addr = defaultAddress
	}
	u, err := url.Parse(addr)
	prefix := ""
	if err == nil {
		prefix = strings.TrimRight(u.Path, "/")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return errors.New("the address is https://app.chatwoot.com or your server, like https://chat.example.com")
	}
	var acct flexID
	if len(c.AccountID) == 0 || json.Unmarshal(c.AccountID, &acct) != nil || !idRe.MatchString(string(acct)) {
		return errors.New("the account id is the number in your Chatwoot address: /app/accounts/<number>/")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	site := u.Scheme + "://" + u.Host + prefix
	ref := c.Token
	api := rest.New(site+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("api_access_token", strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	// api_access_token is a custom header, which Go would forward on a redirect.
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, site: site, account: string(acct)})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Chatwoot refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Chatwoot refused: this user can't do that here")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusUnprocessableEntity):
		return fmt.Errorf("Chatwoot refused the change: %v", err)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Chatwoot's rate limit was hit; try again in a minute")
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
		Name     string `json:"name"`
		Accounts []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"accounts"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/profile", nil, nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "Chatwoot API here").Error()}
	}
	for _, a := range me.Accounts {
		if strconv.FormatInt(a.ID, 10) == c.account {
			return sdk.Health{Status: "ok", Message: clip(me.Name, 80) + " in " + clip(a.Name, 80)}
		}
	}
	return sdk.Health{Status: "down", Message: "the token's user isn't a member of account " + c.account}
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
	Conversation flexID `json:"conversation"`
	Note         flexID `json:"note"`
	Status       string `json:"status"`
	Assignee     flexID `json:"assignee"`
	Unassign     bool   `json:"unassign"`
	Limit        int    `json:"limit"`
	Text         string `json:"text"`
}

type person struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone_number"`
	Type  string `json:"type"`
}

type message struct {
	ID          int64   `json:"id"`
	Content     string  `json:"content"`
	MessageType int     `json:"message_type"` // 0 incoming, 1 outgoing, 2 activity, 3 template
	Private     bool    `json:"private"`
	CreatedAt   float64 `json:"created_at"`
	Sender      *person `json:"sender"`
}

type conversation struct {
	ID             int64   `json:"id"`
	Status         string  `json:"status"`
	InboxID        int64   `json:"inbox_id"`
	Unread         int     `json:"unread_count"`
	LastActivityAt float64 `json:"last_activity_at"`
	Meta           struct {
		Sender   *person `json:"sender"`
		Assignee *person `json:"assignee"`
		Channel  string  `json:"channel"`
	} `json:"meta"`
	Messages []message `json:"messages"`
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

func when(unix float64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(int64(unix), 0).UTC().Format(time.RFC3339)
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

func contact(p *person) map[string]any {
	if p == nil {
		return nil
	}
	o := map[string]any{"name": clip(p.Name, 80)}
	if p.Email != "" {
		o["email"] = clip(p.Email, 200)
	}
	if p.Phone != "" {
		o["phone"] = clip(p.Phone, 40)
	}
	return o
}

func name(p *person) string {
	if p == nil {
		return "nobody"
	}
	return clip(p.Name, 80)
}

func (c *conn) path(rest string) string { return "/accounts/" + c.account + rest }

func (c *conn) summary(cv conversation) map[string]any {
	o := map[string]any{"conversation": cv.ID, "status": cv.Status, "inbox": cv.InboxID, "contact": contact(cv.Meta.Sender), "assignee": name(cv.Meta.Assignee),
		"unread": cv.Unread, "lastActivity": when(cv.LastActivityAt), "url": c.site + "/app/accounts/" + c.account + "/conversations/" + strconv.FormatInt(cv.ID, 10)}
	if n := len(cv.Messages); n > 0 {
		o["lastMessage"] = clip(cv.Messages[n-1].Content, 300)
	}
	return o
}

func (c *conn) get(ctx context.Context, id string) (conversation, error) {
	var cv conversation
	if _, err := c.api.Do(ctx, http.MethodGet, c.path("/conversations/"+id), nil, nil, &cv); err != nil {
		return conversation{}, friendly(err, "conversation "+id)
	}
	return cv, nil
}

func (c *conn) messages(ctx context.Context, id string, before int64) ([]message, error) {
	var a struct {
		Payload []message `json:"payload"`
	}
	var q url.Values
	if before > 0 {
		q = url.Values{"before": {strconv.FormatInt(before, 10)}}
	}
	if _, err := c.api.Do(ctx, http.MethodGet, c.path("/conversations/"+id+"/messages"), q, nil, &a); err != nil {
		return nil, friendly(err, "conversation "+id)
	}
	return a.Payload, nil
}

// findMessage looks for a message among the conversation's latest pages.
func (c *conn) findMessage(ctx context.Context, cid, mid string) (*message, error) {
	var before int64
	for page := 0; page < 5; page++ {
		ms, err := c.messages(ctx, cid, before)
		if err != nil {
			return nil, err
		}
		if len(ms) == 0 {
			break
		}
		for i := range ms {
			if strconv.FormatInt(ms[i].ID, 10) == mid {
				return &ms[i], nil
			}
			if before == 0 || ms[i].ID < before {
				before = ms[i].ID
			}
		}
	}
	return nil, fmt.Errorf("conversation %s has no message %s among its latest", cid, mid)
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
	if call.Action != "conversations" && call.Action != "agents" && !idRe.MatchString(cid) {
		return sdk.Result{}, errors.New("the conversation is its number, e.g. 42")
	}
	switch call.Action {
	case "conversations":
		st, as := p.Status, p.Assignee
		if st == "" {
			st = "open"
		}
		if as == "" {
			as = "all"
		}
		switch st {
		case "open", "pending", "resolved", "snoozed", "all":
		default:
			return sdk.Result{}, errors.New("the status is open, pending, resolved, snoozed or all")
		}
		switch as {
		case "me", "unassigned", "assigned", "all":
		default:
			return sdk.Result{}, errors.New("the assignee is me, unassigned, assigned or all")
		}
		n := p.Limit
		if n == 0 {
			n = 25
		}
		if n < 1 || n > 100 {
			return sdk.Result{}, errors.New("the limit is 1 to 100")
		}
		out := []map[string]any{}
		for page := 1; page <= 5 && len(out) < n; page++ {
			var a struct {
				Data struct {
					Payload []conversation `json:"payload"`
				} `json:"data"`
			}
			q := url.Values{"status": {st}, "assignee_type": {string(as)}, "page": {strconv.Itoa(page)}}
			if _, err := c.api.Do(ctx, http.MethodGet, c.path("/conversations"), q, nil, &a); err != nil {
				return sdk.Result{}, friendly(err, "account "+c.account)
			}
			for _, cv := range a.Data.Payload {
				if len(out) < n {
					out = append(out, c.summary(cv))
				}
			}
			if len(a.Data.Payload) < 25 {
				break
			}
		}
		return sdk.JSON(out)

	case "messages":
		cv, err := c.get(ctx, cid)
		if err != nil {
			return sdk.Result{}, err
		}
		ms, err := c.messages(ctx, cid, 0)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, x := range ms {
			kind := map[int]string{0: "contact", 1: "agent", 2: "activity", 3: "template"}[x.MessageType]
			if x.Private {
				kind = "private note"
			}
			e := map[string]any{"id": x.ID, "kind": kind, "at": when(x.CreatedAt), "text": clip(x.Content, 4000)}
			if x.Sender != nil {
				e["from"] = clip(x.Sender.Name, 80)
			}
			list = append(list, e)
		}
		o := c.summary(cv)
		delete(o, "lastMessage")
		o["channel"] = cv.Meta.Channel
		o["messages"] = list
		return sdk.JSON(o)

	case "agents":
		var as []struct {
			ID           int64  `json:"id"`
			Name         string `json:"name"`
			Role         string `json:"role"`
			Availability string `json:"availability_status"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, c.path("/agents"), nil, nil, &as); err != nil {
			return sdk.Result{}, friendly(err, "account "+c.account)
		}
		list := []map[string]any{}
		for _, a := range as {
			list = append(list, map[string]any{"id": a.ID, "name": clip(a.Name, 80), "role": a.Role, "availability": a.Availability})
		}
		return sdk.JSON(list)

	case "add_note", "reply":
		body, err := text(p.Text)
		if err != nil {
			return sdk.Result{}, err
		}
		cv, err := c.get(ctx, cid)
		if err != nil {
			return sdk.Result{}, err
		}
		private := call.Action == "add_note"
		if call.DryRun {
			if private {
				return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add a private note to conversation %s; the contact isn't sent anything", cid),
					Changes: []sdk.Change{{Target: "conversation " + cid, Op: "note", After: mustJSON(map[string]any{"text": clip(body, 2000)})}}}}, nil
			}
			via := strings.TrimPrefix(cv.Meta.Channel, "Channel::")
			if via == "" {
				via = "its channel"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Send a reply on conversation %s to %s via %s; it can't be unsent", cid, name(cv.Meta.Sender), via),
				Changes: []sdk.Change{{Target: "conversation " + cid, Op: "reply", After: mustJSON(map[string]any{"to": contact(cv.Meta.Sender), "via": via, "text": clip(body, 2000)})}}}}, nil
		}
		var out message
		in := map[string]any{"content": body, "message_type": "outgoing", "private": private}
		if _, err := c.api.Do(ctx, http.MethodPost, c.path("/conversations/"+cid+"/messages"), nil, in, &out); err != nil {
			return sdk.Result{}, friendly(err, "conversation "+cid)
		}
		if !private {
			return sdk.JSON(map[string]any{"conversation": cv.ID, "reply": out.ID})
		}
		r, err := sdk.JSON(map[string]any{"conversation": cv.ID, "note": out.ID})
		if out.ID > 0 {
			r.Undo = sdk.UndoWith("delete_note", map[string]string{"conversation": cid, "note": strconv.FormatInt(out.ID, 10)}, "Delete the note on conversation "+cid)
		}
		return r, err

	case "delete_note":
		nid := string(p.Note)
		if !idRe.MatchString(nid) {
			return sdk.Result{}, errors.New("the note is its message id")
		}
		msg, err := c.findMessage(ctx, cid, nid)
		if err != nil {
			return sdk.Result{}, err
		}
		if !msg.Private {
			return sdk.Result{}, fmt.Errorf("message %s isn't a private note; only private notes can be deleted here", nid)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete private note %s on conversation %s", nid, cid),
				Changes: []sdk.Change{{Target: "conversation " + cid, Op: "delete", Before: mustJSON(map[string]any{"text": clip(msg.Content, 500)})}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodDelete, c.path("/conversations/"+cid+"/messages/"+nid), nil, nil, nil); err != nil {
			return sdk.Result{}, friendly(err, "note "+nid)
		}
		return sdk.JSON(map[string]any{"conversation": cid, "deleted": nid})

	case "set_status", "resolve":
		to := p.Status
		switch {
		case call.Action == "resolve":
			to = "resolved"
		case to == "resolved":
			return sdk.Result{}, errors.New("resolving a conversation may message the contact; use resolve")
		case to != "open" && to != "pending":
			return sdk.Result{}, errors.New("the status is open or pending (resolve resolves it)")
		}
		cv, err := c.get(ctx, cid)
		if err != nil {
			return sdk.Result{}, err
		}
		if cv.Status == to {
			return sdk.JSON(map[string]any{"conversation": cv.ID, "status": cv.Status, "note": "the conversation already has this status"})
		}
		if call.DryRun {
			// Ids and statuses only: this plan goes in the audit log as is.
			summary := fmt.Sprintf("Set conversation %s from %s to %s", cid, cv.Status, to)
			if to == "resolved" {
				summary = fmt.Sprintf("Resolve conversation %s (now %s); it may message the contact (satisfaction survey or resolution notice)", cid, cv.Status)
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: summary,
				Changes: []sdk.Change{{Target: "conversation " + cid, Op: "update", Before: mustJSON(map[string]any{"status": cv.Status}), After: mustJSON(map[string]any{"status": to})}}}}, nil
		}
		var a struct {
			Payload struct {
				CurrentStatus string `json:"current_status"`
			} `json:"payload"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, c.path("/conversations/"+cid+"/toggle_status"), nil, map[string]any{"status": to}, &a); err != nil {
			return sdk.Result{}, friendly(err, "conversation "+cid)
		}
		now := a.Payload.CurrentStatus
		if now == "" {
			now = to
		}
		r, err := sdk.JSON(map[string]any{"conversation": cv.ID, "from": cv.Status, "to": now})
		switch cv.Status {
		case "open", "pending":
			r.Undo = sdk.UndoWith("set_status", map[string]any{"conversation": cid, "status": cv.Status}, fmt.Sprintf("Set conversation %s back to %s", cid, cv.Status))
		case "resolved":
			r.Undo = sdk.UndoWith("resolve", map[string]any{"conversation": cid}, fmt.Sprintf("Resolve conversation %s again", cid))
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
		cv, err := c.get(ctx, cid)
		if err != nil {
			return sdk.Result{}, err
		}
		prev := cv.Meta.Assignee
		if (to == nil && prev == nil) || (to != nil && prev != nil && *to == prev.ID) {
			return sdk.JSON(map[string]any{"conversation": cv.ID, "note": "the conversation is already assigned that way"})
		}
		if call.DryRun {
			after := "nobody"
			if to != nil {
				after = "agent " + strconv.FormatInt(*to, 10)
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Assign conversation %s from %s to %s", cid, name(prev), after),
				Changes: []sdk.Change{{Target: "conversation " + cid, Op: "assign", Before: mustJSON(map[string]any{"assignee": name(prev)}), After: mustJSON(map[string]any{"assignee": after})}}}}, nil
		}
		var got *person
		if _, err := c.api.Do(ctx, http.MethodPost, c.path("/conversations/"+cid+"/assignments"), nil, map[string]any{"assignee_id": to}, &got); err != nil {
			return sdk.Result{}, friendly(err, "conversation "+cid)
		}
		undo := map[string]any{"conversation": cid, "unassign": true}
		if prev != nil {
			undo = map[string]any{"conversation": cid, "assignee": strconv.FormatInt(prev.ID, 10)}
		}
		r, err := sdk.JSON(map[string]any{"conversation": cv.ID, "from": name(prev), "to": name(got)})
		r.Undo = sdk.UndoWith("assign", undo, fmt.Sprintf("Give conversation %s back to %s", cid, name(prev)))
		return r, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
