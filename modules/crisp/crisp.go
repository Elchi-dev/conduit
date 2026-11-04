// Package crisp works with a Crisp website's inbox through the REST API and
// a plugin token (identifier and key): conversations, their messages,
// messages to the visitor, private notes, and resolving and reopening.
//
// A message reaches the visitor (in the chat, or by email when they're
// away) and can't be unsent, so it's destructive; so is resolving, which
// can ask the visitor to rate the conversation. Conversations are personal
// data, so the actions that return them are sensitive.
package crisp

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
	"github.com/elchi-dev/conduit/modules/internal/mention"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Crisp website.
type Config struct {
	WebsiteID  string `json:"websiteId"`  // the website's id (Settings, Website settings, Setup)
	Identifier string `json:"identifier"` // secret:// plugin token identifier
	Key        string `json:"key"`        // secret:// plugin token key
}

type conn struct {
	api     *rest.Client
	website string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.crisp.chat/v1 (tests).
	Base string
}

// New returns the Crisp module.
func New() *Module { return &Module{} }

const maxText = 10000

var (
	uuidRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	sessionRe = regexp.MustCompile(`^session_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ctrlRe    = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	cv := `"conversation":{"type":"string","description":"The conversation's session id, e.g. session_1f2e…"}`
	text := `"text":{"type":"string","format":"textarea","maxLength":10000}`
	return sdk.Manifest{
		ID: "crisp", Name: "Crisp", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "Crisp: conversations and their messages, messages to visitors (destructive: they're sent), private notes, resolving and reopening.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["websiteId","identifier","key"],"properties":{
			"websiteId":{"type":"string","description":"The website id (Settings, Website settings, Setup instructions)"},
			"identifier":{"type":"string","x-secret":true,"description":"The plugin token's identifier (Marketplace, your plugin, Tokens)"},
			"key":{"type":"string","x-secret":true,"description":"The plugin token's key"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "conversations", Title: "Conversations", Description: "Conversations by state (unresolved by default, resolved or all), most recent first: session id, visitor, state, unread count, assignee and the last message.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"state":{"type":"string","enum":["unresolved","resolved","all"],"default":"unresolved"},"limit":{"type":"integer","minimum":1,"maximum":50,"default":20}}}`)},
			{Name: "messages", Title: "Open a conversation", Description: "A conversation's visitor and state with its latest messages, private notes included.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation"],"properties":{` + cv + `}}`)},
			{Name: "send_message", Title: "Message the visitor", Description: "A text message from an operator, shown in the chat (and emailed when the visitor is away). It can't be unsent, so it's destructive. The preview shows who gets it and the text.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","text"],"properties":{` + cv + `,` + text + `}}`)},
			{Name: "add_note", Title: "Add a private note", Description: "A note only operators see; the visitor isn't sent anything.", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","text"],"properties":{` + cv + `,` + text + `}}`)},
			{Name: "set_state", Title: "Reopen or set pending", Description: "Sets a conversation unresolved or pending (also reopens a resolved one). Resolving is resolve. Undo sets the state it had.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","state"],"properties":{` + cv + `,"state":{"type":"string","enum":["unresolved","pending"]}}}`)},
			{Name: "resolve", Title: "Resolve a conversation", Description: "Sets a conversation resolved. Crisp may ask the visitor to rate it or email a transcript, which can't be unsent, so it's destructive. Undo sets the state it had.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
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
	website := strings.ToLower(strings.TrimSpace(c.WebsiteID))
	if !uuidRe.MatchString(website) {
		return errors.New("the website id looks like 8c842203-7ed8-4e29-a608-7cf78a7d2fcc (Settings, Website settings, Setup instructions)")
	}
	if !strings.HasPrefix(c.Identifier, "secret://") || !strings.HasPrefix(c.Key, "secret://") {
		return errors.New("store the plugin token's identifier and key in the vault and enter their secret:// references")
	}
	base := "https://api.crisp.chat/v1"
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	idRef, keyRef := c.Identifier, c.Key
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		ident, err := h.Secret(ctx, idRef)
		if err != nil {
			return err
		}
		key, err := h.Secret(ctx, keyRef)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(ident)+":"+strings.TrimSpace(key))))
		return nil
	})
	api.Header.Set("X-Crisp-Tier", "plugin")
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, website: website})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Crisp refused the plugin token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Crisp refused: the plugin token lacks the scope for this, or isn't installed on this website")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusBadRequest):
		return fmt.Errorf("Crisp refused the request: %v", err)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Crisp's rate limit was hit; try again in a minute")
	}
	return err
}

// do calls Crisp, which wraps every answer in {"error","reason","data"}.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any, what string) error {
	var env struct {
		Error  bool            `json:"error"`
		Reason string          `json:"reason"`
		Data   json.RawMessage `json:"data"`
	}
	if _, err := c.api.Do(ctx, method, "/website/"+c.website+path, q, body, &env); err != nil {
		return friendly(err, what)
	}
	if env.Error {
		return fmt.Errorf("Crisp refused the request (%s)", clip(rest.Redact(env.Reason), 60))
	}
	if out != nil && len(env.Data) > 0 && string(env.Data) != "null" {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("unexpected answer from Crisp: %w", err)
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
	var w struct {
		Name   string `json:"name"`
		Domain string `json:"domain"`
	}
	if err := c.do(ctx, http.MethodGet, "", nil, nil, &w, "website "+c.website); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "Website " + clip(w.Name, 80)}
}

type input struct {
	Conversation string `json:"conversation"`
	State        string `json:"state"`
	Limit        int    `json:"limit"`
	Text         string `json:"text"`
}

type meta struct {
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
}

type conversation struct {
	SessionID   string `json:"session_id"`
	State       string `json:"state"`
	LastMessage string `json:"last_message"`
	Topic       string `json:"topic"`
	UpdatedAt   int64  `json:"updated_at"`
	CreatedAt   int64  `json:"created_at"`
	Unread      struct {
		Operator int `json:"operator"`
	} `json:"unread"`
	Assigned *struct {
		UserID string `json:"user_id"`
	} `json:"assigned"`
	Meta meta `json:"meta"`
}

type message struct {
	Type        string          `json:"type"`
	From        string          `json:"from"`
	Origin      string          `json:"origin"`
	Content     json.RawMessage `json:"content"`
	Timestamp   int64           `json:"timestamp"`
	Fingerprint int64           `json:"fingerprint"`
	User        struct {
		Nickname string `json:"nickname"`
	} `json:"user"`
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

func when(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
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

func visitor(mt meta) map[string]any {
	o := map[string]any{"name": clip(mt.Nickname, 80)}
	if mt.Email != "" {
		o["email"] = clip(mt.Email, 200)
	}
	if mt.Phone != "" {
		o["phone"] = clip(mt.Phone, 40)
	}
	return o
}

func summary(cv conversation) map[string]any {
	o := map[string]any{"conversation": cv.SessionID, "state": cv.State, "visitor": visitor(cv.Meta), "unread": cv.Unread.Operator,
		"updated": when(cv.UpdatedAt), "lastMessage": clip(cv.LastMessage, 300)}
	if cv.Topic != "" {
		o["topic"] = clip(cv.Topic, 200)
	}
	if cv.Assigned != nil && cv.Assigned.UserID != "" {
		o["assigneeId"] = cv.Assigned.UserID
	}
	return o
}

func (c *conn) get(ctx context.Context, sid string) (conversation, error) {
	var cv conversation
	if err := c.do(ctx, http.MethodGet, "/conversation/"+url.PathEscape(sid), nil, nil, &cv, "conversation "+sid); err != nil {
		return conversation{}, err
	}
	return cv, nil
}

// undoTo is the undo that brings a conversation back to the state it had.
func undoTo(sid, state string) *sdk.Undo {
	switch state {
	case "resolved":
		return sdk.UndoWith("resolve", map[string]string{"conversation": sid}, "Resolve the conversation again")
	case "unresolved", "pending":
		return sdk.UndoWith("set_state", map[string]string{"conversation": sid, "state": state}, "Set the conversation back to "+state)
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
	sid := strings.TrimSpace(p.Conversation)
	if call.Action != "conversations" && !sessionRe.MatchString(sid) {
		return sdk.Result{}, errors.New("the conversation is its session id, like session_700c65e1-85e2-465a-b9ac-ecb5ec2c9881")
	}
	switch call.Action {
	case "conversations":
		st := p.State
		if st == "" {
			st = "unresolved"
		}
		n := p.Limit
		if n == 0 {
			n = 20
		}
		if n < 1 || n > 50 {
			return sdk.Result{}, errors.New("the limit is 1 to 50")
		}
		q := url.Values{"per_page": {strconv.Itoa(max(n, 20))}} // 20 is Crisp's smallest page
		switch st {
		case "unresolved":
			q.Set("filter_not_resolved", "1")
		case "resolved":
			q.Set("filter_resolved", "1")
		case "all":
		default:
			return sdk.Result{}, errors.New("the state is unresolved, resolved or all")
		}
		var list []conversation
		if err := c.do(ctx, http.MethodGet, "/conversations/1", q, nil, &list, "website "+c.website); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i, cv := range list {
			if i >= n {
				break
			}
			out = append(out, summary(cv))
		}
		return sdk.JSON(out)

	case "messages":
		cv, err := c.get(ctx, sid)
		if err != nil {
			return sdk.Result{}, err
		}
		var ms []message
		if err := c.do(ctx, http.MethodGet, "/conversation/"+url.PathEscape(sid)+"/messages", nil, nil, &ms, "conversation "+sid); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, x := range ms {
			kind := map[string]string{"user": "visitor", "operator": "operator"}[x.From]
			if x.Type == "note" {
				kind = "private note"
			}
			e := map[string]any{"id": x.Fingerprint, "kind": kind, "type": x.Type, "at": when(x.Timestamp)}
			if x.Origin != "" {
				e["origin"] = x.Origin
			}
			if x.User.Nickname != "" {
				e["from"] = clip(x.User.Nickname, 80)
			}
			var s string
			if json.Unmarshal(x.Content, &s) == nil {
				e["text"] = clip(s, 4000)
			}
			list = append(list, e)
		}
		o := summary(cv)
		delete(o, "lastMessage")
		o["messages"] = list
		return sdk.JSON(o)

	case "send_message", "add_note":
		body, err := text(p.Text)
		if err != nil {
			return sdk.Result{}, err
		}
		note := call.Action == "add_note"
		if f := mention.Find(body); note && f.Wildcard != "" {
			return sdk.Result{}, fmt.Errorf("%s would notify every operator; wildcard mentions aren't sent from Conduit", f.Wildcard)
		}
		cv, err := c.get(ctx, sid)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			if note {
				return sdk.Result{Plan: &sdk.Plan{Summary: "Add a private note to the conversation; the visitor isn't sent anything",
					Changes: []sdk.Change{{Target: "conversation " + sid, Op: "note", After: mustJSON(map[string]any{"text": clip(body, 2000)})}}}}, nil
			}
			to := "the visitor"
			if cv.Meta.Nickname != "" {
				to = clip(cv.Meta.Nickname, 80)
			}
			if cv.Meta.Email != "" {
				to += " <" + clip(cv.Meta.Email, 200) + ">"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Send a message to %s in the chat (Crisp emails it if they're away); it can't be unsent", to),
				Changes: []sdk.Change{{Target: "conversation " + sid, Op: "message", After: mustJSON(map[string]any{"to": to, "text": clip(body, 2000)})}}}}, nil
		}
		typ := "text"
		if note {
			typ = "note"
		}
		var out struct {
			Fingerprint int64 `json:"fingerprint"`
		}
		in := map[string]any{"type": typ, "from": "operator", "origin": "chat", "content": body}
		if err := c.do(ctx, http.MethodPost, "/conversation/"+url.PathEscape(sid)+"/message", nil, in, &out, "conversation "+sid); err != nil {
			return sdk.Result{}, err
		}
		added := "message"
		if note {
			added = "note"
		}
		return sdk.JSON(map[string]any{"conversation": sid, "added": added, "id": out.Fingerprint})

	case "set_state", "resolve":
		to := p.State
		switch {
		case call.Action == "resolve":
			if to != "" {
				return sdk.Result{}, errors.New("resolve takes no state")
			}
			to = "resolved"
		case to == "resolved":
			return sdk.Result{}, errors.New("resolving may message the visitor; use resolve")
		case to != "unresolved" && to != "pending":
			return sdk.Result{}, errors.New("the state is unresolved or pending (resolve resolves it)")
		}
		cv, err := c.get(ctx, sid)
		if err != nil {
			return sdk.Result{}, err
		}
		if cv.State == to {
			return sdk.JSON(map[string]any{"conversation": sid, "state": cv.State, "note": "nothing to change: the conversation is already " + to})
		}
		if call.DryRun {
			// Ids and states only: this plan goes in the audit log as is.
			s := fmt.Sprintf("Set the conversation from %s to %s", cv.State, to)
			if to == "resolved" {
				s = fmt.Sprintf("Resolve the conversation (now %s); Crisp may ask the visitor to rate it", cv.State)
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: s,
				Changes: []sdk.Change{{Target: "conversation " + sid, Op: "update", Before: mustJSON(map[string]any{"state": cv.State}), After: mustJSON(map[string]any{"state": to})}}}}, nil
		}
		if err := c.do(ctx, http.MethodPatch, "/conversation/"+url.PathEscape(sid)+"/state", nil, map[string]any{"state": to}, nil, "conversation "+sid); err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"conversation": sid, "from": cv.State, "to": to})
		r.Undo = undoTo(sid, cv.State)
		return r, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
