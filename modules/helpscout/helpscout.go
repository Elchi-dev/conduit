// Package helpscout works with Help Scout's Inbox API 2.0 through an OAuth
// app (client credentials): mailboxes, conversations by status, one
// conversation with its threads, replies to the customer, internal notes
// and status changes.
//
// A reply emails the customer and can't be unsent, so it's destructive; so
// is closing, which can run workflows that email the customer.
// Conversations are personal data, so the actions that return them are
// sensitive.
package helpscout

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
	"github.com/elchi-dev/conduit/modules/internal/mention"
	"github.com/elchi-dev/conduit/modules/internal/oauth"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Help Scout account, through an OAuth app.
type Config struct {
	AppID     string `json:"appId"`     // secret:// app id (client id)
	AppSecret string `json:"appSecret"` // secret:// app secret (client secret)
}

type conn struct {
	api      *rest.Client
	http     *http.Client
	tokenURL string
	host     sdk.Host
	cfg      Config
	tok      oauth.Cache
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.helpscout.net/v2, and the token endpoint
	// with it (tests).
	Base string
}

// New returns the Help Scout module.
func New() *Module { return &Module{} }

const maxText = 20000

var (
	idRe   = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	ctrlRe = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
	tagRe  = regexp.MustCompile(`<[^>]*>`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	cv := `"conversation":{"type":["string","integer"],"description":"Conversation id (from conversations), e.g. 123456789"}`
	text := `"text":{"type":"string","format":"textarea","maxLength":20000}`
	return sdk.Manifest{
		ID: "helpscout", Name: "Help Scout", Version: "0.1.0", Category: "Communication", Icon: "headset",
		Description: "Help Scout: mailboxes, conversations and their threads, replies to customers (destructive: they're emailed), internal notes, and status changes.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["appId","appSecret"],"properties":{
			"appId":{"type":"string","x-secret":true,"description":"The app id of an OAuth app (Your Profile, My Apps, Create My App)"},
			"appSecret":{"type":"string","x-secret":true,"description":"That app's secret"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "mailboxes", Title: "Mailboxes", Description: "The mailboxes (id, name and address), to list conversations from.", Risk: sdk.RiskRead},
			{Name: "conversations", Title: "Conversations", Description: "Conversations by status (active by default, pending, open for both, closed or all), in one mailbox or all, most recently updated first: id, number, subject, status, customer, assignee, tags and a preview.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["active","pending","open","closed","all"],"default":"active"},"mailbox":{"type":["string","integer"],"description":"Mailbox id from mailboxes"},"limit":{"type":"integer","minimum":1,"maximum":50,"default":25}}}`)},
			{Name: "conversation", Title: "Open a conversation", Description: "A conversation with customer, assignee, tags and its threads: customer emails, replies and internal notes.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation"],"properties":{` + cv + `}}`)},
			{Name: "add_note", Title: "Add an internal note", Description: "A note only your team sees; the customer isn't emailed. Help Scout's API can't delete threads, so there's no undo.", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","text"],"properties":{` + cv + `,` + text + `}}`)},
			{Name: "reply", Title: "Reply to the customer", Description: "A reply emailed to the conversation's customer. It can't be unsent, so it's destructive. The preview shows who gets it and the text.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","text"],"properties":{` + cv + `,` + text + `}}`)},
			{Name: "set_status", Title: "Set the status", Description: "Active or pending (also reopens a closed conversation). Closing is close. Undo sets the status it had.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","status"],"properties":{` + cv + `,"status":{"type":"string","enum":["active","pending"]}}}`)},
			{Name: "close", Title: "Close a conversation", Description: "Closes a conversation. Help Scout workflows may email the customer when it closes, which can't be unsent, so it's destructive. Undo sets the status it had.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
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
	if !strings.HasPrefix(c.AppID, "secret://") || !strings.HasPrefix(c.AppSecret, "secret://") {
		return errors.New("store the app id and app secret in the vault and enter their secret:// references")
	}
	base := "https://api.helpscout.net/v2"
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	client = rest.SameHostOnly(client)
	cn := &conn{http: client, tokenURL: base + "/oauth2/token", host: h, cfg: c}
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := cn.token(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// token returns a cached access token or gets a new one.
func (c *conn) token(ctx context.Context) (string, error) {
	return c.tok.Get(ctx, func(ctx context.Context) (oauth.Grant, error) {
		appID, err := c.host.Secret(ctx, c.cfg.AppID)
		if err != nil {
			return oauth.Grant{}, err
		}
		secret, err := c.host.Secret(ctx, c.cfg.AppSecret)
		if err != nil {
			return oauth.Grant{}, err
		}
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {strings.TrimSpace(appID)}, "client_secret": {strings.TrimSpace(secret)}}
		g, err := oauth.Exchange(ctx, c.http, c.tokenURL, form, "", "")
		var e *oauth.Error
		if errors.As(err, &e) {
			if e.Code == "invalid_client" || e.Status == http.StatusUnauthorized {
				return g, errors.New("Help Scout refused the app id or secret")
			}
			return g, fmt.Errorf("Help Scout didn't issue a token: %v", e)
		}
		return g, err
	})
}

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Help Scout refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Help Scout refused: the app's user can't do that")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusBadRequest), rest.IsStatus(err, http.StatusUnprocessableEntity):
		return fmt.Errorf("Help Scout refused the request: %v", err)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Help Scout's rate limit was hit; try again in a minute")
	}
	return err
}

// do calls Help Scout; a 401 drops the cached token and tries once more.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any, what string) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.tok.Drop()
		_, err = c.api.Do(ctx, method, path, q, body, out)
	}
	return friendly(err, what)
}

type person struct {
	ID    int64  `json:"id"`
	Type  string `json:"type"`
	First string `json:"first"`
	Last  string `json:"last"`
	Email string `json:"email"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		ID        int64  `json:"id"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/me", nil, nil, &me, "Help Scout API here"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "Signed in as " + clip(me.FirstName+" "+me.LastName, 80)}
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
	Mailbox      flexID `json:"mailbox"`
	Status       string `json:"status"`
	Limit        int    `json:"limit"`
	Text         string `json:"text"`
}

type thread struct {
	ID        int64   `json:"id"`
	Type      string  `json:"type"`
	Body      string  `json:"body"`
	CreatedAt string  `json:"createdAt"`
	CreatedBy *person `json:"createdBy"`
}

type conversation struct {
	ID            int64   `json:"id"`
	Number        int64   `json:"number"`
	Subject       string  `json:"subject"`
	Status        string  `json:"status"`
	MailboxID     int64   `json:"mailboxId"`
	Preview       string  `json:"preview"`
	UserUpdatedAt string  `json:"userUpdatedAt"`
	CreatedAt     string  `json:"createdAt"`
	Customer      *person `json:"primaryCustomer"`
	Assignee      *person `json:"assignee"`
	Tags          []struct {
		Tag string `json:"tag"`
	} `json:"tags"`
	Embedded struct {
		Threads []thread `json:"threads"`
	} `json:"_embedded"`
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// plain turns HTML bodies into text.
func plain(s string) string {
	s = strings.NewReplacer("<br>", "\n", "<br/>", "\n", "<br />", "\n", "</p>", "\n", "</div>", "\n").Replace(s)
	return strings.TrimSpace(html.UnescapeString(tagRe.ReplaceAllString(s, "")))
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
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

func fullName(p *person) string {
	if p == nil {
		return ""
	}
	return clip(strings.TrimSpace(p.First+" "+p.Last), 80)
}

func contact(p *person) map[string]any {
	if p == nil {
		return nil
	}
	o := map[string]any{"id": p.ID, "name": fullName(p)}
	if p.Email != "" {
		o["email"] = clip(p.Email, 200)
	}
	return o
}

func summary(cv conversation) map[string]any {
	o := map[string]any{"conversation": cv.ID, "number": cv.Number, "subject": clip(cv.Subject, 200), "status": cv.Status, "mailbox": cv.MailboxID,
		"customer": contact(cv.Customer), "updated": cv.UserUpdatedAt, "preview": clip(cv.Preview, 300)}
	if cv.Assignee != nil {
		o["assignee"] = fullName(cv.Assignee)
	} else {
		o["assignee"] = nil
	}
	tags := []string{}
	for _, t := range cv.Tags {
		tags = append(tags, clip(t.Tag, 80))
	}
	o["tags"] = tags
	return o
}

func (c *conn) get(ctx context.Context, id string, threads bool) (conversation, error) {
	var cv conversation
	var q url.Values
	if threads {
		q = url.Values{"embed": {"threads"}}
	}
	if err := c.do(ctx, http.MethodGet, "/conversations/"+url.PathEscape(id), q, nil, &cv, "conversation "+id); err != nil {
		return conversation{}, err
	}
	return cv, nil
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
	case "mailboxes", "conversations":
	default:
		if !idRe.MatchString(cid) {
			return sdk.Result{}, errors.New("the conversation is its id from conversations, e.g. 123456789")
		}
	}
	switch call.Action {
	case "mailboxes":
		var a struct {
			Embedded struct {
				Mailboxes []struct {
					ID    int64  `json:"id"`
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"mailboxes"`
			} `json:"_embedded"`
		}
		if err := c.do(ctx, http.MethodGet, "/mailboxes", nil, nil, &a, "mailbox list"); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, x := range a.Embedded.Mailboxes {
			list = append(list, map[string]any{"mailbox": x.ID, "name": clip(x.Name, 120), "email": clip(x.Email, 200)})
		}
		return sdk.JSON(list)

	case "conversations":
		st := p.Status
		if st == "" {
			st = "active"
		}
		switch st {
		case "active", "pending", "open", "closed", "all":
		default:
			return sdk.Result{}, errors.New("the status is active, pending, open, closed or all")
		}
		n := p.Limit
		if n == 0 {
			n = 25
		}
		if n < 1 || n > 50 {
			return sdk.Result{}, errors.New("the limit is 1 to 50")
		}
		q := url.Values{"status": {st}, "sortField": {"modifiedAt"}, "sortOrder": {"desc"}}
		if p.Mailbox != "" {
			if !idRe.MatchString(string(p.Mailbox)) {
				return sdk.Result{}, errors.New("the mailbox is its id from mailboxes")
			}
			q.Set("mailbox", string(p.Mailbox))
		}
		out := []map[string]any{}
		for page := 1; page <= 2 && len(out) < n; page++ {
			var a struct {
				Embedded struct {
					Conversations []conversation `json:"conversations"`
				} `json:"_embedded"`
				Page struct {
					TotalPages int `json:"totalPages"`
				} `json:"page"`
			}
			q.Set("page", strconv.Itoa(page))
			if err := c.do(ctx, http.MethodGet, "/conversations", q, nil, &a, "conversation list"); err != nil {
				return sdk.Result{}, err
			}
			for _, cv := range a.Embedded.Conversations {
				if len(out) < n {
					out = append(out, summary(cv))
				}
			}
			if page >= a.Page.TotalPages {
				break
			}
		}
		return sdk.JSON(out)

	case "conversation":
		cv, err := c.get(ctx, cid, true)
		if err != nil {
			return sdk.Result{}, err
		}
		threads := []map[string]any{}
		for _, t := range cv.Embedded.Threads {
			kind := t.Type
			switch t.Type {
			case "customer":
				kind = "customer"
			case "message", "reply":
				kind = "reply"
			case "note":
				kind = "internal note"
			}
			e := map[string]any{"id": t.ID, "kind": kind, "at": t.CreatedAt}
			if n := fullName(t.CreatedBy); n != "" {
				e["from"] = n
			}
			if b := plain(t.Body); b != "" {
				e["text"] = clip(b, 4000)
			}
			threads = append(threads, e)
		}
		o := summary(cv)
		delete(o, "preview")
		o["created"] = cv.CreatedAt
		o["threads"] = threads
		return sdk.JSON(o)

	case "add_note", "reply":
		body, err := text(p.Text)
		if err != nil {
			return sdk.Result{}, err
		}
		note := call.Action == "add_note"
		if f := mention.Find(body); note && f.Wildcard != "" {
			return sdk.Result{}, fmt.Errorf("%s would notify the whole team; wildcard mentions aren't sent from Conduit", f.Wildcard)
		}
		cv, err := c.get(ctx, cid, false)
		if err != nil {
			return sdk.Result{}, err
		}
		if !note && (cv.Customer == nil || cv.Customer.ID == 0) {
			return sdk.Result{}, fmt.Errorf("conversation %s has no customer to reply to", cid)
		}
		if call.DryRun {
			if note {
				s := fmt.Sprintf("Add an internal note to conversation %s; the customer isn't emailed", cid)
				if pv := mention.Find(body).Preview(); pv != "" {
					s += "; it " + pv
				}
				return sdk.Result{Plan: &sdk.Plan{Summary: s,
					Changes: []sdk.Change{{Target: "conversation " + cid, Op: "note", After: mustJSON(map[string]any{"text": clip(body, 2000)})}}}}, nil
			}
			to := fullName(cv.Customer)
			if cv.Customer.Email != "" {
				to += " <" + clip(cv.Customer.Email, 200) + ">"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Email a reply on conversation %s (%s) to %s; it can't be unsent", cid, clip(cv.Subject, 100), strings.TrimSpace(to)),
				Changes: []sdk.Change{{Target: "conversation " + cid, Op: "reply", After: mustJSON(map[string]any{"to": strings.TrimSpace(to), "text": clip(body, 2000)})}}}}, nil
		}
		path, in := "/conversations/"+cid+"/notes", map[string]any{"text": body}
		if !note {
			path, in = "/conversations/"+cid+"/reply", map[string]any{"text": body, "customer": map[string]any{"id": cv.Customer.ID}}
		}
		if err := c.do(ctx, http.MethodPost, path, nil, in, nil, "conversation "+cid); err != nil {
			return sdk.Result{}, err
		}
		added := "reply"
		if note {
			added = "note"
		}
		return sdk.JSON(map[string]any{"conversation": cv.ID, "added": added})

	case "set_status", "close":
		to := p.Status
		switch {
		case call.Action == "close":
			if to != "" {
				return sdk.Result{}, errors.New("close takes no status")
			}
			to = "closed"
		case to == "closed":
			return sdk.Result{}, errors.New("closing may email the customer; use close")
		case to != "active" && to != "pending":
			return sdk.Result{}, errors.New("the status is active or pending (close closes it)")
		}
		cv, err := c.get(ctx, cid, false)
		if err != nil {
			return sdk.Result{}, err
		}
		if cv.Status == to {
			return sdk.JSON(map[string]any{"conversation": cv.ID, "status": cv.Status, "note": "nothing to change: the conversation is already " + to})
		}
		if call.DryRun {
			// Ids and statuses only: this plan goes in the audit log as is.
			s := fmt.Sprintf("Set conversation %s from %s to %s", cid, cv.Status, to)
			if to == "closed" {
				s = fmt.Sprintf("Close conversation %s (now %s); Help Scout workflows may email the customer", cid, cv.Status)
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: s,
				Changes: []sdk.Change{{Target: "conversation " + cid, Op: "update", Before: mustJSON(map[string]any{"status": cv.Status}), After: mustJSON(map[string]any{"status": to})}}}}, nil
		}
		in := map[string]any{"op": "replace", "path": "/status", "value": to}
		if err := c.do(ctx, http.MethodPatch, "/conversations/"+cid, nil, in, nil, "conversation "+cid); err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"conversation": cv.ID, "from": cv.Status, "to": to})
		switch cv.Status {
		case "active", "pending":
			r.Undo = sdk.UndoWith("set_status", map[string]any{"conversation": cid, "status": cv.Status}, fmt.Sprintf("Set conversation %s back to %s", cid, cv.Status))
		case "closed":
			r.Undo = sdk.UndoWith("close", map[string]any{"conversation": cid}, fmt.Sprintf("Close conversation %s again", cid))
		}
		return r, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
