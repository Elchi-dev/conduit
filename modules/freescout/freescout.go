// Package freescout works with a self-hosted FreeScout help desk through
// its API & Webhooks module and an API key: mailboxes, conversations by
// status, one conversation with its threads, replies to the customer,
// internal notes and status changes, as one FreeScout user.
//
// A reply emails the customer and can't be unsent, so it's destructive; so
// is closing, which can run workflows that email the customer.
// Conversations are personal data, so the actions that return them are
// sensitive.
package freescout

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
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one FreeScout server.
type Config struct {
	URL                string          `json:"url"`    // https://support.example.com
	APIKey             string          `json:"apiKey"` // secret:// API key (Manage, API & Webhooks)
	UserID             json.RawMessage `json:"userId"` // the user replies, notes and changes are made as
	Fingerprint        string          `json:"fingerprint"`
	InsecureSkipVerify bool            `json:"insecureSkipVerify"`
}

type conn struct {
	api  *rest.Client
	site string
	user int64
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the FreeScout module.
func New() *Module { return &Module{} }

const maxText = 20000

var (
	idRe     = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	prefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
	ctrlRe   = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
	tagRe    = regexp.MustCompile(`<[^>]*>`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	cv := `"conversation":{"type":["string","integer"],"description":"Conversation id (from conversations), e.g. 42"}`
	text := `"text":{"type":"string","format":"textarea","maxLength":20000}`
	return sdk.Manifest{
		ID: "freescout", Name: "FreeScout", Version: "0.1.0", Category: "Communication", Icon: "headset",
		Description: "FreeScout: mailboxes, conversations and their threads, replies to customers (destructive: they're emailed), internal notes, and status changes.",
		Presets:     []string{"team", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey","userId"],"properties":{
			"url":{"type":"string","description":"Your FreeScout address, e.g. https://support.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"An API key (Manage, API & Webhooks; the module must be installed)"},
			"userId":{"type":["string","integer"],"description":"The id of the FreeScout user replies, notes and status changes are made as (Manage, Users: the number in the user's address)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "mailboxes", Title: "Mailboxes", Description: "The mailboxes (id, name and address), to list conversations from.", Risk: sdk.RiskRead},
			{Name: "conversations", Title: "Conversations", Description: "Conversations by status (active by default, pending, closed or all), in one mailbox or all, most recently updated first: id, number, subject, status, customer, assignee and a preview.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["active","pending","closed","all"],"default":"active"},"mailbox":{"type":["string","integer"],"description":"Mailbox id from mailboxes"},"limit":{"type":"integer","minimum":1,"maximum":50,"default":25}}}`)},
			{Name: "conversation", Title: "Open a conversation", Description: "A conversation with customer, assignee and its threads: customer emails, replies and internal notes.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation"],"properties":{` + cv + `}}`)},
			{Name: "add_note", Title: "Add an internal note", Description: "A note only your team sees; the customer isn't emailed. FreeScout's API can't delete threads, so there's no undo.", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","text"],"properties":{` + cv + `,` + text + `}}`)},
			{Name: "reply", Title: "Reply to the customer", Description: "A reply emailed to the conversation's customer. It can't be unsent, so it's destructive. The preview shows who gets it and the text.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","text"],"properties":{` + cv + `,` + text + `}}`)},
			{Name: "set_status", Title: "Set the status", Description: "Active or pending (also reopens a closed conversation). Closing is close. Undo sets the status it had.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","status"],"properties":{` + cv + `,"status":{"type":"string","enum":["active","pending"]}}}`)},
			{Name: "close", Title: "Close a conversation", Description: "Closes a conversation. FreeScout workflows may email the customer when it closes, which can't be unsent, so it's destructive. Undo sets the status it had.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation"],"properties":{` + cv + `}}`)},
		},
	}
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

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	prefix := ""
	if err == nil {
		prefix = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return errors.New("the address is your FreeScout server, like https://support.example.com")
	}
	var uid flexID
	if len(c.UserID) == 0 || json.Unmarshal(c.UserID, &uid) != nil || !idRe.MatchString(string(uid)) {
		return errors.New("the user id is a FreeScout user's number (Manage, Users: the number in the user's address)")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	site := u.Scheme + "://" + u.Host + prefix
	ref := c.APIKey
	api := rest.New(site+"/api", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-FreeScout-API-Key", strings.TrimSpace(k))
		return nil
	})
	// X-FreeScout-API-Key is a custom header, which Go would forward on a redirect.
	api.HTTP = rest.SameHostOnly(client)
	n, _ := strconv.ParseInt(string(uid), 10, 64)
	m.set.Put(id, &conn{api: api, site: site, user: n})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("FreeScout refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("FreeScout refused: the API key or user can't do that")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s (is the API & Webhooks module on?)", what)
	case rest.IsStatus(err, http.StatusBadRequest), rest.IsStatus(err, http.StatusUnprocessableEntity):
		return fmt.Errorf("FreeScout refused the request: %v", err)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("FreeScout's rate limit was hit; try again in a minute")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any, what string) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err, what)
}

type person struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me person
	uid := strconv.FormatInt(c.user, 10)
	if err := c.do(ctx, http.MethodGet, "/users/"+uid, nil, nil, &me, "user "+uid); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if me.ID != c.user {
		return sdk.Health{Status: "down", Message: "FreeScout didn't return user " + uid}
	}
	return sdk.Health{Status: "ok", Message: "Acting as " + fullName(&me)}
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
	ID        int64   `json:"id"`
	Number    int64   `json:"number"`
	Subject   string  `json:"subject"`
	Status    string  `json:"status"`
	MailboxID int64   `json:"mailboxId"`
	Preview   string  `json:"preview"`
	UpdatedAt string  `json:"updatedAt"`
	CreatedAt string  `json:"createdAt"`
	Customer  *person `json:"customer"`
	Assignee  *person `json:"assignee"`
	Embedded  struct {
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
	return clip(strings.TrimSpace(p.FirstName+" "+p.LastName), 80)
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

func (c *conn) summary(cv conversation) map[string]any {
	o := map[string]any{"conversation": cv.ID, "number": cv.Number, "subject": clip(cv.Subject, 200), "status": cv.Status, "mailbox": cv.MailboxID,
		"customer": contact(cv.Customer), "updated": cv.UpdatedAt, "preview": clip(cv.Preview, 300),
		"url": c.site + "/conversation/" + strconv.FormatInt(cv.ID, 10)}
	if cv.Assignee != nil && cv.Assignee.ID > 0 {
		o["assignee"] = fullName(cv.Assignee)
	} else {
		o["assignee"] = nil
	}
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
			return sdk.Result{}, errors.New("the conversation is its id from conversations, e.g. 42")
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
		n := p.Limit
		if n == 0 {
			n = 25
		}
		if n < 1 || n > 50 {
			return sdk.Result{}, errors.New("the limit is 1 to 50")
		}
		q := url.Values{"pageSize": {strconv.Itoa(n)}, "page": {"1"}, "sortField": {"updatedAt"}, "sortOrder": {"desc"}}
		switch st {
		case "active", "pending", "closed":
			q.Set("status", st)
		case "all":
		default:
			return sdk.Result{}, errors.New("the status is active, pending, closed or all")
		}
		if p.Mailbox != "" {
			if !idRe.MatchString(string(p.Mailbox)) {
				return sdk.Result{}, errors.New("the mailbox is its id from mailboxes")
			}
			q.Set("mailboxId", string(p.Mailbox))
		}
		var a struct {
			Embedded struct {
				Conversations []conversation `json:"conversations"`
			} `json:"_embedded"`
		}
		if err := c.do(ctx, http.MethodGet, "/conversations", q, nil, &a, "conversation list"); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i, cv := range a.Embedded.Conversations {
			if i >= n {
				break
			}
			out = append(out, c.summary(cv))
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
			case "message":
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
		o := c.summary(cv)
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
		if call.DryRun {
			if note {
				s := fmt.Sprintf("Add an internal note to conversation %s; the customer isn't emailed", cid)
				if pv := mention.Find(body).Preview(); pv != "" {
					s += "; it " + pv
				}
				return sdk.Result{Plan: &sdk.Plan{Summary: s,
					Changes: []sdk.Change{{Target: "conversation " + cid, Op: "note", After: mustJSON(map[string]any{"text": clip(body, 2000)})}}}}, nil
			}
			to := "the customer"
			if cv.Customer != nil {
				to = fullName(cv.Customer)
				if cv.Customer.Email != "" {
					to = strings.TrimSpace(to + " <" + clip(cv.Customer.Email, 200) + ">")
				}
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Email a reply on conversation %s (%s) to %s; it can't be unsent", cid, clip(cv.Subject, 100), to),
				Changes: []sdk.Change{{Target: "conversation " + cid, Op: "reply", After: mustJSON(map[string]any{"to": to, "text": clip(body, 2000)})}}}}, nil
		}
		typ := "message"
		if note {
			typ = "note"
		}
		in := map[string]any{"type": typ, "text": body, "user": c.user}
		if err := c.do(ctx, http.MethodPost, "/conversations/"+cid+"/threads", nil, in, nil, "conversation "+cid); err != nil {
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
				s = fmt.Sprintf("Close conversation %s (now %s); FreeScout workflows may email the customer", cid, cv.Status)
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: s,
				Changes: []sdk.Change{{Target: "conversation " + cid, Op: "update", Before: mustJSON(map[string]any{"status": cv.Status}), After: mustJSON(map[string]any{"status": to})}}}}, nil
		}
		if err := c.do(ctx, http.MethodPut, "/conversations/"+cid, nil, map[string]any{"status": to, "byUser": c.user}, nil, "conversation "+cid); err != nil {
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
