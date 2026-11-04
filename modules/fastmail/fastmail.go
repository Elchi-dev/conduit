// Package fastmail works with a Fastmail account over JMAP (RFC 8620, 8621)
// with an API token: mailboxes and their counts, listing, searching and
// reading mail, and sending through an EmailSubmission.
package fastmail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/mimemsg"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Fastmail account.
type Config struct {
	Token string `json:"token"` // secret:// API token
	From  string `json:"from"`  // address to send from (default: the first identity)
}

type session struct {
	account   string
	apiPath   string
	uploadTpl string // path with {accountId}
}

type conn struct {
	cfg  Config
	host sdk.Host
	api  *rest.Client

	mu      sync.Mutex
	session *session
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://api.fastmail.com and HTTP the client (tests).
	// They aren't settings, so an instance can't send its token anywhere
	// else; the session's API and upload addresses must be on the same host.
	Base string
	HTTP *http.Client
}

// New returns the Fastmail module.
func New() *Module { return &Module{} }

const (
	capCore       = "urn:ietf:params:jmap:core"
	capMail       = "urn:ietf:params:jmap:mail"
	capSubmission = "urn:ietf:params:jmap:submission"
)

var (
	idRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
	roleRe    = regexp.MustCompile(`^(inbox|archive|drafts|sent|trash|junk|important)$`)
	accountRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	addrs := `"to":{"type":"array","items":{"type":"string"}},"cc":{"type":"array","items":{"type":"string"}},"bcc":{"type":"array","items":{"type":"string"}}`
	return sdk.Manifest{
		ID: "fastmail", Name: "Fastmail", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "Your Fastmail account over JMAP: mailboxes, newest and matching mail, reading messages and sending.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An API token (Settings, Privacy & Security, Manage API tokens) with Email access, plus Email submission to send"},
			"from":{"type":"string","description":"Address to send from, one of your sending identities (default: the first)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "mailboxes", Title: "Mailboxes", Description: "Every mailbox with its role, message and unread counts.", Risk: sdk.RiskRead},
			{Name: "mail_list", Title: "Mail", Description: "Newest messages in a mailbox, or matching words: sender, subject, preview, received, unread.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"mailbox":{"type":"string","default":"inbox","description":"A role (inbox, archive, sent, drafts, trash, junk) or a mailbox id"},"text":{"type":"string","description":"Words anywhere in the message"},"unreadOnly":{"type":"boolean"},"limit":{"type":"integer","default":25,"maximum":50}}}`)},
			{Name: "mail_read", Title: "Read a message", Description: "Sender, recipients, subject, date, the text (HTML reduced to text, never rendered) and attachment names. Doesn't mark it read.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Message id from mail_list"}}}`)},
			{Name: "send_mail", Title: "Send mail", Description: "Sends a plain-text message from your identity and files it in Sent; it can't be called back. The preview shows recipients, subject and body.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["to","subject","body"],"properties":{` + addrs + `,"subject":{"type":"string"},"body":{"type":"string","x-multiline":true,"description":"Plain text"}}}`)},
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
	c.From = strings.TrimSpace(c.From)
	if c.From != "" {
		if _, err := mimemsg.Addresses([]string{c.From}, "from"); err != nil || strings.Contains(c.From, "<") {
			return errors.New("from is a plain address like you@fastmail.com")
		}
	}
	base := m.Base
	if base == "" {
		base = "https://api.fastmail.com"
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
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
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{cfg: c, host: h, api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Fastmail refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API token doesn't have this access (give it Email, and Email submission to send)")
	}
	return err
}

// sameHost checks a session address and returns its path: the token is
// only ever sent to the host it was configured for.
func (c *conn) sameHost(raw string) (string, error) {
	b, _ := url.Parse(c.api.Base)
	u, err := url.Parse(strings.ReplaceAll(raw, "{accountId}", "ACCOUNTID"))
	if err != nil || u.Scheme != b.Scheme || !strings.EqualFold(u.Host, b.Host) || u.RawQuery != "" {
		return "", errors.New("the JMAP session points at another host; refusing to send the token there")
	}
	return strings.ReplaceAll(u.EscapedPath(), "ACCOUNTID", "{accountId}"), nil
}

func (c *conn) getSession(ctx context.Context) (*session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		return c.session, nil
	}
	var s struct {
		APIURL          string            `json:"apiUrl"`
		UploadURL       string            `json:"uploadUrl"`
		PrimaryAccounts map[string]string `json:"primaryAccounts"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/jmap/session", nil, nil, &s); err != nil {
		return nil, friendly(err)
	}
	acct := s.PrimaryAccounts[capMail]
	if !accountRe.MatchString(acct) {
		return nil, errors.New("the API token has no mail account (give it Email access)")
	}
	apiPath, err := c.sameHost(s.APIURL)
	if err != nil {
		return nil, err
	}
	up, err := c.sameHost(s.UploadURL)
	if err != nil {
		return nil, err
	}
	c.session = &session{account: acct, apiPath: apiPath, uploadTpl: up}
	return c.session, nil
}

func (c *conn) dropSession() {
	c.mu.Lock()
	c.session = nil
	c.mu.Unlock()
}

// call is one JMAP method call; Args may reference earlier results.
type call struct {
	Name string
	Args map[string]any
}

// jmap sends method calls in one request and returns each response's
// arguments by call index. A method error fails the whole call.
func (c *conn) jmap(ctx context.Context, using []string, calls ...call) ([]json.RawMessage, error) {
	s, err := c.getSession(ctx)
	if err != nil {
		return nil, err
	}
	mc := []any{}
	for i, x := range calls {
		args := map[string]any{"accountId": s.account}
		for k, v := range x.Args {
			args[k] = v
		}
		mc = append(mc, []any{x.Name, args, fmt.Sprint(i)})
	}
	var out struct {
		MethodResponses []json.RawMessage `json:"methodResponses"`
	}
	req := map[string]any{"using": append([]string{capCore}, using...), "methodCalls": mc}
	if _, err := c.api.Do(ctx, http.MethodPost, s.apiPath, nil, req, &out); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusNotFound) {
			c.dropSession()
		}
		return nil, friendly(err)
	}
	res := make([]json.RawMessage, len(calls))
	for _, raw := range out.MethodResponses {
		var r [3]json.RawMessage
		if json.Unmarshal(raw, &r) != nil {
			return nil, errors.New("unexpected answer from Fastmail")
		}
		var name, id string
		_ = json.Unmarshal(r[0], &name)
		_ = json.Unmarshal(r[2], &id)
		var i int
		if _, err := fmt.Sscan(id, &i); err != nil || i < 0 || i >= len(calls) {
			continue
		}
		if name == "error" {
			var e struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal(r[1], &e)
			return nil, methodError(calls[i].Name, e.Type)
		}
		if res[i] == nil {
			res[i] = r[1]
		}
	}
	for i, r := range res {
		if r == nil {
			return nil, fmt.Errorf("Fastmail didn't answer %s", calls[i].Name)
		}
	}
	return res, nil
}

var typeRe = regexp.MustCompile(`^[A-Za-z]{1,64}$`)

func methodError(method, typ string) error {
	switch typ {
	case "forbidden", "accountReadOnly":
		return errors.New("the API token isn't allowed to do this (give it Email, and Email submission to send)")
	case "accountNotFound", "accountNotSupportedByMethod":
		return errors.New("the API token's account can't do this (give it Email access)")
	}
	if !typeRe.MatchString(typ) {
		typ = "error"
	}
	return fmt.Errorf("Fastmail refused %s (%s)", method, typ)
}

type mailbox struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Role   string `json:"role"`
	Parent string `json:"parentId"`
	Total  int    `json:"totalEmails"`
	Unread int    `json:"unreadEmails"`
}

func (c *conn) mailboxes(ctx context.Context) ([]mailbox, error) {
	res, err := c.jmap(ctx, []string{capMail}, call{"Mailbox/get", map[string]any{"ids": nil,
		"properties": []string{"id", "name", "role", "parentId", "totalEmails", "unreadEmails"}}})
	if err != nil {
		return nil, err
	}
	var out struct {
		List []mailbox `json:"list"`
	}
	if err := json.Unmarshal(res[0], &out); err != nil {
		return nil, errors.New("unexpected answer from Fastmail")
	}
	return out.List, nil
}

func byRole(bs []mailbox, role string) *mailbox {
	for i := range bs {
		if bs[i].Role == role {
			return &bs[i]
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
	bs, err := c.mailboxes(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if in := byRole(bs, "inbox"); in != nil {
		return sdk.Health{Status: "ok", Message: fmt.Sprintf("Inbox: %d messages, %d unread", in.Total, in.Unread)}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d mailboxes", len(bs))}
}

type input struct {
	ID         string   `json:"id"`
	Mailbox    string   `json:"mailbox"`
	Text       string   `json:"text"`
	UnreadOnly bool     `json:"unreadOnly"`
	Limit      int      `json:"limit"`
	To         []string `json:"to"`
	Cc         []string `json:"cc"`
	Bcc        []string `json:"bcc"`
	Subject    string   `json:"subject"`
	Body       string   `json:"body"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, sc sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(sc.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(sc, &p); err != nil {
		return sdk.Result{}, err
	}
	switch sc.Action {
	case "mailboxes":
		bs, err := c.mailboxes(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		names := map[string]string{}
		for _, b := range bs {
			names[b.ID] = b.Name
		}
		out := []map[string]any{}
		for _, b := range bs {
			row := map[string]any{"id": b.ID, "name": b.Name, "total": b.Total, "unread": b.Unread}
			if b.Role != "" {
				row["role"] = b.Role
			}
			if b.Parent != "" {
				row["parent"] = names[b.Parent]
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	case "mail_list":
		return c.list(ctx, p)
	case "mail_read":
		id := strings.TrimSpace(p.ID)
		if !idRe.MatchString(id) {
			return sdk.Result{}, errors.New("give the message id from mail_list")
		}
		return c.read(ctx, id)
	case "send_mail":
		return c.send(ctx, sc, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(sc.Action)
}

type jaddr struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (a jaddr) String() string {
	if a.Name != "" && a.Name != a.Email {
		return a.Name + " <" + a.Email + ">"
	}
	return a.Email
}

func joinAddrs(as []jaddr) []string {
	out := []string{}
	for _, a := range as {
		out = append(out, a.String())
	}
	return out
}

func (c *conn) list(ctx context.Context, p input) (sdk.Result, error) {
	box := strings.TrimSpace(p.Mailbox)
	if box == "" {
		box = "inbox"
	}
	if !roleRe.MatchString(box) && !idRe.MatchString(box) {
		return sdk.Result{}, errors.New("the mailbox is a role (inbox, archive, sent, drafts, trash, junk) or a mailbox id")
	}
	text := strings.TrimSpace(p.Text)
	if len(text) > 500 || strings.ContainsFunc(text, func(r rune) bool { return r < 0x20 }) {
		return sdk.Result{}, errors.New("the search text is one line of up to 500 characters")
	}
	n := p.Limit
	if n <= 0 {
		n = 25
	}
	if n > 50 {
		n = 50
	}
	bs, err := c.mailboxes(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	var mb *mailbox
	if roleRe.MatchString(box) {
		mb = byRole(bs, box)
	}
	for i := range bs {
		if mb == nil && bs[i].ID == box {
			mb = &bs[i]
		}
	}
	if mb == nil {
		return sdk.Result{}, fmt.Errorf("there's no mailbox %s", box)
	}
	filter := map[string]any{"inMailbox": mb.ID}
	if p.UnreadOnly {
		filter["notKeyword"] = "$seen"
	}
	if text != "" {
		filter["text"] = text
	}
	res, err := c.jmap(ctx, []string{capMail},
		call{"Email/query", map[string]any{"filter": filter, "sort": []map[string]any{{"property": "receivedAt", "isAscending": false}}, "limit": n}},
		call{"Email/get", map[string]any{"#ids": map[string]string{"resultOf": "0", "name": "Email/query", "path": "/ids"},
			"properties": []string{"id", "threadId", "receivedAt", "from", "subject", "preview", "keywords", "hasAttachment"}}})
	if err != nil {
		return sdk.Result{}, err
	}
	var got struct {
		List []struct {
			ID       string          `json:"id"`
			Thread   string          `json:"threadId"`
			Received string          `json:"receivedAt"`
			From     []jaddr         `json:"from"`
			Subject  string          `json:"subject"`
			Preview  string          `json:"preview"`
			Keywords map[string]bool `json:"keywords"`
			Attach   bool            `json:"hasAttachment"`
		} `json:"list"`
	}
	if err := json.Unmarshal(res[1], &got); err != nil {
		return sdk.Result{}, errors.New("unexpected answer from Fastmail")
	}
	out := []map[string]any{}
	for _, e := range got.List {
		out = append(out, map[string]any{"id": e.ID, "thread": e.Thread, "received": e.Received, "from": strings.Join(joinAddrs(e.From), ", "),
			"subject": e.Subject, "preview": e.Preview, "unread": !e.Keywords["$seen"], "attachments": e.Attach})
	}
	return sdk.JSON(out)
}

var (
	dropRe  = regexp.MustCompile(`(?is)<(script|style|head)[^>]*>.*?</(script|style|head)>`)
	blockRe = regexp.MustCompile(`(?i)<(br|/?p|/?div|/?li|/?tr|/?h[1-6]|/?blockquote)\b[^>]*>`)
	tagRe   = regexp.MustCompile(`<[^>]*>`)
	blankRe = regexp.MustCompile(`[ \t]+`)
	spaceRe = regexp.MustCompile(`\n\s*\n\s*(\n\s*)+`)
)

func htmlText(s string) string {
	s = dropRe.ReplaceAllString(s, "")
	s = blockRe.ReplaceAllString(s, "\n")
	s = html.UnescapeString(tagRe.ReplaceAllString(s, ""))
	s = blankRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(spaceRe.ReplaceAllString(s, "\n\n"))
}

func (c *conn) read(ctx context.Context, id string) (sdk.Result, error) {
	res, err := c.jmap(ctx, []string{capMail}, call{"Email/get", map[string]any{"ids": []string{id},
		"properties":          []string{"id", "threadId", "receivedAt", "from", "to", "cc", "subject", "keywords", "textBody", "bodyValues", "attachments"},
		"fetchTextBodyValues": true, "maxBodyValueBytes": 256 << 10}})
	if err != nil {
		return sdk.Result{}, err
	}
	type bodyPart struct {
		PartID string `json:"partId"`
		Type   string `json:"type"`
		Name   string `json:"name"`
		Size   int    `json:"size"`
	}
	var got struct {
		List []struct {
			ID         string          `json:"id"`
			Thread     string          `json:"threadId"`
			Received   string          `json:"receivedAt"`
			From       []jaddr         `json:"from"`
			To         []jaddr         `json:"to"`
			Cc         []jaddr         `json:"cc"`
			Subject    string          `json:"subject"`
			Keywords   map[string]bool `json:"keywords"`
			TextBody   []bodyPart      `json:"textBody"`
			Attach     []bodyPart      `json:"attachments"`
			BodyValues map[string]struct {
				Value     string `json:"value"`
				Truncated bool   `json:"isTruncated"`
			} `json:"bodyValues"`
		} `json:"list"`
		NotFound []string `json:"notFound"`
	}
	if err := json.Unmarshal(res[0], &got); err != nil {
		return sdk.Result{}, errors.New("unexpected answer from Fastmail")
	}
	if len(got.List) == 0 {
		return sdk.Result{}, fmt.Errorf("there's no message %s", id)
	}
	e := got.List[0]
	var text []string
	truncated := false
	for _, p := range e.TextBody {
		v, ok := e.BodyValues[p.PartID]
		if !ok {
			continue
		}
		t := v.Value
		if strings.HasPrefix(p.Type, "text/html") {
			t = htmlText(t)
		}
		text = append(text, strings.ReplaceAll(t, "\r\n", "\n"))
		truncated = truncated || v.Truncated
	}
	files := []map[string]any{}
	for _, a := range e.Attach {
		files = append(files, map[string]any{"name": a.Name, "type": a.Type, "sizeKB": a.Size / 1024})
	}
	out := map[string]any{"id": e.ID, "thread": e.Thread, "received": e.Received, "from": strings.Join(joinAddrs(e.From), ", "),
		"to": joinAddrs(e.To), "cc": joinAddrs(e.Cc), "subject": e.Subject, "unread": !e.Keywords["$seen"], "text": strings.Join(text, "\n\n"), "attachments": files}
	if truncated {
		out["truncated"] = true
	}
	return sdk.JSON(out)
}

func (c *conn) send(ctx context.Context, sc sdk.Call, p input) (sdk.Result, error) {
	// Bcc recipients go in the envelope only.
	msg, err := mimemsg.Message{From: c.cfg.From, To: p.To, Cc: p.Cc, Bcc: p.Bcc, Subject: p.Subject, Text: p.Body, OmitBcc: true}.Check()
	if err != nil {
		return sdk.Result{}, err
	}
	if sc.DryRun {
		b, _ := json.Marshal(msg.Preview())
		return sdk.Result{Plan: &sdk.Plan{Summary: msg.Summary(), Changes: []sdk.Change{{Target: fmt.Sprintf("%d recipients", msg.Count()), Op: "send", After: b}}}}, nil
	}
	res, err := c.jmap(ctx, []string{capMail, capSubmission},
		call{"Identity/get", map[string]any{"ids": nil, "properties": []string{"id", "email", "name"}}},
		call{"Mailbox/get", map[string]any{"ids": nil, "properties": []string{"id", "role"}}})
	if err != nil {
		return sdk.Result{}, err
	}
	var ids struct {
		List []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"list"`
	}
	var boxes struct {
		List []mailbox `json:"list"`
	}
	if json.Unmarshal(res[0], &ids) != nil || json.Unmarshal(res[1], &boxes) != nil {
		return sdk.Result{}, errors.New("unexpected answer from Fastmail")
	}
	identity, from := "", ""
	for _, x := range ids.List {
		e := strings.ToLower(x.Email)
		want := strings.ToLower(c.cfg.From)
		switch {
		case want == "" && identity == "":
			identity, from = x.ID, x.Email
		case want != "" && e == want:
			identity, from = x.ID, x.Email
		case want != "" && identity == "" && strings.HasPrefix(e, "*@") && strings.HasSuffix(want, e[1:]):
			identity, from = x.ID, c.cfg.From
		}
	}
	if !idRe.MatchString(identity) {
		if c.cfg.From != "" {
			return sdk.Result{}, fmt.Errorf("%s isn't one of your sending identities", c.cfg.From)
		}
		return sdk.Result{}, errors.New("the account has no sending identity")
	}
	drafts, sent := byRole(boxes.List, "drafts"), byRole(boxes.List, "sent")
	if drafts == nil || sent == nil || !idRe.MatchString(drafts.ID) || !idRe.MatchString(sent.ID) {
		return sdk.Result{}, errors.New("the account has no Drafts or Sent mailbox")
	}
	msg2, err := mimemsg.Message{From: from, To: p.To, Cc: p.Cc, Bcc: p.Bcc, Subject: p.Subject, Text: p.Body, OmitBcc: true}.Check()
	if err != nil {
		return sdk.Result{}, err
	}
	blob, err := c.upload(ctx, msg2.Build(time.Now()))
	if err != nil {
		return sdk.Result{}, err
	}
	rcpt := []map[string]string{}
	for _, a := range msg2.Recipients() {
		rcpt = append(rcpt, map[string]string{"email": a})
	}
	res, err = c.jmap(ctx, []string{capMail, capSubmission},
		call{"Email/import", map[string]any{"emails": map[string]any{"m": map[string]any{"blobId": blob,
			"mailboxIds": map[string]bool{drafts.ID: true}, "keywords": map[string]bool{"$draft": true, "$seen": true}}}}},
		call{"EmailSubmission/set", map[string]any{
			"create": map[string]any{"s": map[string]any{"identityId": identity, "emailId": "#m",
				"envelope": map[string]any{"mailFrom": map[string]string{"email": from}, "rcptTo": rcpt}}},
			"onSuccessUpdateEmail": map[string]any{"#s": map[string]any{"mailboxIds/" + drafts.ID: nil, "mailboxIds/" + sent.ID: true, "keywords/$draft": nil}}}})
	if err != nil {
		return sdk.Result{}, err
	}
	var imp, sub struct {
		Created    map[string]struct{ ID string } `json:"created"`
		NotCreated map[string]struct {
			Type string `json:"type"`
		} `json:"notCreated"`
	}
	if json.Unmarshal(res[0], &imp) != nil || json.Unmarshal(res[1], &sub) != nil {
		return sdk.Result{}, errors.New("unexpected answer from Fastmail")
	}
	if e, ok := imp.NotCreated["m"]; ok {
		return sdk.Result{}, methodError("Email/import", e.Type)
	}
	if e, ok := sub.NotCreated["s"]; ok {
		return sdk.Result{}, methodError("EmailSubmission/set", e.Type)
	}
	if _, ok := sub.Created["s"]; !ok {
		return sdk.Result{}, errors.New("Fastmail didn't confirm the submission")
	}
	return sdk.JSON(map[string]any{"sent": true, "id": imp.Created["m"].ID, "recipients": msg2.Count(), "subject": msg2.Subject})
}

// upload stores the message as a blob and returns its id.
func (c *conn) upload(ctx context.Context, raw []byte) (string, error) {
	s, err := c.getSession(ctx)
	if err != nil {
		return "", err
	}
	path := strings.ReplaceAll(s.uploadTpl, "{accountId}", url.PathEscape(s.account))
	res, err := c.api.Send(ctx, http.MethodPost, path, nil, bytes.NewReader(raw), http.Header{"Content-Type": {"message/rfc822"}, "Accept": {"application/json"}})
	if err != nil {
		return "", friendly(err)
	}
	defer res.Body.Close()
	var b struct {
		BlobID string `json:"blobId"`
	}
	if res.StatusCode >= 300 || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&b) != nil || !idRe.MatchString(b.BlobID) {
		return "", errors.New("Fastmail didn't accept the message upload")
	}
	return b.BlobID, nil
}
