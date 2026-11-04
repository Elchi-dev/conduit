// Package googleworkspace works with Google Workspace (and personal Google
// accounts) through Google's REST APIs: Gmail (list, read, send), Calendar
// events (list, create, delete) and Drive files (list, search). It signs in
// with an OAuth refresh token, or with a service account using domain-wide
// delegation to act as one user.
package googleworkspace

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
	"github.com/elchi-dev/conduit/modules/internal/mimemsg"
	"github.com/elchi-dev/conduit/modules/internal/oauth"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Scopes are what the module asks for. With a refresh token, consent to
// them when getting it; with domain-wide delegation, authorize all of them
// for the service account's client id.
var Scopes = []string{
	"https://www.googleapis.com/auth/gmail.readonly",
	"https://www.googleapis.com/auth/gmail.send",
	"https://www.googleapis.com/auth/calendar.events",
	"https://www.googleapis.com/auth/drive.metadata.readonly",
}

// Config is one Google account.
type Config struct {
	ClientID       string `json:"clientId"`       // OAuth client
	ClientSecret   string `json:"clientSecret"`   // secret://
	RefreshToken   string `json:"refreshToken"`   // secret://
	ServiceAccount string `json:"serviceAccount"` // secret:// JSON key (domain-wide delegation)
	Subject        string `json:"subject"`        // the user a service account acts as
	Calendar       string `json:"calendar"`       // default "primary"
}

type conn struct {
	cfg      Config
	host     sdk.Host
	http     *http.Client
	gmail    *rest.Client
	www      *rest.Client
	tokenURL string
	tok      oauth.Cache
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://gmail.googleapis.com and
	// https://www.googleapis.com, TokenURL the token endpoint and HTTP the
	// client (tests). They aren't settings, so an instance can't send its
	// credentials anywhere else; a key's own token_uri is never used.
	Base     string
	TokenURL string
	HTTP     *http.Client
}

// New returns the Google Workspace module.
func New() *Module { return &Module{} }

const defaultToken = "https://oauth2.googleapis.com/token"

var (
	clientIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{8,200}$`)
	emailRe    = regexp.MustCompile(`^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,253}$`)
	calendarRe = regexp.MustCompile(`^(primary|[A-Za-z0-9._%+'-]{1,128}@[A-Za-z0-9.-]{1,253})$`)
	msgIDRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{6,64}$`)
	eventIDRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,1000}$`)
	fileIDRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{10,200}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	addrs := `"to":{"type":"array","items":{"type":"string"}},"cc":{"type":"array","items":{"type":"string"}},"bcc":{"type":"array","items":{"type":"string"}}`
	cal := `"calendar":{"type":"string","description":"Calendar id (default: the instance's, else primary)"}`
	event := cal + `,"subject":{"type":"string"},"start":{"type":"string","description":"RFC 3339, e.g. 2026-11-05T10:00:00+01:00"},"end":{"type":"string","description":"RFC 3339"},"location":{"type":"string"},"body":{"type":"string","x-multiline":true,"description":"Description"}`
	return sdk.Manifest{
		ID: "googleworkspace", Name: "Google Workspace", Version: "0.1.0", Category: "Productivity", Icon: "mail",
		Description: "Gmail (read and send), Google Calendar events and Google Drive files, for a Workspace or personal Google account.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"clientId":{"type":"string","description":"OAuth sign-in: the OAuth client id (Google Cloud Console, APIs & Services, Credentials)"},
			"clientSecret":{"type":"string","x-secret":true,"description":"OAuth sign-in: the client secret"},
			"refreshToken":{"type":"string","x-secret":true,"description":"OAuth sign-in: a refresh token with the scopes the docs list"},
			"serviceAccount":{"type":"string","x-secret":true,"description":"Workspace instead: a service account's JSON key, with domain-wide delegation for the scopes the docs list"},
			"subject":{"type":"string","description":"With a service account: the user to act as, e.g. alex@example.com"},
			"calendar":{"type":"string","default":"primary","description":"Calendar the calendar actions use when none is given"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "mail_list", Title: "Mail", Description: "Newest messages matching a Gmail search (default: the inbox): sender, subject, date, snippet, unread.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string","default":"in:inbox","description":"Gmail search, e.g. is:unread from:kim newer_than:7d"},"limit":{"type":"integer","default":20,"maximum":25}}}`)},
			{Name: "mail_read", Title: "Read a message", Description: "Sender, recipients, subject, date, the plain text (HTML reduced to text, never rendered) and attachment names. Doesn't mark it read.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Message id from mail_list"}}}`)},
			{Name: "send_mail", Title: "Send mail", Description: "Sends a plain-text message from the account; it can't be called back. The preview shows recipients, subject and body.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["to","subject","body"],"properties":{` + addrs + `,"subject":{"type":"string"},"body":{"type":"string","x-multiline":true,"description":"Plain text"}}}`)},
			{Name: "events", Title: "Calendar", Description: "Events in the coming days: title, start, end, location, organizer and attendees with their answers.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + cal + `,"days":{"type":"integer","default":7,"minimum":1,"maximum":60}}}`)},
			{Name: "create_event", Title: "Add a private event", Description: "Adds an event without attendees; nobody is invited or notified. Undo deletes it.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["subject","start","end"],"properties":{` + event + `}}`)},
			{Name: "schedule_meeting", Title: "Schedule a meeting", Description: "Adds an event and emails an invitation to every attendee. Undo deletes it, which sends them a cancellation.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["subject","start","end","attendees"],"properties":{` + event + `,"attendees":{"type":"array","items":{"type":"string"},"maxItems":50},"online":{"type":"boolean","description":"Add a Google Meet link"}}}`)},
			{Name: "delete_event", Title: "Delete an event", Description: "Deletes an event; attendees get a cancellation. The preview shows its time and how many attendees it has.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + cal + `,"id":{"type":"string","description":"Event id"}}}`)},
			{Name: "files", Title: "Drive files", Description: "Files in Drive, newest first: name, type, size, modified and link. Filter by a folder or by words in the name.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"folder":{"type":"string","description":"Folder id (from a folder's link); empty: everywhere"},"name":{"type":"string","description":"Words the name contains"},"limit":{"type":"integer","default":50,"maximum":100}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.ClientID, c.Subject, c.Calendar = strings.TrimSpace(c.ClientID), strings.TrimSpace(c.Subject), strings.TrimSpace(c.Calendar)
	oauthSet := c.ClientID != "" || c.ClientSecret != "" || c.RefreshToken != ""
	switch {
	case oauthSet && c.ServiceAccount != "":
		return errors.New("use either the OAuth sign-in (client and refresh token) or a service account, not both")
	case oauthSet:
		if !clientIDRe.MatchString(c.ClientID) {
			return errors.New("add the OAuth client id (it ends in .apps.googleusercontent.com)")
		}
		if !strings.HasPrefix(c.ClientSecret, "secret://") || !strings.HasPrefix(c.RefreshToken, "secret://") {
			return errors.New("store the client secret and the refresh token in the vault and enter their secret:// references")
		}
		if c.Subject != "" {
			return errors.New("subject is only for a service account; the refresh token already names its user")
		}
	case c.ServiceAccount != "":
		if !strings.HasPrefix(c.ServiceAccount, "secret://") {
			return errors.New("store the service-account JSON key in the vault and enter its secret:// reference")
		}
		if !emailRe.MatchString(c.Subject) {
			return errors.New("with a service account, subject is the user to act as, e.g. alex@example.com")
		}
	default:
		return errors.New("add an OAuth client with a refresh token, or a service account with domain-wide delegation and a subject")
	}
	if c.Calendar == "" {
		c.Calendar = "primary"
	}
	if !calendarRe.MatchString(c.Calendar) {
		return errors.New("the calendar is primary or a calendar id like team@group.calendar.google.com")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	client = rest.SameHostOnly(client)
	tokenURL := defaultToken
	if m.TokenURL != "" {
		tokenURL = m.TokenURL
	}
	cn := &conn{cfg: c, host: h, http: client, tokenURL: tokenURL}
	auth := func(ctx context.Context, r *http.Request) error {
		t, err := cn.token(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	}
	gmailBase, wwwBase := "https://gmail.googleapis.com", "https://www.googleapis.com"
	if m.Base != "" {
		gmailBase, wwwBase = m.Base, m.Base
	}
	cn.gmail, cn.www = rest.New(gmailBase, auth), rest.New(wwwBase, auth)
	cn.gmail.HTTP, cn.www.HTTP = client, client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) token(ctx context.Context) (string, error) {
	return c.tok.Get(ctx, func(ctx context.Context) (oauth.Grant, error) {
		if c.cfg.ServiceAccount != "" {
			raw, err := c.host.Secret(ctx, c.cfg.ServiceAccount)
			if err != nil {
				return oauth.Grant{}, err
			}
			sa, key, err := oauth.ParseServiceAccount(raw)
			if err != nil {
				return oauth.Grant{}, err
			}
			now := time.Now()
			jwt, err := oauth.SignRS256(key, sa.PrivateKeyID, map[string]any{"iss": sa.ClientEmail, "sub": c.cfg.Subject,
				"scope": strings.Join(Scopes, " "), "aud": c.tokenURL, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
			if err != nil {
				return oauth.Grant{}, errors.New("couldn't sign with the service-account key")
			}
			g, err := oauth.Exchange(ctx, c.http, c.tokenURL, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {jwt}}, "", "")
			return g, c.explainToken(err)
		}
		secret, err := c.host.Secret(ctx, c.cfg.ClientSecret)
		if err != nil {
			return oauth.Grant{}, err
		}
		refresh, err := c.host.Secret(ctx, c.cfg.RefreshToken)
		if err != nil {
			return oauth.Grant{}, err
		}
		g, err := oauth.Exchange(ctx, c.http, c.tokenURL, url.Values{"grant_type": {"refresh_token"}, "client_id": {c.cfg.ClientID},
			"client_secret": {strings.TrimSpace(secret)}, "refresh_token": {strings.TrimSpace(refresh)}}, "", "")
		return g, c.explainToken(err)
	})
}

func (c *conn) explainToken(err error) error {
	var e *oauth.Error
	if !errors.As(err, &e) {
		return err
	}
	if c.cfg.ServiceAccount != "" {
		switch e.Code {
		case "unauthorized_client", "access_denied":
			return errors.New("Google refused the service account: authorize its client id for the module's scopes under domain-wide delegation in the Admin console")
		case "invalid_grant":
			return errors.New("Google refused the service account's sign-in (unknown or suspended subject, a deleted key, or this machine's clock is off)")
		}
		return fmt.Errorf("Google didn't issue a token for the service account: %v", e)
	}
	switch e.Code {
	case "invalid_client", "unauthorized_client":
		return errors.New("Google refused the OAuth client id or secret")
	case "invalid_grant":
		return errors.New("Google refused the refresh token (expired, revoked, or issued to another client); get a new one as the docs describe")
	}
	return fmt.Errorf("Google didn't issue a token: %v", e)
}

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Google refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Google refused this: the API may be off in the Cloud project, or the token lacks the scope the docs name")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("Google has nothing at that id")
	}
	return err
}

// do calls an API; a 401 drops the cached token and tries once more.
func (c *conn) do(ctx context.Context, api *rest.Client, method, path string, q url.Values, body, out any) error {
	_, err := api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.tok.Drop()
		_, err = api.Do(ctx, method, path, q, body, out)
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var p struct {
		Messages int `json:"messagesTotal"`
		Threads  int `json:"threadsTotal"`
	}
	if err := c.do(ctx, c.gmail, http.MethodGet, "/gmail/v1/users/me/profile", nil, nil, &p); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err).Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("Gmail: %d messages in %d conversations", p.Messages, p.Threads)}
}

type input struct {
	ID        string   `json:"id"`
	Query     string   `json:"query"`
	Limit     int      `json:"limit"`
	To        []string `json:"to"`
	Cc        []string `json:"cc"`
	Bcc       []string `json:"bcc"`
	Subject   string   `json:"subject"`
	Body      string   `json:"body"`
	Calendar  string   `json:"calendar"`
	Days      int      `json:"days"`
	Start     string   `json:"start"`
	End       string   `json:"end"`
	Location  string   `json:"location"`
	Attendees []string `json:"attendees"`
	Online    bool     `json:"online"`
	Folder    string   `json:"folder"`
	Name      string   `json:"name"`
}

func limit(n, def, max int) int {
	if n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func oneLine(s string, max int) bool {
	return len(s) <= max && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
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
	p.ID = strings.TrimSpace(p.ID)
	cal := strings.TrimSpace(p.Calendar)
	if cal == "" {
		cal = c.cfg.Calendar
	}
	calOK := func() error {
		if !calendarRe.MatchString(cal) {
			return errors.New("the calendar is primary or a calendar id like team@group.calendar.google.com")
		}
		return nil
	}
	var res sdk.Result
	switch call.Action {
	case "mail_list":
		res, err = c.mailList(ctx, p)
	case "mail_read":
		if !msgIDRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("give the message id from mail_list")
		}
		res, err = c.mailRead(ctx, p.ID)
	case "send_mail":
		res, err = c.sendMail(ctx, call, p)
	case "events":
		if err := calOK(); err != nil {
			return sdk.Result{}, err
		}
		res, err = c.events(ctx, cal, p)
	case "create_event", "schedule_meeting":
		if err := calOK(); err != nil {
			return sdk.Result{}, err
		}
		res, err = c.createEvent(ctx, call, cal, p)
	case "delete_event":
		if err := calOK(); err != nil {
			return sdk.Result{}, err
		}
		if !eventIDRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("give the event id from events")
		}
		res, err = c.deleteEvent(ctx, call, cal, p.ID)
	case "files":
		res, err = c.files(ctx, p)
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	return res, friendly(err)
}

type header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type part struct {
	MimeType string   `json:"mimeType"`
	Filename string   `json:"filename"`
	Headers  []header `json:"headers"`
	Body     struct {
		Size int    `json:"size"`
		Data string `json:"data"`
	} `json:"body"`
	Parts []part `json:"parts"`
}

func (p part) header(name string) string {
	for _, h := range p.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

type gmailMsg struct {
	ID       string   `json:"id"`
	ThreadID string   `json:"threadId"`
	Labels   []string `json:"labelIds"`
	Snippet  string   `json:"snippet"`
	Payload  part     `json:"payload"`
}

func (g gmailMsg) unread() bool {
	for _, l := range g.Labels {
		if l == "UNREAD" {
			return true
		}
	}
	return false
}

func (c *conn) mailList(ctx context.Context, p input) (sdk.Result, error) {
	q := strings.TrimSpace(p.Query)
	if q == "" {
		q = "in:inbox"
	}
	if !oneLine(q, 500) {
		return sdk.Result{}, errors.New("the query is one line of up to 500 characters")
	}
	var list struct {
		Messages []struct {
			ID string `json:"id"`
		} `json:"messages"`
	}
	if err := c.do(ctx, c.gmail, http.MethodGet, "/gmail/v1/users/me/messages", url.Values{"q": {q}, "maxResults": {strconv.Itoa(limit(p.Limit, 20, 25))}}, nil, &list); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, x := range list.Messages {
		if !msgIDRe.MatchString(x.ID) {
			continue
		}
		var g gmailMsg
		q := url.Values{"format": {"metadata"}, "metadataHeaders": {"From", "Subject", "Date"}}
		if err := c.do(ctx, c.gmail, http.MethodGet, "/gmail/v1/users/me/messages/"+x.ID, q, nil, &g); err != nil {
			return sdk.Result{}, err
		}
		out = append(out, map[string]any{"id": g.ID, "thread": g.ThreadID, "from": g.Payload.header("From"), "subject": g.Payload.header("Subject"),
			"date": g.Payload.header("Date"), "snippet": html.UnescapeString(g.Snippet), "unread": g.unread()})
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

// htmlText reduces HTML to its text: block elements become line breaks,
// scripts and styles are dropped, entities are decoded.
func htmlText(s string) string {
	s = dropRe.ReplaceAllString(s, "")
	s = blockRe.ReplaceAllString(s, "\n")
	s = html.UnescapeString(tagRe.ReplaceAllString(s, ""))
	s = blankRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(spaceRe.ReplaceAllString(s, "\n\n"))
}

// text finds the message's plain text, or reduces its HTML to text.
func text(p part) (plain, htm string, files []map[string]any) {
	var walk func(p part)
	walk = func(p part) {
		if p.Filename != "" {
			files = append(files, map[string]any{"name": p.Filename, "type": p.MimeType, "sizeKB": p.Body.Size / 1024})
			return
		}
		switch p.MimeType {
		case "text/plain":
			if plain == "" {
				if b, err := b64(p.Body.Data); err == nil {
					plain = string(b)
				}
			}
		case "text/html":
			if htm == "" {
				if b, err := b64(p.Body.Data); err == nil {
					htm = string(b)
				}
			}
		}
		for _, sub := range p.Parts {
			walk(sub)
		}
	}
	walk(p)
	return plain, htm, files
}

func (c *conn) mailRead(ctx context.Context, id string) (sdk.Result, error) {
	var g gmailMsg
	if err := c.do(ctx, c.gmail, http.MethodGet, "/gmail/v1/users/me/messages/"+id, url.Values{"format": {"full"}}, nil, &g); err != nil {
		return sdk.Result{}, err
	}
	plain, htm, files := text(g.Payload)
	if plain == "" && htm != "" {
		plain = htmlText(htm)
	}
	if files == nil {
		files = []map[string]any{}
	}
	h := g.Payload.header
	return sdk.JSON(map[string]any{"id": g.ID, "thread": g.ThreadID, "from": h("From"), "to": h("To"), "cc": h("Cc"), "subject": h("Subject"),
		"date": h("Date"), "unread": g.unread(), "text": strings.ReplaceAll(plain, "\r\n", "\n"), "attachments": files})
}

func (c *conn) sendMail(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	from := ""
	if c.cfg.ServiceAccount != "" {
		from = c.cfg.Subject
	}
	msg, err := mimemsg.Message{From: from, To: p.To, Cc: p.Cc, Bcc: p.Bcc, Subject: p.Subject, Text: p.Body}.Check()
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		b, _ := json.Marshal(msg.Preview())
		return sdk.Result{Plan: &sdk.Plan{Summary: msg.Summary(), Changes: []sdk.Change{{Target: fmt.Sprintf("%d recipients", msg.Count()), Op: "send", After: b}}}}, nil
	}
	// Gmail removes the Bcc header from what it delivers.
	var out struct {
		ID       string `json:"id"`
		ThreadID string `json:"threadId"`
	}
	raw := base64.RawURLEncoding.EncodeToString(msg.Build(time.Now()))
	if err := c.do(ctx, c.gmail, http.MethodPost, "/gmail/v1/users/me/messages/send", nil, map[string]string{"raw": raw}, &out); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"sent": true, "id": out.ID, "recipients": msg.Count(), "subject": msg.Subject})
}

type gEvent struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Summary   string `json:"summary"`
	Location  string `json:"location"`
	HTMLLink  string `json:"htmlLink"`
	Start     gTime  `json:"start"`
	End       gTime  `json:"end"`
	Organizer struct {
		Email string `json:"email"`
		Self  bool   `json:"self"`
	} `json:"organizer"`
	Attendees []struct {
		Email    string `json:"email"`
		Name     string `json:"displayName"`
		Response string `json:"responseStatus"`
		Self     bool   `json:"self"`
	} `json:"attendees"`
	Meet       string   `json:"hangoutLink"`
	Recurrence []string `json:"recurrence"` // set on a recurring series itself
}

type gTime struct {
	DateTime string `json:"dateTime,omitempty"`
	Date     string `json:"date,omitempty"`
}

func (t gTime) String() string {
	if t.DateTime != "" {
		return t.DateTime
	}
	return t.Date
}

func calPath(cal string) string { return "/calendar/v3/calendars/" + url.PathEscape(cal) + "/events" }

func (c *conn) events(ctx context.Context, cal string, p input) (sdk.Result, error) {
	now := time.Now().UTC()
	q := url.Values{"timeMin": {now.Format(time.RFC3339)}, "timeMax": {now.AddDate(0, 0, limit(p.Days, 7, 60)).Format(time.RFC3339)},
		"singleEvents": {"true"}, "orderBy": {"startTime"}, "maxResults": {"250"}}
	var out struct {
		Items []gEvent `json:"items"`
	}
	if err := c.do(ctx, c.www, http.MethodGet, calPath(cal), q, nil, &out); err != nil {
		return sdk.Result{}, err
	}
	list := []map[string]any{}
	for _, e := range out.Items {
		att := []string{}
		for _, a := range e.Attendees {
			s := a.Email
			if a.Name != "" {
				s = a.Name + " <" + a.Email + ">"
			}
			if a.Response != "" && a.Response != "needsAction" {
				s += " (" + a.Response + ")"
			}
			att = append(att, s)
		}
		row := map[string]any{"id": e.ID, "subject": e.Summary, "start": e.Start.String(), "end": e.End.String(), "organizer": e.Organizer.Email, "attendees": att}
		if e.Start.DateTime == "" {
			row["allDay"] = true
		}
		if e.Location != "" {
			row["location"] = e.Location
		}
		if e.Meet != "" {
			row["meet"] = e.Meet
		}
		list = append(list, row)
	}
	return sdk.JSON(list)
}

func eventIn(p input, meeting bool) (start, end time.Time, attendees []string, err error) {
	if strings.TrimSpace(p.Subject) == "" || !oneLine(p.Subject, 255) {
		return start, end, nil, errors.New("a subject is one line of up to 255 characters")
	}
	if !oneLine(p.Location, 255) {
		return start, end, nil, errors.New("the location is one line of up to 255 characters")
	}
	if len(p.Body) > 32<<10 {
		return start, end, nil, errors.New("the description is over 32 KB")
	}
	if start, err = time.Parse(time.RFC3339, strings.TrimSpace(p.Start)); err != nil {
		return start, end, nil, errors.New("start is RFC 3339, like 2026-11-05T10:00:00+01:00")
	}
	if end, err = time.Parse(time.RFC3339, strings.TrimSpace(p.End)); err != nil {
		return start, end, nil, errors.New("end is RFC 3339, like 2026-11-05T11:00:00+01:00")
	}
	if !end.After(start) {
		return start, end, nil, errors.New("the end is after the start")
	}
	if end.Sub(start) > 31*24*time.Hour {
		return start, end, nil, errors.New("an event lasts at most 31 days")
	}
	if !meeting {
		if len(p.Attendees) > 0 {
			return start, end, nil, errors.New("create_event adds a private event; to invite people use schedule_meeting")
		}
		return start, end, nil, nil
	}
	as, err := mimemsg.Addresses(p.Attendees, "attendees")
	if err != nil {
		return start, end, nil, err
	}
	if len(as) == 0 {
		return start, end, nil, errors.New("add at least one attendee (without attendees, use create_event)")
	}
	if len(as) > mimemsg.MaxRecipients {
		return start, end, nil, fmt.Errorf("at most %d attendees", mimemsg.MaxRecipients)
	}
	return start, end, mimemsg.Bare(as), nil
}

// preview is the start of a long text, as the plans show it.
func preview(s string) string {
	if len(s) <= 4000 {
		return s
	}
	s = s[:4000]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}

func (c *conn) createEvent(ctx context.Context, call sdk.Call, cal string, p input) (sdk.Result, error) {
	meeting := call.Action == "schedule_meeting"
	start, end, attendees, err := eventIn(p, meeting)
	if err != nil {
		return sdk.Result{}, err
	}
	subject := strings.TrimSpace(p.Subject)
	if call.DryRun {
		after := map[string]any{"calendar": cal, "subject": subject, "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}
		if p.Location != "" {
			after["location"] = p.Location
		}
		if p.Body != "" {
			// The description goes out with every invitation.
			after["body"] = preview(p.Body)
		}
		summary := fmt.Sprintf("Add %q on %s", subject, start.Format("Mon 2 Jan 15:04 MST"))
		if meeting {
			after["attendees"] = attendees
			after["online"] = p.Online
			summary = fmt.Sprintf("Invite %d people to %q on %s", len(attendees), subject, start.Format("Mon 2 Jan 15:04 MST"))
		}
		b, _ := json.Marshal(after)
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "calendar " + cal, Op: "create", After: b}}}}, nil
	}
	body := map[string]any{"summary": subject, "start": gTime{DateTime: start.Format(time.RFC3339)}, "end": gTime{DateTime: end.Format(time.RFC3339)}}
	if p.Body != "" {
		body["description"] = p.Body
	}
	if p.Location != "" {
		body["location"] = p.Location
	}
	q := url.Values{"sendUpdates": {"none"}}
	if meeting {
		list := []map[string]string{}
		for _, a := range attendees {
			list = append(list, map[string]string{"email": a})
		}
		body["attendees"] = list
		q.Set("sendUpdates", "all")
		if p.Online {
			body["conferenceData"] = map[string]any{"createRequest": map[string]any{"requestId": strconv.FormatInt(time.Now().UnixNano(), 36),
				"conferenceSolutionKey": map[string]string{"type": "hangoutsMeet"}}}
			q.Set("conferenceDataVersion", "1")
		}
	}
	var out gEvent
	if err := c.do(ctx, c.www, http.MethodPost, calPath(cal), q, body, &out); err != nil {
		return sdk.Result{}, err
	}
	if !eventIDRe.MatchString(out.ID) {
		return sdk.Result{}, errors.New("Google answered without the new event's id")
	}
	r, err := sdk.JSON(map[string]any{"id": out.ID, "calendar": cal, "subject": out.Summary, "start": out.Start.String(), "end": out.End.String(),
		"invited": len(attendees), "link": out.HTMLLink, "meet": out.Meet})
	undo := "Delete the event"
	if meeting {
		undo = "Delete the meeting (attendees get a cancellation)"
	}
	r.Undo = sdk.UndoWith("delete_event", map[string]string{"calendar": cal, "id": out.ID}, undo)
	return r, err
}

func (c *conn) deleteEvent(ctx context.Context, call sdk.Call, cal, id string) (sdk.Result, error) {
	path := calPath(cal) + "/" + url.PathEscape(id)
	var e gEvent
	if err := c.do(ctx, c.www, http.MethodGet, path, nil, nil, &e); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusGone) {
			return sdk.JSON(map[string]any{"id": id, "deleted": true, "note": "nothing to change"})
		}
		return sdk.Result{}, err
	}
	if e.Status == "cancelled" {
		return sdk.JSON(map[string]any{"id": id, "deleted": true, "note": "nothing to change"})
	}
	others := 0
	for _, a := range e.Attendees {
		if !a.Self {
			others++
		}
	}
	if call.DryRun {
		// Not a sensitive action: the plan names no title or attendee.
		before := map[string]any{"start": e.Start.String(), "end": e.End.String(), "attendees": others}
		summary := "Delete the event starting " + e.Start.String()
		if len(e.Recurrence) > 0 {
			// Deleting the series itself deletes every occurrence.
			before["series"] = true
			summary = "Delete the whole recurring series starting " + e.Start.String()
		}
		b, _ := json.Marshal(before)
		if others > 0 {
			summary += fmt.Sprintf(" (%d attendees get a cancellation)", others)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "event " + id, Op: "delete", Before: b}}}}, nil
	}
	if err := c.do(ctx, c.www, http.MethodDelete, path, url.Values{"sendUpdates": {"all"}}, nil, nil); err != nil {
		if rest.IsStatus(err, http.StatusGone) {
			return sdk.JSON(map[string]any{"id": id, "deleted": true, "note": "nothing to change"})
		}
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"id": id, "deleted": true})
}

// quote makes a Drive query string literal.
func quote(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `'`, `\'`) + "'"
}

func (c *conn) files(ctx context.Context, p input) (sdk.Result, error) {
	conds := []string{"trashed = false"}
	if f := strings.TrimSpace(p.Folder); f != "" {
		if !fileIDRe.MatchString(f) {
			return sdk.Result{}, errors.New("the folder is its id, from its link (…/folders/<id>)")
		}
		conds = append(conds, quote(f)+" in parents")
	}
	if n := strings.TrimSpace(p.Name); n != "" {
		if !oneLine(n, 200) {
			return sdk.Result{}, errors.New("the name filter is one line of up to 200 characters")
		}
		conds = append(conds, "name contains "+quote(n))
	}
	q := url.Values{"q": {strings.Join(conds, " and ")}, "pageSize": {strconv.Itoa(limit(p.Limit, 50, 100))}, "orderBy": {"modifiedTime desc"},
		"fields": {"files(id,name,mimeType,size,modifiedTime,webViewLink)"}, "supportsAllDrives": {"true"}, "includeItemsFromAllDrives": {"true"}}
	var out struct {
		Files []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Type     string `json:"mimeType"`
			Size     string `json:"size"`
			Modified string `json:"modifiedTime"`
			Link     string `json:"webViewLink"`
		} `json:"files"`
	}
	if err := c.do(ctx, c.www, http.MethodGet, "/drive/v3/files", q, nil, &out); err != nil {
		return sdk.Result{}, err
	}
	list := []map[string]any{}
	for _, f := range out.Files {
		row := map[string]any{"id": f.ID, "name": f.Name, "type": f.Type, "modified": f.Modified, "link": f.Link,
			"folder": f.Type == "application/vnd.google-apps.folder"}
		if n, err := strconv.ParseInt(f.Size, 10, 64); err == nil {
			row["size"] = n
		}
		list = append(list, row)
	}
	return sdk.JSON(list)
}

// b64 decodes Gmail's base64url, with or without padding.
func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
