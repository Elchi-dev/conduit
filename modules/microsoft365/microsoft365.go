// Package microsoft365 works with Microsoft 365 through Microsoft Graph:
// Outlook mail (list, read, send), calendar events (list, create, delete),
// posting to a Teams channel and listing OneDrive files. It signs in as an
// app (client credentials, acting on one mailbox) or as a user (a delegated
// refresh token from the vault).
package microsoft365

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/mention"
	"github.com/elchi-dev/conduit/modules/internal/mimemsg"
	"github.com/elchi-dev/conduit/modules/internal/oauth"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Microsoft 365 sign-in.
type Config struct {
	Tenant       string `json:"tenant"`       // directory (tenant) id or domain
	ClientID     string `json:"clientId"`     // application (client) id
	ClientSecret string `json:"clientSecret"` // secret://
	RefreshToken string `json:"refreshToken"` // secret://, delegated sign-in; empty: app sign-in
	User         string `json:"user"`         // app sign-in: the mailbox (user principal name or id)
}

type conn struct {
	cfg      Config
	host     sdk.Host
	http     *http.Client
	api      *rest.Client
	tokenURL string
	tok      oauth.Cache

	mu         sync.Mutex
	rotated    string   // the newest refresh token Microsoft sent, in memory only
	rotatedFor [32]byte // hash of the stored refresh token it descends from
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://graph.microsoft.com/v1.0, TokenURL the token
	// endpoint and HTTP the client (tests). They aren't settings, so an
	// instance can't send its credentials anywhere else.
	Base     string
	TokenURL string
	HTTP     *http.Client
}

// New returns the Microsoft 365 module.
func New() *Module { return &Module{} }

const graphScope = "https://graph.microsoft.com/.default"

var (
	tenantRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
	guidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	userRe    = regexp.MustCompile(`^[A-Za-z0-9._%+'-]{1,113}@[A-Za-z0-9.-]{1,253}$`)
	idRe      = regexp.MustCompile(`^[A-Za-z0-9=_+-]{1,512}$`)
	folderRe  = regexp.MustCompile(`^(inbox|sentitems|drafts|archive|deleteditems|junkemail|[A-Za-z0-9=_+-]{20,512})$`)
	channelRe = regexp.MustCompile(`^19:[A-Za-z0-9_.-]{1,200}@thread\.(tacv2|skype)$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	addrs := `"to":{"type":"array","items":{"type":"string"}},"cc":{"type":"array","items":{"type":"string"}},"bcc":{"type":"array","items":{"type":"string"}}`
	event := `"subject":{"type":"string"},"start":{"type":"string","description":"RFC 3339, e.g. 2026-11-05T10:00:00+01:00"},"end":{"type":"string","description":"RFC 3339"},"location":{"type":"string"},"body":{"type":"string","x-multiline":true}`
	id := `{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}`
	return sdk.Manifest{
		ID: "microsoft365", Name: "Microsoft 365", Version: "0.1.0", Category: "Productivity", Icon: "mail",
		Description: "Microsoft 365 through Microsoft Graph: Outlook mail (read and send), calendar events, Teams channel posts and OneDrive files.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["tenant","clientId","clientSecret"],"properties":{
			"tenant":{"type":"string","description":"Directory (tenant) id or primary domain, from the app registration's overview"},
			"clientId":{"type":"string","description":"Application (client) id of the app registration"},
			"clientSecret":{"type":"string","x-secret":true,"description":"A client secret of the app registration (Certificates & secrets)"},
			"refreshToken":{"type":"string","x-secret":true,"description":"Optional: a delegated refresh token, to act as that user (needed for Teams posts). Without it the app signs in as itself and acts on the mailbox below."},
			"user":{"type":"string","description":"App sign-in: the mailbox to act on, e.g. alex@contoso.com"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "mail_list", Title: "Mail", Description: "Newest messages in a folder: sender, subject, preview, received, read and attachments.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"folder":{"type":"string","default":"inbox","description":"inbox, sentitems, drafts, archive, deleteditems, junkemail or a folder id"},"limit":{"type":"integer","default":25,"maximum":50},"unreadOnly":{"type":"boolean"}}}`)},
			{Name: "mail_read", Title: "Read a message", Description: "Sender, recipients, subject, the text of the body (HTML is converted by Microsoft, never rendered) and attachment names. Doesn't mark it read.", Risk: sdk.RiskRead, Sensitive: true, Input: sdk.Schema(id)},
			{Name: "send_mail", Title: "Send mail", Description: "Sends a plain-text message from the mailbox; it can't be called back. The preview shows recipients, subject and body.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["to","subject","body"],"properties":{` + addrs + `,"subject":{"type":"string"},"body":{"type":"string","x-multiline":true,"description":"Plain text"}}}`)},
			{Name: "events", Title: "Calendar", Description: "Events in the coming days: subject, start, end, location, organizer and attendees.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","default":7,"minimum":1,"maximum":60}}}`)},
			{Name: "create_event", Title: "Add a private event", Description: "Adds an event without attendees to the calendar; nobody is invited. Undo deletes it.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["subject","start","end"],"properties":{` + event + `}}`)},
			{Name: "schedule_meeting", Title: "Schedule a meeting", Description: "Adds an event and sends an invitation to every attendee. Undo deletes it, which sends them a cancellation.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["subject","start","end","attendees"],"properties":{` + event + `,"attendees":{"type":"array","items":{"type":"string"},"maxItems":50},"online":{"type":"boolean","description":"Add a Teams meeting link"}}}`)},
			{Name: "delete_event", Title: "Delete an event", Description: "Deletes an event; for a meeting you organize, attendees get a cancellation. The preview shows its time and how many attendees it has.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(id)},
			{Name: "post_channel_message", Title: "Post to a Teams channel", Description: "Posts plain text to a channel as the signed-in user (delegated sign-in only). Mentions of the whole channel or team are refused.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["team","channel","message"],"properties":{"team":{"type":"string","description":"Team id (a GUID)"},"channel":{"type":"string","description":"Channel id, like 19:…@thread.tacv2"},"message":{"type":"string","x-multiline":true,"maxLength":4000}}}`)},
			{Name: "files", Title: "OneDrive files", Description: "Files and folders in a OneDrive folder: name, size, modified and type.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"path":{"type":"string","description":"Folder path, e.g. Documents/Reports (empty: the root)"},"limit":{"type":"integer","default":100,"maximum":200}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.Tenant, c.ClientID, c.User = strings.TrimSpace(c.Tenant), strings.TrimSpace(c.ClientID), strings.TrimSpace(c.User)
	if !tenantRe.MatchString(c.Tenant) {
		return errors.New("the tenant is the directory (tenant) id or a domain such as contoso.onmicrosoft.com")
	}
	if !guidRe.MatchString(c.ClientID) {
		return errors.New("the client id is the app registration's application (client) id, a GUID")
	}
	if !strings.HasPrefix(c.ClientSecret, "secret://") {
		return errors.New("store the client secret in the vault and enter its secret:// reference")
	}
	if c.RefreshToken != "" && !strings.HasPrefix(c.RefreshToken, "secret://") {
		return errors.New("store the refresh token in the vault and enter its secret:// reference")
	}
	if c.RefreshToken == "" {
		if c.User == "" {
			return errors.New("with the app sign-in, name the mailbox to act on (user), e.g. alex@contoso.com")
		}
		if !userRe.MatchString(c.User) && !guidRe.MatchString(c.User) {
			return errors.New("the user is a user principal name like alex@contoso.com, or a user id")
		}
	} else if c.User != "" {
		return errors.New("with a refresh token the module acts as that user; leave user empty")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	client = rest.SameHostOnly(client)
	base, tokenURL := m.Base, m.TokenURL
	if base == "" {
		base = "https://graph.microsoft.com/v1.0"
	}
	if tokenURL == "" {
		tokenURL = "https://login.microsoftonline.com/" + url.PathEscape(c.Tenant) + "/oauth2/v2.0/token"
	}
	cn := &conn{cfg: c, host: h, http: client, tokenURL: tokenURL}
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := cn.token(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = client
	cn.api.Header.Set("Prefer", `outlook.body-content-type="text", outlook.timezone="UTC"`)
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) delegated() bool { return c.cfg.RefreshToken != "" }

// token returns a cached access token or gets a new one.
func (c *conn) token(ctx context.Context) (string, error) {
	return c.tok.Get(ctx, func(ctx context.Context) (oauth.Grant, error) {
		secret, err := c.host.Secret(ctx, c.cfg.ClientSecret)
		if err != nil {
			return oauth.Grant{}, err
		}
		form := url.Values{"client_id": {c.cfg.ClientID}, "client_secret": {strings.TrimSpace(secret)}}
		if !c.delegated() {
			form.Set("grant_type", "client_credentials")
			form.Set("scope", graphScope)
			g, err := oauth.Exchange(ctx, c.http, c.tokenURL, form, "", "")
			return g, explainToken(err)
		}
		stored, err := c.host.Secret(ctx, c.cfg.RefreshToken)
		if err != nil {
			return oauth.Grant{}, err
		}
		stored = strings.TrimSpace(stored)
		// A rotated token is used only while the vault still holds the token
		// it came from: one replaced there (another user, a new consent)
		// takes over at once.
		sum := sha256.Sum256([]byte(stored))
		refresh := stored
		c.mu.Lock()
		if c.rotated != "" && c.rotatedFor == sum {
			refresh = c.rotated
		}
		c.mu.Unlock()
		form.Set("grant_type", "refresh_token")
		form.Set("scope", graphScope+" offline_access")
		form.Set("refresh_token", refresh)
		g, err := oauth.Exchange(ctx, c.http, c.tokenURL, form, "", "")
		if err != nil && refresh != stored {
			// The rotated token was refused: fall back to the stored one.
			form.Set("refresh_token", stored)
			g, err = oauth.Exchange(ctx, c.http, c.tokenURL, form, "", "")
		}
		if err != nil {
			return g, explainToken(err)
		}
		if g.Refresh != "" {
			c.mu.Lock()
			c.rotated, c.rotatedFor = g.Refresh, sum
			c.mu.Unlock()
		}
		return g, nil
	})
}

func explainToken(err error) error {
	var e *oauth.Error
	if !errors.As(err, &e) {
		return err
	}
	switch e.Code {
	case "invalid_client", "unauthorized_client":
		return errors.New("Microsoft refused the client id or secret (expired secret, or the wrong tenant)")
	case "invalid_grant", "interaction_required":
		return errors.New("Microsoft refused the refresh token (expired, revoked, or consent was withdrawn); sign in again for a new one")
	}
	return fmt.Errorf("Microsoft didn't issue a token: %v", e)
}

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Microsoft Graph refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the app isn't allowed to do this; grant the Graph permission the docs name (and admin consent)")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("Microsoft Graph has nothing at that id or path")
	}
	return err
}

// do calls Graph; a 401 drops the cached token and tries once more.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.tok.Drop()
		_, err = c.api.Do(ctx, method, path, q, body, out)
	}
	return err
}

// me is the path of the mailbox and drive the instance acts on.
func (c *conn) me() string {
	if c.delegated() {
		return "/me"
	}
	return "/users/" + url.PathEscape(c.cfg.User)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var f struct {
		Total  int `json:"totalItemCount"`
		Unread int `json:"unreadItemCount"`
	}
	if err := c.do(ctx, http.MethodGet, c.me()+"/mailFolders/inbox", url.Values{"$select": {"totalItemCount,unreadItemCount"}}, nil, &f); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err).Error()}
	}
	mode := "app sign-in"
	if c.delegated() {
		mode = "delegated sign-in"
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("Inbox: %d messages, %d unread (%s)", f.Total, f.Unread, mode)}
}

type address struct {
	EmailAddress struct {
		Name    string `json:"name"`
		Address string `json:"address"`
	} `json:"emailAddress"`
}

func (a address) String() string {
	if a.EmailAddress.Name != "" && a.EmailAddress.Name != a.EmailAddress.Address {
		return a.EmailAddress.Name + " <" + a.EmailAddress.Address + ">"
	}
	return a.EmailAddress.Address
}

func addrs(as []address) []string {
	out := []string{}
	for _, a := range as {
		out = append(out, a.String())
	}
	return out
}

type input struct {
	ID         string   `json:"id"`
	Folder     string   `json:"folder"`
	Limit      int      `json:"limit"`
	UnreadOnly bool     `json:"unreadOnly"`
	To         []string `json:"to"`
	Cc         []string `json:"cc"`
	Bcc        []string `json:"bcc"`
	Subject    string   `json:"subject"`
	Body       string   `json:"body"`
	Days       int      `json:"days"`
	Start      string   `json:"start"`
	End        string   `json:"end"`
	Location   string   `json:"location"`
	Attendees  []string `json:"attendees"`
	Online     bool     `json:"online"`
	Team       string   `json:"team"`
	Channel    string   `json:"channel"`
	Message    string   `json:"message"`
	Path       string   `json:"path"`
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

func checkID(id string) error {
	if !idRe.MatchString(strings.TrimSpace(id)) {
		return errors.New("give the id from a list action")
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
	p.ID = strings.TrimSpace(p.ID)
	var res sdk.Result
	switch call.Action {
	case "mail_list":
		res, err = c.mailList(ctx, p)
	case "mail_read":
		if err := checkID(p.ID); err != nil {
			return sdk.Result{}, err
		}
		res, err = c.mailRead(ctx, p.ID)
	case "send_mail":
		res, err = c.sendMail(ctx, call, p)
	case "events":
		res, err = c.events(ctx, p)
	case "create_event", "schedule_meeting":
		res, err = c.createEvent(ctx, call, p)
	case "delete_event":
		if err := checkID(p.ID); err != nil {
			return sdk.Result{}, err
		}
		res, err = c.deleteEvent(ctx, call, p.ID)
	case "post_channel_message":
		res, err = c.post(ctx, call, p)
	case "files":
		res, err = c.files(ctx, p)
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	return res, friendly(err)
}

func (c *conn) mailList(ctx context.Context, p input) (sdk.Result, error) {
	folder := strings.TrimSpace(p.Folder)
	if folder == "" {
		folder = "inbox"
	}
	if !folderRe.MatchString(folder) {
		return sdk.Result{}, errors.New("the folder is inbox, sentitems, drafts, archive, deleteditems, junkemail or a folder id")
	}
	q := url.Values{"$top": {strconv.Itoa(limit(p.Limit, 25, 50))}, "$orderby": {"receivedDateTime desc"},
		"$select": {"id,receivedDateTime,from,subject,bodyPreview,isRead,hasAttachments"}}
	if p.UnreadOnly {
		// Graph wants the sort property in the filter, first.
		q.Set("$filter", "receivedDateTime ge 1900-01-01T00:00:00Z and isRead eq false")
	}
	var out struct {
		Value []struct {
			ID          string  `json:"id"`
			Received    string  `json:"receivedDateTime"`
			From        address `json:"from"`
			Subject     string  `json:"subject"`
			Preview     string  `json:"bodyPreview"`
			IsRead      bool    `json:"isRead"`
			Attachments bool    `json:"hasAttachments"`
		} `json:"value"`
	}
	if err := c.do(ctx, http.MethodGet, c.me()+"/mailFolders/"+url.PathEscape(folder)+"/messages", q, nil, &out); err != nil {
		return sdk.Result{}, err
	}
	list := []map[string]any{}
	for _, x := range out.Value {
		list = append(list, map[string]any{"id": x.ID, "received": x.Received, "from": x.From.String(), "subject": x.Subject,
			"preview": x.Preview, "unread": !x.IsRead, "attachments": x.Attachments})
	}
	return sdk.JSON(list)
}

func (c *conn) mailRead(ctx context.Context, id string) (sdk.Result, error) {
	var msg struct {
		ID       string    `json:"id"`
		Subject  string    `json:"subject"`
		From     address   `json:"from"`
		To       []address `json:"toRecipients"`
		Cc       []address `json:"ccRecipients"`
		Received string    `json:"receivedDateTime"`
		IsRead   bool      `json:"isRead"`
		HasAtt   bool      `json:"hasAttachments"`
		Body     struct {
			Content string `json:"content"`
		} `json:"body"`
	}
	q := url.Values{"$select": {"id,subject,from,toRecipients,ccRecipients,receivedDateTime,isRead,hasAttachments,body"}}
	if err := c.do(ctx, http.MethodGet, c.me()+"/messages/"+url.PathEscape(id), q, nil, &msg); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"id": msg.ID, "subject": msg.Subject, "from": msg.From.String(), "to": addrs(msg.To), "cc": addrs(msg.Cc),
		"received": msg.Received, "unread": !msg.IsRead, "text": msg.Body.Content}
	if msg.HasAtt {
		var att struct {
			Value []struct {
				Name string `json:"name"`
				Type string `json:"contentType"`
				Size int    `json:"size"`
			} `json:"value"`
		}
		if c.do(ctx, http.MethodGet, c.me()+"/messages/"+url.PathEscape(id)+"/attachments", url.Values{"$select": {"name,contentType,size"}}, nil, &att) == nil {
			files := []map[string]any{}
			for _, a := range att.Value {
				files = append(files, map[string]any{"name": a.Name, "type": a.Type, "sizeKB": a.Size / 1024})
			}
			out["attachments"] = files
		}
	}
	return sdk.JSON(out)
}

func (c *conn) sendMail(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	from := ""
	if !c.delegated() && userRe.MatchString(c.cfg.User) {
		from = c.cfg.User
	}
	msg, err := mimemsg.Message{From: from, To: p.To, Cc: p.Cc, Bcc: p.Bcc, Subject: p.Subject, Text: p.Body}.Check()
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		b, _ := json.Marshal(msg.Preview())
		return sdk.Result{Plan: &sdk.Plan{Summary: msg.Summary(), Changes: []sdk.Change{{Target: fmt.Sprintf("%d recipients", msg.Count()), Op: "send", After: b}}}}, nil
	}
	// Graph takes the MIME message base64-encoded as text/plain.
	raw := base64.StdEncoding.EncodeToString(msg.Build(time.Now()))
	send := func() error {
		res, err := c.api.Send(ctx, http.MethodPost, c.me()+"/sendMail", nil, bytes.NewReader([]byte(raw)), http.Header{"Content-Type": {"text/plain"}})
		if err != nil {
			return err
		}
		res.Body.Close()
		return nil
	}
	err = send()
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.tok.Drop()
		err = send()
	}
	if err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"sent": true, "recipients": msg.Count(), "subject": msg.Subject})
}

type graphEvent struct {
	ID       string `json:"id"`
	Subject  string `json:"subject"`
	WebLink  string `json:"webLink"`
	Start    when   `json:"start"`
	End      when   `json:"end"`
	Location struct {
		Name string `json:"displayName"`
	} `json:"location"`
	Organizer address `json:"organizer"`
	Attendees []struct {
		address
		Status struct {
			Response string `json:"response"`
		} `json:"status"`
	} `json:"attendees"`
	Online      bool   `json:"isOnlineMeeting"`
	Cancelled   bool   `json:"isCancelled"`
	AllDay      bool   `json:"isAllDay"`
	IsOrganizer bool   `json:"isOrganizer"`
	Type        string `json:"type"` // singleInstance, occurrence, exception, seriesMaster
}

type when struct {
	DateTime string `json:"dateTime"`
	TimeZone string `json:"timeZone"`
}

// rfc3339 turns Graph's dateTime (no offset, in TimeZone) into RFC 3339
// when the zone is UTC (the Prefer header asks for UTC).
func (w when) rfc3339() string {
	if strings.EqualFold(w.TimeZone, "UTC") {
		if t, err := time.Parse("2006-01-02T15:04:05.9999999", w.DateTime); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return w.DateTime
}

func (c *conn) events(ctx context.Context, p input) (sdk.Result, error) {
	days := limit(p.Days, 7, 60)
	now := time.Now().UTC()
	q := url.Values{"startDateTime": {now.Format(time.RFC3339)}, "endDateTime": {now.AddDate(0, 0, days).Format(time.RFC3339)},
		"$orderby": {"start/dateTime"}, "$top": {"100"},
		"$select": {"id,subject,start,end,location,organizer,attendees,isOnlineMeeting,isCancelled,isAllDay,isOrganizer"}}
	var out struct {
		Value []graphEvent `json:"value"`
	}
	if err := c.do(ctx, http.MethodGet, c.me()+"/calendarView", q, nil, &out); err != nil {
		return sdk.Result{}, err
	}
	list := []map[string]any{}
	for _, e := range out.Value {
		att := []string{}
		for _, a := range e.Attendees {
			s := a.String()
			if r := a.Status.Response; r != "" && r != "none" {
				s += " (" + r + ")"
			}
			att = append(att, s)
		}
		row := map[string]any{"id": e.ID, "subject": e.Subject, "start": e.Start.rfc3339(), "end": e.End.rfc3339(), "organizer": e.Organizer.String(), "attendees": att}
		if e.Location.Name != "" {
			row["location"] = e.Location.Name
		}
		if e.Online {
			row["online"] = true
		}
		if e.Cancelled {
			row["cancelled"] = true
		}
		if e.AllDay {
			row["allDay"] = true
		}
		list = append(list, row)
	}
	return sdk.JSON(list)
}

// eventIn checks an event's fields; it's shared with the tests.
func eventIn(p input, meeting bool) (start, end time.Time, attendees []string, err error) {
	if strings.TrimSpace(p.Subject) == "" || len(p.Subject) > 255 || strings.ContainsAny(p.Subject, "\r\n") {
		return start, end, nil, errors.New("a subject is one line of up to 255 characters")
	}
	if len(p.Location) > 255 || strings.ContainsAny(p.Location, "\r\n") {
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

func (c *conn) createEvent(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	meeting := call.Action == "schedule_meeting"
	start, end, attendees, err := eventIn(p, meeting)
	if err != nil {
		return sdk.Result{}, err
	}
	subject := strings.TrimSpace(p.Subject)
	if call.DryRun {
		after := map[string]any{"subject": subject, "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}
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
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "calendar", Op: "create", After: b}}}}, nil
	}
	const layout = "2006-01-02T15:04:05"
	body := map[string]any{"subject": subject,
		"start": when{DateTime: start.UTC().Format(layout), TimeZone: "UTC"},
		"end":   when{DateTime: end.UTC().Format(layout), TimeZone: "UTC"}}
	if p.Body != "" {
		body["body"] = map[string]string{"contentType": "text", "content": p.Body}
	}
	if p.Location != "" {
		body["location"] = map[string]string{"displayName": p.Location}
	}
	if meeting {
		list := []map[string]any{}
		for _, a := range attendees {
			list = append(list, map[string]any{"emailAddress": map[string]string{"address": a}, "type": "required"})
		}
		body["attendees"] = list
		if p.Online {
			body["isOnlineMeeting"] = true
			body["onlineMeetingProvider"] = "teamsForBusiness"
		}
	}
	var out graphEvent
	if err := c.do(ctx, http.MethodPost, c.me()+"/events", nil, body, &out); err != nil {
		return sdk.Result{}, err
	}
	if !idRe.MatchString(out.ID) {
		return sdk.Result{}, errors.New("Microsoft Graph answered without the new event's id")
	}
	res, err := sdk.JSON(map[string]any{"id": out.ID, "subject": out.Subject, "start": out.Start.rfc3339(), "end": out.End.rfc3339(), "invited": len(attendees), "link": out.WebLink})
	undo := "Delete the event"
	if meeting {
		undo = "Delete the meeting (attendees get a cancellation)"
	}
	res.Undo = sdk.UndoWith("delete_event", map[string]string{"id": out.ID}, undo)
	return res, err
}

func (c *conn) deleteEvent(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	var e graphEvent
	path := c.me() + "/events/" + url.PathEscape(id)
	if err := c.do(ctx, http.MethodGet, path, url.Values{"$select": {"id,start,end,attendees,isOrganizer,type"}}, nil, &e); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.JSON(map[string]any{"id": id, "deleted": true, "note": "nothing to change"})
		}
		return sdk.Result{}, err
	}
	if call.DryRun {
		// Not a sensitive action: the plan names no subject or attendee.
		before := map[string]any{"start": e.Start.rfc3339(), "end": e.End.rfc3339(), "attendees": len(e.Attendees)}
		summary := "Delete the event starting " + e.Start.rfc3339()
		if e.Type == "seriesMaster" {
			// Deleting the series' master deletes every occurrence.
			before["series"] = true
			summary = "Delete the whole recurring series starting " + e.Start.rfc3339()
		}
		b, _ := json.Marshal(before)
		if len(e.Attendees) > 0 && e.IsOrganizer {
			summary += fmt.Sprintf(" (%d attendees get a cancellation)", len(e.Attendees))
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "event " + id, Op: "delete", Before: b}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"id": id, "deleted": true})
}

// wildcardRe catches Teams-style whole-channel and whole-team mentions
// that the mention package doesn't know.
var wildcardRe = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_.-])@(team|channel|everyone|all|here)\b`)

func (c *conn) post(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	team, channel := strings.TrimSpace(p.Team), strings.TrimSpace(p.Channel)
	if !guidRe.MatchString(team) {
		return sdk.Result{}, errors.New("the team is its id, a GUID (Get link to team, groupId)")
	}
	if !channelRe.MatchString(channel) {
		return sdk.Result{}, errors.New("the channel is its id, like 19:abc…@thread.tacv2")
	}
	msg := strings.TrimSpace(p.Message)
	if msg == "" || len(msg) > 4000 {
		return sdk.Result{}, errors.New("a message is 1 to 4000 characters")
	}
	f := mention.Find(msg)
	if f.Wildcard != "" {
		return sdk.Result{}, fmt.Errorf("%s would notify the whole channel; mention people by name instead", f.Wildcard)
	}
	if wildcardRe.MatchString(msg) || strings.Contains(strings.ToLower(msg), "<at") {
		return sdk.Result{}, errors.New("mentions of the whole team or channel (and <at> tags) aren't sent; mention people by name instead")
	}
	if !c.delegated() {
		return sdk.Result{}, errors.New("posting to Teams needs the delegated sign-in (a refresh token): Microsoft doesn't let an app post as itself")
	}
	if call.DryRun {
		summary := "Post to a Teams channel"
		if pv := f.Preview(); pv != "" {
			summary += "; " + pv
		}
		b, _ := json.Marshal(map[string]any{"message": msg})
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "channel " + channel, Op: "post", After: b}}}}, nil
	}
	var out struct {
		ID      string `json:"id"`
		WebURL  string `json:"webUrl"`
		Created string `json:"createdDateTime"`
	}
	body := map[string]any{"body": map[string]string{"contentType": "text", "content": msg}}
	if err := c.do(ctx, http.MethodPost, "/teams/"+url.PathEscape(team)+"/channels/"+url.PathEscape(channel)+"/messages", nil, body, &out); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"posted": true, "id": out.ID, "created": out.Created, "link": out.WebURL})
}

// drivePath checks a OneDrive folder path and escapes each part.
func drivePath(s string) (string, error) {
	s = strings.Trim(strings.TrimSpace(s), "/")
	if s == "" {
		return "", nil
	}
	if len(s) > 400 {
		return "", errors.New("the path is too long")
	}
	var parts []string
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, ":*?\"<>|\\#%") || strings.ContainsFunc(seg, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return "", errors.New("the path is folder names separated by /, without .., : or other special characters")
		}
		parts = append(parts, url.PathEscape(seg))
	}
	return strings.Join(parts, "/"), nil
}

func (c *conn) files(ctx context.Context, p input) (sdk.Result, error) {
	dp, err := drivePath(p.Path)
	if err != nil {
		return sdk.Result{}, err
	}
	path := c.me() + "/drive/root/children"
	if dp != "" {
		path = c.me() + "/drive/root:/" + dp + ":/children"
	}
	q := url.Values{"$top": {strconv.Itoa(limit(p.Limit, 100, 200))}, "$select": {"id,name,size,lastModifiedDateTime,folder,file,webUrl"}}
	var out struct {
		Value []struct {
			ID       string           `json:"id"`
			Name     string           `json:"name"`
			Size     int64            `json:"size"`
			Modified string           `json:"lastModifiedDateTime"`
			Folder   *struct{ N int } `json:"folder"`
			File     *struct {
				Type string `json:"mimeType"`
			} `json:"file"`
			WebURL string `json:"webUrl"`
		} `json:"value"`
	}
	if err := c.do(ctx, http.MethodGet, path, q, nil, &out); err != nil {
		return sdk.Result{}, err
	}
	list := []map[string]any{}
	for _, x := range out.Value {
		row := map[string]any{"id": x.ID, "name": x.Name, "size": x.Size, "modified": x.Modified, "folder": x.Folder != nil, "link": x.WebURL}
		if x.File != nil && x.File.Type != "" {
			row["type"] = x.File.Type
		}
		list = append(list, row)
	}
	return sdk.JSON(list)
}
