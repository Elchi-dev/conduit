// Package mail connects any mailbox over IMAP and SMTP: Gmail, Outlook,
// iCloud, Fastmail, Proton Bridge or a self-hosted server.
package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	gomsg "github.com/emersion/go-message/mail"
	gomail "github.com/wneessen/go-mail"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Provider presets fill in server settings.
var providers = map[string]Config{
	"gmail":    {IMAPHost: "imap.gmail.com", IMAPPort: 993, SMTPHost: "smtp.gmail.com", SMTPPort: 465, ServerSavesSent: true},
	"outlook":  {IMAPHost: "outlook.office365.com", IMAPPort: 993, SMTPHost: "smtp.office365.com", SMTPPort: 587, ServerSavesSent: true},
	"icloud":   {IMAPHost: "imap.mail.me.com", IMAPPort: 993, SMTPHost: "smtp.mail.me.com", SMTPPort: 587},
	"fastmail": {IMAPHost: "imap.fastmail.com", IMAPPort: 993, SMTPHost: "smtp.fastmail.com", SMTPPort: 465},
	"yahoo":    {IMAPHost: "imap.mail.yahoo.com", IMAPPort: 993, SMTPHost: "smtp.mail.yahoo.com", SMTPPort: 465},
	"proton":   {IMAPHost: "127.0.0.1", IMAPPort: 1143, SMTPHost: "127.0.0.1", SMTPPort: 1025, InsecureLocal: true},
}

// Config is one mailbox's settings.
type Config struct {
	Provider string `json:"provider"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"` // secret:// reference (app password)
	IMAPHost string `json:"imapHost"`
	IMAPPort int    `json:"imapPort"`
	SMTPHost string `json:"smtpHost"`
	SMTPPort int    `json:"smtpPort"`
	// ServerSavesSent: the provider stores sent mail itself (Gmail, Outlook).
	ServerSavesSent bool `json:"serverSavesSent"`
	// InsecureLocal allows plain connections to 127.0.0.1 (Proton Bridge).
	InsecureLocal bool `json:"insecureLocal"`
	// Watch publishes mail.received events for new mail.
	Watch bool `json:"watch"`
}

func (c *Config) applyProvider() {
	p, ok := providers[c.Provider]
	if !ok {
		return
	}
	if c.IMAPHost == "" {
		c.IMAPHost, c.IMAPPort = p.IMAPHost, p.IMAPPort
	}
	if c.SMTPHost == "" {
		c.SMTPHost, c.SMTPPort = p.SMTPHost, p.SMTPPort
	}
	if !c.ServerSavesSent {
		c.ServerSavesSent = p.ServerSavesSent
	}
	if !c.InsecureLocal {
		c.InsecureLocal = p.InsecureLocal
	}
}

type account struct {
	cfg  Config
	host sdk.Host

	mu   sync.Mutex
	conn *imapclient.Client

	stop    context.CancelFunc
	lastUID imap.UID
}

// Module implements sdk.Module.
type Module struct {
	mu       sync.Mutex
	accounts map[string]*account
	// dial is replaceable in tests.
	dial func(ctx context.Context, a *account) (*imapclient.Client, error)
}

// New returns the mail module.
func New() *Module {
	m := &Module{accounts: map[string]*account{}}
	m.dial = dialIMAP
	return m
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	uid := `{"type":"object","required":["uid"],"properties":{"uid":{"type":"integer"},"mailbox":{"type":"string","default":"INBOX"}}}`
	return sdk.Manifest{
		ID: "mail", Name: "Mail", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "Any mailbox over IMAP and SMTP: read, search, send, sort.",
		Presets:     []string{"developer", "gamer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["email","password"],"properties":{
			"provider":{"type":"string","enum":["gmail","outlook","icloud","fastmail","yahoo","proton","other"],"default":"gmail","description":"Fills in the server settings below"},
			"email":{"type":"string","description":"Your address"},
			"name":{"type":"string","description":"Name shown on mail you send"},
			"username":{"type":"string","description":"Login, if not your address"},
			"password":{"type":"string","x-secret":true,"description":"Vault reference to an app password. Gmail, Outlook and iCloud need an app password, not your normal one."},
			"imapHost":{"type":"string"},"imapPort":{"type":"integer"},
			"smtpHost":{"type":"string"},"smtpPort":{"type":"integer"},
			"watch":{"type":"boolean","title":"Announce new mail","description":"Check every 2 minutes and publish an event for automations and notifications"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "inbox", Title: "Inbox", Description: "Newest messages.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"mailbox":{"type":"string","default":"INBOX"},"limit":{"type":"integer","default":30,"maximum":200},"unreadOnly":{"type":"boolean"}}}`)},
			{Name: "search", Title: "Search", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"text":{"type":"string","description":"Words anywhere in the message"},"from":{"type":"string"},"subject":{"type":"string"},"sinceDays":{"type":"integer"},"unreadOnly":{"type":"boolean"},"mailbox":{"type":"string","default":"INBOX"},"limit":{"type":"integer","default":50}}}`)},
			{Name: "read", Title: "Read a message", Description: "Text, sender and attachments. Doesn't mark it read.", Risk: sdk.RiskRead, Input: sdk.Schema(uid)},
			{Name: "mailboxes", Title: "Folders", Risk: sdk.RiskRead},
			{Name: "mark_read", Title: "Mark read", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(uid)},
			{Name: "mark_unread", Title: "Mark unread", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(uid)},
			{Name: "flag", Title: "Flag", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(uid)},
			{Name: "unflag", Title: "Remove flag", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(uid)},
			{Name: "move", Title: "Move to folder", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["uid","to"],"properties":{"uid":{"type":"integer"},"mailbox":{"type":"string","default":"INBOX"},"to":{"type":"string","description":"Folder name, e.g. Archive"}}}`)},
			{Name: "draft", Title: "Save a draft", Description: "Write a message into Drafts without sending it.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(composeSchema)},
			{Name: "send", Title: "Send", Description: "Send a message from this address.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(composeSchema)},
		},
		Events: []sdk.EventSpec{{Type: "mail.received", Description: "New messages arrived (when Announce new mail is on)"}},
	}
}

const composeSchema = `{"type":"object","required":["to","subject","body"],"properties":{
	"to":{"type":"array","items":{"type":"string"}},
	"cc":{"type":"array","items":{"type":"string"}},
	"subject":{"type":"string"},
	"body":{"type":"string","x-multiline":true},
	"replyToUid":{"type":"integer","description":"Reply in the thread of this message (INBOX)"}}}`

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	cfg.applyProvider()
	if cfg.Email == "" || cfg.Password == "" {
		return errors.New("email and password are required")
	}
	if cfg.IMAPHost == "" || cfg.SMTPHost == "" {
		return errors.New("choose a provider or fill in the IMAP and SMTP servers")
	}
	if cfg.IMAPPort == 0 {
		cfg.IMAPPort = 993
	}
	if cfg.SMTPPort == 0 {
		cfg.SMTPPort = 587
	}
	if cfg.Username == "" {
		cfg.Username = cfg.Email
	}
	a := &account{cfg: cfg, host: h}
	m.mu.Lock()
	if old := m.accounts[id]; old != nil {
		old.close()
	}
	m.accounts[id] = a
	m.mu.Unlock()
	if cfg.Watch {
		ctx, cancel := context.WithCancel(context.Background())
		a.stop = cancel
		go m.watch(ctx, id, a)
	}
	return nil
}

func (a *account) close() {
	if a.stop != nil {
		a.stop()
	}
	a.mu.Lock()
	if a.conn != nil {
		_ = a.conn.Close()
		a.conn = nil
	}
	a.mu.Unlock()
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error {
	m.mu.Lock()
	a := m.accounts[id]
	delete(m.accounts, id)
	m.mu.Unlock()
	if a != nil {
		a.close()
	}
	return nil
}

func (m *Module) account(id string) (*account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a := m.accounts[id]; a != nil {
		return a, nil
	}
	return nil, errors.New("mailbox is not configured")
}

func dialIMAP(ctx context.Context, a *account) (*imapclient.Client, error) {
	pw, err := a.host.Secret(ctx, a.cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}
	addr := net.JoinHostPort(a.cfg.IMAPHost, strconv.Itoa(a.cfg.IMAPPort))
	opts := &imapclient.Options{Dialer: &net.Dialer{Timeout: 15 * time.Second}}
	var c *imapclient.Client
	switch {
	case a.cfg.InsecureLocal && (a.cfg.IMAPHost == "127.0.0.1" || a.cfg.IMAPHost == "localhost"):
		c, err = imapclient.DialInsecure(addr, opts)
	case a.cfg.IMAPPort == 143:
		c, err = imapclient.DialStartTLS(addr, opts)
	default:
		c, err = imapclient.DialTLS(addr, opts)
	}
	if err != nil {
		return nil, err
	}
	if err := c.Login(a.cfg.Username, pw).Wait(); err != nil {
		c.Close()
		return nil, fmt.Errorf("sign-in failed (for Gmail, Outlook and iCloud use an app password): %w", err)
	}
	return c, nil
}

// with runs f on a live, logged-in connection, reconnecting once on failure.
func (m *Module) with(ctx context.Context, a *account, f func(c *imapclient.Client) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if a.conn == nil {
			c, err := m.dial(ctx, a)
			if err != nil {
				return err
			}
			a.conn = c
		}
		err := f(a.conn)
		if err == nil {
			return nil
		}
		var ie *imap.Error
		if errors.As(err, &ie) || attempt == 1 {
			return err // a protocol answer, not a dead connection
		}
		_ = a.conn.Close()
		a.conn = nil
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	a, err := m.account(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var unseen uint32
	err = m.with(ctx, a, func(c *imapclient.Client) error {
		st, err := c.Status("INBOX", &imap.StatusOptions{NumUnseen: true}).Wait()
		if err != nil {
			return err
		}
		if st.NumUnseen != nil {
			unseen = *st.NumUnseen
		}
		return nil
	})
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d unread", unseen)}
}

// Summary is a message in a list.
type Summary struct {
	UID     uint32   `json:"uid"`
	From    string   `json:"from"`
	Subject string   `json:"subject"`
	Date    string   `json:"date"`
	Unread  bool     `json:"unread"`
	Flagged bool     `json:"flagged"`
	Size    int64    `json:"sizeKB,omitempty"`
	Labels  []string `json:"-"`
}

func addrs(list []imap.Address) string {
	var out []string
	for _, a := range list {
		if a.Name != "" {
			out = append(out, a.Name+" <"+a.Addr()+">")
		} else {
			out = append(out, a.Addr())
		}
	}
	return strings.Join(out, ", ")
}

func summarize(msgs []*imapclient.FetchMessageBuffer) []Summary {
	out := make([]Summary, 0, len(msgs))
	for _, msg := range msgs {
		s := Summary{UID: uint32(msg.UID), Unread: true, Size: msg.RFC822Size / 1024}
		for _, f := range msg.Flags {
			switch f {
			case imap.FlagSeen:
				s.Unread = false
			case imap.FlagFlagged:
				s.Flagged = true
			}
		}
		if e := msg.Envelope; e != nil {
			s.From, s.Subject = addrs(e.From), e.Subject
			if !e.Date.IsZero() {
				s.Date = e.Date.Format(time.RFC3339)
			}
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID > out[j].UID })
	return out
}

func listFetch() *imap.FetchOptions {
	return &imap.FetchOptions{UID: true, Flags: true, Envelope: true, RFC822Size: true}
}

type uidIn struct {
	UID     uint32 `json:"uid"`
	Mailbox string `json:"mailbox"`
	To      string `json:"to"`
}

func (u *uidIn) mailbox() string {
	if u.Mailbox == "" {
		return "INBOX"
	}
	return u.Mailbox
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	a, err := m.account(c.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "inbox", "search":
		var in struct {
			Mailbox    string `json:"mailbox"`
			Limit      int    `json:"limit"`
			UnreadOnly bool   `json:"unreadOnly"`
			Text       string `json:"text"`
			From       string `json:"from"`
			Subject    string `json:"subject"`
			SinceDays  int    `json:"sinceDays"`
		}
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		if in.Mailbox == "" {
			in.Mailbox = "INBOX"
		}
		if in.Limit <= 0 || in.Limit > 200 {
			in.Limit = 30
		}
		crit := &imap.SearchCriteria{}
		if in.UnreadOnly {
			crit.NotFlag = []imap.Flag{imap.FlagSeen}
		}
		if in.Text != "" {
			crit.Text = []string{in.Text}
		}
		if in.From != "" {
			crit.Header = append(crit.Header, imap.SearchCriteriaHeaderField{Key: "From", Value: in.From})
		}
		if in.Subject != "" {
			crit.Header = append(crit.Header, imap.SearchCriteriaHeaderField{Key: "Subject", Value: in.Subject})
		}
		if in.SinceDays > 0 {
			crit.Since = time.Now().AddDate(0, 0, -in.SinceDays)
		}
		var list []Summary
		err := m.with(ctx, a, func(cl *imapclient.Client) error {
			if _, err := cl.Select(in.Mailbox, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
				return err
			}
			res, err := cl.UIDSearch(crit, nil).Wait()
			if err != nil {
				return err
			}
			uids := res.AllUIDs()
			if len(uids) == 0 {
				list = []Summary{}
				return nil
			}
			sort.Slice(uids, func(i, j int) bool { return uids[i] > uids[j] })
			if len(uids) > in.Limit {
				uids = uids[:in.Limit]
			}
			msgs, err := cl.Fetch(imap.UIDSetNum(uids...), listFetch()).Collect()
			if err != nil {
				return err
			}
			list = summarize(msgs)
			return nil
		})
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(list)

	case "read":
		var in uidIn
		if err := sdk.Decode(c, &in); err != nil || in.UID == 0 {
			return sdk.Result{}, errors.New("uid is required")
		}
		var msg *Message
		err := m.with(ctx, a, func(cl *imapclient.Client) error {
			if _, err := cl.Select(in.mailbox(), &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
				return err
			}
			sec := &imap.FetchItemBodySection{Peek: true}
			msgs, err := cl.Fetch(imap.UIDSetNum(imap.UID(in.UID)), &imap.FetchOptions{UID: true, Flags: true, Envelope: true, RFC822Size: true, BodySection: []*imap.FetchItemBodySection{sec}}).Collect()
			if err != nil {
				return err
			}
			if len(msgs) == 0 {
				return fmt.Errorf("no message %d in %s", in.UID, in.mailbox())
			}
			if msgs[0].RFC822Size > 25<<20 {
				return errors.New("message is larger than 25 MB")
			}
			msg, err = parse(msgs[0], msgs[0].FindBodySection(sec))
			return err
		})
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(msg)

	case "mailboxes":
		var out []map[string]any
		err := m.with(ctx, a, func(cl *imapclient.Client) error {
			list, err := cl.List("", "*", &imap.ListOptions{ReturnStatus: &imap.StatusOptions{NumMessages: true, NumUnseen: true}}).Collect()
			if err != nil {
				return err
			}
			for _, l := range list {
				row := map[string]any{"name": l.Mailbox}
				for _, attr := range l.Attrs {
					if s := specialUse(attr); s != "" {
						row["role"] = s
					}
				}
				if l.Status != nil {
					if l.Status.NumMessages != nil {
						row["messages"] = *l.Status.NumMessages
					}
					if l.Status.NumUnseen != nil {
						row["unread"] = *l.Status.NumUnseen
					}
				}
				out = append(out, row)
			}
			return nil
		})
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(out)

	case "mark_read", "mark_unread", "flag", "unflag":
		var in uidIn
		if err := sdk.Decode(c, &in); err != nil || in.UID == 0 {
			return sdk.Result{}, errors.New("uid is required")
		}
		flag, op, inverse := imap.FlagSeen, imap.StoreFlagsAdd, "mark_unread"
		switch c.Action {
		case "mark_unread":
			op, inverse = imap.StoreFlagsDel, "mark_read"
		case "flag":
			flag, inverse = imap.FlagFlagged, "unflag"
		case "unflag":
			flag, op, inverse = imap.FlagFlagged, imap.StoreFlagsDel, "flag"
		}
		err := m.with(ctx, a, func(cl *imapclient.Client) error {
			if _, err := cl.Select(in.mailbox(), nil).Wait(); err != nil {
				return err
			}
			return cl.Store(imap.UIDSetNum(imap.UID(in.UID)), &imap.StoreFlags{Op: op, Silent: true, Flags: []imap.Flag{flag}}, nil).Close()
		})
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"uid": in.UID, "done": c.Action})
		r.Undo = sdk.UndoWith(inverse, map[string]any{"uid": in.UID, "mailbox": in.mailbox()}, "Undo "+strings.ReplaceAll(c.Action, "_", " "))
		return r, err

	case "move":
		var in uidIn
		if err := sdk.Decode(c, &in); err != nil || in.UID == 0 || in.To == "" {
			return sdk.Result{}, errors.New("uid and to are required")
		}
		var newUID uint32
		err := m.with(ctx, a, func(cl *imapclient.Client) error {
			if _, err := cl.Select(in.mailbox(), nil).Wait(); err != nil {
				return err
			}
			data, err := cl.Move(imap.UIDSetNum(imap.UID(in.UID)), in.To).Wait()
			if err != nil {
				return err
			}
			if data != nil {
				if uids, ok := data.DestUIDs.(imap.UIDSet); ok {
					if list, ok := uids.Nums(); ok && len(list) == 1 {
						newUID = uint32(list[0])
					}
				}
			}
			return nil
		})
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"uid": in.UID, "movedTo": in.To, "newUid": newUID})
		if newUID != 0 {
			r.Undo = sdk.UndoWith("move", map[string]any{"uid": newUID, "mailbox": in.To, "to": in.mailbox()}, "Move back to "+in.mailbox())
		}
		return r, err

	case "draft", "send":
		var in Compose
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		if len(in.To) == 0 || in.Subject == "" {
			return sdk.Result{}, errors.New("to and subject are required")
		}
		if c.DryRun {
			return sdk.Result{Plan: &sdk.Plan{
				Summary: fmt.Sprintf("Send %q from %s", in.Subject, a.cfg.Email),
				Changes: []sdk.Change{{Target: strings.Join(append(append([]string{}, in.To...), in.CC...), ", "), Op: "send",
					After: mustJSON(map[string]any{"subject": in.Subject, "body": truncate(in.Body, 2000)})}},
			}}, nil
		}
		return m.compose(ctx, a, in, c.Action == "send")
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

func specialUse(a imap.MailboxAttr) string {
	switch a {
	case imap.MailboxAttrSent:
		return "sent"
	case imap.MailboxAttrDrafts:
		return "drafts"
	case imap.MailboxAttrTrash:
		return "trash"
	case imap.MailboxAttrArchive:
		return "archive"
	case imap.MailboxAttrJunk:
		return "junk"
	case imap.MailboxAttrAll:
		return "all"
	}
	return ""
}

// Compose is a message to send or save.
type Compose struct {
	To         []string `json:"to"`
	CC         []string `json:"cc"`
	Subject    string   `json:"subject"`
	Body       string   `json:"body"`
	ReplyToUID uint32   `json:"replyToUid"`
}

func (m *Module) folder(ctx context.Context, a *account, role imap.MailboxAttr, fallback string) string {
	name := fallback
	_ = m.with(ctx, a, func(cl *imapclient.Client) error {
		list, err := cl.List("", "*", nil).Collect()
		if err != nil {
			return err
		}
		for _, l := range list {
			for _, at := range l.Attrs {
				if at == role {
					name = l.Mailbox
				}
			}
		}
		return nil
	})
	return name
}

func (m *Module) compose(ctx context.Context, a *account, in Compose, send bool) (sdk.Result, error) {
	msg := gomail.NewMsg()
	from := a.cfg.Email
	if a.cfg.Name != "" {
		from = fmt.Sprintf("%q <%s>", a.cfg.Name, a.cfg.Email)
	}
	if err := msg.From(from); err != nil {
		return sdk.Result{}, err
	}
	if err := msg.To(in.To...); err != nil {
		return sdk.Result{}, err
	}
	if len(in.CC) > 0 {
		if err := msg.Cc(in.CC...); err != nil {
			return sdk.Result{}, err
		}
	}
	subject := in.Subject
	if in.ReplyToUID != 0 {
		var orig *imapclient.FetchMessageBuffer
		_ = m.with(ctx, a, func(cl *imapclient.Client) error {
			if _, err := cl.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
				return err
			}
			msgs, err := cl.Fetch(imap.UIDSetNum(imap.UID(in.ReplyToUID)), &imap.FetchOptions{Envelope: true}).Collect()
			if err == nil && len(msgs) == 1 {
				orig = msgs[0]
			}
			return err
		})
		if orig != nil && orig.Envelope != nil && orig.Envelope.MessageID != "" {
			id := "<" + orig.Envelope.MessageID + ">"
			msg.SetGenHeader(gomail.HeaderInReplyTo, id)
			msg.SetGenHeader(gomail.HeaderReferences, id)
			if !strings.HasPrefix(strings.ToLower(subject), "re:") {
				subject = "Re: " + subject
			}
		}
	}
	msg.Subject(subject)
	msg.SetDate()
	msg.SetMessageID()
	msg.SetBodyString(gomail.TypeTextPlain, in.Body)
	var raw bytes.Buffer
	if _, err := msg.WriteTo(&raw); err != nil {
		return sdk.Result{}, err
	}

	if send {
		pw, err := a.host.Secret(ctx, a.cfg.Password)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("password: %w", err)
		}
		opts := []gomail.Option{gomail.WithPort(a.cfg.SMTPPort), gomail.WithSMTPAuth(gomail.SMTPAuthAutoDiscover),
			gomail.WithUsername(a.cfg.Username), gomail.WithPassword(pw), gomail.WithTimeout(30 * time.Second)}
		switch {
		case a.cfg.InsecureLocal && (a.cfg.SMTPHost == "127.0.0.1" || a.cfg.SMTPHost == "localhost"):
			opts = append(opts, gomail.WithTLSPolicy(gomail.NoTLS))
		case a.cfg.SMTPPort == 465:
			opts = append(opts, gomail.WithSSL())
		default:
			opts = append(opts, gomail.WithTLSPolicy(gomail.TLSMandatory))
		}
		client, err := gomail.NewClient(a.cfg.SMTPHost, opts...)
		if err != nil {
			return sdk.Result{}, err
		}
		if err := client.DialAndSendWithContext(ctx, msg); err != nil {
			return sdk.Result{}, fmt.Errorf("sending failed: %w", err)
		}
		if !a.cfg.ServerSavesSent {
			sent := m.folder(ctx, a, imap.MailboxAttrSent, "Sent")
			_ = m.appendTo(ctx, a, sent, raw.Bytes(), []imap.Flag{imap.FlagSeen})
		}
		return sdk.JSON(map[string]any{"sent": true, "to": in.To, "subject": subject, "messageId": msg.GetMessageID()})
	}

	drafts := m.folder(ctx, a, imap.MailboxAttrDrafts, "Drafts")
	if err := m.appendTo(ctx, a, drafts, raw.Bytes(), []imap.Flag{imap.FlagDraft, imap.FlagSeen}); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"saved": true, "folder": drafts, "subject": subject})
}

func (m *Module) appendTo(ctx context.Context, a *account, mailbox string, raw []byte, flags []imap.Flag) error {
	return m.with(ctx, a, func(cl *imapclient.Client) error {
		cmd := cl.Append(mailbox, int64(len(raw)), &imap.AppendOptions{Flags: flags, Time: time.Now()})
		if _, err := cmd.Write(raw); err != nil {
			return err
		}
		if err := cmd.Close(); err != nil {
			return err
		}
		_, err := cmd.Wait()
		return err
	})
}

// watch polls INBOX for new UIDs and publishes mail.received.
func (m *Module) watch(ctx context.Context, id string, a *account) {
	tick := time.NewTicker(2 * time.Minute)
	defer tick.Stop()
	for {
		var fresh []Summary
		_ = m.with(ctx, a, func(cl *imapclient.Client) error {
			sel, err := cl.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
			if err != nil {
				return err
			}
			next := sel.UIDNext
			if a.lastUID == 0 {
				a.lastUID = next - 1 // first run: only announce mail that arrives from now on
				return nil
			}
			if next-1 <= a.lastUID {
				return nil
			}
			msgs, err := cl.Fetch(imap.UIDSetNum(uidRange(a.lastUID+1, next-1)...), listFetch()).Collect()
			if err != nil {
				return err
			}
			fresh = summarize(msgs)
			a.lastUID = next - 1
			return nil
		})
		if len(fresh) > 0 && a.host != nil {
			a.host.Publish(ctx, sdk.Event{Type: "mail.received", Instance: id, Data: mustJSON(map[string]any{"count": len(fresh), "messages": fresh})})
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func uidRange(from, to imap.UID) []imap.UID {
	if to-from > 200 {
		from = to - 200
	}
	var out []imap.UID
	for u := from; u <= to; u++ {
		out = append(out, u)
	}
	return out
}

// Message is a parsed message.
type Message struct {
	UID         uint32       `json:"uid"`
	From        string       `json:"from"`
	To          string       `json:"to"`
	CC          string       `json:"cc,omitempty"`
	Subject     string       `json:"subject"`
	Date        string       `json:"date"`
	Text        string       `json:"text"`
	Attachments []Attachment `json:"attachments"`
}

// Attachment describes an attached file.
type Attachment struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	SizeKB int    `json:"sizeKB"`
}

var (
	tagRe   = regexp.MustCompile(`(?s)<(script|style)[^>]*>.*?</(script|style)>|<[^>]+>`)
	blankRe = regexp.MustCompile(`\n{3,}`)
	brRe    = regexp.MustCompile(`(?i)<br\s*/?>|</p>|</div>|</tr>|</h[1-6]>`)
)

// htmlToText strips markup for reading. It is not a renderer; mail HTML is
// never shown as HTML, which also keeps tracking pixels and scripts out.
func htmlToText(s string) string {
	s = brRe.ReplaceAllString(s, "\n")
	s = tagRe.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return strings.TrimSpace(blankRe.ReplaceAllString(strings.Join(lines, "\n"), "\n\n"))
}

func parse(buf *imapclient.FetchMessageBuffer, raw []byte) (*Message, error) {
	m := &Message{UID: uint32(buf.UID), Attachments: []Attachment{}}
	if e := buf.Envelope; e != nil {
		m.From, m.To, m.CC, m.Subject = addrs(e.From), addrs(e.To), addrs(e.Cc), e.Subject
		if !e.Date.IsZero() {
			m.Date = e.Date.Format(time.RFC3339)
		}
	}
	r, err := gomsg.CreateReader(bytes.NewReader(raw))
	if err != nil {
		m.Text = string(raw)
		return m, nil
	}
	var plain, htmlBody string
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		switch h := p.Header.(type) {
		case *gomsg.InlineHeader:
			ct, _, _ := h.ContentType()
			b, _ := io.ReadAll(io.LimitReader(p.Body, 2<<20))
			switch ct {
			case "text/plain":
				if plain == "" {
					plain = string(b)
				}
			case "text/html":
				if htmlBody == "" {
					htmlBody = string(b)
				}
			}
		case *gomsg.AttachmentHeader:
			name, _ := h.Filename()
			ct, _, _ := h.ContentType()
			n, _ := io.Copy(io.Discard, p.Body)
			m.Attachments = append(m.Attachments, Attachment{Name: name, Type: ct, SizeKB: int(n / 1024)})
		}
	}
	if plain != "" {
		m.Text = strings.TrimSpace(plain)
	} else {
		m.Text = htmlToText(htmlBody)
	}
	return m, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
