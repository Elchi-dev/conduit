// Package mail connects any mailbox over IMAP and SMTP: Gmail, Outlook,
// iCloud, Fastmail, Proton Mail Bridge or a self-hosted server. It reads,
// searches, threads, sorts, labels, deletes (to Trash, with undo), drafts,
// sends, replies and forwards, and announces new mail as events.
package mail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// preset fills in a provider's servers and habits.
type preset struct {
	IMAPHost, SMTPHost string
	IMAPPort, SMTPPort int
	Security           string // "" picks by port
	Trust              string
	ServerSavesSent    bool
	LabelMode          string // "folders" or "keywords"
	LabelPrefix        string
}

var providers = map[string]preset{
	"gmail":    {IMAPHost: "imap.gmail.com", IMAPPort: 993, SMTPHost: "smtp.gmail.com", SMTPPort: 465, ServerSavesSent: true, LabelMode: "folders"},
	"outlook":  {IMAPHost: "outlook.office365.com", IMAPPort: 993, SMTPHost: "smtp.office365.com", SMTPPort: 587, ServerSavesSent: true},
	"icloud":   {IMAPHost: "imap.mail.me.com", IMAPPort: 993, SMTPHost: "smtp.mail.me.com", SMTPPort: 587},
	"fastmail": {IMAPHost: "imap.fastmail.com", IMAPPort: 993, SMTPHost: "smtp.fastmail.com", SMTPPort: 465},
	"yahoo":    {IMAPHost: "imap.mail.yahoo.com", IMAPPort: 993, SMTPHost: "smtp.mail.yahoo.com", SMTPPort: 465},
	// Proton Mail Bridge runs on this machine with a self-signed certificate
	// and STARTTLS on both ports. Its labels are folders under "Labels/", and
	// it files sent mail in Sent itself.
	"proton": {IMAPHost: "127.0.0.1", IMAPPort: 1143, SMTPHost: "127.0.0.1", SMTPPort: 1025, Security: secStartTLS, Trust: trustPinned,
		ServerSavesSent: true, LabelMode: "folders", LabelPrefix: "Labels/"},
}

// Config is one mailbox's settings.
type Config struct {
	Provider string `json:"provider"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"` // secret:// reference (app or Bridge password)
	IMAPHost string `json:"imapHost"`
	IMAPPort int    `json:"imapPort"`
	SMTPHost string `json:"smtpHost"`
	SMTPPort int    `json:"smtpPort"`
	// Security is "tls", "starttls" or "none" (loopback only); empty picks
	// by port, or the provider's choice.
	Security     string `json:"security"`
	SMTPSecurity string `json:"smtpSecurity"`
	// TLSTrust is "system" (certificate authorities) or "pinned" (one
	// certificate, trusted on first use or given below).
	TLSTrust       string `json:"tlsTrust"`
	TLSCertificate string `json:"tlsCertificate"` // PEM, e.g. Proton Bridge's exported cert.pem
	TLSFingerprint string `json:"tlsFingerprint"` // SHA-256 hex
	// ServerSavesSent: the provider stores sent mail itself.
	ServerSavesSent *bool `json:"serverSavesSent"`
	// InsecureLocal is the old Proton setting; it now only allows a plain
	// connection when Security is empty and the host is loopback.
	InsecureLocal bool `json:"insecureLocal"`
	// LabelMode is "folders" (a label is a folder: Proton, Gmail) or
	// "keywords" (IMAP keywords).
	LabelMode   string `json:"labelMode"`
	LabelPrefix string `json:"labelPrefix"`
	// AttachmentsDir is the folder attachments may be read from when
	// sending by path (for example the Files module's folder).
	AttachmentsDir  string `json:"attachmentsDir"`
	MaxAttachmentMB int    `json:"maxAttachmentMB"`
	// Watch publishes mail.received and mail.unread events.
	Watch        bool `json:"watch"`
	WatchSeconds int  `json:"watchSeconds"`
}

type account struct {
	id    string
	cfg   Config
	host  sdk.Host
	state *state

	imapSec, smtpSec string
	trust            string
	configPin        string // from tlsFingerprint or tlsCertificate
	configPinSource  string
	saveSent         bool
	labelMode        string
	labelPrefix      string
	maxAttach        int64

	mu   sync.Mutex
	conn *imapclient.Client

	stop context.CancelFunc
	done chan struct{}
}

func (a *account) log(level, msg string, kv ...any) {
	if a.host != nil {
		a.host.Log(level, msg, kv...)
	}
}

// Module implements sdk.Module.
type Module struct {
	// Dir holds each instance's state (pinned certificates, watcher
	// position). Empty uses the daemon's default data folder.
	Dir string

	mu       sync.Mutex
	accounts map[string]*account
	// dial is replaceable in tests.
	dial func(ctx context.Context, a *account) (*imapclient.Client, error)
	// now is replaceable in tests.
	now func() time.Time
}

// New returns the mail module.
func New() *Module {
	m := &Module{accounts: map[string]*account{}, now: time.Now}
	m.dial = dialIMAP
	return m
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	a, err := newAccount(id, cfg, h)
	if err != nil {
		return err
	}
	dir := m.Dir
	if dir == "" {
		if d, ok := h.(interface{ DataDir() string }); ok && d.DataDir() != "" {
			dir = d.DataDir()
		} else {
			dir = defaultDir("mail")
		}
	}
	a.state = openState(dir, id)

	m.mu.Lock()
	if old := m.accounts[id]; old != nil {
		old.close()
	}
	m.accounts[id] = a
	m.mu.Unlock()
	if a.cfg.Watch {
		ctx, cancel := context.WithCancel(context.Background())
		a.stop, a.done = cancel, make(chan struct{})
		go m.watch(ctx, a)
	}
	return nil
}

func newAccount(id string, cfg Config, h sdk.Host) (*account, error) {
	p := providers[cfg.Provider]
	if cfg.IMAPHost == "" {
		cfg.IMAPHost, cfg.IMAPPort = p.IMAPHost, p.IMAPPort
	}
	if cfg.SMTPHost == "" {
		cfg.SMTPHost, cfg.SMTPPort = p.SMTPHost, p.SMTPPort
	}
	if cfg.Email == "" || cfg.Password == "" {
		return nil, errors.New("email and password are required")
	}
	if cfg.IMAPHost == "" || cfg.SMTPHost == "" {
		return nil, errors.New("choose a provider or fill in the IMAP and SMTP servers")
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
	a := &account{id: id, cfg: cfg, host: h}
	var err error
	sec := cfg.Security
	if sec == "" {
		sec = p.Security
	}
	if a.imapSec, err = security(sec, cfg.IMAPHost, cfg.IMAPPort, cfg.InsecureLocal); err != nil {
		return nil, fmt.Errorf("IMAP: %w", err)
	}
	ssec := cfg.SMTPSecurity
	if ssec == "" {
		ssec = p.Security // else picked by the SMTP port
		if strings.EqualFold(cfg.Security, secNone) {
			ssec = secNone
		}
	}
	if a.smtpSec, err = security(ssec, cfg.SMTPHost, cfg.SMTPPort, cfg.InsecureLocal); err != nil {
		return nil, fmt.Errorf("SMTP: %w", err)
	}

	a.trust = strings.ToLower(cfg.TLSTrust)
	if a.trust == "" {
		a.trust = p.Trust
	}
	if cfg.TLSCertificate != "" || cfg.TLSFingerprint != "" {
		a.trust = trustPinned
	}
	if a.trust == "" {
		a.trust = trustSystem
	}
	if a.trust != trustSystem && a.trust != trustPinned {
		return nil, fmt.Errorf("unknown certificate trust %q (use system or pinned)", cfg.TLSTrust)
	}
	switch {
	case cfg.TLSFingerprint != "":
		if a.configPin, err = normFingerprint(cfg.TLSFingerprint); err != nil {
			return nil, err
		}
		a.configPinSource = "settings (fingerprint)"
	case cfg.TLSCertificate != "":
		fp, _, err := pemFingerprint(cfg.TLSCertificate)
		if err != nil {
			return nil, err
		}
		a.configPin, a.configPinSource = fp, "settings (certificate)"
	}

	a.saveSent = !p.ServerSavesSent
	if cfg.ServerSavesSent != nil {
		a.saveSent = !*cfg.ServerSavesSent
	}
	a.labelMode, a.labelPrefix = cfg.LabelMode, cfg.LabelPrefix
	if a.labelMode == "" {
		a.labelMode = p.LabelMode
		if a.labelPrefix == "" {
			a.labelPrefix = p.LabelPrefix
		}
	}
	if a.labelMode == "" {
		a.labelMode = "keywords"
	}
	if a.labelMode != "folders" && a.labelMode != "keywords" {
		return nil, fmt.Errorf("unknown label mode %q (use folders or keywords)", cfg.LabelMode)
	}
	mb := cfg.MaxAttachmentMB
	if mb <= 0 || mb > 50 {
		mb = 25
	}
	a.maxAttach = int64(mb) << 20
	return a, nil
}

func (a *account) close() {
	if a.stop != nil {
		a.stop()
		<-a.done
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
	opts := &imapclient.Options{Dialer: &net.Dialer{Timeout: 15 * time.Second}, TLSConfig: a.tlsConfig("imap", a.cfg.IMAPHost)}
	var c *imapclient.Client
	switch a.imapSec {
	case secNone:
		c, err = imapclient.DialInsecure(addr, opts)
	case secStartTLS:
		c, err = imapclient.DialStartTLS(addr, opts)
	default:
		c, err = imapclient.DialTLS(addr, opts)
	}
	if err != nil {
		return nil, tlsHint(err)
	}
	if err := c.Login(a.cfg.Username, pw).Wait(); err != nil {
		c.Close()
		hint := "for Gmail, Outlook and iCloud use an app password"
		if a.cfg.Provider == "proton" {
			hint = "use the password Proton Mail Bridge shows for this account, not your Proton password"
		}
		return nil, fmt.Errorf("sign-in failed (%s): %w", hint, err)
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
		if errors.As(err, &ie) || attempt == 1 || ctx.Err() != nil {
			return err // a protocol answer, not a dead connection
		}
		var ue userError
		if errors.As(err, &ue) {
			return err
		}
		_ = a.conn.Close()
		a.conn = nil
	}
	return nil
}

// userError is a problem with the request, not the connection.
type userError struct{ msg string }

func (e userError) Error() string { return e.msg }

func userErr(format string, args ...any) error { return userError{fmt.Sprintf(format, args...)} }

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
	tlsNote := ""
	if a.trust == trustPinned && a.imapSec != secNone {
		if fp := a.pinFor("imap"); fp != "" {
			src := "pinned on first use"
			if a.configPin != "" {
				src = "pinned in settings"
			}
			tlsNote = fmt.Sprintf("; certificate %s SHA-256 %s", src, fp)
		}
	}
	if a.imapSec == secNone || a.smtpSec == secNone {
		tlsNote += "; unencrypted (this machine only)"
	}
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error() + tlsNote}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d unread%s", unseen, tlsNote)}
}

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// don't split a UTF-8 sequence
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}
