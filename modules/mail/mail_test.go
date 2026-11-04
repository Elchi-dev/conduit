package mail

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type lit struct {
	*bytes.Reader
}

func (l lit) Size() int64 { return int64(l.Len()) }

const sample = "From: Ada <ada@example.com>\r\nTo: me@example.com\r\nSubject: Server bill\r\nMessage-ID: <abc@example.com>\r\nDate: Mon, 02 Nov 2026 10:00:00 +0000\r\n" +
	"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
	"--b\r\nContent-Type: text/html\r\n\r\n<p>Your bill is <b>12 EUR</b>.</p><script>x()</script>\r\n" +
	"--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=bill.pdf\r\n\r\nPDFDATA\r\n--b--\r\n"

const sentReply = "From: me@example.com\r\nTo: Ada <ada@example.com>\r\nSubject: Re: Server bill\r\nMessage-ID: <def@example.com>\r\nIn-Reply-To: <abc@example.com>\r\nReferences: <abc@example.com>\r\nDate: Mon, 02 Nov 2026 11:00:00 +0000\r\n\r\nWill pay.\r\n"

const group = "From: Bob <bob@example.com>\r\nTo: me@example.com, dave@example.com\r\nCc: Carol <carol@example.com>\r\nSubject: Lunch?\r\nMessage-ID: <lunch@example.com>\r\nDate: Tue, 03 Nov 2026 09:00:00 +0000\r\n\r\nNoon at the usual place?\r\nBob\r\n"

// selfSigned makes a certificate like Proton Bridge's: self-signed, for
// 127.0.0.1.
func selfSigned(t *testing.T, cn string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type fakeIMAP struct {
	addr string
	user *imapmemserver.User
}

func (f *fakeIMAP) put(t *testing.T, mailbox, raw string, flags ...imap.Flag) {
	t.Helper()
	if _, err := f.user.Append(mailbox, lit{bytes.NewReader([]byte(raw))}, &imap.AppendOptions{Time: time.Now(), Flags: flags}); err != nil {
		t.Fatal(err)
	}
}

// imapServer runs an in-memory IMAP server that only allows sign-in after
// STARTTLS (or with plain set, without TLS).
func imapServer(t *testing.T, cert *tls.Certificate) *fakeIMAP {
	t.Helper()
	mem := imapmemserver.New()
	u := imapmemserver.NewUser("me@example.com", "bridge-pw")
	for _, mb := range []string{"INBOX", "Archive", "Drafts", "Sent", "Trash", "Labels/Work", "Folders/Receipts"} {
		if err := u.Create(mb, nil); err != nil && mb != "INBOX" {
			t.Fatal(err)
		}
	}
	mem.AddUser(u)
	opts := &imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps:   imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapIMAP4rev2: {}},
		Logger: nopLogger{},
	}
	if cert != nil {
		opts.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*cert}}
	} else {
		opts.InsecureAuth = true
	}
	srv := imapserver.New(opts)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return &fakeIMAP{addr: ln.Addr().String(), user: u}
}

type nopLogger struct{}

func (nopLogger) Printf(string, ...any) {}

// fakeSMTP records what it is sent; sign-in needs STARTTLS.
type fakeSMTP struct {
	addr string
	mu   sync.Mutex
	msgs []sentMsg
}

type sentMsg struct {
	From string
	To   []string
	Data string
}

func (f *fakeSMTP) last(t *testing.T) sentMsg {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) == 0 {
		t.Fatal("nothing was sent")
	}
	return f.msgs[len(f.msgs)-1]
}

func (f *fakeSMTP) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.msgs) }

type smtpSession struct {
	f      *fakeSMTP
	conn   *smtp.Conn
	authed bool
	cur    sentMsg
}

func (s *smtpSession) AuthMechanisms() []string { return []string{sasl.Plain} }
func (s *smtpSession) Auth(string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, user, pass string) error {
		if _, isTLS := s.conn.TLSConnectionState(); !isTLS {
			return errors.New("TLS required")
		}
		if user != "me@example.com" || pass != "bridge-pw" {
			return errors.New("bad credentials")
		}
		s.authed = true
		return nil
	}), nil
}
func (s *smtpSession) Mail(from string, _ *smtp.MailOptions) error {
	if !s.authed {
		return errors.New("sign in first")
	}
	s.cur = sentMsg{From: from}
	return nil
}
func (s *smtpSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.cur.To = append(s.cur.To, to)
	return nil
}
func (s *smtpSession) Data(r io.Reader) error {
	b, _ := io.ReadAll(r)
	s.cur.Data = string(b)
	s.f.mu.Lock()
	s.f.msgs = append(s.f.msgs, s.cur)
	s.f.mu.Unlock()
	return nil
}
func (s *smtpSession) Reset()        {}
func (s *smtpSession) Logout() error { return nil }

func smtpServer(t *testing.T, cert tls.Certificate) *fakeSMTP {
	t.Helper()
	f := &fakeSMTP{}
	srv := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) { return &smtpSession{f: f, conn: c}, nil }))
	srv.Domain = "localhost"
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.AllowInsecureAuth = false
	srv.ReadTimeout, srv.WriteTimeout = 10*time.Second, 10*time.Second
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	f.addr = ln.Addr().String()
	return f
}

func hostPort(t *testing.T, addr string) (string, int) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	return h, n
}

// bridge is a Proton Mail Bridge stand-in: IMAP and SMTP with STARTTLS
// and one self-signed certificate.
type bridge struct {
	imap *fakeIMAP
	smtp *fakeSMTP
	pem  string
	cert tls.Certificate
}

func newBridge(t *testing.T) *bridge {
	cert, p := selfSigned(t, "127.0.0.1")
	return &bridge{imap: imapServer(t, &cert), smtp: smtpServer(t, cert), pem: p, cert: cert}
}

func (b *bridge) config(t *testing.T, extra map[string]any) json.RawMessage {
	_, ip := hostPort(t, b.imap.addr)
	_, sp := hostPort(t, b.smtp.addr)
	cfg := map[string]any{"provider": "proton", "email": "me@example.com", "name": "Me", "password": "secret://bridge",
		"imapHost": "127.0.0.1", "imapPort": ip, "smtpHost": "127.0.0.1", "smtpPort": sp}
	for k, v := range extra {
		cfg[k] = v
	}
	raw, _ := json.Marshal(cfg)
	return raw
}

var testHost = fakehost.New(map[string]string{"secret://bridge": "bridge-pw"})

type tester struct {
	t  *testing.T
	m  *Module
	id string
}

func (x tester) call(action string, in any) sdk.Result {
	x.t.Helper()
	r, err := x.try(action, in, false)
	if err != nil {
		x.t.Fatalf("%s: %v", action, err)
	}
	return r
}

func (x tester) try(action string, in any, dry bool) (sdk.Result, error) {
	var raw json.RawMessage
	switch v := in.(type) {
	case nil:
	case json.RawMessage:
		raw = v
	default:
		raw, _ = json.Marshal(v)
	}
	return x.m.Invoke(context.Background(), sdk.Call{Instance: x.id, Action: action, Input: raw, DryRun: dry})
}

func (x tester) dry(action string, in any) *sdk.Plan {
	x.t.Helper()
	r, err := x.try(action, in, true)
	if err != nil || r.Plan == nil {
		x.t.Fatalf("%s dry run: %v", action, err)
	}
	return r.Plan
}

func (x tester) list(action string, in any) []Summary {
	x.t.Helper()
	var out []Summary
	if err := json.Unmarshal(x.call(action, in).Output, &out); err != nil {
		x.t.Fatal(err)
	}
	return out
}

func (x tester) undo(r sdk.Result) sdk.Result {
	x.t.Helper()
	if r.Undo == nil {
		x.t.Fatalf("no undo in %s", r.Output)
	}
	return x.call(r.Undo.Action, r.Undo.Input)
}

func setup(t *testing.T, extra map[string]any) (*bridge, tester) {
	b := newBridge(t)
	m := New()
	m.Dir = t.TempDir()
	if err := m.Configure(context.Background(), testHost, "proton", b.config(t, extra)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close("proton") })
	return b, tester{t, m, "proton"}
}

func TestProtonBridgeTrustOnFirstUse(t *testing.T) {
	b, x := setup(t, nil)
	b.imap.put(t, "INBOX", sample)
	ctx := context.Background()
	h := x.m.Health(ctx, "proton")
	want := Fingerprint(b.cert.Certificate[0])
	if h.Status != "ok" || !strings.HasPrefix(h.Message, "1 unread") || !strings.Contains(h.Message, want) || !strings.Contains(h.Message, "first use") {
		t.Fatalf("health = %+v (want fingerprint %s)", h, want)
	}
	// The pin is on disk, so a restart keeps trusting only this certificate.
	b2, err := os.ReadFile(filepath.Join(x.m.Dir, "proton.json"))
	if err != nil || !strings.Contains(string(b2), want) {
		t.Fatalf("pin not saved: %v %s", err, b2)
	}

	var st map[string]map[string]any
	_ = json.Unmarshal(x.call("tls_status", nil).Output, &st)
	for _, ep := range []string{"imap", "smtp"} {
		if st[ep]["presented"] != want || st[ep]["security"] != "starttls" || st[ep]["selfSigned"] != true {
			t.Fatalf("tls_status %s = %v", ep, st[ep])
		}
	}
	if st["imap"]["matches"] != true || st["imap"]["pinned"] != want {
		t.Fatalf("imap pin %v", st["imap"])
	}

	// Sending pins the SMTP side on first use too.
	x.call("send", map[string]any{"to": []string{"ada@example.com"}, "subject": "Hi", "body": "Hello"})
	if d := x.m.accounts["proton"].state.get(); d.Pins["smtp"].Fingerprint != want {
		t.Fatalf("smtp pin %+v", d.Pins)
	}

	// Bridge regenerates its certificate: the same instance refuses it.
	other := newBridge(t)
	m2 := New()
	m2.Dir = x.m.Dir
	cfg := other.config(t, nil)
	if err := m2.Configure(ctx, testHost, "proton", cfg); err != nil {
		t.Fatal(err)
	}
	defer m2.Close("proton")
	h = m2.Health(ctx, "proton")
	var mm *ErrPinMismatch
	if h.Status != "down" || !strings.Contains(h.Message, "certificate changed") {
		t.Fatalf("mismatch health = %+v", h)
	}
	_, err = m2.Invoke(ctx, sdk.Call{Instance: "proton", Action: "inbox"})
	if !errors.As(err, &mm) || mm.Got != Fingerprint(other.cert.Certificate[0]) {
		t.Fatalf("want a pin mismatch, got %v", err)
	}
	// The person checks the new fingerprint and trusts it.
	x2 := tester{t, m2, "proton"}
	r := x2.call("trust_certificate", map[string]any{"fingerprint": strings.ToLower(strings.ReplaceAll(mm.Got, ":", ""))})
	if h := m2.Health(ctx, "proton"); h.Status != "ok" {
		t.Fatalf("after trusting: %+v", h)
	}
	x2.undo(r)
	if h := m2.Health(ctx, "proton"); h.Status != "down" {
		t.Fatalf("undo should restore the old pin: %+v", h)
	}
}

func TestPinnedFromSettings(t *testing.T) {
	b := newBridge(t)
	other := newBridge(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		extra map[string]any
		ok    bool
	}{
		"exported cert":      {map[string]any{"tlsCertificate": b.pem}, true},
		"fingerprint":        {map[string]any{"tlsFingerprint": "SHA256 Fingerprint=" + Fingerprint(b.cert.Certificate[0])}, true},
		"wrong cert":         {map[string]any{"tlsCertificate": other.pem}, false},
		"system trust fails": {map[string]any{"tlsTrust": "system"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			m := New()
			m.Dir = t.TempDir()
			if err := m.Configure(ctx, testHost, "p", b.config(t, tc.extra)); err != nil {
				t.Fatal(err)
			}
			defer m.Close("p")
			h := m.Health(ctx, "p")
			if (h.Status == "ok") != tc.ok {
				t.Fatalf("health = %+v", h)
			}
			if name == "system trust fails" && !strings.Contains(h.Message, "Pinned") {
				t.Fatalf("no hint: %s", h.Message)
			}
			if tc.ok && !strings.Contains(h.Message, "pinned in settings") {
				t.Fatalf("health = %+v", h)
			}
			if tc.ok {
				// a settings pin can't be overridden by an agent
				if _, err := m.Invoke(ctx, sdk.Call{Instance: "p", Action: "trust_certificate", Input: json.RawMessage(`{"fingerprint":""}`)}); err == nil {
					t.Fatal("trust_certificate overrode the settings")
				}
			}
		})
	}
}

func TestPlainOnlyToLoopback(t *testing.T) {
	m := New()
	m.Dir = t.TempDir()
	bad, _ := json.Marshal(map[string]any{"provider": "other", "email": "me@example.com", "password": "secret://bridge", "imapHost": "mail.example.com", "smtpHost": "mail.example.com", "security": "none"})
	if err := m.Configure(context.Background(), testHost, "x", bad); err == nil || !strings.Contains(err.Error(), "only allowed to this machine") {
		t.Fatalf("plain to a remote host: %v", err)
	}
	// Plain to a local server works (and Health says it's unencrypted).
	srv := imapServer(t, nil)
	srv.put(t, "INBOX", sample)
	h, p := hostPort(t, srv.addr)
	good, _ := json.Marshal(map[string]any{"provider": "other", "email": "me@example.com", "password": "secret://bridge", "imapHost": h, "imapPort": p, "smtpHost": h, "smtpPort": 25, "security": "none"})
	if err := m.Configure(context.Background(), testHost, "x", good); err != nil {
		t.Fatal(err)
	}
	defer m.Close("x")
	if hl := m.Health(context.Background(), "x"); hl.Status != "ok" || !strings.Contains(hl.Message, "unencrypted") {
		t.Fatalf("health %+v", hl)
	}
}

func TestMailboxManagement(t *testing.T) {
	b, x := setup(t, nil)
	b.imap.put(t, "INBOX", sample)
	b.imap.put(t, "INBOX", group, imap.FlagFlagged, imap.FlagSeen)
	b.imap.put(t, "Sent", sentReply, imap.FlagSeen)

	list := x.list("inbox", nil)
	if len(list) != 2 || list[1].Subject != "Server bill" || !list[1].Unread || !list[0].Flagged {
		t.Fatalf("inbox = %+v", list)
	}
	bill, lunch := list[1].UID, list[0].UID

	for name, tc := range map[string]struct {
		in   map[string]any
		want []string
	}{
		"from":       {map[string]any{"from": "ada"}, []string{"Server bill"}},
		"to":         {map[string]any{"to": "dave"}, []string{"Lunch?"}},
		"subject":    {map[string]any{"subject": "lunch"}, []string{"Lunch?"}},
		"body":       {map[string]any{"body": "usual place"}, []string{"Lunch?"}},
		"unread":     {map[string]any{"unread": true}, []string{"Server bill"}},
		"read":       {map[string]any{"unread": false}, []string{"Lunch?"}},
		"flagged":    {map[string]any{"flagged": true}, []string{"Lunch?"}},
		"since":      {map[string]any{"since": "2000-01-01"}, []string{"Lunch?", "Server bill"}},
		"before":     {map[string]any{"before": "2000-01-01"}, nil},
		"combined":   {map[string]any{"from": "bob", "unread": true}, nil},
		"sent mails": {map[string]any{"mailbox": "Sent", "subject": "Re:"}, []string{"Re: Server bill"}},
	} {
		got := x.list("search", tc.in)
		var subj []string
		for _, s := range got {
			subj = append(subj, s.Subject)
		}
		if strings.Join(subj, "|") != strings.Join(tc.want, "|") {
			t.Errorf("search %s = %v, want %v", name, subj, tc.want)
		}
	}

	var msg Message
	_ = json.Unmarshal(x.call("read", map[string]any{"uid": bill}).Output, &msg)
	if msg.Text != "Your bill is 12 EUR." || !msg.HTML || len(msg.Attachments) != 1 || msg.Attachments[0].Name != "bill.pdf" || msg.MessageID != "abc@example.com" {
		t.Fatalf("read = %+v", msg)
	}
	var att map[string]any
	_ = json.Unmarshal(x.call("download_attachment", map[string]any{"uid": bill, "index": 0}).Output, &att)
	if d, _ := base64.StdEncoding.DecodeString(att["base64"].(string)); string(d) != "PDFDATA" || att["name"] != "bill.pdf" {
		t.Fatalf("attachment = %v", att)
	}
	if len(x.list("search", map[string]any{"unread": true})) != 1 {
		t.Fatal("reading must not mark the message read")
	}

	// thread: the original and my reply in Sent
	var th struct {
		Count    int       `json:"count"`
		Messages []Summary `json:"messages"`
	}
	_ = json.Unmarshal(x.call("thread", map[string]any{"uid": bill}).Output, &th)
	if th.Count != 2 || th.Messages[0].Subject != "Server bill" || th.Messages[1].Mailbox != "Sent" {
		t.Fatalf("thread = %+v", th)
	}

	// flags, with undo, for several at once
	r := x.call("mark_read", map[string]any{"uids": []uint32{bill, lunch}})
	if len(x.list("search", map[string]any{"unread": true})) != 0 {
		t.Fatal("mark_read")
	}
	x.undo(r)
	if len(x.list("search", map[string]any{"unread": true})) != 2 {
		t.Fatal("undo mark_read should mark both unread")
	}
	r = x.call("flag", map[string]any{"uid": bill})
	if len(x.list("search", map[string]any{"flagged": true})) != 2 {
		t.Fatal("flag")
	}
	x.undo(r)

	// unread counts and folders
	var counts map[string]any
	_ = json.Unmarshal(x.call("unread_counts", nil).Output, &counts)
	if counts["inbox"] != float64(2) {
		t.Fatalf("unread_counts = %v", counts)
	}
	var boxes []map[string]any
	_ = json.Unmarshal(x.call("mailboxes", nil).Output, &boxes)
	kinds := map[string]string{}
	for _, b := range boxes {
		kinds[b["name"].(string)] = b["kind"].(string)
	}
	if kinds["Labels/Work"] != "label" || kinds["Folders/Receipts"] != "folder" || kinds["INBOX"] != "system" {
		t.Fatalf("mailboxes = %v", boxes)
	}

	// labels are folders under Labels/ on Proton: copied in, removed by
	// erasing the copy there
	r = x.call("label", map[string]any{"uid": bill, "label": "Work"})
	if l := x.list("inbox", map[string]any{"mailbox": "Labels/Work"}); len(l) != 1 || l[0].Subject != "Server bill" {
		t.Fatalf("label: %+v", l)
	}
	if len(x.list("inbox", nil)) != 2 {
		t.Fatal("labelling must leave the message in the inbox")
	}
	x.undo(r)
	if l := x.list("inbox", map[string]any{"mailbox": "Labels/Work"}); len(l) != 0 {
		t.Fatalf("unlabel: %+v", l)
	}
	if _, err := x.try("label", map[string]any{"uid": bill, "label": "Nope"}, false); err == nil {
		t.Fatal("unknown label without create")
	}
	x.call("label", map[string]any{"uid": bill, "label": "Taxes", "create": true})
	if l := x.list("inbox", map[string]any{"mailbox": "Labels/Taxes"}); len(l) != 1 {
		t.Fatal("label with create")
	}

	// archive and move, with undo
	r = x.call("archive", map[string]any{"uid": lunch})
	if len(x.list("inbox", map[string]any{"mailbox": "Archive"})) != 1 || len(x.list("inbox", nil)) != 1 {
		t.Fatal("archive")
	}
	x.undo(r)
	if len(x.list("inbox", nil)) != 2 {
		t.Fatal("undo archive")
	}
	list = x.list("inbox", nil)
	lunch = list[0].UID
	r = x.call("copy", map[string]any{"uid": lunch, "to": "Folders/Receipts"})
	if len(x.list("inbox", map[string]any{"mailbox": "Folders/Receipts"})) != 1 || len(x.list("inbox", nil)) != 2 {
		t.Fatal("copy")
	}
	x.undo(r)
	if len(x.list("inbox", map[string]any{"mailbox": "Folders/Receipts"})) != 0 {
		t.Fatal("undo copy")
	}

	// delete: preview, to Trash, undo brings it back; in Trash it's erased
	plan := x.dry("delete", map[string]any{"uid": lunch})
	if len(plan.Changes) != 1 || plan.Changes[0].Op != "trash" || !strings.Contains(plan.Changes[0].Target, "Lunch?") {
		t.Fatalf("delete plan = %+v", plan)
	}
	if len(x.list("inbox", nil)) != 2 {
		t.Fatal("a dry run deleted something")
	}
	r = x.call("delete", map[string]any{"uid": lunch})
	if len(x.list("inbox", nil)) != 1 || len(x.list("inbox", map[string]any{"mailbox": "Trash"})) != 1 {
		t.Fatal("delete")
	}
	x.undo(r)
	if len(x.list("inbox", nil)) != 2 || len(x.list("inbox", map[string]any{"mailbox": "Trash"})) != 0 {
		t.Fatal("undo delete")
	}
	lunch = x.list("inbox", nil)[0].UID
	x.call("delete", map[string]any{"uid": lunch})
	trashed := x.list("inbox", map[string]any{"mailbox": "Trash"})
	plan = x.dry("delete", map[string]any{"uid": trashed[0].UID, "mailbox": "Trash"})
	if plan.Changes[0].Op != "delete" {
		t.Fatalf("delete from trash should erase: %+v", plan)
	}
	r = x.call("delete", map[string]any{"uid": trashed[0].UID, "mailbox": "Trash"})
	if r.Undo != nil || len(x.list("inbox", map[string]any{"mailbox": "Trash"})) != 0 {
		t.Fatal("erase")
	}
}

func TestSendReplyForward(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello file"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, x := setup(t, map[string]any{"attachmentsDir": dir, "maxAttachmentMB": 1})
	b.imap.put(t, "INBOX", sample)
	b.imap.put(t, "INBOX", group)
	list := x.list("inbox", nil)
	bill, lunch := list[1].UID, list[0].UID

	// send: preview shows recipients, subject, body and attachments
	send := map[string]any{"to": []string{"ada@example.com"}, "cc": []string{"Bob <bob@example.com>"}, "bcc": []string{"secret@example.com"},
		"subject": "Report", "body": "See attached.",
		"attachments": []map[string]any{{"path": "notes.txt"}, {"name": "data.csv", "base64": base64.StdEncoding.EncodeToString([]byte("a,b\n1,2\n"))}}}
	plan := x.dry("send", send)
	after := string(plan.Changes[0].After)
	for _, w := range []string{"ada@example.com", "bob@example.com", "secret@example.com", "Report", "See attached.", "notes.txt", "data.csv"} {
		if !strings.Contains(after+plan.Summary+plan.Changes[0].Target, w) {
			t.Fatalf("plan lacks %q: %s %+v", w, plan.Summary, plan.Changes)
		}
	}
	if b.smtp.count() != 0 {
		t.Fatal("dry run sent mail")
	}
	x.call("send", send)
	got := b.smtp.last(t)
	if strings.Join(got.To, ",") != "ada@example.com,bob@example.com,secret@example.com" {
		t.Fatalf("rcpts %v", got.To)
	}
	if strings.Contains(got.Data, "secret@example.com") {
		t.Fatal("Bcc leaked into the message")
	}
	for _, w := range []string{"Subject: Report", "notes.txt", "data.csv", base64.StdEncoding.EncodeToString([]byte("hello file"))} {
		if !strings.Contains(got.Data, w) {
			t.Fatalf("sent message lacks %q:\n%s", w, got.Data)
		}
	}
	// Proton Bridge files sent mail itself; nothing appended to Sent.
	if len(x.list("inbox", map[string]any{"mailbox": "Sent"})) != 0 {
		t.Fatal("appended to Sent although the server saves it")
	}

	// attachments stay inside the folder and under the cap
	for _, bad := range []map[string]any{
		{"path": "../etc/passwd"},
		{"path": "/etc/passwd"},
		{"name": "big.bin", "base64": base64.StdEncoding.EncodeToString(make([]byte, 2<<20))},
	} {
		in := map[string]any{"to": []string{"ada@example.com"}, "subject": "x", "body": "x", "attachments": []map[string]any{bad}}
		if _, err := x.try("send", in, false); err == nil {
			t.Fatalf("attachment %v accepted", bad)
		}
	}
	if _, err := x.try("send", map[string]any{"to": []string{"not an address"}, "subject": "x", "body": "x"}, false); err == nil {
		t.Fatal("bad address accepted")
	}

	// reply: threaded, Re:, quoted, to the sender only
	plan = x.dry("reply", map[string]any{"uid": bill, "body": "Paid, thanks."})
	if !strings.Contains(plan.Summary, "Re: Server bill") || !strings.Contains(string(plan.Changes[0].After), "abc@example.com") {
		t.Fatalf("reply plan = %+v", plan)
	}
	x.call("reply", map[string]any{"uid": bill, "body": "Paid, thanks."})
	got = b.smtp.last(t)
	for _, w := range []string{"Subject: Re: Server bill", "In-Reply-To: <abc@example.com>", "References: <abc@example.com>", "Paid, thanks.", "> Your bill is 12 EUR.", "Ada <ada@example.com> wrote:"} {
		if !strings.Contains(got.Data, w) {
			t.Fatalf("reply lacks %q:\n%s", w, got.Data)
		}
	}
	if strings.Join(got.To, ",") != "ada@example.com" {
		t.Fatalf("reply rcpts %v", got.To)
	}
	if s := x.list("search", map[string]any{"from": "ada"}); !s[0].Answered {
		t.Fatalf("original not marked answered: %+v", s)
	}

	// reply all: everyone but me
	x.call("reply_all", map[string]any{"uid": lunch, "body": "Yes!", "quote": false})
	got = b.smtp.last(t)
	if strings.Join(got.To, ",") != "bob@example.com,dave@example.com,carol@example.com" {
		t.Fatalf("reply all rcpts %v", got.To)
	}
	if !strings.Contains(got.Data, "Subject: Re: Lunch?") || strings.Contains(got.Data, "> Noon") {
		t.Fatalf("reply all:\n%s", got.Data)
	}

	// forward with the attachment
	x.call("forward", map[string]any{"uid": bill, "to": []string{"accounting@example.com"}, "body": "FYI"})
	got = b.smtp.last(t)
	for _, w := range []string{"Subject: Fwd: Server bill", "FYI", "Forwarded message", "From: Ada <ada@example.com>", "bill.pdf", base64.StdEncoding.EncodeToString([]byte("PDFDATA"))} {
		if !strings.Contains(got.Data, w) {
			t.Fatalf("forward lacks %q:\n%s", w, got.Data)
		}
	}
}

func TestDrafts(t *testing.T) {
	b, x := setup(t, nil)
	b.imap.put(t, "INBOX", sample)
	bill := x.list("inbox", nil)[0].UID

	var saved map[string]any
	_ = json.Unmarshal(x.call("draft", map[string]any{"to": []string{"ada@example.com"}, "bcc": []string{"me2@example.com"}, "subject": "Draft one", "body": "First"}).Output, &saved)
	uid := uint32(saved["uid"].(float64))
	if uid == 0 || saved["folder"] != "Drafts" {
		t.Fatalf("draft = %v", saved)
	}
	d := x.list("drafts", nil)
	if len(d) != 1 || !d[0].Draft || d[0].Subject != "Draft one" {
		t.Fatalf("drafts = %+v", d)
	}

	_ = json.Unmarshal(x.call("update_draft", map[string]any{"uid": uid, "subject": "Draft two"}).Output, &saved)
	uid2 := uint32(saved["uid"].(float64))
	d = x.list("drafts", nil)
	if len(d) != 1 || d[0].Subject != "Draft two" || d[0].UID != uid2 {
		t.Fatalf("after update = %+v", d)
	}
	var m Message
	_ = json.Unmarshal(x.call("read", map[string]any{"uid": uid2, "mailbox": "Drafts"}).Output, &m)
	if m.Text != "First" || !strings.Contains(m.To, "ada@example.com") {
		t.Fatalf("update must keep the other fields: %+v", m)
	}

	plan := x.dry("send_draft", map[string]any{"uid": uid2})
	if !strings.Contains(plan.Summary, "Draft two") || !strings.Contains(plan.Summary, "me2@example.com") {
		t.Fatalf("send_draft plan %+v", plan)
	}
	x.call("send_draft", map[string]any{"uid": uid2})
	got := b.smtp.last(t)
	if strings.Join(got.To, ",") != "ada@example.com,me2@example.com" || strings.Contains(got.Data, "me2@example.com") || !strings.Contains(got.Data, "First") {
		t.Fatalf("sent draft %+v", got)
	}
	if len(x.list("drafts", nil)) != 0 {
		t.Fatal("sent draft still in Drafts")
	}

	// a reply saved as a draft keeps its threading through send_draft
	_ = json.Unmarshal(x.call("reply", map[string]any{"uid": bill, "body": "Later", "draft": true}).Output, &saved)
	rid := uint32(saved["uid"].(float64))
	x.call("send_draft", map[string]any{"uid": rid})
	if got := b.smtp.last(t); !strings.Contains(got.Data, "In-Reply-To: <abc@example.com>") {
		t.Fatalf("draft reply lost threading:\n%s", got.Data)
	}

	_ = json.Unmarshal(x.call("draft", map[string]any{"subject": "Scratch", "body": "x"}).Output, &saved)
	uid = uint32(saved["uid"].(float64))
	if p := x.dry("delete_draft", map[string]any{"uid": uid}); !strings.Contains(p.Summary, "Scratch") {
		t.Fatalf("delete_draft plan %+v", p)
	}
	x.call("delete_draft", map[string]any{"uid": uid})
	if len(x.list("drafts", nil)) != 0 {
		t.Fatal("delete_draft")
	}
}

func TestWatchEvents(t *testing.T) {
	b := newBridge(t)
	b.imap.put(t, "INBOX", sample)
	h := fakehost.New(map[string]string{"secret://bridge": "bridge-pw"})
	m := New()
	m.Dir = t.TempDir()
	if err := m.Configure(context.Background(), h, "w", b.config(t, nil)); err != nil {
		t.Fatal(err)
	}
	defer m.Close("w")
	a, _ := m.account("w")
	ctx := context.Background()
	m.checkNew(ctx, a) // baseline: existing mail isn't announced
	if len(h.Events()) != 0 {
		t.Fatalf("events on first check: %+v", h.Events())
	}
	b.imap.put(t, "INBOX", group)
	m.checkNew(ctx, a)
	ev := h.Events()
	if len(ev) != 2 || ev[0].Type != "mail.received" || ev[1].Type != "mail.unread" {
		t.Fatalf("events = %+v", ev)
	}
	var data struct {
		Count    int       `json:"count"`
		Unread   int       `json:"unread"`
		Messages []Summary `json:"messages"`
	}
	_ = json.Unmarshal(ev[0].Data, &data)
	if data.Count != 1 || data.Unread != 2 || data.Messages[0].Subject != "Lunch?" {
		t.Fatalf("mail.received = %s", ev[0].Data)
	}
	m.checkNew(ctx, a)
	if len(h.Events()) != 2 {
		t.Fatal("nothing new, yet events")
	}

	// A restart remembers the position: mail that arrived meanwhile is
	// announced once.
	m.Close("w")
	b.imap.put(t, "INBOX", sentReply)
	m2 := New()
	m2.Dir = m.Dir
	if err := m2.Configure(ctx, h, "w", b.config(t, nil)); err != nil {
		t.Fatal(err)
	}
	defer m2.Close("w")
	a2, _ := m2.account("w")
	m2.checkNew(ctx, a2)
	ev = h.Events()
	if len(ev) != 4 || ev[2].Type != "mail.received" || !strings.Contains(string(ev[2].Data), "Re: Server bill") {
		t.Fatalf("after restart = %+v", ev)
	}
}

func TestLegacyDialOverride(t *testing.T) {
	// Plain in-process server through the dial hook, as other tests in the
	// tree do.
	srv := imapServer(t, nil)
	srv.put(t, "INBOX", sample)
	m := New()
	m.Dir = t.TempDir()
	m.dial = func(ctx context.Context, a *account) (*imapclient.Client, error) {
		c, err := imapclient.DialInsecure(srv.addr, nil)
		if err != nil {
			return nil, err
		}
		pw, _ := a.host.Secret(ctx, a.cfg.Password)
		return c, c.Login(a.cfg.Username, pw).Wait()
	}
	cfg, _ := json.Marshal(map[string]string{"provider": "other", "email": "me@example.com", "password": "secret://bridge", "imapHost": "x", "smtpHost": "y"})
	if err := m.Configure(context.Background(), testHost, "m1", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "m1"); h.Status != "ok" || h.Message != "1 unread" {
		t.Fatalf("health = %+v", h)
	}
	// keyword labels on servers without label folders
	x := tester{t, m, "m1"}
	uid := x.list("inbox", nil)[0].UID
	r := x.call("label", map[string]any{"uid": uid, "label": "work"})
	if l := x.list("inbox", nil); len(l[0].Keywords) != 1 || l[0].Keywords[0] != "work" {
		t.Fatalf("keyword label: %+v", l)
	}
	x.undo(r)
	if l := x.list("inbox", nil); len(l[0].Keywords) != 0 {
		t.Fatalf("keyword unlabel: %+v", l)
	}
	if _, err := x.try("label", map[string]any{"uid": uid, "label": "two words"}, false); err == nil {
		t.Fatal("bad keyword accepted")
	}
}

func TestHTMLToText(t *testing.T) {
	got := htmlToText(`<style>p{}</style><p>Hi&nbsp;there</p><p>Line<br>two</p><ul><li>a</li></ul><a href="https://x.example/p">site</a>`)
	if got != "Hi there\nLine\ntwo\n\n• a\nsite [https://x.example/p]" {
		t.Fatalf("got %q", got)
	}
}

func TestHelpers(t *testing.T) {
	if replySubject("Re: x") != "Re: x" || replySubject("AW: x") != "AW: x" || replySubject("x") != "Re: x" {
		t.Fatal("replySubject")
	}
	if forwardSubject("Fwd: x") != "Fwd: x" || forwardSubject("x") != "Fwd: x" {
		t.Fatal("forwardSubject")
	}
	if _, err := normFingerprint("abc"); err == nil {
		t.Fatal("short fingerprint accepted")
	}
	fp := Fingerprint([]byte("x"))
	if n, err := normFingerprint(strings.ToLower(strings.ReplaceAll(fp, ":", " "))); err != nil || n != fp {
		t.Fatalf("normFingerprint %q %v", n, err)
	}
	if !isLoopback("127.0.0.1") || !isLoopback("::1") || !isLoopback("localhost") || isLoopback("10.0.0.1") {
		t.Fatal("isLoopback")
	}
	if s, _ := security("", "imap.example.com", 993, false); s != secTLS {
		t.Fatal("993 is TLS")
	}
	if s, _ := security("", "127.0.0.1", 1143, true); s != secNone {
		t.Fatal("legacy insecureLocal")
	}
}
