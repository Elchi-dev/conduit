package mail

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	gomail "github.com/wneessen/go-mail"
)

// Compose is a message to send or save as a draft.
type Compose struct {
	To          []string       `json:"to"`
	CC          []string       `json:"cc"`
	BCC         []string       `json:"bcc"`
	Subject     string         `json:"subject"`
	Body        string         `json:"body"`
	HTML        string         `json:"html,omitempty"`
	Attachments []AttachmentIn `json:"attachments"`
	// ReplyToUID threads a new message under an INBOX message (older
	// callers; reply does this properly).
	ReplyToUID uint32 `json:"replyToUid"`

	inReplyTo  string   // message id without brackets
	references []string // message ids without brackets
	files      []part   // resolved attachments
}

// AttachmentIn is an attachment to send: a file under the instance's
// attachments folder, or content given as base64.
type AttachmentIn struct {
	Name   string `json:"name"`
	Path   string `json:"path,omitempty"`
	Base64 string `json:"base64,omitempty"`
	Type   string `json:"type,omitempty"`
}

func validAddrs(list []string, field string) ([]string, error) {
	var out []string
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.ContainsAny(s, "\r\n") {
			return nil, userErr("%s has a line break", field)
		}
		if _, err := mail.ParseAddress(s); err != nil {
			return nil, userErr("%q in %s isn't an email address", s, field)
		}
		out = append(out, s)
	}
	return out, nil
}

// resolve checks addresses and loads attachments, enforcing the size cap.
func (a *account) resolve(c *Compose) error {
	var err error
	if c.To, err = validAddrs(c.To, "to"); err != nil {
		return err
	}
	if c.CC, err = validAddrs(c.CC, "cc"); err != nil {
		return err
	}
	if c.BCC, err = validAddrs(c.BCC, "bcc"); err != nil {
		return err
	}
	if strings.ContainsAny(c.Subject, "\r\n") {
		return userErr("the subject has a line break")
	}
	var total int64
	for _, f := range c.files {
		total += int64(len(f.Data))
	}
	for _, in := range c.Attachments {
		p, err := a.loadAttachment(in, a.maxAttach-total)
		if err != nil {
			return err
		}
		total += int64(len(p.Data))
		c.files = append(c.files, p)
	}
	c.Attachments = nil
	if total > a.maxAttach {
		return userErr("attachments add up to %d MB; the limit is %d MB", total>>20, a.maxAttach>>20)
	}
	return nil
}

func (a *account) loadAttachment(in AttachmentIn, room int64) (part, error) {
	if room < 0 {
		room = 0
	}
	name := in.Name
	var data []byte
	switch {
	case in.Base64 != "" && in.Path != "":
		return part{}, userErr("give an attachment as path or base64, not both")
	case in.Base64 != "":
		if int64(base64.StdEncoding.DecodedLen(len(in.Base64))) > room+3 {
			return part{}, userErr("attachment %q is over the %d MB limit", name, a.maxAttach>>20)
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(in.Base64))
		if err != nil {
			return part{}, userErr("attachment %q isn't valid base64", name)
		}
		data = b
	case in.Path != "":
		if a.cfg.AttachmentsDir == "" {
			return part{}, userErr("sending files by path needs an attachments folder in this mailbox's settings; or give the content as base64")
		}
		root, err := os.OpenRoot(a.cfg.AttachmentsDir)
		if err != nil {
			return part{}, fmt.Errorf("attachments folder: %w", err)
		}
		defer root.Close()
		rel := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(in.Path, "/")))
		f, err := root.Open(rel) // os.Root refuses paths that leave the folder
		if err != nil {
			return part{}, userErr("can't open %q in the attachments folder: %v", in.Path, err)
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			return part{}, userErr("%q isn't a file", in.Path)
		}
		if st.Size() > room {
			return part{}, userErr("%q is %d MB; the attachment limit is %d MB", in.Path, st.Size()>>20, a.maxAttach>>20)
		}
		data, err = io.ReadAll(io.LimitReader(f, room+1))
		if err != nil {
			return part{}, err
		}
		if name == "" {
			name = filepath.Base(rel)
		}
	default:
		return part{}, userErr("attachment %q has neither path nor base64", name)
	}
	if int64(len(data)) > room {
		return part{}, userErr("attachment %q is over the %d MB limit", name, a.maxAttach>>20)
	}
	if name == "" {
		name = "attachment"
	}
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	ct, err := attachmentType(in.Type, name)
	if err != nil {
		return part{}, err
	}
	return part{Attachment: Attachment{Name: name, Type: ct, SizeKB: len(data) / 1024}, Data: data}, nil
}

// attachmentType checks and normalises an attachment's media type: it must
// parse as one (type/subtype with optional parameters) and is re-formatted,
// so nothing the caller sends reaches the MIME header raw. Empty uses the
// file name's extension, else application/octet-stream.
func attachmentType(t, name string) (string, error) {
	if strings.ContainsAny(t, "\r\n") {
		return "", userErr("attachment %q has an invalid type", name)
	}
	t = strings.TrimSpace(t)
	if t == "" {
		t = mime.TypeByExtension(filepath.Ext(name))
		if t == "" {
			return "application/octet-stream", nil
		}
	}
	mt, params, err := mime.ParseMediaType(t)
	if err != nil || !strings.Contains(mt, "/") {
		return "", userErr("attachment %q has an invalid type %q", name, t)
	}
	out := mime.FormatMediaType(mt, params)
	if out == "" || strings.ContainsAny(out, "\r\n") {
		return "", userErr("attachment %q has an invalid type %q", name, t)
	}
	return out, nil
}

// bracket makes a message id for In-Reply-To and References: angle brackets
// around it, with CR, LF and other control characters and any brackets or
// spaces inside removed, so an id taken from a received message can't add
// header lines.
func bracket(id string) string {
	id = strings.Map(func(r rune) rune {
		if r < 0x21 || r == 0x7f || r == '<' || r == '>' {
			return -1
		}
		return r
	}, id)
	return "<" + id + ">"
}

// build turns a Compose into a go-mail message. With forDraft the Bcc list
// is kept as a header so the draft remembers it.
func (a *account) build(c *Compose, forDraft bool) (*gomail.Msg, error) {
	msg := gomail.NewMsg()
	from := a.cfg.Email
	if a.cfg.Name != "" {
		from = (&mail.Address{Name: a.cfg.Name, Address: a.cfg.Email}).String()
	}
	if err := msg.From(from); err != nil {
		return nil, err
	}
	if len(c.To) > 0 {
		if err := msg.To(c.To...); err != nil {
			return nil, err
		}
	}
	if len(c.CC) > 0 {
		if err := msg.Cc(c.CC...); err != nil {
			return nil, err
		}
	}
	if len(c.BCC) > 0 {
		if forDraft {
			msg.SetGenHeader(gomail.Header("Bcc"), strings.Join(c.BCC, ", "))
		} else if err := msg.Bcc(c.BCC...); err != nil {
			return nil, err
		}
	}
	if id := bracket(c.inReplyTo); id != "<>" {
		msg.SetGenHeaderPreformatted(gomail.HeaderInReplyTo, id)
	}
	refs := make([]string, 0, len(c.references))
	for _, r := range c.references {
		if id := bracket(r); id != "<>" {
			refs = append(refs, id)
		}
	}
	if len(refs) > 0 {
		msg.SetGenHeaderPreformatted(gomail.HeaderReferences, strings.Join(refs, "\r\n "))
	}
	msg.Subject(c.Subject)
	msg.SetDate()
	msg.SetMessageID()
	msg.SetBodyString(gomail.TypeTextPlain, c.Body)
	if c.HTML != "" {
		msg.AddAlternativeString(gomail.TypeTextHTML, c.HTML)
	}
	for _, f := range c.files {
		if err := msg.AttachReader(f.Name, bytes.NewReader(f.Data), gomail.WithFileContentType(gomail.ContentType(f.Type))); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

func raw(msg *gomail.Msg) ([]byte, error) {
	var b bytes.Buffer
	if _, err := msg.WriteTo(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// smtpClient returns a client for the account's SMTP server.
func (a *account) smtpClient(ctx context.Context) (*gomail.Client, error) {
	pw, err := a.host.Secret(ctx, a.cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}
	opts := []gomail.Option{gomail.WithPort(a.cfg.SMTPPort), gomail.WithSMTPAuth(gomail.SMTPAuthAutoDiscover),
		gomail.WithUsername(a.cfg.Username), gomail.WithPassword(pw), gomail.WithTimeout(30 * time.Second)}
	switch a.smtpSec {
	case secNone:
		opts = append(opts, gomail.WithTLSPolicy(gomail.NoTLS))
	case secTLS:
		opts = append(opts, gomail.WithSSL(), gomail.WithTLSConfig(a.tlsConfig("smtp", a.cfg.SMTPHost)))
	default:
		opts = append(opts, gomail.WithTLSPolicy(gomail.TLSMandatory), gomail.WithTLSConfig(a.tlsConfig("smtp", a.cfg.SMTPHost)))
	}
	return gomail.NewClient(a.cfg.SMTPHost, opts...)
}

// send delivers a message over SMTP and files it in Sent when the server
// doesn't do that itself.
func (m *Module) send(ctx context.Context, a *account, c *Compose) (map[string]any, error) {
	if len(c.To)+len(c.CC)+len(c.BCC) == 0 {
		return nil, userErr("add at least one recipient")
	}
	msg, err := a.build(c, false)
	if err != nil {
		return nil, err
	}
	client, err := a.smtpClient(ctx)
	if err != nil {
		return nil, err
	}
	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return nil, fmt.Errorf("sending failed: %w", tlsHint(err))
	}
	out := map[string]any{"sent": true, "to": c.To, "subject": c.Subject, "messageId": strings.Trim(msg.GetMessageID(), "<>")}
	if len(c.CC) > 0 {
		out["cc"] = c.CC
	}
	if len(c.BCC) > 0 {
		out["bcc"] = c.BCC
	}
	if a.saveSent {
		if b, err := raw(msg); err == nil {
			sent := m.folder(ctx, a, imap.MailboxAttrSent, "Sent", "Sent Items", "Sent Messages")
			if _, err := m.appendTo(ctx, a, sent, b, []imap.Flag{imap.FlagSeen}); err != nil {
				out["sentCopy"] = "not saved: " + err.Error()
			}
		}
	}
	return out, nil
}

// preview is the dry-run plan for sending or saving c.
func (a *account) preview(c *Compose, verb string) map[string]any {
	after := map[string]any{"from": a.cfg.Email, "to": c.To, "subject": c.Subject, "body": truncate(c.Body, 4000)}
	if len(c.CC) > 0 {
		after["cc"] = c.CC
	}
	if len(c.BCC) > 0 {
		after["bcc"] = c.BCC
	}
	if c.HTML != "" {
		after["html"] = "included (" + fmt.Sprint(len(c.HTML)/1024) + " KB)"
	}
	if c.inReplyTo != "" {
		after["inReplyTo"] = c.inReplyTo
	}
	var files []string
	for _, f := range c.files {
		files = append(files, fmt.Sprintf("%s (%s, %d KB)", f.Name, f.Type, f.SizeKB))
	}
	if len(files) > 0 {
		after["attachments"] = files
	}
	after["action"] = verb
	return after
}

var rePrefix = []string{"re:", "aw:", "sv:", "antw:", "réf:", "rif:"}

func replySubject(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	for _, p := range rePrefix {
		if strings.HasPrefix(t, p) {
			return strings.TrimSpace(s)
		}
	}
	return "Re: " + strings.TrimSpace(s)
}

func forwardSubject(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(t, "fwd:") || strings.HasPrefix(t, "fw:") || strings.HasPrefix(t, "wg:") {
		return strings.TrimSpace(s)
	}
	return "Fwd: " + strings.TrimSpace(s)
}

func quote(text, from, date string) string {
	var b strings.Builder
	if date != "" {
		if t, err := time.Parse(time.RFC3339, date); err == nil {
			date = t.Format("Mon, 2 Jan 2006 at 15:04")
		}
		fmt.Fprintf(&b, "On %s, %s wrote:\n", date, from)
	} else {
		fmt.Fprintf(&b, "%s wrote:\n", from)
	}
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if strings.HasPrefix(l, ">") {
			b.WriteString(">" + l + "\n")
		} else {
			b.WriteString("> " + l + "\n")
		}
	}
	return b.String()
}

func sameAddr(a, b string) bool {
	pa, err1 := mail.ParseAddress(a)
	pb, err2 := mail.ParseAddress(b)
	if err1 != nil || err2 != nil {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	return strings.EqualFold(pa.Address, pb.Address)
}

// dedupe drops repeated addresses and any in skip.
func dedupe(list []string, skip ...string) []string {
	var out []string
outer:
	for _, x := range list {
		for _, s := range append(append([]string{}, skip...), out...) {
			if sameAddr(x, s) {
				continue outer
			}
		}
		out = append(out, x)
	}
	return out
}

// errNoMessage is returned when a uid isn't in the mailbox.
func errNoMessage(uid uint32, mailbox string) error {
	return userErr("no message %d in %s (uids change when messages move; list the folder again)", uid, mailbox)
}

var errTooBig = errors.New("message is larger than 25 MB")
