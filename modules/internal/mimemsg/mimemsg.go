// Package mimemsg checks and builds the plain-text messages the hosted mail
// modules send (Microsoft 365, Google Workspace, Fastmail). Addresses and
// subjects with line breaks or other control characters are refused, so
// nothing a caller sends can add a header; headers are encoded with the
// mime package and the body is quoted-printable.
package mimemsg

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxRecipients caps To, Cc and Bcc together.
	MaxRecipients = 50
	// MaxSubject is the longest subject accepted, in characters.
	MaxSubject = 500
	// MaxBody is the longest body accepted, in bytes.
	MaxBody = 200 << 10
)

// Message is a plain-text message.
type Message struct {
	From    string // optional: the provider fills in the account's address
	To      []string
	Cc      []string
	Bcc     []string
	Subject string
	Text    string
	// OmitBcc leaves the Bcc header out of the built message (when the
	// envelope carries those recipients instead).
	OmitBcc bool
}

func control(s string) bool {
	for _, r := range s {
		if r == '\r' || r == '\n' || (unicode.IsControl(r) && r != '\t') {
			return true
		}
	}
	return false
}

// Addresses checks a list of addresses and returns them as written by
// net/mail (a display name encoded, the address plain). Empty entries are
// skipped.
func Addresses(list []string, field string) ([]*mail.Address, error) {
	var out []*mail.Address
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if control(s) {
			return nil, fmt.Errorf("an address in %s has a line break or control character", field)
		}
		a, err := mail.ParseAddress(s)
		if err != nil || control(a.Name) || !strings.Contains(a.Address, "@") {
			return nil, fmt.Errorf("%q in %s isn't an email address", s, field)
		}
		out = append(out, a)
	}
	return out, nil
}

// Bare returns the plain addresses.
func Bare(list []*mail.Address) []string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Address)
	}
	return out
}

// CheckSubject refuses a subject with a line break or control character, or
// one that's too long.
func CheckSubject(s string) error {
	if control(s) {
		return errors.New("the subject has a line break or control character")
	}
	if !utf8.ValidString(s) {
		return errors.New("the subject isn't valid UTF-8")
	}
	if utf8.RuneCountInString(s) > MaxSubject {
		return fmt.Errorf("the subject is over %d characters", MaxSubject)
	}
	return nil
}

// Checked is a validated message.
type Checked struct {
	From          *mail.Address
	To, Cc, Bcc   []*mail.Address
	Subject, Text string
	omitBcc       bool
}

// Count is the number of recipients.
func (c *Checked) Count() int { return len(c.To) + len(c.Cc) + len(c.Bcc) }

// Recipients are every recipient's plain address.
func (c *Checked) Recipients() []string {
	return append(append(Bare(c.To), Bare(c.Cc)...), Bare(c.Bcc)...)
}

// Check validates m.
func (m Message) Check() (*Checked, error) {
	c := &Checked{Subject: strings.TrimSpace(m.Subject), Text: m.Text, omitBcc: m.OmitBcc}
	var err error
	if strings.TrimSpace(m.From) != "" {
		f, err := Addresses([]string{m.From}, "from")
		if err != nil {
			return nil, err
		}
		c.From = f[0]
	}
	if c.To, err = Addresses(m.To, "to"); err != nil {
		return nil, err
	}
	if c.Cc, err = Addresses(m.Cc, "cc"); err != nil {
		return nil, err
	}
	if c.Bcc, err = Addresses(m.Bcc, "bcc"); err != nil {
		return nil, err
	}
	if c.Count() == 0 {
		return nil, errors.New("add at least one recipient")
	}
	if c.Count() > MaxRecipients {
		return nil, fmt.Errorf("at most %d recipients at once", MaxRecipients)
	}
	if err := CheckSubject(c.Subject); err != nil {
		return nil, err
	}
	if c.Subject == "" {
		return nil, errors.New("add a subject")
	}
	if !utf8.ValidString(c.Text) {
		return nil, errors.New("the body isn't valid UTF-8")
	}
	if len(c.Text) > MaxBody {
		return nil, fmt.Errorf("the body is over %d KB", MaxBody>>10)
	}
	return c, nil
}

func list(as []*mail.Address) string {
	s := make([]string, 0, len(as))
	for _, a := range as {
		s = append(s, a.String())
	}
	return strings.Join(s, ", ")
}

// Build writes the message as RFC 5322 with CRLF line ends.
func (c *Checked) Build(now time.Time) []byte {
	var b bytes.Buffer
	h := func(k, v string) {
		if v != "" {
			b.WriteString(k + ": " + v + "\r\n")
		}
	}
	domain := "conduit.invalid"
	if c.From != nil {
		h("From", c.From.String())
		if i := strings.LastIndex(c.From.Address, "@"); i >= 0 {
			domain = c.From.Address[i+1:]
		}
	}
	h("To", list(c.To))
	h("Cc", list(c.Cc))
	if !c.omitBcc {
		h("Bcc", list(c.Bcc))
	}
	h("Subject", mime.QEncoding.Encode("utf-8", c.Subject))
	h("Date", now.Format(time.RFC1123Z))
	var id [12]byte
	_, _ = rand.Read(id[:])
	h("Message-ID", "<"+hex.EncodeToString(id[:])+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Content-Type", mime.FormatMediaType("text/plain", map[string]string{"charset": "utf-8"}))
	h("Content-Transfer-Encoding", "quoted-printable")
	b.WriteString("\r\n")
	text := strings.ReplaceAll(strings.ReplaceAll(c.Text, "\r\n", "\n"), "\r", "\n")
	w := quotedprintable.NewWriter(&b)
	_, _ = w.Write([]byte(strings.ReplaceAll(text, "\n", "\r\n")))
	_ = w.Close()
	return b.Bytes()
}

// Preview is what a dry run shows of a message to send (the send actions
// are sensitive, so the plan is private): recipients, subject and the start
// of the body, as the mail module shows them.
func (c *Checked) Preview() map[string]any {
	p := map[string]any{"to": Bare(c.To), "subject": c.Subject, "recipients": c.Count()}
	if c.From != nil {
		p["from"] = c.From.Address
	}
	if len(c.Cc) > 0 {
		p["cc"] = Bare(c.Cc)
	}
	if len(c.Bcc) > 0 {
		p["bcc"] = Bare(c.Bcc)
	}
	body := c.Text
	if len(body) > 4000 {
		body = body[:4000]
		for !utf8.ValidString(body) {
			body = body[:len(body)-1]
		}
		body += "…"
	}
	p["body"] = body
	return p
}

// Summary is the dry run's one line: the subject and how many recipients.
func (c *Checked) Summary() string {
	n := c.Count()
	if n == 1 {
		return fmt.Sprintf("Send %q to 1 recipient", c.Subject)
	}
	return fmt.Sprintf("Send %q to %d recipients", c.Subject, n)
}
