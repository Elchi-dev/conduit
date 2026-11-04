package mail

import (
	"bytes"
	"encoding/base64"
	"html"
	"io"
	"mime"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	gomsg "github.com/emersion/go-message/mail"
)

// Summary is a message in a list.
type Summary struct {
	UID       uint32   `json:"uid"`
	Mailbox   string   `json:"mailbox,omitempty"`
	From      string   `json:"from"`
	To        string   `json:"to,omitempty"`
	Subject   string   `json:"subject"`
	Date      string   `json:"date"`
	Unread    bool     `json:"unread"`
	Flagged   bool     `json:"flagged"`
	Draft     bool     `json:"draft,omitempty"`
	Answered  bool     `json:"answered,omitempty"`
	Keywords  []string `json:"keywords,omitempty"`
	Size      int64    `json:"sizeKB,omitempty"`
	MessageID string   `json:"messageId,omitempty"`
	InReplyTo string   `json:"inReplyTo,omitempty"`
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

func summary(msg *imapclient.FetchMessageBuffer, mailbox string) Summary {
	s := Summary{UID: uint32(msg.UID), Mailbox: mailbox, Unread: true, Size: msg.RFC822Size / 1024}
	for _, f := range msg.Flags {
		switch f {
		case imap.FlagSeen:
			s.Unread = false
		case imap.FlagFlagged:
			s.Flagged = true
		case imap.FlagDraft:
			s.Draft = true
		case imap.FlagAnswered:
			s.Answered = true
		default:
			if !strings.HasPrefix(string(f), "\\") && !strings.HasPrefix(string(f), "$") {
				s.Keywords = append(s.Keywords, string(f))
			}
		}
	}
	if e := msg.Envelope; e != nil {
		s.From, s.To, s.Subject, s.MessageID = addrs(e.From), addrs(e.To), e.Subject, e.MessageID
		if len(e.InReplyTo) > 0 {
			s.InReplyTo = e.InReplyTo[0]
		}
		if !e.Date.IsZero() {
			s.Date = e.Date.Format(time.RFC3339)
		}
	}
	return s
}

func summarize(msgs []*imapclient.FetchMessageBuffer, mailbox string) []Summary {
	out := make([]Summary, 0, len(msgs))
	for _, msg := range msgs {
		out = append(out, summary(msg, mailbox))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID > out[j].UID })
	return out
}

func listFetch() *imap.FetchOptions {
	return &imap.FetchOptions{UID: true, Flags: true, Envelope: true, RFC822Size: true}
}

// Message is a parsed message.
type Message struct {
	UID         uint32       `json:"uid"`
	Mailbox     string       `json:"mailbox"`
	MessageID   string       `json:"messageId,omitempty"`
	From        string       `json:"from"`
	ReplyTo     string       `json:"replyTo,omitempty"`
	To          string       `json:"to"`
	CC          string       `json:"cc,omitempty"`
	BCC         string       `json:"bcc,omitempty"`
	Subject     string       `json:"subject"`
	Date        string       `json:"date"`
	Unread      bool         `json:"unread"`
	Flagged     bool         `json:"flagged"`
	InReplyTo   string       `json:"inReplyTo,omitempty"`
	References  []string     `json:"references,omitempty"`
	Text        string       `json:"text"`
	HTML        bool         `json:"hadHtml,omitempty"`   // the text was converted from HTML
	Truncated   bool         `json:"truncated,omitempty"` // the text was cut at maxText
	Attachments []Attachment `json:"attachments"`
}

// Attachment describes an attached file.
type Attachment struct {
	Index  int    `json:"index"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	SizeKB int    `json:"sizeKB"`
	Inline bool   `json:"inline,omitempty"`
}

const maxText = 200 << 10

var (
	tagRe    = regexp.MustCompile(`(?is)<(script|style|head)[^>]*>.*?</(script|style|head)>|<!--.*?-->|<[^>]+>`)
	blankRe  = regexp.MustCompile(`\n{3,}`)
	spaceRe  = regexp.MustCompile(`[ \t\x{00a0}]+`)
	brRe     = regexp.MustCompile(`(?i)<br\s*/?>|</p>|</div>|</tr>|</h[1-6]>|</li>|</blockquote>`)
	liRe     = regexp.MustCompile(`(?i)<li[^>]*>`)
	linkRe   = regexp.MustCompile(`(?is)<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>`)
	tdRe     = regexp.MustCompile(`(?i)</t[dh]>`)
	stripTag = regexp.MustCompile(`<[^>]+>`)
)

// htmlToText strips markup for reading. It is not a renderer; mail HTML is
// never shown as HTML, which also keeps tracking pixels and scripts out.
// Links keep their address in brackets when it differs from their text.
func htmlToText(s string) string {
	s = linkRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := linkRe.FindStringSubmatch(m)
		href, text := sub[1], strings.TrimSpace(stripTag.ReplaceAllString(sub[2], ""))
		if strings.HasPrefix(strings.ToLower(href), "mailto:") || text == "" || text == href || !strings.HasPrefix(href, "http") {
			return text
		}
		return text + " [" + href + "]"
	})
	s = liRe.ReplaceAllString(s, "\n• ")
	s = tdRe.ReplaceAllString(s, " ")
	s = brRe.ReplaceAllString(s, "\n")
	s = tagRe.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(spaceRe.ReplaceAllString(l, " "))
	}
	return strings.TrimSpace(blankRe.ReplaceAllString(strings.Join(lines, "\n"), "\n\n"))
}

// part is one attachment's content.
type part struct {
	Attachment
	Data []byte
}

// parsed is a message read from its raw form.
type parsed struct {
	Header      gomsg.Header
	Text        string
	HTML        string
	Attachments []part
}

// parseRaw reads a message. Attachment contents are kept only when keep is
// true, up to limit bytes each (longer ones are marked by Data == nil).
func parseRaw(raw []byte, keep bool, limit int64) (*parsed, error) {
	r, err := gomsg.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return &parsed{Text: string(raw)}, nil //nolint:nilerr // not MIME: show it as is
	}
	p := &parsed{Header: r.Header}
	for {
		pt, err := r.NextPart()
		if err != nil {
			break // io.EOF or a broken part: keep what was read
		}
		var name, ct string
		inline := false
		switch h := pt.Header.(type) {
		case *gomsg.InlineHeader:
			ct, _, _ = h.ContentType()
			_, params, _ := h.ContentDisposition()
			name = params["filename"]
			if name == "" {
				_, cp, _ := h.ContentType()
				name = cp["name"]
			}
			if name == "" && (ct == "text/plain" || ct == "text/html" || ct == "") {
				b, _ := io.ReadAll(io.LimitReader(pt.Body, 4<<20))
				if ct == "text/html" {
					if p.HTML == "" {
						p.HTML = string(b)
					}
				} else if p.Text == "" {
					p.Text = string(b)
				}
				continue
			}
			inline = true
		case *gomsg.AttachmentHeader:
			name, _ = h.Filename()
			ct, _, _ = h.ContentType()
		default:
			continue
		}
		if name == "" {
			name = "attachment"
			if exts, _ := mime.ExtensionsByType(ct); len(exts) > 0 {
				name += exts[0]
			}
		}
		at := part{Attachment: Attachment{Index: len(p.Attachments), Name: name, Type: ct, Inline: inline}}
		if keep {
			b, _ := io.ReadAll(io.LimitReader(pt.Body, limit+1))
			if int64(len(b)) <= limit {
				at.Data = b
			}
			n, _ := io.Copy(io.Discard, pt.Body)
			at.SizeKB = int((int64(len(b)) + n) / 1024)
		} else {
			n, _ := io.Copy(io.Discard, pt.Body)
			at.SizeKB = int(n / 1024)
		}
		p.Attachments = append(p.Attachments, at)
	}
	return p, nil
}

// body is the readable text of a parsed message.
func (p *parsed) body() (string, bool) {
	if strings.TrimSpace(p.Text) != "" {
		return strings.TrimSpace(strings.ReplaceAll(p.Text, "\r\n", "\n")), false
	}
	if p.HTML != "" {
		return htmlToText(p.HTML), true
	}
	return "", false
}

func headerAddrs(h gomsg.Header, key string) []string {
	list, err := h.AddressList(key)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.String())
	}
	return out
}

func bareAddrs(h gomsg.Header, key string) []string {
	list, err := h.AddressList(key)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Address)
	}
	return out
}

func toMessage(buf *imapclient.FetchMessageBuffer, mailbox string, raw []byte) (*Message, error) {
	s := summary(buf, mailbox)
	m := &Message{UID: s.UID, Mailbox: mailbox, From: s.From, To: s.To, Subject: s.Subject, Date: s.Date, Unread: s.Unread, Flagged: s.Flagged,
		MessageID: s.MessageID, InReplyTo: s.InReplyTo, Attachments: []Attachment{}}
	if e := buf.Envelope; e != nil {
		m.CC, m.BCC = addrs(e.Cc), addrs(e.Bcc)
		if len(e.ReplyTo) > 0 && addrs(e.ReplyTo) != m.From {
			m.ReplyTo = addrs(e.ReplyTo)
		}
	}
	p, _ := parseRaw(raw, false, 0)
	if p.Header.Header.Len() > 0 {
		m.References, _ = p.Header.MsgIDList("References")
	}
	m.Text, m.HTML = p.body()
	if len(m.Text) > maxText {
		m.Text, m.Truncated = truncate(m.Text, maxText), true
	}
	for _, a := range p.Attachments {
		m.Attachments = append(m.Attachments, a.Attachment)
	}
	return m, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
