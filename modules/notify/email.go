package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// sendMail delivers a notification over SMTP: implicit TLS on port 465,
// otherwise STARTTLS. Credentials are only ever sent over TLS, and without
// TLS mail is only sent to a server on this machine.
func (m *Module) sendMail(ctx context.Context, c Config, h sdk.Host, n Note) error {
	port := c.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(c.SMTPHost, strconv.Itoa(port))
	tc := &tls.Config{ServerName: c.SMTPHost, RootCAs: m.roots, MinVersion: tls.VersionTLS12}
	d := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if port == 465 {
		conn, err = tls.DialWithDialer(d, "tcp", addr, tc)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("couldn't reach the mail server: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	cl, err := smtp.NewClient(conn, c.SMTPHost)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	secure := port == 465
	if !secure {
		if ok, _ := cl.Extension("STARTTLS"); ok {
			if err := cl.StartTLS(tc); err != nil {
				return fmt.Errorf("STARTTLS: %w", err)
			}
			secure = true
		}
	}
	if !secure && !loopback(c.SMTPHost) {
		return errors.New("the mail server doesn't offer TLS; Conduit won't send mail to it unencrypted")
	}
	if c.SMTPUser != "" {
		if !secure {
			return errors.New("won't send the SMTP password without TLS")
		}
		pass, err := m.secret(ctx, h, c.SMTPPass)
		if err != nil {
			return err
		}
		if err := cl.Auth(smtp.PlainAuth("", c.SMTPUser, pass, c.SMTPHost)); err != nil {
			return fmt.Errorf("the mail server refused the login: %w", err)
		}
	}
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return errors.New("the From address isn't valid")
	}
	to, err := mail.ParseAddressList(c.To)
	if err != nil || len(to) == 0 {
		return errors.New("the To addresses aren't valid")
	}
	if err := cl.Mail(from.Address); err != nil {
		return err
	}
	var rcpt []string
	for _, a := range to {
		if err := cl.Rcpt(a.Address); err != nil {
			return fmt.Errorf("%s: %w", a.Address, err)
		}
		rcpt = append(rcpt, a.String())
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	subject := n.Title
	if subject == "" {
		subject = "Conduit"
	}
	if n.Priority == "urgent" || n.Priority == "high" {
		subject = "[" + n.Priority + "] " + subject
	}
	body := n.Message
	if n.Link != "" {
		body += "\n\n" + n.Link
	}
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\n", from.String())
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(rcpt, ", "))
	fmt.Fprintf(&msg, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", oneLine(subject)))
	fmt.Fprintf(&msg, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&msg, "Message-ID: <conduit-%d@%s>\r\n", time.Now().UnixNano(), strings.Trim(from.Address[strings.LastIndex(from.Address, "@")+1:], "<>"))
	msg.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\nAuto-Submitted: auto-generated\r\n\r\n")
	msg.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	msg.WriteString("\r\n")
	if _, err := w.Write(msg.Bytes()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

func oneLine(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
