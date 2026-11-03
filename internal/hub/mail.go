package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	gomail "github.com/wneessen/go-mail"
)

// Mailer sends account emails. Each hub operator chooses their own provider;
// accounts and mail settings are never shared between hubs.
type Mailer interface {
	Send(ctx context.Context, to, subject, text string) error
	Name() string
}

// MailConfig selects and configures the mail driver.
type MailConfig struct {
	Driver string // console (default), resend, smtp
	From   string // "Conduit <hub@example.com>"

	ResendKey string // Resend API key

	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string
}

// NewMailer returns the configured driver.
func NewMailer(c MailConfig, log *slog.Logger) (Mailer, error) {
	switch c.Driver {
	case "", "console":
		return consoleMailer{log: log}, nil
	case "resend":
		if c.ResendKey == "" || c.From == "" {
			return nil, fmt.Errorf("the resend mail driver needs CONDUIT_HUB_RESEND_KEY and CONDUIT_HUB_MAIL_FROM")
		}
		return &resendMailer{key: c.ResendKey, from: c.From, http: &http.Client{Timeout: 20 * time.Second}}, nil
	case "smtp":
		if c.SMTPHost == "" || c.From == "" {
			return nil, fmt.Errorf("the smtp mail driver needs CONDUIT_HUB_SMTP_HOST and CONDUIT_HUB_MAIL_FROM")
		}
		return &smtpMailer{c: c}, nil
	}
	return nil, fmt.Errorf("unknown mail driver %q (use console, resend or smtp)", c.Driver)
}

// consoleMailer prints mail to the log: for development and for hubs whose
// operator hasn't set up mail yet.
type consoleMailer struct{ log *slog.Logger }

func (m consoleMailer) Name() string { return "console" }
func (m consoleMailer) Send(_ context.Context, to, subject, text string) error {
	m.log.Info("mail (console driver; set CONDUIT_HUB_MAIL=resend or smtp to send for real)", "to", to, "subject", subject, "text", text)
	return nil
}

type resendMailer struct {
	key, from string
	http      *http.Client
}

func (m *resendMailer) Name() string { return "resend" }
func (m *resendMailer) Send(ctx context.Context, to, subject, text string) error {
	body, _ := json.Marshal(map[string]any{"from": m.from, "to": []string{to}, "subject": subject, "text": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.key)
	req.Header.Set("Content-Type", "application/json")
	res, err := m.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("resend answered %s: %s", res.Status, b)
	}
	return nil
}

type smtpMailer struct{ c MailConfig }

func (m *smtpMailer) Name() string { return "smtp" }
func (m *smtpMailer) Send(ctx context.Context, to, subject, text string) error {
	msg := gomail.NewMsg()
	if err := msg.From(m.c.From); err != nil {
		return err
	}
	if err := msg.To(to); err != nil {
		return err
	}
	msg.Subject(subject)
	msg.SetDate()
	msg.SetMessageID()
	msg.SetBodyString(gomail.TypeTextPlain, text)
	port := m.c.SMTPPort
	if port == 0 {
		port = 587
	}
	opts := []gomail.Option{gomail.WithPort(port), gomail.WithTimeout(20 * time.Second)}
	if m.c.SMTPUser != "" {
		opts = append(opts, gomail.WithSMTPAuth(gomail.SMTPAuthAutoDiscover), gomail.WithUsername(m.c.SMTPUser), gomail.WithPassword(m.c.SMTPPass))
	}
	if port == 465 {
		opts = append(opts, gomail.WithSSL())
	} else {
		opts = append(opts, gomail.WithTLSPolicy(gomail.TLSMandatory))
	}
	cl, err := gomail.NewClient(m.c.SMTPHost, opts...)
	if err != nil {
		return err
	}
	return cl.DialAndSendWithContext(ctx, msg)
}

func atoiDefault(s string, d int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return d
}
