// Package resend reads a Resend account through its API: sending domains
// with their verification status and DNS records, recently sent emails
// with their delivery status, and audiences with contact counts. It can send
// a test email, but only to an address listed in the instance's settings.
//
// Recipient addresses and message content are personal data, so the emails
// listing and the test send are sensitive (kept out of the audit log); the
// other actions return no addresses at all, only counts.
package resend

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Resend account.
type Config struct {
	Key string `json:"key"` // secret:// API key (re_…)
	// From is the sender of test emails, at a verified domain
	// ("Conduit <test@example.com>").
	From string `json:"from"`
	// TestRecipients are the only addresses send_test_email may reach.
	TestRecipients []string `json:"testRecipients"`
}

const defaultBase = "https://api.resend.com"

// maxContactPages bounds how many pages of 100 contacts one audience count
// reads, so a huge audience can't turn one call into thousands of requests.
const maxContactPages = 20

type conn struct {
	h     sdk.Host
	key   string
	base  string
	http  *http.Client
	from  string
	allow []string // lower-case addresses
	sleep func(context.Context, time.Duration) error
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.resend.com (tests).
	Base string
	// Sleep replaces the pause before retrying a rate-limited request (tests).
	Sleep func(context.Context, time.Duration) error
}

// New returns the Resend module.
func New() *Module { return &Module{} }

var (
	keyRe   = regexp.MustCompile(`^re_[A-Za-z0-9_]{8,200}$`)
	uuidRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	emailRe = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+=?^_{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "resend", Name: "Resend", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "A Resend account: sending domains and their verification, recent emails and their status, audience counts; test emails to allow-listed addresses only.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"key":{"type":"string","x-secret":true,"description":"A Resend API key (re_…) with full access; a sending-only key can't read domains or emails"},
			"from":{"type":"string","description":"Sender of test emails, at one of your verified domains, e.g. Conduit <test@example.com>"},
			"testRecipients":{"type":"array","maxItems":10,"items":{"type":"string"},"description":"The only addresses send_test_email may send to (yours, a team inbox); anything else is refused"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "domains", Title: "Domains", Description: "Sending domains with their verification status and region.", Risk: sdk.RiskRead},
			{Name: "domain", Title: "Domain", Description: "One domain's status and the DNS records (SPF, DKIM, MX) Resend checks, each with its own status.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Domain id (see domains)"}}}`)},
			{Name: "emails", Title: "Sent emails", Description: "Recently sent emails, newest first: recipients, sender, subject and the last delivery event (delivered, bounced, complained…).", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":20,"minimum":1,"maximum":100},"after":{"type":"string","description":"Id of the last email of the previous page"}}}`)},
			{Name: "audiences", Title: "Audiences", Description: "Audiences with how many contacts each has, and how many unsubscribed. Counts only, no addresses.", Risk: sdk.RiskRead},
			{Name: "send_test_email", Title: "Send a test email", Description: "Sends a short test email from the configured sender to one of the test recipients in this instance's settings; any other address is refused.", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"to":{"type":"string","description":"One of the test recipients (default: the only one, when there's one)"},"subject":{"type":"string","maxLength":200,"default":"Conduit test email"},"text":{"type":"string","maxLength":5000}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Key, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	from := strings.TrimSpace(c.From)
	if from != "" {
		a, err := mail.ParseAddress(from)
		if err != nil || strings.ContainsAny(from, "\r\n") || !emailRe.MatchString(a.Address) || len(from) > 200 {
			return errors.New("from is a sender address like Conduit <test@example.com>")
		}
	}
	if len(c.TestRecipients) > 10 {
		return errors.New("list at most 10 test recipients")
	}
	allow := []string{}
	for _, r := range c.TestRecipients {
		r = strings.ToLower(strings.TrimSpace(r))
		if len(r) > 254 || !emailRe.MatchString(r) {
			return fmt.Errorf("test recipient %q isn't a plain email address", r)
		}
		allow = append(allow, r)
	}
	base := defaultBase
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 30*time.Second)
	}
	m.set.Put(id, &conn{h: h, key: c.Key, base: base, http: rest.SameHostOnly(hc), from: from, allow: allow, sleep: m.Sleep})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) secret(ctx context.Context) (string, error) {
	k, err := c.h.Secret(ctx, c.key)
	if err != nil {
		return "", err
	}
	k = strings.TrimSpace(k)
	if !keyRe.MatchString(k) {
		return "", errors.New("the stored key doesn't look like a Resend API key (re_…)")
	}
	return k, nil
}

// apiError is Resend's error, with the error's name (restricted_api_key,
// validation_error, rate_limit_exceeded…).
type apiError struct {
	err  *rest.Error
	Name string
}

func (e *apiError) Error() string { return e.err.Message }
func (e *apiError) Unwrap() error { return e.err }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do sends one request with a JSON body, retrying a rate-limited GET once.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	key, err := c.secret(ctx)
	if err != nil {
		return err
	}
	var payload []byte
	if body != nil {
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	idem := ""
	if method == http.MethodPost {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		idem = "conduit-" + hex.EncodeToString(b)
	}
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, rd)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Conduit")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if idem != "" {
			req.Header.Set("Idempotency-Key", idem)
		}
		res, err := c.http.Do(req)
		if err != nil {
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
		res.Body.Close()
		if err != nil {
			return err
		}
		if res.StatusCode == http.StatusTooManyRequests && method == http.MethodGet && attempt == 0 {
			wait := time.Second
			if s, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && s >= 0 && s <= 2 {
				wait = time.Duration(s) * time.Second
			}
			sleep := c.sleep
			if sleep == nil {
				sleep = sleepCtx
			}
			if err := sleep(ctx, wait); err != nil {
				return err
			}
			continue
		}
		if res.StatusCode >= 300 {
			var e struct {
				Name    string `json:"name"`
				Message string `json:"message"`
			}
			msg := res.Status
			if json.Unmarshal(raw, &e) == nil && e.Message != "" {
				msg = rest.Redact(e.Message)
			}
			return &apiError{err: &rest.Error{Status: res.StatusCode, Message: "Resend: " + msg}, Name: e.Name}
		}
		if out != nil {
			if err := json.Unmarshal(raw, out); err != nil {
				return errors.New("unexpected answer from Resend")
			}
		}
		return nil
	}
}

func errName(err error) string {
	var e *apiError
	if errors.As(err, &e) {
		return e.Name
	}
	return ""
}

type domain struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Region    string `json:"region"`
	CreatedAt string `json:"created_at"`
	Records   []struct {
		Record   string `json:"record"`
		Name     string `json:"name"`
		Type     string `json:"type"`
		TTL      string `json:"ttl"`
		Status   string `json:"status"`
		Value    string `json:"value"`
		Priority *int   `json:"priority"`
	} `json:"records"`
}

type list[T any] struct {
	Data    []T  `json:"data"`
	HasMore bool `json:"has_more"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var l list[domain]
	if err := c.do(ctx, http.MethodGet, "/domains", nil, nil, &l); err != nil {
		if errName(err) == "restricted_api_key" {
			return sdk.Health{Status: "degraded", Message: "the key can only send email; give it full access so domains and emails can be read"}
		}
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "Resend refused the key"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	verified := 0
	for _, d := range l.Data {
		if d.Status == "verified" {
			verified++
		}
	}
	msg := fmt.Sprintf("connected: %d of %d domains verified", verified, len(l.Data))
	if len(l.Data) > 0 && verified == 0 {
		return sdk.Health{Status: "degraded", Message: msg + "; nothing can be sent until one is"}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	ID      string `json:"id"`
	Limit   int    `json:"limit"`
	After   string `json:"after"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
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
	switch call.Action {
	case "domains":
		var l list[domain]
		if err := c.do(ctx, http.MethodGet, "/domains", nil, nil, &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range l.Data {
			out = append(out, map[string]any{"id": d.ID, "name": d.Name, "status": d.Status, "verified": d.Status == "verified", "region": d.Region, "created": d.CreatedAt})
		}
		return sdk.JSON(map[string]any{"items": out})

	case "domain":
		id := strings.TrimSpace(p.ID)
		if !uuidRe.MatchString(id) {
			return sdk.Result{}, errors.New("the domain is its id (see domains)")
		}
		var d domain
		if err := c.do(ctx, http.MethodGet, "/domains/"+id, nil, nil, &d); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no domain %s", id)
			}
			return sdk.Result{}, err
		}
		recs := []map[string]any{}
		pending := 0
		for _, r := range d.Records {
			o := map[string]any{"record": r.Record, "type": r.Type, "name": r.Name, "value": r.Value, "status": r.Status}
			if r.TTL != "" {
				o["ttl"] = r.TTL
			}
			if r.Priority != nil {
				o["priority"] = *r.Priority
			}
			if r.Status != "verified" {
				pending++
			}
			recs = append(recs, o)
		}
		return sdk.JSON(map[string]any{"id": d.ID, "name": d.Name, "status": d.Status, "verified": d.Status == "verified", "region": d.Region, "created": d.CreatedAt, "records": recs, "recordsNotVerified": pending})

	case "emails":
		q := url.Values{}
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 20
		}
		q.Set("limit", strconv.Itoa(limit))
		if p.After != "" {
			if !uuidRe.MatchString(p.After) {
				return sdk.Result{}, errors.New("after is the id of the last email of the previous page")
			}
			q.Set("after", p.After)
		}
		var l list[struct {
			ID          string   `json:"id"`
			To          []string `json:"to"`
			Cc          []string `json:"cc"`
			Bcc         []string `json:"bcc"`
			From        string   `json:"from"`
			Subject     string   `json:"subject"`
			CreatedAt   string   `json:"created_at"`
			LastEvent   string   `json:"last_event"`
			ScheduledAt string   `json:"scheduled_at"`
		}]
		if err := c.do(ctx, http.MethodGet, "/emails", q, nil, &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range l.Data {
			o := map[string]any{"id": e.ID, "to": e.To, "from": e.From, "subject": e.Subject, "created": e.CreatedAt, "status": e.LastEvent}
			if len(e.Cc) > 0 {
				o["cc"] = e.Cc
			}
			if len(e.Bcc) > 0 {
				o["bcc"] = len(e.Bcc) // how many, not who
			}
			if e.ScheduledAt != "" {
				o["scheduledAt"] = e.ScheduledAt
			}
			out = append(out, o)
		}
		res := map[string]any{"items": out, "hasMore": l.HasMore}
		if l.HasMore && len(out) > 0 {
			res["next"] = out[len(out)-1]["id"]
		}
		return sdk.JSON(res)

	case "audiences":
		return c.audiences(ctx)

	case "send_test_email":
		return c.sendTest(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) audiences(ctx context.Context) (sdk.Result, error) {
	var l list[struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}]
	if err := c.do(ctx, http.MethodGet, "/audiences", nil, nil, &l); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for i, a := range l.Data {
		o := map[string]any{"id": a.ID, "name": a.Name, "created": a.CreatedAt}
		if i >= 20 {
			o["note"] = "not counted: only the first 20 audiences are"
			out = append(out, o)
			continue
		}
		if !uuidRe.MatchString(a.ID) {
			o["note"] = "not counted: unexpected id"
			out = append(out, o)
			continue
		}
		total, unsub, capped := 0, 0, false
		after := ""
		for pg := 0; ; pg++ {
			if pg == maxContactPages {
				capped = true
				break
			}
			q := url.Values{"limit": {"100"}}
			if after != "" {
				q.Set("after", after)
			}
			var cl list[struct {
				ID           string `json:"id"`
				Unsubscribed bool   `json:"unsubscribed"`
			}]
			if err := c.do(ctx, http.MethodGet, "/audiences/"+a.ID+"/contacts", q, nil, &cl); err != nil {
				return sdk.Result{}, err
			}
			for _, ct := range cl.Data {
				total++
				if ct.Unsubscribed {
					unsub++
				}
			}
			if !cl.HasMore || len(cl.Data) == 0 {
				break
			}
			next := cl.Data[len(cl.Data)-1].ID
			if !uuidRe.MatchString(next) || next == after {
				break
			}
			after = next
		}
		o["contacts"], o["unsubscribed"], o["subscribed"] = total, unsub, total-unsub
		if capped {
			o["atLeast"] = true
		}
		out = append(out, o)
	}
	return sdk.JSON(map[string]any{"items": out})
}

func (c *conn) sendTest(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if c.from == "" {
		return sdk.Result{}, errors.New("set a sender (from) in this instance's settings first")
	}
	if len(c.allow) == 0 {
		return sdk.Result{}, errors.New("add test recipients to this instance's settings first; test emails go only to them")
	}
	to := strings.ToLower(strings.TrimSpace(p.To))
	if to == "" {
		if len(c.allow) > 1 {
			return sdk.Result{}, errors.New("say which test recipient to send to")
		}
		to = c.allow[0]
	}
	allowed := false
	for _, a := range c.allow {
		allowed = allowed || a == to
	}
	if !allowed {
		return sdk.Result{}, errors.New("that address isn't one of the test recipients in this instance's settings; test emails go only to them")
	}
	subject := strings.TrimSpace(p.Subject)
	if subject == "" {
		subject = "Conduit test email"
	}
	if strings.ContainsAny(subject, "\r\n") || len([]rune(subject)) > 200 {
		return sdk.Result{}, errors.New("the subject is one line of at most 200 characters")
	}
	text := p.Text
	if strings.TrimSpace(text) == "" {
		text = "This is a test email sent from Conduit through Resend."
	}
	if len([]rune(text)) > 5000 {
		return sdk.Result{}, errors.New("the text is at most 5000 characters")
	}
	if call.DryRun {
		after, _ := json.Marshal(map[string]any{"from": c.from, "to": to, "subject": subject, "text": text})
		return sdk.Result{Plan: &sdk.Plan{Summary: "Send a test email from " + c.from + " to " + to, Changes: []sdk.Change{{Target: "email to " + to, Op: "send", After: after}}}}, nil
	}
	var r struct {
		ID string `json:"id"`
	}
	body := map[string]any{"from": c.from, "to": []string{to}, "subject": subject, "text": text}
	if err := c.do(ctx, http.MethodPost, "/emails", nil, body, &r); err != nil {
		if rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusUnprocessableEntity) {
			return sdk.Result{}, fmt.Errorf("%w (is the sender's domain verified?)", err)
		}
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"id": r.ID, "to": to, "from": c.from, "subject": subject})
}
