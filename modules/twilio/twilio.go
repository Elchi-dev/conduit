// Package twilio works with a Twilio account through its account SID and
// auth token: the balance, the account's phone numbers, sent and received
// messages, calls, and sending an SMS.
//
// Sending a text reaches a real person and can't be taken back, so send_sms
// is destructive, shows the recipient and the text first, and can be limited
// to a list of allowed recipients. Messages and calls carry phone numbers
// and message text, so those actions are sensitive; error text is scrubbed
// of phone numbers before it's passed on.
package twilio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Twilio account.
type Config struct {
	AccountSID        string   `json:"accountSid"` // AC…
	AuthToken         string   `json:"authToken"`  // secret:// auth token
	From              string   `json:"from"`       // default sender: a number (+1…) or a messaging service (MG…)
	AllowedRecipients []string `json:"allowedRecipients"`
}

const defaultBase = "https://api.twilio.com"

type conn struct {
	api     *rest.Client
	account string // /2010-04-01/Accounts/AC…
	from    string
	allowed map[string]bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.twilio.com (tests).
	Base string
}

// New returns the Twilio module.
func New() *Module { return &Module{} }

var (
	accountRe = regexp.MustCompile(`^AC[0-9a-f]{32}$`)
	serviceRe = regexp.MustCompile(`^MG[0-9a-f]{32}$`)
	tokenRe   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	e164Re    = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
	pageTokRe = regexp.MustCompile(`^PA[A-Za-z0-9]{10,64}$`)
	dateRe    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	phoneRe   = regexp.MustCompile(`\+?[0-9][0-9 ().-]{6,}[0-9]`)
)

var callStatuses = map[string]bool{"queued": true, "ringing": true, "in-progress": true, "canceled": true, "completed": true, "failed": true, "busy": true, "no-answer": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	page := `"limit":{"type":"integer","default":20,"minimum":1,"maximum":100},"page":{"type":"integer","minimum":0,"description":"page of the previous answer's next"},"pageToken":{"type":"string","description":"pageToken of the previous answer's next"}`
	filter := `"to":{"type":"string","description":"Only to this number (+1…)"},"from":{"type":"string","description":"Only from this number (+1…)"}`
	return sdk.Manifest{
		ID: "twilio", Name: "Twilio", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "A Twilio account: balance, phone numbers, messages and calls; send an SMS with a preview.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["accountSid","authToken"],"properties":{
			"accountSid":{"type":"string","description":"The account SID (AC…) from the Twilio Console"},
			"authToken":{"type":"string","x-secret":true,"description":"The account's auth token"},
			"from":{"type":"string","description":"Default sender: one of your numbers (+1…) or a messaging service SID (MG…)"},
			"allowedRecipients":{"type":"array","items":{"type":"string"},"description":"When set, send_sms only texts these numbers (+1…)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "balance", Title: "Balance", Description: "The account's balance and currency.", Risk: sdk.RiskRead},
			{Name: "numbers", Title: "Phone numbers", Description: "The account's phone numbers: number, name, status and what they can do (voice, SMS, MMS).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":50,"minimum":1,"maximum":100}}}`)},
			{Name: "messages", Title: "Messages", Description: "Sent and received messages, newest first: from, to, text, status, segments, price and any error code.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + filter + `,"since":{"type":"string","description":"Only messages sent on or after this date (YYYY-MM-DD)"},` + page + `}}`)},
			{Name: "calls", Title: "Calls", Description: "Calls, newest first: from, to, direction, status, start time, duration and price.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + filter + `,"status":{"type":"string","enum":["","queued","ringing","in-progress","canceled","completed","failed","busy","no-answer"]},` + page + `}}`)},
			{Name: "send_sms", Title: "Send an SMS", Description: "Texts one number. It reaches a real person, costs money and can't be taken back; the preview shows the recipient and the text.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["to","body"],"properties":{"to":{"type":"string","description":"The recipient (+1…)"},"body":{"type":"string","maxLength":1600},"from":{"type":"string","description":"A number (+1…) or messaging service (MG…); the default from settings when empty"}}}`)},
		},
	}
}

func validSender(s string) bool { return e164Re.MatchString(s) || serviceRe.MatchString(s) }

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	sid := strings.TrimSpace(c.AccountSID)
	if !accountRe.MatchString(sid) {
		return errors.New("the account SID is AC followed by 32 letters and digits, from the Twilio Console")
	}
	if !strings.HasPrefix(c.AuthToken, "secret://") {
		return errors.New("store the auth token in the vault and enter its secret:// reference")
	}
	from := strings.TrimSpace(c.From)
	if from != "" && !validSender(from) {
		return errors.New("the sender is a number like +15551234567 or a messaging service SID (MG…)")
	}
	allowed := map[string]bool{}
	for _, r := range c.AllowedRecipients {
		r = strings.TrimSpace(r)
		if !e164Re.MatchString(r) {
			return errors.New("allowed recipients are numbers like +15551234567")
		}
		allowed[r] = true
	}
	base := defaultBase
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 30*time.Second)
	}
	ref := c.AuthToken
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if !tokenRe.MatchString(t) {
			return errors.New("the stored auth token doesn't look like a Twilio auth token")
		}
		r.SetBasicAuth(sid, t)
		return nil
	})
	api.HTTP = rest.SameHostOnly(hc)
	m.set.Put(id, &conn{api: api, account: "/2010-04-01/Accounts/" + sid, from: from, allowed: allowed})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func scrub(s string) string {
	s = phoneRe.ReplaceAllString(rest.Redact(s), "[number]")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func friendly(err error) error {
	var e *rest.Error
	switch {
	case err == nil:
		return nil
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Twilio refused the account SID and auth token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Twilio doesn't allow this for the account")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Twilio is limiting requests; try again in a moment")
	case errors.As(err, &e):
		return &rest.Error{Status: e.Status, Message: "Twilio: " + scrub(e.Message)}
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, c.account+path, q, nil, out)
	return friendly(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var a struct {
		Status string `json:"status"`
		Type   string `json:"type"`
	}
	if err := c.get(ctx, ".json", nil, &a); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("connected: %s account, %s", strings.ToLower(a.Type), a.Status)
	if a.Status != "active" {
		return sdk.Health{Status: "degraded", Message: msg}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	To        string `json:"to"`
	From      string `json:"from"`
	Since     string `json:"since"`
	Status    string `json:"status"`
	Limit     int    `json:"limit"`
	Page      int    `json:"page"`
	PageToken string `json:"pageToken"`
	Body      string `json:"body"`
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
	case "balance":
		var b struct {
			Balance  string `json:"balance"`
			Currency string `json:"currency"`
		}
		if err := c.get(ctx, "/Balance.json", nil, &b); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"balance": b.Balance, "currency": b.Currency, "display": b.Balance + " " + b.Currency})
	case "numbers":
		return c.numbers(ctx, p)
	case "messages", "calls":
		return c.history(ctx, call.Action, p)
	case "send_sms":
		return c.send(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func size(n, def int) string {
	if n <= 0 || n > 100 {
		n = def
	}
	return strconv.Itoa(n)
}

func (c *conn) numbers(ctx context.Context, p input) (sdk.Result, error) {
	var l struct {
		Numbers []struct {
			SID          string `json:"sid"`
			PhoneNumber  string `json:"phone_number"`
			FriendlyName string `json:"friendly_name"`
			Status       string `json:"status"`
			DateCreated  string `json:"date_created"`
			Capabilities struct {
				Voice bool `json:"voice"`
				SMS   bool `json:"sms"`
				MMS   bool `json:"mms"`
			} `json:"capabilities"`
			// Webhook URLs aren't decoded: they can carry credentials.
		} `json:"incoming_phone_numbers"`
	}
	if err := c.get(ctx, "/IncomingPhoneNumbers.json", url.Values{"PageSize": {size(p.Limit, 50)}}, &l); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, n := range l.Numbers {
		out = append(out, map[string]any{"sid": n.SID, "number": n.PhoneNumber, "name": n.FriendlyName, "status": n.Status, "created": n.DateCreated,
			"voice": n.Capabilities.Voice, "sms": n.Capabilities.SMS, "mms": n.Capabilities.MMS})
	}
	return sdk.JSON(map[string]any{"items": out})
}

type record struct {
	SID         string  `json:"sid"`
	From        string  `json:"from"`
	To          string  `json:"to"`
	Body        string  `json:"body"`
	Status      string  `json:"status"`
	Direction   string  `json:"direction"`
	NumSegments string  `json:"num_segments"`
	Price       *string `json:"price"`
	PriceUnit   string  `json:"price_unit"`
	DateSent    string  `json:"date_sent"`
	DateCreated string  `json:"date_created"`
	ErrorCode   *int    `json:"error_code"`
	StartTime   string  `json:"start_time"`
	Duration    string  `json:"duration"`
}

func (c *conn) history(ctx context.Context, kind string, p input) (sdk.Result, error) {
	q := url.Values{"PageSize": {size(p.Limit, 20)}}
	if t := strings.TrimSpace(p.To); t != "" {
		if !e164Re.MatchString(t) {
			return sdk.Result{}, errors.New("to is a number like +15551234567")
		}
		q.Set("To", t)
	}
	if f := strings.TrimSpace(p.From); f != "" {
		if !e164Re.MatchString(f) {
			return sdk.Result{}, errors.New("from is a number like +15551234567")
		}
		q.Set("From", f)
	}
	if p.Since != "" {
		if _, err := time.Parse("2006-01-02", p.Since); err != nil || !dateRe.MatchString(p.Since) {
			return sdk.Result{}, errors.New("since is a date like 2026-11-01")
		}
		if kind == "messages" {
			q.Set("DateSent>", p.Since)
		} else {
			q.Set("StartTime>", p.Since)
		}
	}
	if p.Status != "" {
		if kind != "calls" || !callStatuses[p.Status] {
			return sdk.Result{}, fmt.Errorf("status %q isn't a call status", p.Status)
		}
		q.Set("Status", p.Status)
	}
	if p.Page < 0 {
		return sdk.Result{}, errors.New("page is the number from the previous answer's next")
	}
	if p.PageToken != "" || p.Page > 0 {
		if !pageTokRe.MatchString(p.PageToken) || p.Page == 0 {
			return sdk.Result{}, errors.New("page and pageToken are the values from the previous answer's next")
		}
		q.Set("Page", strconv.Itoa(p.Page))
		q.Set("PageToken", p.PageToken)
	}
	path, key := "/Messages.json", "messages"
	if kind == "calls" {
		path, key = "/Calls.json", "calls"
	}
	var l map[string]json.RawMessage
	if err := c.get(ctx, path, q, &l); err != nil {
		return sdk.Result{}, err
	}
	var rs []record
	if err := json.Unmarshal(l[key], &rs); err != nil && len(l[key]) > 0 {
		return sdk.Result{}, errors.New("unexpected answer from Twilio")
	}
	out := []map[string]any{}
	for _, r := range rs {
		row := map[string]any{"sid": r.SID, "from": r.From, "to": r.To, "status": r.Status, "direction": r.Direction}
		if r.Price != nil && *r.Price != "" {
			row["price"] = *r.Price + " " + r.PriceUnit
		}
		if kind == "messages" {
			row["body"], row["segments"], row["sent"] = r.Body, r.NumSegments, r.DateSent
			if r.DateSent == "" {
				row["sent"] = r.DateCreated
			}
			if r.ErrorCode != nil && *r.ErrorCode != 0 {
				row["errorCode"] = *r.ErrorCode
			}
		} else {
			row["started"], row["durationSeconds"] = r.StartTime, r.Duration
		}
		out = append(out, row)
	}
	res := map[string]any{"items": out}
	var next string
	_ = json.Unmarshal(l["next_page_uri"], &next)
	if next != "" {
		if u, err := url.Parse(next); err == nil {
			pg, _ := strconv.Atoi(u.Query().Get("Page"))
			if tok := u.Query().Get("PageToken"); pageTokRe.MatchString(tok) && pg > 0 {
				res["next"] = map[string]any{"page": pg, "pageToken": tok}
			}
		}
	}
	return sdk.JSON(res)
}

// gsmBasic and gsmExtended are the GSM-7 alphabet: a text made only of
// these is sent in 7-bit parts, where an extended character takes two
// places. Anything else (a backtick, most accents, emoji) makes the whole
// text UCS-2, with far fewer characters per part.
const (
	gsmBasic    = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
	gsmExtended = "^{}\\[~]|€\f"
)

// segments estimates how many SMS parts a text takes (each is billed).
func segments(s string) int {
	gsm, n := true, 0
	for _, r := range s {
		switch {
		case strings.ContainsRune(gsmBasic, r):
			n++
		case strings.ContainsRune(gsmExtended, r):
			n += 2
		default:
			gsm = false
		}
		if !gsm {
			break
		}
	}
	one, many := 160, 153
	if !gsm {
		// UCS-2 counts UTF-16 units: an emoji takes two.
		n = len(utf16.Encode([]rune(s)))
		one, many = 70, 67
	}
	if n <= one {
		return 1
	}
	return (n + many - 1) / many
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (c *conn) send(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	to := strings.TrimSpace(p.To)
	if !e164Re.MatchString(to) {
		return sdk.Result{}, errors.New("to is a number like +15551234567")
	}
	if len(c.allowed) > 0 && !c.allowed[to] {
		return sdk.Result{}, errors.New("this number isn't in the instance's allowed recipients")
	}
	from := strings.TrimSpace(p.From)
	if from == "" {
		from = c.from
	}
	if from == "" {
		return sdk.Result{}, errors.New("give from (a number or messaging service), or set a default sender in the settings")
	}
	if !validSender(from) {
		return sdk.Result{}, errors.New("from is a number like +15551234567 or a messaging service SID (MG…)")
	}
	body := strings.TrimSpace(p.Body)
	if body == "" || utf8.RuneCountInString(body) > 1600 || !utf8.ValidString(body) || strings.ContainsRune(body, 0) {
		return sdk.Result{}, errors.New("the text is 1 to 1,600 characters")
	}
	parts := segments(body)
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Text %s from %s (%d characters, about %d SMS parts)", to, from, utf8.RuneCountInString(body), parts),
			Changes: []sdk.Change{{Target: to, Op: "send", After: mustJSON(map[string]any{"from": from, "body": body})}}}}, nil
	}
	form := url.Values{"To": {to}, "Body": {body}}
	if serviceRe.MatchString(from) {
		form.Set("MessagingServiceSid", from)
	} else {
		form.Set("From", from)
	}
	res, err := c.api.Send(ctx, http.MethodPost, c.account+"/Messages.json", nil, strings.NewReader(form.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}})
	if err != nil {
		return sdk.Result{}, friendly(err)
	}
	defer res.Body.Close()
	var r record
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 || json.Unmarshal(raw, &r) != nil || r.SID == "" {
		return sdk.Result{}, fmt.Errorf("unexpected answer from Twilio (HTTP %d)", res.StatusCode)
	}
	return sdk.JSON(map[string]any{"sid": r.SID, "to": r.To, "from": r.From, "status": r.Status, "segments": r.NumSegments})
}
