// Package pushover sends Pushover notifications to your own devices through
// an application token and your user key, checks the user key and reports
// the application's monthly message allowance.
package pushover

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
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Pushover application and user.
type Config struct {
	AppToken string `json:"appToken"` // secret:// application API token
	UserKey  string `json:"userKey"`  // secret:// your user key
}

type conn struct {
	http           *http.Client
	base           string
	h              sdk.Host
	tokRef, usrRef string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://api.pushover.net (tests).
	Base string
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Pushover module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://api.pushover.net"
	maxMessage  = 1024
	maxTitle    = 250
	maxURL      = 512
	maxURLTitle = 100
	maxTTL      = 30 * 24 * 3600
	maxExpire   = 10800
	minRetry    = 30
)

var (
	deviceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,25}$`)
	soundRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	common := fmt.Sprintf(`"message":{"type":"string","maxLength":%d,"description":"The text, up to %d characters"},"title":{"type":"string","maxLength":%d,"description":"Defaults to the application's name"},"device":{"type":"string","description":"Only this one of your devices (name from validate_user); all of them when left out"},"url":{"type":"string","maxLength":%d,"description":"A supplementary http(s) link"},"urlTitle":{"type":"string","maxLength":%d},"sound":{"type":"string","description":"A sound name such as pushover, siren or none; your default when left out"},"html":{"type":"boolean","default":false,"description":"Allow basic HTML (b, i, u, a, font color)"}`, maxMessage, maxMessage, maxTitle, maxURL, maxURLTitle)
	return sdk.Manifest{
		ID: "pushover", Name: "Pushover", Version: "0.1.0", Category: "Communication", Icon: "notification",
		Description: "Pushover: send notifications to your own devices, check your user key and see the application's monthly allowance.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["appToken","userKey"],"properties":{
			"appToken":{"type":"string","x-secret":true,"description":"An application's API token (pushover.net, Your Applications, Create an Application)"},
			"userKey":{"type":"string","x-secret":true,"description":"Your user key (shown on your pushover.net dashboard); notifications go to your devices"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "validate_user", Title: "Check the user key", Description: "Whether the user key is valid and has an active device: your device names and licensed platforms. Sends nothing.", Risk: sdk.RiskRead},
			{Name: "limits", Title: "Monthly allowance", Description: "The application's monthly message limit, how many are left and when it resets.", Risk: sdk.RiskRead},
			{Name: "send_notification", Title: "Send a notification", Description: "Sends a notification to your own devices (or one of them), at priority -2 (no alert) to 1 (high, past quiet hours). Can't be taken back once delivered.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["message"],"properties":{` + common + `,"priority":{"type":"integer","minimum":-2,"maximum":1,"default":0,"description":"-2 no alert, -1 quiet, 0 normal, 1 high (bypasses quiet hours)"},"ttl":{"type":"integer","minimum":1,"description":"Seconds after which the notification is removed from the devices"}}}`)},
			{Name: "send_emergency", Title: "Send an emergency notification", Description: "Sends an emergency (priority 2) notification to your own devices: it sounds again every retry seconds until someone acknowledges it or expire seconds pass, past quiet hours. Returns its receipt.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["message","retry","expire"],"properties":{` + common + fmt.Sprintf(`,"retry":{"type":"integer","minimum":%d,"maximum":%d,"description":"Seconds between repeats, at least %d"},"expire":{"type":"integer","minimum":%d,"maximum":%d,"description":"Seconds to keep repeating, at most %d (3 hours)"}}}`, minRetry, maxExpire, minRetry, minRetry, maxExpire, maxExpire))},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.AppToken, "secret://") || !strings.HasPrefix(c.UserKey, "secret://") {
		return errors.New("store the application token and the user key in the vault and enter their secret:// references")
	}
	base := defaultBase
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	// The token travels in the query of limits.json; never follow it elsewhere.
	m.set.Put(id, &conn{http: rest.SameHostOnly(client), base: base, h: h, tokRef: c.AppToken, usrRef: c.UserKey})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// answer is Pushover's reply. Its request id and receipt are kept; token and
// user only say which parameter was wrong ("invalid").
type answer struct {
	Status   int      `json:"status"`
	Errors   []string `json:"errors"`
	Token    string   `json:"token"`
	User     string   `json:"user"`
	Receipt  string   `json:"receipt"`
	Devices  []string `json:"devices"`
	Licenses []string `json:"licenses"`
	Limit    *int     `json:"limit"`
	Left     *int     `json:"remaining"`
	Reset    int64    `json:"reset"`
}

func (c *conn) secrets(ctx context.Context, user bool) (tok, usr string, err error) {
	t, err := c.h.Secret(ctx, c.tokRef)
	if err != nil {
		return "", "", err
	}
	if user {
		u, err := c.h.Secret(ctx, c.usrRef)
		if err != nil {
			return "", "", err
		}
		usr = strings.TrimSpace(u)
	}
	return strings.TrimSpace(t), usr, nil
}

// call sends form values (POST) or a query (GET) and reads Pushover's answer.
func (c *conn) call(ctx context.Context, method, path string, form url.Values) (answer, error) {
	u := c.base + path
	var body io.Reader
	if method == http.MethodGet {
		u += "?" + form.Encode()
	} else {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return answer{}, errors.New("couldn't build the request")
	}
	req.Header.Set("User-Agent", "Conduit")
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return answer{}, rest.TransportError(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var a answer
	jsonErr := json.Unmarshal(raw, &a)
	if res.StatusCode == http.StatusTooManyRequests {
		return a, errors.New("the application has used its monthly Pushover messages")
	}
	if res.StatusCode >= 500 || (jsonErr != nil && res.StatusCode >= 300) {
		return a, fmt.Errorf("Pushover answered %s", res.Status)
	}
	if jsonErr != nil {
		return a, errors.New("unexpected answer from Pushover")
	}
	if res.StatusCode >= 300 || a.Status != 1 {
		switch {
		case a.Token == "invalid":
			return a, errors.New("Pushover refused the application token")
		case a.User == "invalid":
			return a, errors.New("Pushover doesn't know the user key, or it has no active device")
		}
		msg := "Pushover refused the request"
		if len(a.Errors) > 0 {
			msg += ": " + clip(rest.Redact(strings.Join(a.Errors, "; ")), 300)
		}
		return a, errors.New(msg)
	}
	return a, nil
}

// clip shortens s to n bytes on a character boundary, after redaction.
func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// masked shows a user key as its first four characters.
func masked(k string) string {
	if len(k) < 8 {
		return "…"
	}
	return k[:4] + "…"
}

func (c *conn) validate(ctx context.Context) (answer, string, error) {
	tok, usr, err := c.secrets(ctx, true)
	if err != nil {
		return answer{}, "", err
	}
	a, err := c.call(ctx, http.MethodPost, "/1/users/validate.json", url.Values{"token": {tok}, "user": {usr}})
	return a, masked(usr), err
}

func (c *conn) limits(ctx context.Context) (map[string]any, error) {
	tok, _, err := c.secrets(ctx, false)
	if err != nil {
		return nil, err
	}
	a, err := c.call(ctx, http.MethodGet, "/1/apps/limits.json", url.Values{"token": {tok}})
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if a.Limit != nil {
		out["limit"] = *a.Limit
	}
	if a.Left != nil {
		out["remaining"] = *a.Left
	}
	if a.Reset > 0 {
		out["reset"] = time.Unix(a.Reset, 0).UTC().Format(time.RFC3339)
	}
	return out, nil
}

// Health implements sdk.Module. It checks the user key and reads the
// allowance; nothing is sent.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	a, _, err := c.validate(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("Pushover · %d devices", len(a.Devices))
	l, err := c.limits(ctx)
	if err != nil {
		return sdk.Health{Status: "degraded", Message: msg + " · " + err.Error()}
	}
	if left, ok := l["remaining"].(int); ok {
		msg += fmt.Sprintf(" · %d messages left this month", left)
		if left == 0 {
			return sdk.Health{Status: "degraded", Message: msg}
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Message  string `json:"message"`
	Title    string `json:"title"`
	Device   string `json:"device"`
	URL      string `json:"url"`
	URLTitle string `json:"urlTitle"`
	Sound    string `json:"sound"`
	HTML     bool   `json:"html"`
	Priority int    `json:"priority"`
	TTL      int    `json:"ttl"`
	Retry    int    `json:"retry"`
	Expire   int    `json:"expire"`
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
	case "validate_user":
		a, key, err := c.validate(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"valid": true, "user": key, "devices": nonNil(a.Devices), "licenses": nonNil(a.Licenses)}
		return sdk.JSON(out)
	case "limits":
		l, err := c.limits(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(l)
	case "send_notification", "send_emergency":
		form, err := build(p, call.Action == "send_emergency")
		if err != nil {
			return sdk.Result{}, err
		}
		return c.send(ctx, call, form)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// build checks the input and returns the form fields without credentials.
func build(p input, emergency bool) (url.Values, error) {
	p.Title = strings.TrimSpace(p.Title)
	if strings.TrimSpace(p.Message) == "" {
		return nil, errors.New("enter the notification's text")
	}
	if utf8.RuneCountInString(p.Message) > maxMessage || utf8.RuneCountInString(p.Title) > maxTitle {
		return nil, fmt.Errorf("the title is at most %d characters and the message at most %d", maxTitle, maxMessage)
	}
	f := url.Values{"message": {p.Message}}
	if p.Title != "" {
		f.Set("title", p.Title)
	}
	if p.Device != "" {
		if !deviceRe.MatchString(p.Device) {
			return nil, errors.New("a device is one device name from validate_user (letters, digits, - and _, up to 25)")
		}
		f.Set("device", p.Device)
	}
	if p.URL != "" {
		u, err := url.Parse(p.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || len(p.URL) > maxURL {
			return nil, fmt.Errorf("the link is an http(s) address of at most %d characters, without a user name or password", maxURL)
		}
		f.Set("url", p.URL)
	}
	if p.URLTitle != "" {
		if p.URL == "" || utf8.RuneCountInString(p.URLTitle) > maxURLTitle {
			return nil, fmt.Errorf("a link title goes with a link and is at most %d characters", maxURLTitle)
		}
		f.Set("url_title", p.URLTitle)
	}
	if p.Sound != "" {
		if !soundRe.MatchString(p.Sound) {
			return nil, errors.New("a sound is a name such as pushover, siren, vibrate or none")
		}
		f.Set("sound", p.Sound)
	}
	if p.HTML {
		f.Set("html", "1")
	}
	if emergency {
		if p.Retry < minRetry || p.Retry > maxExpire || p.Expire < minRetry || p.Expire > maxExpire {
			return nil, fmt.Errorf("retry is at least %d seconds and expire at most %d (3 hours)", minRetry, maxExpire)
		}
		if p.Priority != 0 || p.TTL != 0 {
			return nil, errors.New("an emergency notification has priority 2 and no ttl")
		}
		f.Set("priority", "2")
		f.Set("retry", strconv.Itoa(p.Retry))
		f.Set("expire", strconv.Itoa(p.Expire))
		return f, nil
	}
	if p.Retry != 0 || p.Expire != 0 {
		return nil, errors.New("retry and expire are for send_emergency")
	}
	if p.Priority < -2 || p.Priority > 1 {
		return nil, errors.New("the priority is -2 to 1; priority 2 (emergency) is send_emergency")
	}
	if p.Priority != 0 {
		f.Set("priority", strconv.Itoa(p.Priority))
	}
	if p.TTL < 0 || p.TTL > maxTTL {
		return nil, fmt.Errorf("ttl is between 1 and %d seconds", maxTTL)
	}
	if p.TTL > 0 {
		f.Set("ttl", strconv.Itoa(p.TTL))
	}
	return f, nil
}

func (c *conn) send(ctx context.Context, call sdk.Call, f url.Values) (sdk.Result, error) {
	if call.DryRun {
		shown := map[string]any{}
		for k := range f {
			shown[k] = f.Get(k)
		}
		after, _ := json.Marshal(shown)
		target := "all your devices"
		if d := f.Get("device"); d != "" {
			target = "your device " + d
		}
		summary := fmt.Sprintf("Send a Pushover notification to %s", target)
		if f.Get("priority") == "2" {
			summary = fmt.Sprintf("Send an emergency Pushover notification to %s, repeating every %s s for up to %s s until acknowledged", target, f.Get("retry"), f.Get("expire"))
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "Pushover", Op: "send", After: after}}}}, nil
	}
	tok, usr, err := c.secrets(ctx, true)
	if err != nil {
		return sdk.Result{}, err
	}
	f.Set("token", tok)
	f.Set("user", usr)
	a, err := c.call(ctx, http.MethodPost, "/1/messages.json", f)
	if err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"sent": true}
	if a.Receipt != "" {
		out["receipt"] = a.Receipt
	}
	return sdk.JSON(out)
}
