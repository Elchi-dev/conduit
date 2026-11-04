// Package signal works with a self-hosted signal-cli-rest-api
// (github.com/bbernhard/signal-cli-rest-api) for one registered or linked
// number: the accounts on the server, receiving messages, sending to the
// recipients the instance allows and listing groups.
//
// Receiving takes messages off the Signal server's queue for this device:
// signal-cli-rest-api hands each message out once. The module keeps the
// messages it received in a small in-memory buffer so that reading twice
// still shows them, but anything else polling the same number won't see
// them. Receiving over REST needs the API's normal or native mode; in
// json-rpc mode messages are only delivered over its websocket.
package signal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one number on one signal-cli-rest-api server.
type Config struct {
	Address            string   `json:"address"`  // http://signal:8080
	Number             string   `json:"number"`   // +4912345678
	Username           string   `json:"username"` // basic auth in front of the API (optional)
	Password           string   `json:"password"` // secret://, with username
	Token              string   `json:"token"`    // secret:// bearer token for a proxy (optional)
	AllowedRecipients  []string `json:"allowedRecipients"`
	Fingerprint        string   `json:"fingerprint"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

type conn struct {
	api     *rest.Client
	number  string
	allowed map[string]bool

	fetch sync.Mutex // one receive at a time
	mu    sync.Mutex
	buf   []map[string]any
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Signal module.
func New() *Module { return &Module{} }

const maxBuffer = 200

var (
	numberRe = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
	groupRe  = regexp.MustCompile(`^group\.[A-Za-z0-9+/=_-]{10,200}$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	userRe   = regexp.MustCompile(`^[^\s:\x00-\x1f\x7f]{1,100}$`)
	prefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
)

func validRecipient(s string) bool {
	return numberRe.MatchString(s) || groupRe.MatchString(s) || uuidRe.MatchString(s)
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "signal", Name: "Signal", Version: "0.1.0", Category: "Communication", Icon: "message",
		Description: "Signal through a self-hosted signal-cli-rest-api: accounts, receive messages, send to allowed recipients, groups.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["address","number"],"properties":{
			"address":{"type":"string","description":"The API's address, e.g. http://signal-cli:8080"},
			"number":{"type":"string","description":"The registered or linked number, in international format like +4915112345678"},
			"allowedRecipients":{"type":"array","items":{"type":"string"},"description":"Who Conduit may send to: numbers (+49...), account UUIDs or group ids (group.xxx, see groups)"},
			"username":{"type":"string","description":"User name, when a reverse proxy with basic auth guards the API"},
			"password":{"type":"string","x-secret":true,"description":"Password for that user"},
			"token":{"type":"string","x-secret":true,"description":"Bearer token, when a proxy expects one instead"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "accounts", Title: "Accounts", Description: "Numbers registered or linked on the API server.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "receive", Title: "Receive messages", Description: "Fetches new messages for the number and shows recent ones, oldest first. This takes them off the server's queue: anything else polling this number won't get them.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":20,"minimum":1,"maximum":200}}}`)},
			{Name: "send", Title: "Send a message", Description: "Sends a text message to recipients from allowedRecipients. Can't be undone from here.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["recipients","text"],"properties":{"recipients":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":20,"description":"Numbers, UUIDs or group ids from allowedRecipients"},"text":{"type":"string","maxLength":4000}}}`)},
			{Name: "groups", Title: "Groups", Description: "Groups the number is in, with ids (for allowedRecipients) and member counts.", Risk: sdk.RiskRead, Sensitive: true},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.Address))
	prefix := ""
	if err == nil {
		prefix = strings.TrimRight(u.Path, "/")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return errors.New("the address is the API's URL, like http://signal-cli:8080")
	}
	number := strings.ReplaceAll(strings.TrimSpace(c.Number), " ", "")
	if !numberRe.MatchString(number) {
		return errors.New("the number is in international format, like +4915112345678")
	}
	allowed := map[string]bool{}
	for _, r := range c.AllowedRecipients {
		r = strings.ReplaceAll(strings.TrimSpace(r), " ", "")
		if !validRecipient(r) {
			return fmt.Errorf("%q isn't a number (+49...), account UUID or group id (group.xxx)", r)
		}
		allowed[r] = true
	}
	user, pwRef, tokRef := strings.TrimSpace(c.Username), c.Password, c.Token
	switch {
	case pwRef != "" && !strings.HasPrefix(pwRef, "secret://"), tokRef != "" && !strings.HasPrefix(tokRef, "secret://"):
		return errors.New("store the password or token in the vault and enter its secret:// reference")
	case (user == "") != (pwRef == ""):
		return errors.New("basic auth needs both a username and a password")
	case user != "" && !userRe.MatchString(user):
		return errors.New("the username can't contain spaces or colons")
	case pwRef != "" && tokRef != "":
		return errors.New("use either basic auth or a token, not both")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 60*time.Second) // receive waits for the Signal server
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	api := rest.New(u.Scheme+"://"+u.Host+prefix, func(ctx context.Context, r *http.Request) error {
		switch {
		case pwRef != "":
			pw, err := h.Secret(ctx, pwRef)
			if err != nil {
				return err
			}
			r.SetBasicAuth(user, pw)
		case tokRef != "":
			t, err := h.Secret(ctx, tokRef)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		}
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, number: number, allowed: allowed})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	var e *rest.Error
	if errors.As(err, &e) {
		switch {
		case e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden:
			return errors.New("the API (or the proxy in front of it) refused the credentials")
		case strings.Contains(strings.ToLower(e.Message), "json-rpc"):
			return errors.New("the API runs in json-rpc mode, where messages arrive only over its websocket; switch it to normal or native mode (MODE=native) to receive here")
		}
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var about struct {
		Mode    string `json:"mode"`
		Version string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/about", nil, nil, &about); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var accounts []string
	if err := c.do(ctx, http.MethodGet, "/v1/accounts", nil, nil, &accounts); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	found := false
	for _, a := range accounts {
		found = found || a == c.number
	}
	switch {
	case !found:
		return sdk.Health{Status: "down", Message: "the number isn't registered or linked on this API server"}
	case about.Mode == "json-rpc":
		return sdk.Health{Status: "degraded", Message: "json-rpc mode: sending works, receiving needs normal or native mode"}
	case len(c.allowed) == 0:
		return sdk.Health{Status: "degraded", Message: "no allowed recipients yet; sending is off"}
	}
	return sdk.Health{Status: "ok", Message: clip("signal-cli-rest-api "+about.Version+" ("+about.Mode+" mode)", 100)}
}

type envelope struct {
	Envelope struct {
		Source       string `json:"source"`
		SourceNumber string `json:"sourceNumber"`
		SourceUUID   string `json:"sourceUuid"`
		SourceName   string `json:"sourceName"`
		Timestamp    int64  `json:"timestamp"`
		DataMessage  *struct {
			Message     *string `json:"message"`
			GroupInfo   *group  `json:"groupInfo"`
			Attachments []any   `json:"attachments"`
		} `json:"dataMessage"`
		SyncMessage *struct {
			SentMessage *struct {
				Destination       string  `json:"destination"`
				DestinationNumber string  `json:"destinationNumber"`
				Message           *string `json:"message"`
				GroupInfo         *group  `json:"groupInfo"`
			} `json:"sentMessage"`
		} `json:"syncMessage"`
	} `json:"envelope"`
}

type group struct {
	GroupID string `json:"groupId"`
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// brief turns an envelope into a message, or nil for receipts, typing
// notices and other envelopes without text.
func (e envelope) brief() map[string]any {
	v := e.Envelope
	from := v.SourceNumber
	if from == "" {
		from = v.Source
	}
	if from == "" {
		from = v.SourceUUID
	}
	out := map[string]any{"from": clip(from, 100), "when": time.UnixMilli(v.Timestamp).UTC().Format(time.RFC3339), "timestamp": v.Timestamp}
	if v.SourceName != "" {
		out["name"] = clip(v.SourceName, 100)
	}
	switch {
	case v.DataMessage != nil && (v.DataMessage.Message != nil || len(v.DataMessage.Attachments) > 0):
		out["text"] = clip(str(v.DataMessage.Message), 4000)
		if n := len(v.DataMessage.Attachments); n > 0 {
			out["attachments"] = n
		}
		if g := v.DataMessage.GroupInfo; g != nil && g.GroupID != "" {
			out["group"] = clip(g.GroupID, 200)
		}
	case v.SyncMessage != nil && v.SyncMessage.SentMessage != nil && v.SyncMessage.SentMessage.Message != nil:
		s := v.SyncMessage.SentMessage
		out["text"] = clip(str(s.Message), 4000)
		out["fromMe"] = true
		to := s.DestinationNumber
		if to == "" {
			to = s.Destination
		}
		if s.GroupInfo != nil && s.GroupInfo.GroupID != "" {
			out["group"] = clip(s.GroupInfo.GroupID, 200)
		} else if to != "" {
			out["to"] = clip(to, 100)
		}
	default:
		return nil
	}
	return out
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Limit      int      `json:"limit"`
		Recipients []string `json:"recipients"`
		Text       string   `json:"text"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "accounts":
		var accounts []string
		if err := c.do(ctx, http.MethodGet, "/v1/accounts", nil, nil, &accounts); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, a := range accounts {
			out = append(out, map[string]any{"number": clip(a, 32), "this": a == c.number})
		}
		return sdk.JSON(out)

	case "receive":
		n := p.Limit
		if n <= 0 {
			n = 20
		}
		if n > maxBuffer {
			n = maxBuffer
		}
		c.fetch.Lock()
		var envs []envelope
		q := url.Values{"timeout": {"1"}, "ignore_attachments": {"true"}, "ignore_stories": {"true"}, "send_read_receipts": {"false"}, "max_messages": {"100"}}
		err := c.do(ctx, http.MethodGet, "/v1/receive/"+url.PathEscape(c.number), q, nil, &envs)
		c.fetch.Unlock()
		if err != nil {
			return sdk.Result{}, err
		}
		fresh := 0
		c.mu.Lock()
		for _, e := range envs {
			if b := e.brief(); b != nil {
				c.buf = append(c.buf, b)
				fresh++
			}
		}
		if len(c.buf) > maxBuffer {
			c.buf = append([]map[string]any(nil), c.buf[len(c.buf)-maxBuffer:]...)
		}
		msgs := c.buf
		if len(msgs) > n {
			msgs = msgs[len(msgs)-n:]
		}
		msgs = append([]map[string]any{}, msgs...)
		c.mu.Unlock()
		return sdk.JSON(map[string]any{"new": fresh, "messages": msgs})

	case "send":
		text := strings.TrimSpace(p.Text)
		if text == "" {
			return sdk.Result{}, errors.New("write something to send")
		}
		if len([]rune(text)) > 4000 {
			return sdk.Result{}, errors.New("the message is too long")
		}
		if len(p.Recipients) == 0 || len(p.Recipients) > 20 {
			return sdk.Result{}, errors.New("give 1 to 20 recipients")
		}
		seen := map[string]bool{}
		to := []string{}
		for _, r := range p.Recipients {
			r = strings.ReplaceAll(strings.TrimSpace(r), " ", "")
			if !validRecipient(r) {
				return sdk.Result{}, fmt.Errorf("%q isn't a number, account UUID or group id", clip(r, 40))
			}
			if !c.allowed[r] {
				return sdk.Result{}, fmt.Errorf("%s isn't in this instance's allowedRecipients", r)
			}
			if !seen[r] {
				seen[r] = true
				to = append(to, r)
			}
		}
		if call.DryRun {
			after, _ := json.Marshal(map[string]any{"text": text})
			changes := []sdk.Change{}
			for _, r := range to {
				changes = append(changes, sdk.Change{Target: r, Op: "send", After: after})
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Send %q from %s to %s (can't be undone)", clip(text, 80), c.number, strings.Join(to, ", ")), Changes: changes}}, nil
		}
		var out struct {
			Timestamp string `json:"timestamp"`
		}
		if err := c.do(ctx, http.MethodPost, "/v2/send", nil, map[string]any{"message": text, "number": c.number, "recipients": to}, &out); err != nil {
			return sdk.Result{}, err
		}
		res := map[string]any{"sent": len(to), "recipients": to}
		if ts, err := strconv.ParseInt(out.Timestamp, 10, 64); err == nil {
			res["timestamp"] = ts
		}
		return sdk.JSON(res)

	case "groups":
		var gs []struct {
			Name    string   `json:"name"`
			ID      string   `json:"id"`
			Members []string `json:"members"`
			Admins  []string `json:"admins"`
			Blocked bool     `json:"blocked"`
		}
		if err := c.do(ctx, http.MethodGet, "/v1/groups/"+url.PathEscape(c.number), nil, nil, &gs); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, g := range gs {
			e := map[string]any{"name": clip(g.Name, 200), "id": clip(g.ID, 200), "members": len(g.Members), "allowed": c.allowed[g.ID]}
			if g.Blocked {
				e["blocked"] = true
			}
			out = append(out, e)
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
