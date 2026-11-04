// Package zulip works with a Zulip organization through its REST API with a
// bot's or user's email and API key: subscribed streams (channels), unread
// counts, recent messages in the streams and topics the instance allows,
// and sending messages there (undo deletes them).
//
// Reading and sending are limited to the instance's allowed list, where an
// entry is a whole stream ("general") or one topic in it ("general >
// deploys"). Direct messages are counted, never read or sent.
package zulip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/mention"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Zulip organization and account.
type Config struct {
	URL         string   `json:"url"`    // e.g. https://chat.zulip.org or https://example.zulipchat.com
	Email       string   `json:"email"`  // the account's (or bot's) email
	APIKey      string   `json:"apiKey"` // secret://
	Allowed     []string `json:"allowed"`
	Fingerprint string   `json:"fingerprint"`
}

type conn struct {
	http    *http.Client
	base    string // …/api/v1
	email   string
	key     string
	host    sdk.Host
	streams map[string]bool // whole streams, lowercase
	topics  map[string]bool // "stream\x00topic", lowercase
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Zulip module.
func New() *Module { return &Module{} }

var emailRe = regexp.MustCompile(`^[^\s@/?#]{1,64}@[A-Za-z0-9.-]{1,253}$`)

const (
	maxName    = 60    // Zulip's limit for stream names and topics
	maxContent = 10000 // Zulip's limit for a message, in bytes
	maxUnread  = 1000  // unread messages looked at per call
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	where := `"stream":{"type":"string","description":"Stream (channel) name, e.g. general"},"topic":{"type":"string","maxLength":60,"description":"Topic in the stream"}`
	return sdk.Manifest{
		ID: "zulip", Name: "Zulip", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "Zulip streams and unread counts, recent messages in allowed streams and topics, and sending messages there.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","email","apiKey"],"properties":{
			"url":{"type":"string","description":"The organization's address, e.g. https://example.zulipchat.com"},
			"email":{"type":"string","description":"The account's email; for a bot, the bot's email (Personal settings, Bots)"},
			"apiKey":{"type":"string","x-secret":true,"description":"The API key (Personal settings, Account and privacy, API key, or the bot's key)"},
			"allowed":{"type":"array","items":{"type":"string"},"description":"Streams Conduit may read and send to (general), or single topics in them (general > deploys); everything else is off limits"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "streams", Title: "Streams", Description: "Streams (channels) the account is subscribed to, and whether each is allowed.", Risk: sdk.RiskRead},
			{Name: "unread", Title: "Unread", Description: "Unread message counts by stream, with topics for allowed streams, and the number of unread direct messages.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "messages", Title: "Recent messages", Description: "Recent messages in an allowed stream, or one topic in it, oldest first.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["stream"],"properties":{` + where + `,"limit":{"type":"integer","default":30,"minimum":1,"maximum":100}}}`)},
			{Name: "send_message", Title: "Send a message", Description: "Sends a message (Markdown) to a topic in an allowed stream. The preview names everyone mentioned; wildcard mentions (@**all**, @**everyone**, @**channel**, @**topic**) are refused. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["stream","topic","content"],"properties":{` + where + `,"content":{"type":"string","maxLength":10000}}}`)},
			{Name: "delete_message", Title: "Delete a message", Description: "Deletes a message in an allowed stream for everyone (the organization's settings decide whose messages the account may delete). The preview names its author and time, not its text.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1,"description":"Message id"}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "stream", Title: "Streams", ListAction: "streams", ViewHint: "table"}},
	}
}

// name checks a stream name or topic: 1 to 60 characters, no control
// characters.
func name(s, what string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len([]rune(s)) > maxName || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("the %s is 1 to %d characters", what, maxName)
	}
	return s, nil
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is like https://example.zulipchat.com")
	}
	email := strings.TrimSpace(c.Email)
	if !emailRe.MatchString(email) {
		return errors.New("the email is the account's or bot's email address")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	streams, topics := map[string]bool{}, map[string]bool{}
	for _, a := range c.Allowed {
		s, t, hasTopic := strings.Cut(a, ">")
		st, err := name(strings.TrimPrefix(strings.TrimSpace(s), "#"), "stream")
		if err != nil {
			return fmt.Errorf("%q isn't a stream (general) or a topic in one (general > deploys)", a)
		}
		if !hasTopic {
			streams[strings.ToLower(st)] = true
			continue
		}
		tp, err := name(t, "topic")
		if err != nil {
			return fmt.Errorf("%q isn't a stream (general) or a topic in one (general > deploys)", a)
		}
		topics[strings.ToLower(st)+"\x00"+strings.ToLower(tp)] = true
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, false)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1") + "/api/v1"
	m.set.Put(id, &conn{http: rest.SameHostOnly(client), base: base, email: email, key: c.APIKey, host: h, streams: streams, topics: topics})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// do calls the API. Zulip takes parameters as a query or a form, not JSON,
// and answers errors as {"result":"error","msg":…}.
func (c *conn) do(ctx context.Context, method, path string, q, form url.Values, out any) error {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	key, err := c.host.Secret(ctx, c.key)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.email, strings.TrimSpace(key))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return rest.TransportError(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		var e struct {
			Msg string `json:"msg"`
		}
		_ = json.Unmarshal(raw, &e)
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return &rest.Error{Status: res.StatusCode, Message: "the server refused the email and API key"}
		case http.StatusTooManyRequests:
			return &rest.Error{Status: res.StatusCode, Message: "the server's rate limit was hit; try again shortly"}
		}
		msg := res.Status
		if e.Msg != "" {
			msg = clip(rest.Redact(e.Msg), 300)
		}
		return &rest.Error{Status: res.StatusCode, Message: msg}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("unexpected answer from %s: %w", rest.ShortURL(c.base), err)
		}
	}
	return nil
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func (c *conn) streamAllowed(stream string) bool { return c.streams[strings.ToLower(stream)] }

func (c *conn) allowed(stream, topic string) bool {
	return c.streamAllowed(stream) || (topic != "" && c.topics[strings.ToLower(stream)+"\x00"+strings.ToLower(topic)])
}

// anyTopic says whether some topic of the stream is allowed.
func (c *conn) anyTopic(stream string) bool {
	p := strings.ToLower(stream) + "\x00"
	for k := range c.topics {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// where checks a stream and optional topic against the allowed list.
func (c *conn) where(stream, topic string, needTopic bool) (string, string, error) {
	st, err := name(strings.TrimPrefix(strings.TrimSpace(stream), "#"), "stream")
	if err != nil {
		return "", "", err
	}
	tp := ""
	if strings.TrimSpace(topic) != "" || needTopic {
		if tp, err = name(topic, "topic"); err != nil {
			return "", "", err
		}
	}
	if !c.allowed(st, tp) {
		if tp == "" && c.anyTopic(st) {
			return "", "", fmt.Errorf("only some topics in %s are allowed; name one", st)
		}
		return "", "", fmt.Errorf("%s isn't in this instance's allowed list", label(st, tp))
	}
	return st, tp, nil
}

func label(stream, topic string) string {
	if topic == "" {
		return "#" + stream
	}
	return "#" + stream + " > " + topic
}

type message struct {
	ID        int64  `json:"id"`
	Sender    string `json:"sender_full_name"`
	Content   string `json:"content"`
	Timestamp int64  `json:"timestamp"`
	Subject   string `json:"subject"`
	Type      string `json:"type"` // "stream" or "private"
	Recipient any    `json:"display_recipient"`
}

func (e message) stream() string {
	if s, ok := e.Recipient.(string); ok && e.Type == "stream" {
		return s
	}
	return ""
}

func stamp(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func narrow(stream, topic string) string {
	type term struct {
		Operator string `json:"operator"`
		Operand  string `json:"operand"`
	}
	n := []term{{"stream", stream}}
	if topic != "" {
		n = append(n, term{"topic", topic})
	}
	b, _ := json.Marshal(n)
	return string(b)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		FullName string `json:"full_name"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/me", nil, nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + clip(me.FullName, 100)
	if len(c.streams)+len(c.topics) == 0 {
		return sdk.Health{Status: "degraded", Message: msg + "; nothing is allowed yet (add streams or topics to allowed)"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s, %d allowed streams and %d topics", msg, len(c.streams), len(c.topics))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Stream  string `json:"stream"`
		Topic   string `json:"topic"`
		Content string `json:"content"`
		ID      int64  `json:"id"`
		Limit   int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "streams":
		var r struct {
			Subscriptions []struct {
				ID         int64  `json:"stream_id"`
				Name       string `json:"name"`
				InviteOnly bool   `json:"invite_only"`
				Muted      bool   `json:"is_muted"`
			} `json:"subscriptions"`
		}
		if err := c.do(ctx, http.MethodGet, "/users/me/subscriptions", nil, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range r.Subscriptions {
			row := map[string]any{"stream": clip(s.Name, maxName), "id": s.ID, "private": s.InviteOnly, "allowed": c.streamAllowed(s.Name)}
			if !c.streamAllowed(s.Name) && c.anyTopic(s.Name) {
				row["allowed"] = "some topics"
			}
			if s.Muted {
				row["muted"] = true
			}
			out = append(out, row)
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["stream"].(string) < out[j]["stream"].(string) })
		return sdk.JSON(out)

	case "unread":
		var r struct {
			Messages    []message `json:"messages"`
			FoundOldest bool      `json:"found_oldest"`
		}
		q := url.Values{"anchor": {"newest"}, "num_before": {strconv.Itoa(maxUnread)}, "num_after": {"0"},
			"narrow": {`[{"operator":"is","operand":"unread"}]`}, "apply_markdown": {"false"}}
		if err := c.do(ctx, http.MethodGet, "/messages", q, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		type agg struct {
			n      int
			topics map[string]int
		}
		byStream := map[string]*agg{}
		direct := 0
		for _, e := range r.Messages {
			s := e.stream()
			if s == "" {
				direct++
				continue
			}
			a := byStream[s]
			if a == nil {
				a = &agg{topics: map[string]int{}}
				byStream[s] = a
			}
			a.n++
			if c.allowed(s, e.Subject) {
				a.topics[e.Subject]++
			}
		}
		streams := []map[string]any{}
		for s, a := range byStream {
			row := map[string]any{"stream": clip(s, maxName), "unread": a.n}
			if len(a.topics) > 0 {
				ts := []map[string]any{}
				for t, n := range a.topics {
					ts = append(ts, map[string]any{"topic": clip(t, maxName), "unread": n})
				}
				sort.SliceStable(ts, func(i, j int) bool { return ts[i]["unread"].(int) > ts[j]["unread"].(int) })
				row["topics"] = ts
			}
			streams = append(streams, row)
		}
		sort.SliceStable(streams, func(i, j int) bool {
			a, b := streams[i]["unread"].(int), streams[j]["unread"].(int)
			if a != b {
				return a > b
			}
			return streams[i]["stream"].(string) < streams[j]["stream"].(string)
		})
		out := map[string]any{"total": len(r.Messages), "direct": direct, "streams": streams}
		if !r.FoundOldest && len(r.Messages) >= maxUnread {
			out["note"] = fmt.Sprintf("counted the newest %d unread messages; there are more", maxUnread)
		}
		return sdk.JSON(out)

	case "messages":
		st, tp, err := c.where(p.Stream, p.Topic, false)
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.Limit
		if n <= 0 {
			n = 30
		}
		if n > 100 {
			n = 100
		}
		var r struct {
			Messages []message `json:"messages"`
		}
		q := url.Values{"anchor": {"newest"}, "num_before": {strconv.Itoa(n)}, "num_after": {"0"}, "narrow": {narrow(st, tp)}, "apply_markdown": {"false"}}
		if err := c.do(ctx, http.MethodGet, "/messages", q, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		msgs := []map[string]any{}
		for _, e := range r.Messages { // oldest first already
			if s := e.stream(); s == "" || !c.allowed(s, e.Subject) {
				continue
			}
			msgs = append(msgs, map[string]any{"id": e.ID, "from": clip(e.Sender, 100), "topic": clip(e.Subject, maxName), "when": stamp(e.Timestamp), "text": clip(e.Content, 4000)})
		}
		return sdk.JSON(map[string]any{"stream": st, "topic": tp, "messages": msgs})

	case "send_message":
		content := strings.TrimSpace(p.Content)
		if content == "" {
			return sdk.Result{}, errors.New("write something to send")
		}
		if len(content) > maxContent {
			return sdk.Result{}, fmt.Errorf("the message is longer than Zulip allows (%d bytes)", maxContent)
		}
		found := mention.Find(content)
		if found.Wildcard != "" {
			return sdk.Result{}, fmt.Errorf("%s notifies everyone in the stream or topic; wildcard mentions (@**all**, @**everyone**, @**channel**, @**topic**) aren't sent from Conduit", found.Wildcard)
		}
		st, tp, err := c.where(p.Stream, p.Topic, true)
		if err != nil {
			return sdk.Result{}, err
		}
		target := label(st, tp)
		if call.DryRun {
			after, _ := json.Marshal(map[string]string{"content": content})
			sum := "Send a message to " + target
			if pv := found.Preview(); pv != "" {
				sum += "; " + pv
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: "create", After: after}}}}, nil
		}
		var r struct {
			ID int64 `json:"id"`
		}
		form := url.Values{"type": {"stream"}, "to": {st}, "topic": {tp}, "content": {content}}
		if err := c.do(ctx, http.MethodPost, "/messages", nil, form, &r); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"stream": st, "topic": tp, "id": r.ID})
		if r.ID > 0 {
			res.Undo = sdk.UndoWith("delete_message", map[string]int64{"id": r.ID}, "Delete the message in "+target)
		}
		return res, err

	case "delete_message":
		if p.ID <= 0 {
			return sdk.Result{}, errors.New("id is a message id (a positive number)")
		}
		path := "/messages/" + strconv.FormatInt(p.ID, 10)
		var r struct {
			Message message `json:"message"`
		}
		if err := c.do(ctx, http.MethodGet, path, url.Values{"apply_markdown": {"false"}}, nil, &r); err != nil {
			if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("no message %d that this account can see", p.ID)
			}
			return sdk.Result{}, err
		}
		s := r.Message.stream()
		if s == "" || !c.allowed(s, r.Message.Subject) {
			return sdk.Result{}, fmt.Errorf("message %d isn't in an allowed stream or topic", p.ID)
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]string{"from": r.Message.Sender, "when": stamp(r.Message.Timestamp)})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete %s's message from %s in #%s", clip(r.Message.Sender, 100), stamp(r.Message.Timestamp), s),
				Changes: []sdk.Change{{Target: "#" + s + " message " + strconv.FormatInt(p.ID, 10), Op: "delete", Before: before}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]int64{"deleted": p.ID})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
