// Package matrix works with a Matrix account through the client-server API
// with an access token: the rooms it has joined, recent messages in the
// rooms the instance allows, sending and redacting messages there, and a
// room's member count.
//
// Reading and writing are limited to the rooms in the instance's
// allow-list; joined rooms outside it are listed by id and name only, so
// they can be added. Messages in end-to-end encrypted rooms can't be read
// (Conduit holds no device keys) and are counted instead. Sending to the
// Matrix notification channel is the notify module's job; this module adds
// reading and redaction.
package matrix

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one account on one homeserver.
type Config struct {
	Homeserver         string   `json:"homeserver"` // https://matrix.example.org
	Token              string   `json:"token"`      // secret:// access token
	AllowedRooms       []string `json:"allowedRooms"`
	Fingerprint        string   `json:"fingerprint"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

type conn struct {
	api     *rest.Client
	allowed map[string]bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Matrix module.
func New() *Module { return &Module{} }

var (
	roomRe  = regexp.MustCompile(`^![A-Za-z0-9._=/+-]{1,255}:[A-Za-z0-9.:\[\]-]{1,255}$`)
	eventRe = regexp.MustCompile(`^\$[A-Za-z0-9._=/+:-]{1,255}$`)
)

const maxNames = 50 // rooms whose names are looked up per listing

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	room := `"room":{"type":"string","description":"Room id from allowedRooms, like !abc:example.org"}`
	return sdk.Manifest{
		ID: "matrix", Name: "Matrix", Version: "0.1.0", Category: "Communication", Icon: "network",
		Description: "A Matrix account (Synapse, Conduit, Dendrite): joined rooms, recent messages in allowed rooms, send and redact messages, member counts.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["homeserver","token"],"properties":{
			"homeserver":{"type":"string","description":"Client-server API address, e.g. https://matrix.example.org (not the server name, when they differ)"},
			"token":{"type":"string","x-secret":true,"description":"Access token of the account (Element: Settings, Help and About, Access token), ideally a bot account"},
			"allowedRooms":{"type":"array","items":{"type":"string"},"description":"Room ids (like !abc:example.org) Conduit may read and send to; every other room is off limits"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "rooms", Title: "Joined rooms", Description: "Rooms the account has joined, with names and whether each is allowed.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "messages", Title: "Recent messages", Description: "Recent messages in an allowed room, oldest first. Encrypted messages are counted, not shown.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["room"],"properties":{` + room + `,"limit":{"type":"integer","default":20,"minimum":1,"maximum":100}}}`)},
			{Name: "send_message", Title: "Send a message", Description: "Sends a text message (or a notice, which bots should use) to an allowed room. Undo redacts it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["room","text"],"properties":{` + room + `,"text":{"type":"string","maxLength":16000},"notice":{"type":"boolean","default":false,"description":"Send as m.notice (no notifications for most clients)"}}}`)},
			{Name: "redact", Title: "Redact a message", Description: "Removes a message's content for everyone in an allowed room, for good. The preview quotes it.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["room","event"],"properties":{` + room + `,"event":{"type":"string","description":"Event id, like $abc"},"reason":{"type":"string","maxLength":500}}}`)},
			{Name: "members", Title: "Member count", Description: "How many members have joined an allowed room.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["room"],"properties":{` + room + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	s := strings.TrimSpace(c.Homeserver)
	if s != "" && !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("the homeserver is an address like https://matrix.example.org")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	allowed := map[string]bool{}
	for _, r := range c.AllowedRooms {
		r = strings.TrimSpace(r)
		if !roomRe.MatchString(r) {
			return fmt.Errorf("%q isn't a room id like !abc:example.org (find it in the room's settings, Advanced)", r)
		}
		allowed[r] = true
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	ref := c.Token
	api := rest.New(u.Scheme+"://"+u.Host+"/_matrix/client/v3", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, allowed: allowed})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	var e *rest.Error
	if errors.As(err, &e) {
		switch e.Status {
		case http.StatusUnauthorized:
			return errors.New("the homeserver refused the access token")
		case http.StatusForbidden:
			return fmt.Errorf("the homeserver refused: %s", e.Message)
		case http.StatusTooManyRequests:
			return errors.New("the homeserver's rate limit was hit; try again shortly")
		}
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

func (c *conn) room(raw string) (string, error) {
	r := strings.TrimSpace(raw)
	if !roomRe.MatchString(r) {
		return "", errors.New("the room is a room id like !abc:example.org (see rooms)")
	}
	if !c.allowed[r] {
		return "", fmt.Errorf("%s isn't in this instance's allowedRooms", r)
	}
	return r, nil
}

func txnID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "conduit-" + hex.EncodeToString(b)
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

type event struct {
	EventID string `json:"event_id"`
	Type    string `json:"type"`
	Sender  string `json:"sender"`
	TS      int64  `json:"origin_server_ts"`
	Content struct {
		MsgType string `json:"msgtype"`
		Body    string `json:"body"`
	} `json:"content"`
	Unsigned struct {
		RedactedBecause any `json:"redacted_because"`
	} `json:"unsigned"`
}

func (e event) brief() map[string]any {
	out := map[string]any{"event": e.EventID, "from": e.Sender, "when": time.UnixMilli(e.TS).UTC().Format(time.RFC3339)}
	switch {
	case e.Unsigned.RedactedBecause != nil || (e.Type == "m.room.message" && e.Content.MsgType == ""):
		out["redacted"] = true
	default:
		out["type"] = strings.TrimPrefix(e.Content.MsgType, "m.")
		out["text"] = clip(e.Content.Body, 4000)
	}
	return out
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var who struct {
		UserID string `json:"user_id"`
	}
	if err := c.do(ctx, http.MethodGet, "/account/whoami", nil, nil, &who); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := clip(who.UserID, 255)
	if len(c.allowed) == 0 {
		return sdk.Health{Status: "degraded", Message: msg + "; no rooms are allowed yet (add room ids to allowedRooms)"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s, %d allowed rooms", msg, len(c.allowed))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Room   string `json:"room"`
		Event  string `json:"event"`
		Text   string `json:"text"`
		Notice bool   `json:"notice"`
		Reason string `json:"reason"`
		Limit  int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "rooms":
		var jr struct {
			Rooms []string `json:"joined_rooms"`
		}
		if err := c.do(ctx, http.MethodGet, "/joined_rooms", nil, nil, &jr); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i, r := range jr.Rooms {
			if !roomRe.MatchString(r) {
				continue
			}
			e := map[string]any{"room": r, "allowed": c.allowed[r]}
			if i < maxNames {
				var n struct {
					Name string `json:"name"`
				}
				if err := c.do(ctx, http.MethodGet, "/rooms/"+url.PathEscape(r)+"/state/m.room.name/", nil, nil, &n); err == nil && n.Name != "" {
					e["name"] = clip(n.Name, 200)
				}
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "messages":
		room, err := c.room(p.Room)
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.Limit
		if n <= 0 {
			n = 20
		}
		if n > 100 {
			n = 100
		}
		var res struct {
			Chunk []event `json:"chunk"`
		}
		q := url.Values{"dir": {"b"}, "limit": {strconv.Itoa(n)}, "filter": {`{"types":["m.room.message","m.room.encrypted"]}`}}
		if err := c.do(ctx, http.MethodGet, "/rooms/"+url.PathEscape(room)+"/messages", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		msgs := []map[string]any{}
		encrypted := 0
		for i := len(res.Chunk) - 1; i >= 0; i-- { // the server answers newest first
			e := res.Chunk[i]
			switch e.Type {
			case "m.room.encrypted":
				encrypted++
			case "m.room.message":
				msgs = append(msgs, e.brief())
			}
		}
		out := map[string]any{"room": room, "messages": msgs}
		if encrypted > 0 {
			out["encrypted"] = encrypted
			out["note"] = "encrypted messages can't be read without the account's keys"
		}
		return sdk.JSON(out)

	case "send_message":
		room, err := c.room(p.Room)
		if err != nil {
			return sdk.Result{}, err
		}
		text := strings.TrimSpace(p.Text)
		if text == "" {
			return sdk.Result{}, errors.New("write something to send")
		}
		if len(text) > 16000 {
			return sdk.Result{}, errors.New("the message is too long")
		}
		kind := "m.text"
		if p.Notice {
			kind = "m.notice"
		}
		if call.DryRun {
			after, _ := json.Marshal(map[string]string{"msgtype": kind, "body": text})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Send %q to %s", clip(text, 80), room),
				Changes: []sdk.Change{{Target: room, Op: "create", After: after}}}}, nil
		}
		var out struct {
			EventID string `json:"event_id"`
		}
		if err := c.do(ctx, http.MethodPut, "/rooms/"+url.PathEscape(room)+"/send/m.room.message/"+txnID(), nil, map[string]string{"msgtype": kind, "body": text}, &out); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]string{"room": room, "event": out.EventID})
		if eventRe.MatchString(out.EventID) {
			res.Undo = sdk.UndoWith("redact", map[string]string{"room": room, "event": out.EventID}, "Redact the message")
		}
		return res, err

	case "redact":
		room, err := c.room(p.Room)
		if err != nil {
			return sdk.Result{}, err
		}
		ev := strings.TrimSpace(p.Event)
		if !eventRe.MatchString(ev) {
			return sdk.Result{}, errors.New("the event is an event id like $abc (see messages)")
		}
		reason := strings.TrimSpace(p.Reason)
		if len([]rune(reason)) > 500 || strings.ContainsAny(reason, "\x00") {
			return sdk.Result{}, errors.New("the reason is up to 500 characters")
		}
		if call.DryRun {
			var e event
			if err := c.do(ctx, http.MethodGet, "/rooms/"+url.PathEscape(room)+"/event/"+url.PathEscape(ev), nil, nil, &e); err != nil {
				return sdk.Result{}, err
			}
			before, _ := json.Marshal(e.brief())
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Redact %s's message %q in %s", e.Sender, clip(e.Content.Body, 80), room),
				Changes: []sdk.Change{{Target: room + " " + ev, Op: "delete", Before: before}}}}, nil
		}
		body := map[string]string{}
		if reason != "" {
			body["reason"] = reason
		}
		if err := c.do(ctx, http.MethodPut, "/rooms/"+url.PathEscape(room)+"/redact/"+url.PathEscape(ev)+"/"+txnID(), nil, body, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"room": room, "redacted": ev})

	case "members":
		room, err := c.room(p.Room)
		if err != nil {
			return sdk.Result{}, err
		}
		var jm struct {
			Joined map[string]json.RawMessage `json:"joined"`
		}
		if err := c.do(ctx, http.MethodGet, "/rooms/"+url.PathEscape(room)+"/joined_members", nil, nil, &jm); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"room": room, "members": len(jm.Joined)})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
