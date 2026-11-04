// Package nextcloudtalk works with Nextcloud Talk (the spreed app) through
// its OCS API with an app password: conversations and unread counts,
// recent messages in the conversations the instance allows, and sending
// messages there (undo deletes them).
//
// Reading and sending are limited to the conversation tokens in the
// instance's allowedConversations; the others are listed so they can be
// added.
package nextcloudtalk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/mention"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Nextcloud account.
type Config struct {
	URL                  string   `json:"url"` // e.g. https://cloud.example.com
	User                 string   `json:"user"`
	AppPassword          string   `json:"appPassword"` // secret://
	AllowedConversations []string `json:"allowedConversations"`
	Fingerprint          string   `json:"fingerprint"`
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

// New returns the Nextcloud Talk module.
func New() *Module { return &Module{} }

var (
	userRe  = regexp.MustCompile(`^[A-Za-z0-9_.@ '-]{1,64}$`)
	tokenRe = regexp.MustCompile(`^[a-z0-9]{4,32}$`)
	paramRe = regexp.MustCompile(`\{([A-Za-z0-9_-]{1,64})\}`)
)

const (
	maxText = 32000 // Talk's limit for a chat message
	chat    = "/apps/spreed/api/v1/chat/"
	rooms   = "/apps/spreed/api/v4/room"
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	conv := `"conversation":{"type":"string","description":"Conversation token from allowedConversations (the part after /call/ in its address)"}`
	return sdk.Manifest{
		ID: "nextcloudtalk", Name: "Nextcloud Talk", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "Nextcloud Talk conversations and unread counts, recent messages in allowed conversations, and sending messages there.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","user","appPassword"],"properties":{
			"url":{"type":"string","description":"The Nextcloud address, e.g. https://cloud.example.com"},
			"user":{"type":"string","description":"Your Nextcloud user name (or a bot user's)"},
			"appPassword":{"type":"string","x-secret":true,"description":"An app password (Personal settings, Security, Devices and sessions)"},
			"allowedConversations":{"type":"array","items":{"type":"string"},"description":"Conversation tokens Conduit may read and send to; every other conversation is off limits"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "conversations", Title: "Conversations", Description: "Conversations the account is in, with unread counts and whether each is allowed.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "unread", Title: "Unread", Description: "Conversations with unread messages, with unread and mention counts.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "messages", Title: "Recent messages", Description: "Recent messages in an allowed conversation, oldest first. Doesn't mark them read.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation"],"properties":{` + conv + `,"limit":{"type":"integer","default":30,"minimum":1,"maximum":100}}}`)},
			{Name: "send_message", Title: "Send a message", Description: "Sends a message (Markdown) to an allowed conversation, optionally as a reply. The preview names everyone mentioned; wildcard mentions (@all, @here) and /commands are refused. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","text"],"properties":{` + conv + `,"text":{"type":"string","maxLength":32000},"replyTo":{"type":"integer","minimum":1,"description":"Message id being replied to"}}}`)},
			{Name: "delete_message", Title: "Delete a message", Description: "Deletes a message in an allowed conversation for everyone (Talk allows it for 6 hours, and for moderators). The preview names the conversation and message id, not its text.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["conversation","id"],"properties":{` + conv + `,"id":{"type":"integer","minimum":1,"description":"Message id"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is like https://cloud.example.com")
	}
	user := strings.TrimSpace(c.User)
	if !userRe.MatchString(user) {
		return errors.New("enter your Nextcloud user name")
	}
	if !strings.HasPrefix(c.AppPassword, "secret://") {
		return errors.New("store the app password in the vault and enter its secret:// reference")
	}
	allowed := map[string]bool{}
	for _, t := range c.AllowedConversations {
		t = strings.TrimSpace(t)
		if !tokenRe.MatchString(t) {
			return fmt.Errorf("%q isn't a conversation token (the part after /call/ in its address)", t)
		}
		allowed[t] = true
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
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/index.php") + "/ocs/v2.php"
	ref := c.AppPassword
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, strings.TrimSpace(pw))
		r.Header.Set("OCS-APIRequest", "true")
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, allowed: allowed})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// ocs calls an OCS endpoint and unwraps {"ocs":{"meta":…,"data":…}}.
func (c *conn) ocs(ctx context.Context, method, path string, q url.Values, body, out any) error {
	if q == nil {
		q = url.Values{}
	}
	q.Set("format", "json")
	var env struct {
		OCS struct {
			Data json.RawMessage `json:"data"`
		} `json:"ocs"`
	}
	if _, err := c.api.Do(ctx, method, path, q, body, &env); err != nil {
		var e *rest.Error
		if errors.As(err, &e) {
			switch e.Status {
			case http.StatusUnauthorized:
				return &rest.Error{Status: e.Status, Message: "Nextcloud refused the user name and app password"}
			case http.StatusTooManyRequests:
				return &rest.Error{Status: e.Status, Message: "Nextcloud's rate limit was hit; try again shortly"}
			}
		}
		return err
	}
	if out != nil && len(env.OCS.Data) > 0 {
		if err := json.Unmarshal(env.OCS.Data, out); err != nil {
			return fmt.Errorf("unexpected answer from Nextcloud: %w", err)
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

type room struct {
	Token          string `json:"token"`
	Type           int    `json:"type"`
	DisplayName    string `json:"displayName"`
	UnreadMessages int    `json:"unreadMessages"`
	UnreadMention  bool   `json:"unreadMention"`
	LastActivity   int64  `json:"lastActivity"`
	ReadOnly       int    `json:"readOnly"`
}

func kind(t int) string {
	switch t {
	case 1:
		return "one-to-one"
	case 2:
		return "group"
	case 3:
		return "public"
	case 4:
		return "changelog"
	case 5:
		return "former one-to-one"
	case 6:
		return "note to self"
	}
	return strconv.Itoa(t)
}

func stamp(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func (c *conn) rooms(ctx context.Context) ([]room, error) {
	var rs []room
	if err := c.ocs(ctx, http.MethodGet, rooms, nil, nil, &rs); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return nil, errors.New("Talk isn't installed or enabled on this Nextcloud")
		}
		return nil, err
	}
	return rs, nil
}

// conversation checks a token against the allow-list and looks it up.
func (c *conn) conversation(ctx context.Context, raw string) (room, error) {
	t := strings.TrimSpace(raw)
	if !tokenRe.MatchString(t) {
		return room{}, errors.New("the conversation is its token, like a1b2c3d4 (see conversations)")
	}
	if !c.allowed[t] {
		return room{}, fmt.Errorf("%s isn't in this instance's allowedConversations", t)
	}
	var r room
	if err := c.ocs(ctx, http.MethodGet, rooms+"/"+t, nil, nil, &r); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return room{}, fmt.Errorf("no conversation %s that this account is in", t)
		}
		return room{}, err
	}
	if r.Token != t {
		return room{}, fmt.Errorf("Nextcloud answered with a different conversation for %s", t)
	}
	return r, nil
}

func (r room) label() string { return fmt.Sprintf("%q (%s)", clip(r.DisplayName, 100), r.Token) }

type message struct {
	ID          int64  `json:"id"`
	ActorType   string `json:"actorType"`
	ActorName   string `json:"actorDisplayName"`
	Timestamp   int64  `json:"timestamp"`
	Message     string `json:"message"`
	MessageType string `json:"messageType"`
	System      string `json:"systemMessage"`
	Params      any    `json:"messageParameters"` // an object, or [] when empty
	Parent      *struct {
		ID int64 `json:"id"`
	} `json:"parent"`
}

// text fills in {placeholders} (mentions, files) with their names.
func (e message) text() string {
	ps, _ := e.Params.(map[string]any)
	return paramRe.ReplaceAllStringFunc(e.Message, func(m string) string {
		if p, ok := ps[m[1:len(m)-1]].(map[string]any); ok {
			if n, ok := p["name"].(string); ok {
				return n
			}
		}
		return m
	})
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u struct {
		ID string `json:"id"`
	}
	if err := c.ocs(ctx, http.MethodGet, "/cloud/user", nil, nil, &u); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + clip(u.ID, 64)
	if _, err := c.rooms(ctx); err != nil {
		return sdk.Health{Status: "degraded", Message: msg + "; " + err.Error()}
	}
	if len(c.allowed) == 0 {
		return sdk.Health{Status: "degraded", Message: msg + "; no conversations are allowed yet (add tokens to allowedConversations)"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s, %d allowed conversations", msg, len(c.allowed))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Conversation string `json:"conversation"`
		Text         string `json:"text"`
		ReplyTo      int64  `json:"replyTo"`
		ID           int64  `json:"id"`
		Limit        int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "conversations", "unread":
		rs, err := c.rooms(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].LastActivity > rs[j].LastActivity })
		out := []map[string]any{}
		for _, r := range rs {
			if !tokenRe.MatchString(r.Token) || (call.Action == "unread" && r.UnreadMessages <= 0) {
				continue
			}
			row := map[string]any{"conversation": r.Token, "name": clip(r.DisplayName, 100), "type": kind(r.Type), "unread": r.UnreadMessages, "allowed": c.allowed[r.Token]}
			if r.UnreadMention {
				row["mentioned"] = true
			}
			if call.Action == "conversations" {
				row["lastActivity"] = stamp(r.LastActivity)
				if r.ReadOnly == 1 {
					row["readOnly"] = true
				}
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "messages":
		r, err := c.conversation(ctx, p.Conversation)
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
		var ms []message
		q := url.Values{"lookIntoFuture": {"0"}, "limit": {strconv.Itoa(n)}, "setReadMarker": {"0"}, "includeLastKnown": {"0"}}
		if err := c.ocs(ctx, http.MethodGet, chat+r.Token, q, nil, &ms); err != nil && !rest.IsStatus(err, http.StatusNotModified) {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i := len(ms) - 1; i >= 0; i-- { // the server answers newest first
			e := ms[i]
			row := map[string]any{"id": e.ID, "from": clip(e.ActorName, 100), "when": stamp(e.Timestamp)}
			switch {
			case e.MessageType == "comment_deleted":
				row["deleted"] = true
			case e.System != "" || e.MessageType == "system":
				row["system"] = clip(e.text(), 500)
			default:
				row["text"] = clip(e.text(), 4000)
			}
			if e.Parent != nil && e.Parent.ID > 0 {
				row["replyTo"] = e.Parent.ID
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"conversation": r.Token, "name": clip(r.DisplayName, 100), "messages": out})

	case "send_message":
		text := strings.TrimSpace(p.Text)
		if text == "" {
			return sdk.Result{}, errors.New("write something to send")
		}
		if len([]rune(text)) > maxText {
			return sdk.Result{}, fmt.Errorf("the message is longer than Talk allows (%d characters)", maxText)
		}
		if p.ReplyTo < 0 {
			return sdk.Result{}, errors.New("replyTo is a message id")
		}
		if strings.HasPrefix(text, "/") {
			// Talk runs /commands (bots, /help, admin-defined commands).
			return sdk.Result{}, errors.New("a message starting with / is a Talk command, which Conduit doesn't run; start it with something else")
		}
		found := mention.Find(text)
		if found.Wildcard != "" {
			return sdk.Result{}, fmt.Errorf("%s notifies everyone in the conversation; wildcard mentions (@all, @here) aren't sent from Conduit", found.Wildcard)
		}
		r, err := c.conversation(ctx, p.Conversation)
		if err != nil {
			return sdk.Result{}, err
		}
		if r.ReadOnly == 1 {
			return sdk.Result{}, fmt.Errorf("%s is read-only", r.label())
		}
		if call.DryRun {
			after, _ := json.Marshal(map[string]any{"text": text, "replyTo": p.ReplyTo})
			sum := fmt.Sprintf("Send a message to %s, a %s conversation", r.label(), kind(r.Type))
			if pv := found.Preview(); pv != "" {
				sum += "; " + pv
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum,
				Changes: []sdk.Change{{Target: r.Token, Op: "create", After: after}}}}, nil
		}
		body := map[string]any{"message": text}
		if p.ReplyTo > 0 {
			body["replyTo"] = p.ReplyTo
		}
		var e message
		if err := c.ocs(ctx, http.MethodPost, chat+r.Token, nil, body, &e); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"conversation": r.Token, "id": e.ID, "when": stamp(e.Timestamp)})
		if e.ID > 0 {
			res.Undo = sdk.UndoWith("delete_message", map[string]any{"conversation": r.Token, "id": e.ID}, "Delete the message in "+clip(r.DisplayName, 100))
		}
		return res, err

	case "delete_message":
		if p.ID <= 0 {
			return sdk.Result{}, errors.New("id is a message id (a positive number)")
		}
		r, err := c.conversation(ctx, p.Conversation)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete message %d in %s", p.ID, r.label()),
				Changes: []sdk.Change{{Target: r.Token + " message " + strconv.FormatInt(p.ID, 10), Op: "delete"}}}}, nil
		}
		if err := c.ocs(ctx, http.MethodDelete, chat+r.Token+"/"+strconv.FormatInt(p.ID, 10), nil, nil, nil); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("no message %d in %s", p.ID, r.label())
			}
			if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusForbidden) {
				return sdk.Result{}, fmt.Errorf("Talk didn't allow deleting message %d (only recent messages, and others' only as a moderator)", p.ID)
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"conversation": r.Token, "deleted": p.ID})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
