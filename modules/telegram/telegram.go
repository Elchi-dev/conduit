// Package telegram works with a Telegram bot through the Bot API: who the bot
// is, recent messages in the chats it is allowed to read, chat details,
// sending, editing, deleting and pinning messages.
//
// The bot only ever reads and writes the chats listed in the instance's
// allow-list. Updates are fetched with a bounded, non-blocking getUpdates
// (timeout 0) whose offset is kept in memory, and the messages from allowed
// chats are kept in a small in-memory buffer so that reading them twice
// still shows them.
package telegram

import (
	"bytes"
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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one bot.
type Config struct {
	Token        string   `json:"token"`        // secret:// bot token from @BotFather
	AllowedChats chatList `json:"allowedChats"` // chat ids the bot may read and write
}

// chatList accepts chat ids written as JSON numbers or strings.
type chatList []string

func (l *chatList) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return errors.New("allowedChats is a list of chat ids")
	}
	out := chatList{}
	for _, r := range raw {
		var s string
		if json.Unmarshal(r, &s) != nil {
			var n json.Number
			d := json.NewDecoder(bytes.NewReader(r))
			d.UseNumber()
			if d.Decode(&n) != nil {
				return errors.New("allowedChats is a list of chat ids")
			}
			s = n.String()
		}
		out = append(out, strings.TrimSpace(s))
	}
	*l = out
	return nil
}

const (
	defaultBase = "https://api.telegram.org"
	maxBuffer   = 500            // messages kept per instance
	maxPages    = 5              // getUpdates calls per read, 100 updates each
	deleteLimit = 48 * time.Hour // bots can delete their messages for 48 hours
)

var (
	chatRe  = regexp.MustCompile(`^-?[0-9]{1,20}$`)
	tokenRe = regexp.MustCompile(`^[0-9]{1,20}:[A-Za-z0-9_-]{20,100}$`)
)

type msgKey struct {
	chat int64
	id   int64
}

type conn struct {
	h       sdk.Host
	token   string
	base    string
	http    *http.Client
	allowed map[int64]bool

	fetch  sync.Mutex // one getUpdates at a time
	mu     sync.Mutex
	offset int64
	buf    []message
	sent   map[msgKey]string // text of messages this instance sent or edited, for undoing edits
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.telegram.org (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Telegram module.
func New() *Module { return &Module{} }

func (m *Module) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	chat := `"chat":{"type":"string","description":"Chat id from allowedChats (negative for groups and channels)"}`
	msg := `"message":{"type":"integer","description":"Message id"}`
	return sdk.Manifest{
		ID: "telegram", Name: "Telegram", Version: "0.1.0", Category: "Communication", Icon: "send",
		Description: "A Telegram bot: recent messages in allowed chats, chat details, send, edit, delete and pin messages.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"Bot token from @BotFather (/newbot or /token)"},
			"allowedChats":{"type":"array","items":{"type":"string"},"description":"Chat ids the bot may read and write; every other chat is ignored. A group or channel id starts with -100."}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "me", Title: "Bot", Description: "The bot's id, username and what it is allowed to do.", Risk: sdk.RiskRead},
			{Name: "messages", Title: "Recent messages", Description: "Recent messages in the allowed chats (newest last). Updates from other chats are dropped; their ids are listed so you can add them.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + chat + `,"limit":{"type":"integer","default":20,"maximum":100}}}`)},
			{Name: "chat", Title: "Chat details", Description: "An allowed chat's title, type, description, member count and pinned message.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["chat"],"properties":{` + chat + `}}`)},
			{Name: "send_message", Title: "Send a message", Description: "Sends a message to an allowed chat. Undo deletes it (within 48 hours).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["chat","text"],"properties":{` + chat + `,"text":{"type":"string","maxLength":4096},"parseMode":{"type":"string","enum":["","MarkdownV2","HTML"]},"silent":{"type":"boolean","description":"Deliver without a sound"},"replyTo":{"type":"integer","description":"Message id to reply to"}}}`)},
			{Name: "edit_message", Title: "Edit a message", Description: "Replaces the text of a message the bot sent. Undo puts the old text back when Conduit knows it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["chat","message","text"],"properties":{` + chat + `,` + msg + `,"text":{"type":"string","maxLength":4096},"parseMode":{"type":"string","enum":["","MarkdownV2","HTML"]}}}`)},
			{Name: "delete_message", Title: "Delete a message", Description: "Deletes a message for everyone. Bots can delete their own messages for 48 hours, others' only as an admin. Can't be undone.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["chat","message"],"properties":{` + chat + `,` + msg + `,"sentAt":{"type":"integer","description":"When it was sent (unix seconds); set by undo, to refuse after 48 hours"}}}`)},
			{Name: "pin_message", Title: "Pin a message", Description: "Pins a message in an allowed chat (silently unless notify). Undo unpins it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["chat","message"],"properties":{` + chat + `,` + msg + `,"notify":{"type":"boolean","description":"Notify members about the pin"}}}`)},
			{Name: "unpin_message", Title: "Unpin a message", Description: "Unpins a message (the most recent pin when no message is given). Undo pins it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["chat"],"properties":{` + chat + `,` + msg + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the bot token in the vault and enter its secret:// reference")
	}
	allowed := map[int64]bool{}
	for _, s := range c.AllowedChats {
		if !chatRe.MatchString(s) {
			return fmt.Errorf("%q isn't a chat id; ids are numbers, like 123456789 or -1001234567890", s)
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("%q isn't a chat id", s)
		}
		allowed[n] = true
	}
	base := defaultBase
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 20*time.Second)
	}
	m.set.Put(id, &conn{h: h, token: c.Token, base: base, http: rest.SameHostOnly(hc), allowed: allowed, sent: map[msgKey]string{}})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// apiError is a Bot API error answer.
type apiError struct {
	Code        int
	Description string
	RetryAfter  int
}

func (e *apiError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("Telegram: %s (retry in %d s)", e.Description, e.RetryAfter)
	}
	return "Telegram: " + e.Description
}

func isCode(err error, code int) bool {
	var e *apiError
	return errors.As(err, &e) && e.Code == code
}

// call runs a Bot API method. The token is part of the URL, so transport
// errors are rewritten without the URL to keep it out of messages and logs.
func (c *conn) call(ctx context.Context, method string, params map[string]any, out any) error {
	tok, err := c.h.Secret(ctx, c.token)
	if err != nil {
		return err
	}
	tok = strings.TrimSpace(tok)
	if !tokenRe.MatchString(tok) {
		return errors.New("the stored bot token doesn't look like one from @BotFather (digits, a colon, then letters)")
	}
	if params == nil {
		params = map[string]any{}
	}
	body, _ := json.Marshal(params)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/bot"+tok+"/"+method, bytes.NewReader(body))
	if err != nil {
		return errors.New("couldn't build the Telegram request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	res, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("couldn't reach Telegram: %s", strings.ReplaceAll(err.Error(), tok, "[token]"))
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("reading Telegram's answer: %w", err)
	}
	var env struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		ErrorCode   int             `json:"error_code"`
		Description string          `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return &apiError{Code: res.StatusCode, Description: "unexpected answer (" + res.Status + ")"}
	}
	if !env.OK {
		code := env.ErrorCode
		if code == 0 {
			code = res.StatusCode
		}
		d := env.Description
		if d == "" {
			d = res.Status
		}
		return &apiError{Code: code, Description: strings.ReplaceAll(d, tok, "[token]"), RetryAfter: env.Parameters.RetryAfter}
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return errors.New("unexpected answer from Telegram")
		}
	}
	return nil
}

type user struct {
	ID                      int64  `json:"id"`
	IsBot                   bool   `json:"is_bot"`
	FirstName               string `json:"first_name"`
	LastName                string `json:"last_name"`
	Username                string `json:"username"`
	CanJoinGroups           bool   `json:"can_join_groups"`
	CanReadAllGroupMessages bool   `json:"can_read_all_group_messages"`
}

func (u *user) name() string {
	if u == nil {
		return ""
	}
	return strings.TrimSpace(u.FirstName + " " + u.LastName)
}

type chatInfo struct {
	ID            int64    `json:"id"`
	Type          string   `json:"type"`
	Title         string   `json:"title"`
	Username      string   `json:"username"`
	FirstName     string   `json:"first_name"`
	LastName      string   `json:"last_name"`
	Description   string   `json:"description"`
	PinnedMessage *message `json:"pinned_message"`
}

type message struct {
	MessageID  int64     `json:"message_id"`
	Date       int64     `json:"date"`
	EditDate   int64     `json:"edit_date"`
	Chat       chatInfo  `json:"chat"`
	From       *user     `json:"from"`
	SenderChat *chatInfo `json:"sender_chat"`
	Text       string    `json:"text"`
	Caption    string    `json:"caption"`
	ReplyTo    *struct {
		MessageID int64 `json:"message_id"`
	} `json:"reply_to_message"`
	Photo    []json.RawMessage `json:"photo"`
	Document *struct {
		FileName string `json:"file_name"`
	} `json:"document"`
	Sticker *struct {
		Emoji string `json:"emoji"`
	} `json:"sticker"`
	Voice json.RawMessage `json:"voice"`
	Video json.RawMessage `json:"video"`
}

type update struct {
	UpdateID          int64    `json:"update_id"`
	Message           *message `json:"message"`
	EditedMessage     *message `json:"edited_message"`
	ChannelPost       *message `json:"channel_post"`
	EditedChannelPost *message `json:"edited_channel_post"`
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func msgOut(m message) map[string]any {
	out := map[string]any{"chat": strconv.FormatInt(m.Chat.ID, 10), "message": m.MessageID, "date": time.Unix(m.Date, 0).UTC().Format(time.RFC3339)}
	if m.Chat.Title != "" {
		out["chatTitle"] = m.Chat.Title
	}
	if m.From != nil {
		out["from"] = m.From.name()
		if m.From.Username != "" {
			out["fromUsername"] = m.From.Username
		}
		if m.From.IsBot {
			out["fromBot"] = true
		}
	} else if m.SenderChat != nil {
		out["from"] = m.SenderChat.Title
	}
	text := m.Text
	if text == "" {
		text = m.Caption
	}
	if text != "" {
		out["text"] = clip(text, 4096)
	}
	kind := ""
	switch {
	case len(m.Photo) > 0:
		kind = "photo"
	case m.Document != nil:
		kind = "document"
		if m.Document.FileName != "" {
			out["fileName"] = clip(m.Document.FileName, 200)
		}
	case m.Sticker != nil:
		kind = "sticker"
		if m.Sticker.Emoji != "" {
			out["text"] = m.Sticker.Emoji
		}
	case len(m.Voice) > 0:
		kind = "voice"
	case len(m.Video) > 0:
		kind = "video"
	}
	if kind != "" {
		out["attachment"] = kind
	}
	if m.EditDate > 0 {
		out["edited"] = time.Unix(m.EditDate, 0).UTC().Format(time.RFC3339)
	}
	if m.ReplyTo != nil {
		out["replyTo"] = m.ReplyTo.MessageID
	}
	return out
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u user
	if err := c.call(ctx, "getMe", nil, &u); err != nil {
		if isCode(err, http.StatusUnauthorized) || isCode(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "Telegram refused the bot token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as @" + u.Username
	if len(c.allowed) == 0 {
		return sdk.Health{Status: "degraded", Message: msg + "; no chats are allowed yet, so it can't read or send anything"}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Chat      json.RawMessage `json:"chat"`
	Message   int64           `json:"message"`
	Text      string          `json:"text"`
	ParseMode string          `json:"parseMode"`
	Silent    bool            `json:"silent"`
	Notify    bool            `json:"notify"`
	ReplyTo   int64           `json:"replyTo"`
	Limit     int             `json:"limit"`
	SentAt    int64           `json:"sentAt"`
}

// chatID reads a chat id (string or number) and checks it's allowed.
func (c *conn) chatID(raw json.RawMessage, required bool) (int64, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" || s == `""` {
		if required {
			return 0, errors.New("say which chat (one of allowedChats)")
		}
		return 0, nil
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		s = strings.TrimSpace(str)
	}
	if !chatRe.MatchString(s) {
		return 0, errors.New("a chat is its numeric id, like 123456789 or -1001234567890")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, errors.New("a chat is its numeric id")
	}
	if !c.allowed[n] {
		return 0, fmt.Errorf("chat %d isn't in this instance's allowedChats", n)
	}
	return n, nil
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func checkText(text, mode string) error {
	if strings.TrimSpace(text) == "" {
		return errors.New("the text is empty")
	}
	if n := len([]rune(text)); n > 4096 {
		return fmt.Errorf("the text is %d characters; Telegram allows 4096", n)
	}
	switch mode {
	case "", "MarkdownV2", "HTML":
	default:
		return errors.New("parseMode is MarkdownV2, HTML or empty for plain text")
	}
	return nil
}

func (c *conn) chatLabel(id int64) string { return "chat " + strconv.FormatInt(id, 10) }

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
	case "me":
		var u user
		if err := c.call(ctx, "getMe", nil, &u); err != nil {
			return sdk.Result{}, err
		}
		chats := []string{}
		for id := range c.allowed {
			chats = append(chats, strconv.FormatInt(id, 10))
		}
		sort.Strings(chats)
		return sdk.JSON(map[string]any{"id": u.ID, "username": u.Username, "name": u.name(), "canJoinGroups": u.CanJoinGroups, "canReadAllGroupMessages": u.CanReadAllGroupMessages, "allowedChats": chats})

	case "messages":
		chat, err := c.chatID(p.Chat, false)
		if err != nil {
			return sdk.Result{}, err
		}
		if len(c.allowed) == 0 {
			return sdk.Result{}, errors.New("no chats are allowed yet; add chat ids to allowedChats")
		}
		ignored, err := c.pull(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 20
		}
		c.mu.Lock()
		out := []map[string]any{}
		for i := len(c.buf) - 1; i >= 0 && len(out) < limit; i-- {
			if chat == 0 || c.buf[i].Chat.ID == chat {
				out = append(out, msgOut(c.buf[i]))
			}
		}
		c.mu.Unlock()
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
		res := map[string]any{"messages": out}
		if len(ignored) > 0 {
			res["ignoredChats"] = ignored
		}
		return sdk.JSON(res)

	case "chat":
		chat, err := c.chatID(p.Chat, true)
		if err != nil {
			return sdk.Result{}, err
		}
		var ci chatInfo
		if err := c.call(ctx, "getChat", map[string]any{"chat_id": chat}, &ci); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"id": strconv.FormatInt(ci.ID, 10), "type": ci.Type}
		if ci.Title != "" {
			out["title"] = ci.Title
		} else {
			out["title"] = strings.TrimSpace(ci.FirstName + " " + ci.LastName)
		}
		if ci.Username != "" {
			out["username"] = ci.Username
		}
		if ci.Description != "" {
			out["description"] = clip(ci.Description, 1000)
		}
		if ci.PinnedMessage != nil {
			out["pinned"] = msgOut(*ci.PinnedMessage)
		}
		if ci.Type != "private" {
			var n int
			if err := c.call(ctx, "getChatMemberCount", map[string]any{"chat_id": chat}, &n); err == nil {
				out["members"] = n
			}
		}
		return sdk.JSON(out)

	case "send_message":
		return m.send(ctx, c, call, p)
	case "edit_message":
		return c.edit(ctx, call, p)
	case "delete_message":
		return m.del(ctx, c, call, p)
	case "pin_message", "unpin_message":
		return c.pin(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// pull fetches pending updates without waiting (timeout 0), at most
// maxPages pages, keeps messages from allowed chats and confirms the rest by
// moving the offset past them. It returns the chats that were ignored.
func (c *conn) pull(ctx context.Context) ([]map[string]any, error) {
	c.fetch.Lock()
	defer c.fetch.Unlock()
	ignored := map[int64]string{}
	for page := 0; page < maxPages; page++ {
		c.mu.Lock()
		off := c.offset
		c.mu.Unlock()
		params := map[string]any{"limit": 100, "timeout": 0}
		if off > 0 {
			params["offset"] = off
		}
		var ups []update
		if err := c.call(ctx, "getUpdates", params, &ups); err != nil {
			if isCode(err, http.StatusConflict) {
				return nil, errors.New("Telegram won't hand out updates: the bot has a webhook set, or another program is reading its updates")
			}
			return nil, err
		}
		c.mu.Lock()
		for _, u := range ups {
			if u.UpdateID >= c.offset {
				c.offset = u.UpdateID + 1
			}
			msg, edited := u.Message, false
			switch {
			case u.ChannelPost != nil:
				msg = u.ChannelPost
			case u.EditedMessage != nil:
				msg, edited = u.EditedMessage, true
			case u.EditedChannelPost != nil:
				msg, edited = u.EditedChannelPost, true
			}
			if msg == nil {
				continue
			}
			if !c.allowed[msg.Chat.ID] {
				ignored[msg.Chat.ID] = msg.Chat.Type
				continue
			}
			c.remember(*msg, edited)
		}
		c.mu.Unlock()
		if len(ups) < 100 {
			break
		}
	}
	out := []map[string]any{}
	for id, typ := range ignored {
		out = append(out, map[string]any{"id": strconv.FormatInt(id, 10), "type": typ})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
	return out, nil
}

// remember adds a message to the buffer (or replaces an edited one). c.mu is held.
func (c *conn) remember(msg message, edited bool) {
	if edited {
		for i := range c.buf {
			if c.buf[i].Chat.ID == msg.Chat.ID && c.buf[i].MessageID == msg.MessageID {
				c.buf[i] = msg
				return
			}
		}
	}
	c.buf = append(c.buf, msg)
	if len(c.buf) > maxBuffer {
		c.buf = append([]message(nil), c.buf[len(c.buf)-maxBuffer:]...)
	}
}

func (m *Module) send(ctx context.Context, c *conn, call sdk.Call, p input) (sdk.Result, error) {
	chat, err := c.chatID(p.Chat, true)
	if err != nil {
		return sdk.Result{}, err
	}
	if err := checkText(p.Text, p.ParseMode); err != nil {
		return sdk.Result{}, err
	}
	if p.ReplyTo < 0 {
		return sdk.Result{}, errors.New("replyTo is a message id")
	}
	if call.DryRun {
		sum := fmt.Sprintf("Send a message to chat %d", chat)
		if p.Silent {
			sum += " silently"
		}
		after := map[string]any{"text": p.Text}
		if p.ParseMode != "" {
			after["parseMode"] = p.ParseMode
		}
		if p.ReplyTo > 0 {
			after["replyTo"] = p.ReplyTo
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: c.chatLabel(chat), Op: "send", After: mustJSON(after)}}}}, nil
	}
	params := map[string]any{"chat_id": chat, "text": p.Text}
	if p.ParseMode != "" {
		params["parse_mode"] = p.ParseMode
	}
	if p.Silent {
		params["disable_notification"] = true
	}
	if p.ReplyTo > 0 {
		params["reply_parameters"] = map[string]any{"message_id": p.ReplyTo, "allow_sending_without_reply": true}
	}
	var sent message
	if err := c.call(ctx, "sendMessage", params, &sent); err != nil {
		return sdk.Result{}, err
	}
	c.mu.Lock()
	c.sent[msgKey{chat, sent.MessageID}] = sent.Text
	c.mu.Unlock()
	at := sent.Date
	if at == 0 {
		at = m.now().Unix()
	}
	res, err := sdk.JSON(map[string]any{"chat": strconv.FormatInt(chat, 10), "message": sent.MessageID, "date": time.Unix(at, 0).UTC().Format(time.RFC3339)})
	res.Undo = sdk.UndoWith("delete_message", map[string]any{"chat": strconv.FormatInt(chat, 10), "message": sent.MessageID, "sentAt": at}, fmt.Sprintf("Delete the message sent to chat %d", chat))
	return res, err
}

func (c *conn) edit(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	chat, err := c.chatID(p.Chat, true)
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Message <= 0 {
		return sdk.Result{}, errors.New("say which message (its id)")
	}
	if err := checkText(p.Text, p.ParseMode); err != nil {
		return sdk.Result{}, err
	}
	c.mu.Lock()
	before, known := c.sent[msgKey{chat, p.Message}]
	if !known {
		for _, b := range c.buf {
			if b.Chat.ID == chat && b.MessageID == p.Message && b.From != nil && b.From.IsBot {
				before, known = b.Text, true
			}
		}
	}
	c.mu.Unlock()
	if call.DryRun {
		ch := sdk.Change{Target: fmt.Sprintf("message %d in chat %d", p.Message, chat), Op: "update", After: mustJSON(map[string]any{"text": p.Text})}
		sum := fmt.Sprintf("Replace the text of message %d in chat %d", p.Message, chat)
		if known {
			ch.Before = mustJSON(map[string]any{"text": before})
		} else {
			sum += " (Conduit doesn't know the current text, so this can't be undone)"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{ch}}}, nil
	}
	params := map[string]any{"chat_id": chat, "message_id": p.Message, "text": p.Text}
	if p.ParseMode != "" {
		params["parse_mode"] = p.ParseMode
	}
	var edited message
	if err := c.call(ctx, "editMessageText", params, &edited); err != nil {
		return sdk.Result{}, err
	}
	c.mu.Lock()
	c.sent[msgKey{chat, p.Message}] = edited.Text
	c.mu.Unlock()
	res, err := sdk.JSON(map[string]any{"chat": strconv.FormatInt(chat, 10), "message": p.Message, "edited": true})
	if known && before != "" {
		res.Undo = sdk.UndoWith("edit_message", map[string]any{"chat": strconv.FormatInt(chat, 10), "message": p.Message, "text": before}, fmt.Sprintf("Put the old text of message %d back", p.Message))
	}
	return res, err
}

func (m *Module) del(ctx context.Context, c *conn, call sdk.Call, p input) (sdk.Result, error) {
	chat, err := c.chatID(p.Chat, true)
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Message <= 0 {
		return sdk.Result{}, errors.New("say which message (its id)")
	}
	if p.SentAt > 0 && m.now().Sub(time.Unix(p.SentAt, 0)) > deleteLimit {
		return sdk.Result{}, errors.New("the message is more than 48 hours old; Telegram only lets a bot delete it as a group admin")
	}
	if call.DryRun {
		ch := sdk.Change{Target: fmt.Sprintf("message %d in chat %d", p.Message, chat), Op: "delete"}
		c.mu.Lock()
		if t, ok := c.sent[msgKey{chat, p.Message}]; ok {
			ch.Before = mustJSON(map[string]any{"text": t})
		}
		c.mu.Unlock()
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete message %d in chat %d for everyone", p.Message, chat), Changes: []sdk.Change{ch}}}, nil
	}
	var ok bool
	if err := c.call(ctx, "deleteMessage", map[string]any{"chat_id": chat, "message_id": p.Message}, &ok); err != nil {
		if isCode(err, http.StatusBadRequest) {
			return sdk.Result{}, fmt.Errorf("%w (a bot can delete its own messages for 48 hours, others' only as an admin)", err)
		}
		return sdk.Result{}, err
	}
	c.mu.Lock()
	delete(c.sent, msgKey{chat, p.Message})
	for i := range c.buf {
		if c.buf[i].Chat.ID == chat && c.buf[i].MessageID == p.Message {
			c.buf = append(c.buf[:i], c.buf[i+1:]...)
			break
		}
	}
	c.mu.Unlock()
	return sdk.JSON(map[string]any{"chat": strconv.FormatInt(chat, 10), "message": p.Message, "deleted": true})
}

func (c *conn) pin(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	pinning := call.Action == "pin_message"
	chat, err := c.chatID(p.Chat, true)
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Message < 0 || (pinning && p.Message == 0) {
		return sdk.Result{}, errors.New("say which message (its id)")
	}
	target := p.Message
	if !pinning && target == 0 {
		// Unpin the most recent pin: find it so undo can pin it again.
		var ci chatInfo
		if err := c.call(ctx, "getChat", map[string]any{"chat_id": chat}, &ci); err != nil {
			return sdk.Result{}, err
		}
		if ci.PinnedMessage == nil {
			return sdk.JSON(map[string]any{"chat": strconv.FormatInt(chat, 10), "note": "nothing is pinned"})
		}
		target = ci.PinnedMessage.MessageID
	}
	label := fmt.Sprintf("message %d in chat %d", target, chat)
	if call.DryRun {
		verb, op := "Unpin", "unpin"
		if pinning {
			verb, op = "Pin", "pin"
			if p.Notify {
				verb = "Pin (notifying members)"
			}
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + label, Changes: []sdk.Change{{Target: label, Op: op, Before: mustJSON(map[string]any{"pinned": !pinning}), After: mustJSON(map[string]any{"pinned": pinning})}}}}, nil
	}
	var ok bool
	if pinning {
		err = c.call(ctx, "pinChatMessage", map[string]any{"chat_id": chat, "message_id": target, "disable_notification": !p.Notify}, &ok)
	} else {
		err = c.call(ctx, "unpinChatMessage", map[string]any{"chat_id": chat, "message_id": target}, &ok)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	in := map[string]any{"chat": strconv.FormatInt(chat, 10), "message": target}
	res, err := sdk.JSON(map[string]any{"chat": strconv.FormatInt(chat, 10), "message": target, "pinned": pinning})
	if pinning {
		res.Undo = sdk.UndoWith("unpin_message", in, "Unpin "+label)
	} else {
		res.Undo = sdk.UndoWith("pin_message", in, "Pin "+label+" again")
	}
	return res, err
}
