// Package rocketchat works with a Rocket.Chat server through its REST API
// with a personal access token: the channels the account is in, unread
// counts, recent messages in the rooms the instance allows, and sending
// messages there (undo deletes them).
//
// Reading and sending are limited to the channels and private groups named
// in the instance's allowedRooms; others are listed by name only, so they
// can be added. Direct messages are never read or sent to.
package rocketchat

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
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Rocket.Chat server and account.
type Config struct {
	URL          string   `json:"url"`    // e.g. https://chat.example.com
	UserID       string   `json:"userId"` // the token's user id (not secret)
	Token        string   `json:"token"`  // secret:// personal access token
	AllowedRooms []string `json:"allowedRooms"`
	Fingerprint  string   `json:"fingerprint"`
}

type conn struct {
	api     *rest.Client
	allowed map[string]bool // lowercase room names
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Rocket.Chat module.
func New() *Module { return &Module{} }

var (
	idRe   = regexp.MustCompile(`^[A-Za-z0-9]{10,40}$`)
	roomRe = regexp.MustCompile(`^[\p{L}\p{N}._-]{1,64}$`)
)

const maxText = 5000 // Rocket.Chat's default Message_MaxAllowedSize

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	room := `"room":{"type":"string","description":"Channel or private group name from allowedRooms, e.g. general"}`
	return sdk.Manifest{
		ID: "rocketchat", Name: "Rocket.Chat", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "Rocket.Chat channels and unread counts, recent messages in allowed rooms, and sending messages there.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","userId","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://chat.example.com"},
			"userId":{"type":"string","description":"The user id shown when you create the token (My Account, Personal Access Tokens)"},
			"token":{"type":"string","x-secret":true,"description":"A personal access token, ideally of a bot account"},
			"allowedRooms":{"type":"array","items":{"type":"string"},"description":"Channel and private group names Conduit may read and send to; every other room is off limits"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "channels", Title: "Channels", Description: "Channels and private groups the account is in, and whether each is allowed. Direct messages aren't listed.", Risk: sdk.RiskRead},
			{Name: "unread", Title: "Unread", Description: "Rooms with unread messages, with unread and mention counts (direct messages are named after the other person).", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "messages", Title: "Recent messages", Description: "Recent messages in an allowed room, oldest first.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["room"],"properties":{` + room + `,"limit":{"type":"integer","default":30,"minimum":1,"maximum":100}}}`)},
			{Name: "send_message", Title: "Send a message", Description: "Sends a message (Markdown) to an allowed room, optionally in a thread. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["room","text"],"properties":{` + room + `,"text":{"type":"string","maxLength":5000},"thread":{"type":"string","description":"Message id of the thread to reply in"}}}`)},
			{Name: "delete_message", Title: "Delete a message", Description: "Deletes a message in an allowed room for everyone. The preview names its author and time, not its text.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["room","id"],"properties":{` + room + `,"id":{"type":"string","description":"Message id"}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "channel", Title: "Channels", ListAction: "channels", ViewHint: "table"}},
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
		return errors.New("the address is like https://chat.example.com")
	}
	uid := strings.TrimSpace(c.UserID)
	if !idRe.MatchString(uid) {
		return errors.New("the user id is the one shown with the token (letters and digits)")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	allowed := map[string]bool{}
	for _, r := range c.AllowedRooms {
		r = strings.TrimPrefix(strings.TrimSpace(r), "#")
		if !roomRe.MatchString(r) {
			return fmt.Errorf("%q isn't a room name as in its address, e.g. general", r)
		}
		allowed[strings.ToLower(r)] = true
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
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1")
	ref := c.Token
	api := rest.New(base+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-User-Id", uid)
		r.Header.Set("X-Auth-Token", strings.TrimSpace(t))
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
			return errors.New("the server refused the user id and token")
		case http.StatusForbidden:
			return fmt.Errorf("the server refused: %s", e.Message)
		case http.StatusTooManyRequests:
			return errors.New("the server's rate limit was hit; try again shortly")
		}
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

type room struct {
	ID    string `json:"_id"`
	Name  string `json:"name"`
	FName string `json:"fname"`
	T     string `json:"t"`
}

type message struct {
	ID   string `json:"_id"`
	RID  string `json:"rid"`
	Msg  string `json:"msg"`
	TS   any    `json:"ts"` // an ISO string, or {"$date": ms} from older servers
	T    string `json:"t"`  // system message type
	TMID string `json:"tmid"`
	U    struct {
		Username string `json:"username"`
	} `json:"u"`
}

func when(ts any) string {
	switch v := ts.(type) {
	case string:
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	case map[string]any:
		if ms, ok := v["$date"].(float64); ok {
			return time.UnixMilli(int64(ms)).UTC().Format(time.RFC3339)
		}
	}
	return ""
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func kind(t string) string {
	switch t {
	case "c":
		return "channel"
	case "p":
		return "private"
	case "d":
		return "direct"
	case "l":
		return "livechat"
	}
	return t
}

// room checks a name against the allow-list and looks the room up.
func (c *conn) room(ctx context.Context, raw string) (room, error) {
	name := strings.TrimPrefix(strings.TrimSpace(raw), "#")
	if !roomRe.MatchString(name) {
		return room{}, errors.New("the room is a channel or group name, e.g. general (see channels)")
	}
	if !c.allowed[strings.ToLower(name)] {
		return room{}, fmt.Errorf("%s isn't in this instance's allowedRooms", name)
	}
	var r struct {
		Room room `json:"room"`
	}
	if err := c.do(ctx, http.MethodGet, "/rooms.info", url.Values{"roomName": {name}}, nil, &r); err != nil {
		if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusNotFound) {
			return room{}, fmt.Errorf("no room %s that this account can see", name)
		}
		return room{}, err
	}
	if r.Room.T != "c" && r.Room.T != "p" {
		return room{}, fmt.Errorf("%s isn't a channel or private group", name)
	}
	if !idRe.MatchString(r.Room.ID) || !strings.EqualFold(r.Room.Name, name) {
		return room{}, fmt.Errorf("the server answered with a different room for %s", name)
	}
	return r.Room, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		Username string `json:"username"`
	}
	if err := c.do(ctx, http.MethodGet, "/me", nil, nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + clip(me.Username, 64)
	if len(c.allowed) == 0 {
		return sdk.Health{Status: "degraded", Message: msg + "; no rooms are allowed yet (add names to allowedRooms)"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s, %d allowed rooms", msg, len(c.allowed))}
}

type subscription struct {
	RID          string `json:"rid"`
	Name         string `json:"name"`
	FName        string `json:"fname"`
	T            string `json:"t"`
	Unread       int    `json:"unread"`
	UserMentions int    `json:"userMentions"`
	Alert        bool   `json:"alert"`
	Open         bool   `json:"open"`
	Archived     bool   `json:"archived"`
}

func (c *conn) subscriptions(ctx context.Context) ([]subscription, error) {
	var r struct {
		Update []subscription `json:"update"`
	}
	if err := c.do(ctx, http.MethodGet, "/subscriptions.get", nil, nil, &r); err != nil {
		return nil, err
	}
	return r.Update, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Room   string `json:"room"`
		Text   string `json:"text"`
		Thread string `json:"thread"`
		ID     string `json:"id"`
		Limit  int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "channels":
		subs, err := c.subscriptions(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range subs {
			if (s.T != "c" && s.T != "p") || !roomRe.MatchString(s.Name) {
				continue
			}
			row := map[string]any{"name": s.Name, "type": kind(s.T), "allowed": c.allowed[strings.ToLower(s.Name)]}
			if s.FName != "" && s.FName != s.Name {
				row["displayName"] = clip(s.FName, 100)
			}
			if s.Archived {
				row["archived"] = true
			}
			out = append(out, row)
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
		return sdk.JSON(out)

	case "unread":
		subs, err := c.subscriptions(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		total := 0
		for _, s := range subs {
			if s.Unread <= 0 && !s.Alert {
				continue
			}
			row := map[string]any{"room": clip(s.Name, 100), "type": kind(s.T), "unread": s.Unread}
			if s.UserMentions > 0 {
				row["mentions"] = s.UserMentions
			}
			if s.T == "c" || s.T == "p" {
				row["allowed"] = c.allowed[strings.ToLower(s.Name)]
			}
			total += s.Unread
			out = append(out, row)
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["unread"].(int) > out[j]["unread"].(int) })
		return sdk.JSON(map[string]any{"total": total, "rooms": out})

	case "messages":
		r, err := c.room(ctx, p.Room)
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
		ep := "/channels.history"
		if r.T == "p" {
			ep = "/groups.history"
		}
		var res struct {
			Messages []message `json:"messages"`
		}
		if err := c.do(ctx, http.MethodGet, ep, url.Values{"roomId": {r.ID}, "count": {strconv.Itoa(n)}}, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		msgs := []map[string]any{}
		for i := len(res.Messages) - 1; i >= 0; i-- { // the server answers newest first
			e := res.Messages[i]
			row := map[string]any{"id": e.ID, "from": e.U.Username, "when": when(e.TS)}
			if e.T != "" {
				row["system"] = e.T
			} else {
				row["text"] = clip(e.Msg, 4000)
			}
			if e.TMID != "" {
				row["thread"] = e.TMID
			}
			msgs = append(msgs, row)
		}
		return sdk.JSON(map[string]any{"room": r.Name, "messages": msgs})

	case "send_message":
		text := strings.TrimSpace(p.Text)
		if text == "" {
			return sdk.Result{}, errors.New("write something to send")
		}
		if len([]rune(text)) > maxText {
			return sdk.Result{}, fmt.Errorf("the message is longer than Rocket.Chat allows (%d characters)", maxText)
		}
		thread := strings.TrimSpace(p.Thread)
		if thread != "" && !idRe.MatchString(thread) {
			return sdk.Result{}, errors.New("thread is a message id (letters and digits)")
		}
		r, err := c.room(ctx, p.Room)
		if err != nil {
			return sdk.Result{}, err
		}
		target := "#" + r.Name
		if call.DryRun {
			after, _ := json.Marshal(map[string]string{"text": text, "thread": thread})
			sum := "Send a message to " + target
			if thread != "" {
				sum = "Reply in a thread in " + target
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: "create", After: after}}}}, nil
		}
		msg := map[string]string{"rid": r.ID, "msg": text}
		if thread != "" {
			msg["tmid"] = thread
		}
		var out struct {
			Message message `json:"message"`
		}
		if err := c.do(ctx, http.MethodPost, "/chat.sendMessage", nil, map[string]any{"message": msg}, &out); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]string{"room": r.Name, "id": out.Message.ID, "when": when(out.Message.TS)})
		if idRe.MatchString(out.Message.ID) {
			res.Undo = sdk.UndoWith("delete_message", map[string]string{"room": r.Name, "id": out.Message.ID}, "Delete the message in "+target)
		}
		return res, err

	case "delete_message":
		id := strings.TrimSpace(p.ID)
		if !idRe.MatchString(id) {
			return sdk.Result{}, errors.New("id is a message id (letters and digits)")
		}
		r, err := c.room(ctx, p.Room)
		if err != nil {
			return sdk.Result{}, err
		}
		var got struct {
			Message message `json:"message"`
		}
		if err := c.do(ctx, http.MethodGet, "/chat.getMessage", url.Values{"msgId": {id}}, nil, &got); err != nil {
			if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("no message %s", id)
			}
			return sdk.Result{}, err
		}
		if got.Message.RID != r.ID {
			return sdk.Result{}, fmt.Errorf("message %s isn't in #%s", id, r.Name)
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]string{"from": got.Message.U.Username, "when": when(got.Message.TS)})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete %s's message from %s in #%s", got.Message.U.Username, when(got.Message.TS), r.Name),
				Changes: []sdk.Change{{Target: "#" + r.Name + " " + id, Op: "delete", Before: before}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/chat.delete", nil, map[string]string{"roomId": r.ID, "msgId": id}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"room": r.Name, "deleted": id})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
