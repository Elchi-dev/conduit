package discord

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
	"unicode"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

type message struct {
	ID          string  `json:"id"`
	Author      user    `json:"author"`
	Content     string  `json:"content"`
	Timestamp   string  `json:"timestamp"`
	Edited      *string `json:"edited_timestamp"`
	Pinned      bool    `json:"pinned"`
	WebhookID   string  `json:"webhook_id"`
	Attachments []struct {
		Filename string `json:"filename"`
	} `json:"attachments"`
	Embeds    []json.RawMessage `json:"embeds"`
	Reference *struct {
		MessageID string `json:"message_id"`
	} `json:"message_reference"`
	Thread *struct {
		ID string `json:"id"`
	} `json:"thread"`
	Reactions []struct {
		Me    bool `json:"me"`
		Emoji struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"emoji"`
	} `json:"reactions"`
}

var (
	customEmojiRe  = regexp.MustCompile(`^([A-Za-z0-9_]{2,32}):(\d{17,20})$`)
	writtenEmojiRe = regexp.MustCompile(`^<a?:([A-Za-z0-9_]{2,32}):(\d{17,20})>$`)
)

// emojiRef is a reaction emoji: a unicode emoji, or a server emoji's name
// and id.
type emojiRef struct{ name, id string }

// api is how the emoji goes in a URL path (escaped by seg).
func (e emojiRef) api() string {
	if e.id != "" {
		return e.name + ":" + e.id
	}
	return e.name
}

func (e emojiRef) String() string {
	if e.id != "" {
		return ":" + e.name + ":"
	}
	return e.name
}

// parseEmoji reads 👍, name:id or <:name:id> (as Discord writes it).
func parseEmoji(s string) (emojiRef, error) {
	s = strings.TrimSpace(s)
	if g := writtenEmojiRe.FindStringSubmatch(s); g != nil {
		return emojiRef{g[1], g[2]}, nil
	}
	if g := customEmojiRe.FindStringSubmatch(s); g != nil {
		return emojiRef{g[1], g[2]}, nil
	}
	if unicodeEmoji(s) {
		return emojiRef{name: s}, nil
	}
	return emojiRef{}, errors.New("the emoji is a unicode emoji such as 👍, or a server emoji as name:id")
}

// unicodeEmoji accepts a short run of symbols: emoji, their joiners,
// variation selectors and skin tones, and the digits, # and * of keycaps.
func unicodeEmoji(s string) bool {
	if s == "" || len(s) > 64 || !utf8.ValidString(s) {
		return false
	}
	n, symbol := 0, false
	for _, r := range s {
		n++
		switch {
		case r < 0x80:
			if !(r >= '0' && r <= '9' || r == '#' || r == '*') {
				return false
			}
		case unicode.IsControl(r) || unicode.IsSpace(r) || unicode.IsLetter(r) || unicode.IsDigit(r):
			return false
		default:
			symbol = true
		}
	}
	return symbol && n <= 16
}

// matches reports whether a reaction on a message is this emoji.
func (e emojiRef) matches(id, name string) bool {
	if e.id != "" {
		return id == e.id
	}
	strip := func(s string) string { return strings.ReplaceAll(s, "️", "") }
	return id == "" && strip(name) == strip(e.name)
}

func (m *Module) getMessage(ctx context.Context, c *conn, ch, id string) (message, error) {
	var ms message
	err := m.do(ctx, c.bot, http.MethodGet, seg("channels", ch, "messages", id), nil, nil, &ms)
	return ms, err
}

// channelAction runs the actions on a channel or one of its messages.
func (m *Module) channelAction(ctx context.Context, c *conn, call sdk.Call, p params) (sdk.Result, error) {
	if call.Action == "archive_thread" {
		return m.archiveThread(ctx, c, p)
	}
	if err := checkID("channel", p.Channel); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "messages":
		limit := p.Limit
		if limit <= 0 {
			limit = 25
		}
		if limit > 100 {
			limit = 100
		}
		q := url.Values{"limit": {strconv.Itoa(limit)}}
		if p.Before != "" {
			if err := checkID("before message", p.Before); err != nil {
				return sdk.Result{}, err
			}
			q.Set("before", p.Before)
		}
		if _, err := m.inServer(ctx, c, p.Channel); err != nil {
			return sdk.Result{}, err
		}
		var ms []message
		if err := m.do(ctx, c.bot, http.MethodGet, seg("channels", p.Channel, "messages"), q, nil, &ms); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ms {
			row := map[string]any{"id": x.ID, "author": clip(x.Author.display(), 100), "text": clip(x.Content, maxShown), "sent": stamp(x.Timestamp)}
			if x.Author.Bot || x.WebhookID != "" {
				row["bot"] = true
			}
			if x.Edited != nil && *x.Edited != "" {
				row["edited"] = stamp(*x.Edited)
			}
			if n := len(x.Attachments); n > 0 {
				names := []string{}
				for i, a := range x.Attachments {
					if i == 10 {
						break
					}
					names = append(names, clip(a.Filename, 100))
				}
				row["attachments"] = map[string]any{"count": n, "names": names}
			}
			if n := len(x.Embeds); n > 0 {
				row["embeds"] = n
			}
			if x.Reference != nil && x.Reference.MessageID != "" {
				row["replyTo"] = x.Reference.MessageID
			}
			if x.Thread != nil && x.Thread.ID != "" {
				row["thread"] = x.Thread.ID
			}
			if x.Pinned {
				row["pinned"] = true
			}
			out = append(out, row)
		}
		res := map[string]any{"channel": p.Channel, "messages": out}
		if len(ms) == limit && len(ms) > 0 {
			res["next"] = ms[len(ms)-1].ID
		}
		return sdk.JSON(res)

	case "reply":
		if err := checkID("message", p.ID); err != nil {
			return sdk.Result{}, err
		}
		msg, err := content(p.Message)
		if err != nil {
			return sdk.Result{}, err
		}
		ch, err := m.inServer(ctx, c, p.Channel)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			where := ch.label()
			after, _ := json.Marshal(map[string]string{"message": msg, "replyTo": p.ID})
			return sdk.Result{Plan: &sdk.Plan{Summary: "Reply in " + where + " (mentions notify no one)",
				Changes: []sdk.Change{{Target: where, Op: "create", After: after}}}}, nil
		}
		body := map[string]any{"content": msg, "allowed_mentions": quiet(),
			"message_reference": map[string]any{"message_id": p.ID, "channel_id": p.Channel, "fail_if_not_exists": true}}
		var out struct {
			ID string `json:"id"`
		}
		if err := m.do(ctx, c.bot, http.MethodPost, seg("channels", p.Channel, "messages"), nil, body, &out); err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]string{"id": out.ID, "channel": p.Channel, "replyTo": p.ID})
		r.Undo = sdk.UndoWith("delete_message", map[string]string{"id": out.ID, "channel": p.Channel}, "Delete the reply")
		return r, err

	case "react", "unreact":
		if err := checkID("message", p.ID); err != nil {
			return sdk.Result{}, err
		}
		e, err := parseEmoji(p.Emoji)
		if err != nil {
			return sdk.Result{}, err
		}
		if _, err := m.inServer(ctx, c, p.Channel); err != nil {
			return sdk.Result{}, err
		}
		ms, err := m.getMessage(ctx, c, p.Channel, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		mine := false
		for _, r := range ms.Reactions {
			if r.Me && e.matches(r.Emoji.ID, r.Emoji.Name) {
				mine = true
			}
		}
		add := call.Action == "react"
		out := map[string]any{"channel": p.Channel, "id": p.ID, "emoji": e.String(), "reacted": add}
		if mine == add {
			out["note"] = "nothing to change: the bot's reaction is already " + map[bool]string{true: "there", false: "absent"}[add]
			return sdk.JSON(out)
		}
		method, undo, desc := http.MethodPut, "unreact", "Remove the reaction "+e.String()
		if !add {
			method, undo, desc = http.MethodDelete, "react", "Add the reaction "+e.String()+" back"
		}
		if err := m.do(ctx, c.bot, method, seg("channels", p.Channel, "messages", p.ID, "reactions", e.api(), "@me"), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(out)
		r.Undo = sdk.UndoWith(undo, map[string]string{"channel": p.Channel, "id": p.ID, "emoji": e.api()}, desc)
		return r, err

	case "pin_message", "unpin_message":
		if err := checkID("message", p.ID); err != nil {
			return sdk.Result{}, err
		}
		if _, err := m.inServer(ctx, c, p.Channel); err != nil {
			return sdk.Result{}, err
		}
		ms, err := m.getMessage(ctx, c, p.Channel, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		pin := call.Action == "pin_message"
		out := map[string]any{"channel": p.Channel, "id": p.ID, "pinned": pin}
		if ms.Pinned == pin {
			out["note"] = "nothing to change: the message is already " + map[bool]string{true: "pinned", false: "not pinned"}[pin]
			return sdk.JSON(out)
		}
		method, undo, desc := http.MethodPut, "unpin_message", "Unpin the message"
		if !pin {
			method, undo, desc = http.MethodDelete, "pin_message", "Pin the message again"
		}
		if err := m.do(ctx, c.bot, method, seg("channels", p.Channel, "messages", "pins", p.ID), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(out)
		r.Undo = sdk.UndoWith(undo, map[string]string{"channel": p.Channel, "id": p.ID}, desc)
		return r, err

	case "create_thread":
		name := strings.TrimSpace(p.Name)
		if name == "" || utf8.RuneCountInString(name) > 100 || strings.ContainsFunc(name, unicode.IsControl) {
			return sdk.Result{}, errors.New("a thread name is 1 to 100 characters on one line")
		}
		if p.ID != "" {
			if err := checkID("message", p.ID); err != nil {
				return sdk.Result{}, err
			}
			if p.Private {
				return sdk.Result{}, errors.New("a thread started from a message is public; leave out the message for a private one")
			}
		}
		switch p.ArchiveAfter {
		case 0, 60, 1440, 4320, 10080:
		default:
			return sdk.Result{}, errors.New("archiveAfter is 60, 1440, 4320 or 10080 minutes")
		}
		body := map[string]any{"name": name}
		if p.ArchiveAfter > 0 {
			body["auto_archive_duration"] = p.ArchiveAfter
		}
		path := seg("channels", p.Channel, "messages", p.ID, "threads")
		if p.ID == "" {
			path = seg("channels", p.Channel, "threads")
			body["type"] = 11
			if p.Private {
				body["type"] = 12
			}
		}
		ch, err := m.inServer(ctx, c, p.Channel)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			where := ch.label()
			sum := fmt.Sprintf("Start the thread %q in %s", name, where)
			if p.ID != "" {
				sum += " from message " + p.ID
			} else if p.Private {
				sum = fmt.Sprintf("Start the private thread %q in %s", name, where)
			}
			after, _ := json.Marshal(body)
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: where, Op: "create", After: after}}}}, nil
		}
		var th channel
		if err := m.do(ctx, c.bot, http.MethodPost, path, nil, body, &th); err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"thread": th.ID, "name": th.Name, "channel": p.Channel, "kind": kinds[th.Type]})
		if th.ID != "" {
			r.Undo = sdk.UndoWith("archive_thread", map[string]string{"thread": th.ID}, "Archive the thread")
		}
		return r, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func isThread(t int) bool { return t == 10 || t == 11 || t == 12 }

func (m *Module) archiveThread(ctx context.Context, c *conn, p params) (sdk.Result, error) {
	if err := checkID("thread", p.Thread); err != nil {
		return sdk.Result{}, err
	}
	th, err := m.inServer(ctx, c, p.Thread)
	if err != nil {
		return sdk.Result{}, err
	}
	if !isThread(th.Type) {
		return sdk.Result{}, fmt.Errorf("#%s is a channel, not a thread", th.Name)
	}
	out := map[string]any{"thread": p.Thread, "name": th.Name, "archived": true}
	if th.Meta != nil && th.Meta.Archived {
		out["note"] = "nothing to change: the thread is already archived"
		return sdk.JSON(out)
	}
	if err := m.do(ctx, c.bot, http.MethodPatch, seg("channels", p.Thread), nil, map[string]any{"archived": true}, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(out)
}

// threads lists the server's active threads, most recently created first.
func (m *Module) threads(ctx context.Context, c *conn) (sdk.Result, error) {
	var r struct {
		Threads []channel `json:"threads"`
	}
	if err := m.do(ctx, c.bot, http.MethodGet, seg("guilds", c.cfg.Guild, "threads", "active"), nil, nil, &r); err != nil {
		return sdk.Result{}, err
	}
	parents := map[string]string{}
	if chs, err := m.guildChannels(ctx, c); err == nil {
		for _, x := range chs {
			parents[x.ID] = x.Name
		}
	}
	out := []map[string]any{}
	for _, t := range r.Threads {
		row := map[string]any{"id": t.ID, "name": t.Name, "channel": t.ParentID, "messages": t.Messages, "members": t.Members, "kind": kinds[t.Type]}
		if n := parents[t.ParentID]; n != "" {
			row["channel"] = "#" + n
		}
		if t.Meta != nil {
			row["created"] = stamp(t.Meta.Created)
			if t.Meta.Locked {
				row["locked"] = true
			}
		}
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := out[i]["created"].(string)
		b, _ := out[j]["created"].(string)
		return a > b
	})
	return sdk.JSON(out)
}
