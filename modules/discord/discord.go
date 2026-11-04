// Package discord works with a Discord server through a bot you invite (the
// official bot API, v10) or a channel webhook: posting and replying,
// reactions, pins and threads, reading channels and members, and moderation
// (timeouts, kicks and bans) with previews and undo.
package discord

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
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Discord connection's settings. Either or both may be set.
type Config struct {
	Webhook  string `json:"webhook"`  // secret:// webhook URL
	BotToken string `json:"botToken"` // secret:// bot token
	Guild    string `json:"guild"`    // server id for status, threads, members and moderation
	API      string `json:"api"`      // default https://discord.com/api/v10 (tests)
}

type conn struct {
	cfg  Config
	bot  *rest.Client
	http *http.Client
	host sdk.Host

	mu    sync.Mutex
	botID string
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
	// sleep waits out a rate limit; tests replace it.
	sleep func(context.Context, time.Duration) error
}

// New returns the Discord module.
func New() *Module { return &Module{} }

const (
	maxContent = 2000 // characters in a message
	maxShown   = 1000 // characters of a message shown when reading
	// maxRetryWait is the longest Retry-After waited out (once) before a
	// rate-limited request is given up.
	maxRetryWait = 5 * time.Second
)

var (
	// idRe matches a snowflake id: Discord ids are 17 to 20 digits.
	idRe = regexp.MustCompile(`^\d{17,20}$`)
	// wildcardRe matches the mentions that notify a whole server or channel.
	wildcardRe = regexp.MustCompile(`(?i)@(everyone|here)\b`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	ch := `"channel":{"type":"string","description":"Channel id (Developer Mode, right-click the channel, Copy Channel ID)"}`
	msg := `"id":{"type":"string","description":"Message id (right-click the message, Copy Message ID)"}`
	emoji := `"emoji":{"type":"string","description":"A unicode emoji such as 👍, or a server emoji as name:id"}`
	user := `"user":{"type":"string","description":"User id (right-click the member, Copy User ID)"}`
	reason := `"reason":{"type":"string","maxLength":400,"description":"Kept in the server's audit log after \"Conduit:\""}`
	return sdk.Manifest{
		ID: "discord", Name: "Discord", Version: "0.2.0", Category: "Communication", Icon: "chat",
		Description: "Post, reply, react and pin in your server, read channels, threads and members, and moderate with previews and undo.",
		Presets:     []string{"gamer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"webhook":{"type":"string","x-secret":true,"description":"A channel webhook URL (Channel settings, Integrations); enough for posting"},
			"botToken":{"type":"string","x-secret":true,"description":"The token of a bot you invited to your server (Discord Developer Portal, Bot), for everything beyond posting through the webhook"},
			"guild":{"type":"string","description":"Server id (Developer Mode, right-click the server, Copy Server ID)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "send", Title: "Post a message", Description: "Through the webhook, or with the bot when a channel is given. Mentions notify no one. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["message"],"properties":{"message":{"type":"string","format":"textarea","maxLength":2000},"channel":{"type":"string","description":"Channel id (bot only)"}}}`)},
			{Name: "delete_message", Title: "Delete a message", Description: "With the bot when a channel is given, otherwise one the webhook posted.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + msg + `,` + ch + `}}`)},
			{Name: "server", Title: "Server status", Description: "Members and how many are online.", Risk: sdk.RiskRead},
			{Name: "channels", Title: "Channels", Risk: sdk.RiskRead},
			{Name: "messages", Title: "Recent messages", Description: "The latest messages in a channel the bot can see, newest first: author, text (shortened), times, and attachment names. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["channel"],"properties":{` + ch + `,"limit":{"type":"integer","default":25,"minimum":1,"maximum":100},"before":{"type":"string","description":"Only messages older than this message id (for the next page)"}}}`)},
			{Name: "threads", Title: "Active threads", Description: "Threads open in the server right now, with their channel and activity.", Risk: sdk.RiskRead},
			{Name: "reply", Title: "Reply to a message", Description: "Mentions notify no one, the person replied to included. Undo deletes the reply.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["channel","id","message"],"properties":{` + ch + `,` + msg + `,"message":{"type":"string","format":"textarea","maxLength":2000}}}`)},
			{Name: "react", Title: "Add a reaction", Description: "The bot's own reaction. Undo removes it.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["channel","id","emoji"],"properties":{` + ch + `,` + msg + `,` + emoji + `}}`)},
			{Name: "unreact", Title: "Remove a reaction", Description: "Only the bot's own reaction. Undo adds it back.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["channel","id","emoji"],"properties":{` + ch + `,` + msg + `,` + emoji + `}}`)},
			{Name: "create_thread", Title: "Start a thread", Description: "From a message, or on its own in a channel. Undo archives it, keeping what was said.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["channel","name"],"properties":{` + ch + `,"id":{"type":"string","description":"Start it from this message (optional)"},"name":{"type":"string","maxLength":100},"private":{"type":"boolean","description":"A private thread (only without a message)"},"archiveAfter":{"type":"integer","enum":[60,1440,4320,10080],"description":"Minutes of quiet before it's archived"}}}`)},
			{Name: "archive_thread", Title: "Archive a thread", Description: "Closes it to new messages until someone posts; everything said stays.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["thread"],"properties":{"thread":{"type":"string","description":"Thread id"}}}`)},
			{Name: "pin_message", Title: "Pin a message", Description: "Undo unpins it.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["channel","id"],"properties":{` + ch + `,` + msg + `}}`)},
			{Name: "unpin_message", Title: "Unpin a message", Description: "Undo pins it again.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["channel","id"],"properties":{` + ch + `,` + msg + `}}`)},
			{Name: "members", Title: "Members", Description: "Display names, roles and when they joined, up to 1000 a page. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":100,"minimum":1,"maximum":1000},"after":{"type":"string","description":"Continue after this user id (the previous page's next)"}}}`)},
			{Name: "timeout_member", Title: "Time out a member", Description: "They can read but not talk, react or join voice until it ends (at most 28 days). Undo lifts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["user"],"properties":{` + user + `,"duration":{"type":"string","description":"How long, like 10m, 2h or 7d (at most 28d)"},"until":{"type":"string","format":"date-time","description":"Or when it ends"},` + reason + `}}`)},
			{Name: "remove_timeout", Title: "Lift a timeout", Description: "Lets the member talk again now. Undo puts the timeout back until it would have ended.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["user"],"properties":{` + user + `,` + reason + `}}`)},
			{Name: "kick_member", Title: "Kick a member", Description: "Removes them from the server; they can rejoin with an invite. Can't be undone.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["user"],"properties":{` + user + `,` + reason + `}}`)},
			{Name: "ban_member", Title: "Ban a member", Description: "Removes them and keeps them out. Undo unbans (deleted messages stay deleted).", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["user"],"properties":{` + user + `,"deleteMessageHours":{"type":"integer","minimum":0,"maximum":168,"default":0,"description":"Also delete their messages from this many past hours"},` + reason + `}}`)},
			{Name: "unban_member", Title: "Unban a user", Description: "Lets them rejoin with an invite. Undo bans them again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["user"],"properties":{` + user + `,` + reason + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.Webhook == "" && c.BotToken == "" {
		return errors.New("add a webhook URL, a bot token, or both (stored in the vault)")
	}
	for _, ref := range []string{c.Webhook, c.BotToken} {
		if ref != "" && !strings.HasPrefix(ref, "secret://") {
			return errors.New("store the webhook URL and bot token in the vault and enter their secret:// references")
		}
	}
	if c.Guild != "" && !idRe.MatchString(c.Guild) {
		return errors.New("the server id is a long number (17 to 20 digits)")
	}
	if c.API == "" {
		c.API = "https://discord.com/api/v10"
	}
	if err := rest.ValidBase(c.API); err != nil {
		return err
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 30*time.Second)
	}
	cn := &conn{cfg: c, host: h, http: rest.SameHostOnly(hc)}
	if c.BotToken != "" {
		tok := c.BotToken
		cn.bot = rest.New(c.API, func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, tok)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bot "+strings.TrimSpace(t))
			return nil
		})
		cn.bot.HTTP = cn.http
		cn.bot.Header.Set("X-Audit-Log-Reason", "Conduit")
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// webhook resolves the webhook URL into a client for it.
func (c *conn) webhook(ctx context.Context) (*rest.Client, error) {
	if c.cfg.Webhook == "" {
		return nil, errors.New("no webhook is set; add one, or name a channel for the bot")
	}
	u, err := c.host.Secret(ctx, c.cfg.Webhook)
	if err != nil {
		return nil, err
	}
	p, err := url.Parse(strings.TrimSpace(u))
	if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" || !strings.Contains(p.Path, "/webhooks/") {
		return nil, errors.New("the webhook isn't a Discord webhook URL")
	}
	r := rest.New(strings.TrimRight(p.String(), "/"), nil)
	r.HTTP = c.http
	return r, nil
}

// seg joins escaped path segments: seg("channels", id) is "/channels/<id>".
func seg(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(p))
	}
	return b.String()
}

// do calls Discord. A rate-limited request (429, which Discord didn't act
// on) is sent once more after its Retry-After when that's short. Errors are
// redacted, then shortened.
func (m *Module) do(ctx context.Context, cl *rest.Client, method, path string, q url.Values, body, out any) error {
	for attempt := 0; ; attempt++ {
		h, err := cl.Do(ctx, method, path, q, body, out)
		if err == nil {
			return nil
		}
		if !rest.IsStatus(err, http.StatusTooManyRequests) {
			return discordErr(scrub(err, cl.Base))
		}
		wait := retryAfter(h)
		if attempt > 0 || wait > maxRetryWait {
			return &rest.Error{Status: http.StatusTooManyRequests, Message: fmt.Sprintf("Discord is rate limiting the bot; try again in %d seconds", int(wait.Seconds()+0.999))}
		}
		sleep := m.sleep
		if sleep == nil {
			sleep = sleepCtx
		}
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// retryAfter reads Retry-After (seconds, possibly fractional); 1s when absent.
func retryAfter(h http.Header) time.Duration {
	if h != nil {
		if s, err := strconv.ParseFloat(strings.TrimSpace(h.Get("Retry-After")), 64); err == nil && s >= 0 && s < 1e6 {
			return time.Duration(s * float64(time.Second))
		}
	}
	return time.Second
}

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

// scrub keeps the client's base URL out of an error that isn't an API
// error: rest.Do names it in "unexpected answer from <base>", and the
// webhook's base is its secret URL.
func scrub(err error, base string) error {
	var e *rest.Error
	if err == nil || errors.As(err, &e) || base == "" || !strings.Contains(err.Error(), base) {
		return err
	}
	return errors.New(rest.Redact(strings.ReplaceAll(err.Error(), base, "Discord")))
}

// discordErr explains an API error, redacting before it shortens.
func discordErr(err error) error {
	var e *rest.Error
	if !errors.As(err, &e) {
		return err
	}
	msg := clip(rest.Redact(e.Message), 300)
	switch e.Status {
	case http.StatusUnauthorized:
		msg = "Discord refused the bot token; check the one in the vault"
	case http.StatusForbidden:
		msg = "Discord: " + msg + " (the bot needs a permission, or a role above the member, for this)"
	default:
		msg = "Discord: " + msg
	}
	return &rest.Error{Status: e.Status, Message: msg}
}

// clip shortens s to n characters, marking the cut.
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

// stamp normalises a Discord timestamp to RFC 3339 in UTC.
func stamp(s string) string {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return s
}

// content checks a message's text.
func content(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > maxContent {
		return "", fmt.Errorf("a message is 1 to %d characters", maxContent)
	}
	if w := wildcardRe.FindString(s); w != "" {
		return "", fmt.Errorf("%s would notify everyone; wildcard mentions aren't sent from Conduit", w)
	}
	return s, nil
}

// quiet is the allowed_mentions that notifies no one.
func quiet() map[string]any { return map[string]any{"parse": []string{}, "replied_user": false} }

func checkID(what, id string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("the %s id is a long number (17 to 20 digits)", what)
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if c.bot != nil {
		var u user
		if err := m.do(ctx, c.bot, http.MethodGet, "/users/@me", nil, nil, &u); err != nil {
			return sdk.Health{Status: "down", Message: "Bot: " + err.Error()}
		}
		return sdk.Health{Status: "ok", Message: "Bot " + u.Username}
	}
	w, err := c.webhook(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var info struct {
		Name string `json:"name"`
	}
	if err := m.do(ctx, w, http.MethodGet, "", nil, nil, &info); err != nil {
		return sdk.Health{Status: "down", Message: "Webhook: " + err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "Webhook " + info.Name}
}

// params is every action's input.
type params struct {
	Message      string `json:"message"`
	Channel      string `json:"channel"`
	ID           string `json:"id"`
	Limit        int    `json:"limit"`
	Before       string `json:"before"`
	After        string `json:"after"`
	Emoji        string `json:"emoji"`
	Name         string `json:"name"`
	Private      bool   `json:"private"`
	ArchiveAfter int    `json:"archiveAfter"`
	Thread       string `json:"thread"`
	User         string `json:"user"`
	Duration     string `json:"duration"`
	Until        string `json:"until"`
	Reason       string `json:"reason"`
	DeleteHours  int    `json:"deleteMessageHours"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p params
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	needBot := func() error {
		if c.bot == nil {
			return errors.New("this needs a bot token in the settings")
		}
		return nil
	}
	needGuild := func() error {
		if err := needBot(); err != nil {
			return err
		}
		if c.cfg.Guild == "" {
			return errors.New("set the server id in the settings")
		}
		return nil
	}
	switch call.Action {
	case "send":
		msg, err := content(p.Message)
		if err != nil {
			return sdk.Result{}, err
		}
		body := map[string]any{"content": msg, "allowed_mentions": map[string]any{"parse": []string{}}}
		var out struct {
			ID string `json:"id"`
		}
		if p.Channel != "" {
			if err := needBot(); err != nil {
				return sdk.Result{}, err
			}
			if err := checkID("channel", p.Channel); err != nil {
				return sdk.Result{}, err
			}
			if _, err := m.inServer(ctx, c, p.Channel); err != nil {
				return sdk.Result{}, err
			}
			if err := m.do(ctx, c.bot, http.MethodPost, seg("channels", p.Channel, "messages"), nil, body, &out); err != nil {
				return sdk.Result{}, err
			}
		} else {
			w, err := c.webhook(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := m.do(ctx, w, http.MethodPost, "", url.Values{"wait": {"true"}}, body, &out); err != nil {
				return sdk.Result{}, err
			}
		}
		r, _ := sdk.JSON(map[string]string{"id": out.ID})
		r.Undo = sdk.UndoWith("delete_message", map[string]string{"id": out.ID, "channel": p.Channel}, "Delete the message")
		return r, nil

	case "delete_message":
		if err := checkID("message", p.ID); err != nil {
			return sdk.Result{}, err
		}
		cl, path, where := (*rest.Client)(nil), "", "the webhook's channel"
		if p.Channel != "" {
			if err := needBot(); err != nil {
				return sdk.Result{}, err
			}
			if err := checkID("channel", p.Channel); err != nil {
				return sdk.Result{}, err
			}
			ch, err := m.inServer(ctx, c, p.Channel)
			if err != nil {
				return sdk.Result{}, err
			}
			cl, path, where = c.bot, seg("channels", p.Channel, "messages", p.ID), ch.label()
		} else {
			w, err := c.webhook(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			cl, path = w, seg("messages", p.ID)
		}
		if call.DryRun {
			var ms message
			if err := m.do(ctx, cl, http.MethodGet, path, nil, nil, &ms); err != nil {
				return sdk.Result{}, err
			}
			before, _ := json.Marshal(map[string]string{"author": ms.Author.display(), "message": clip(ms.Content, 200), "sent": stamp(ms.Timestamp)})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete %s's message from %s in %s", ms.Author.display(), stamp(ms.Timestamp), where),
				Changes: []sdk.Change{{Target: "message " + p.ID + " in " + where, Op: "delete", Before: before}}}}, nil
		}
		if err := m.do(ctx, cl, http.MethodDelete, path, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.ID})

	case "server", "channels":
		if err := needGuild(); err != nil {
			return sdk.Result{}, err
		}
		if call.Action == "server" {
			var g struct {
				Name     string `json:"name"`
				Members  int    `json:"approximate_member_count"`
				Presence int    `json:"approximate_presence_count"`
			}
			if err := m.do(ctx, c.bot, http.MethodGet, seg("guilds", c.cfg.Guild), url.Values{"with_counts": {"true"}}, nil, &g); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"name": g.Name, "members": g.Members, "online": g.Presence})
		}
		chs, err := m.guildChannels(ctx, c)
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Kind string `json:"kind"`
		}
		out := []row{}
		for _, x := range chs {
			out = append(out, row{ID: x.ID, Name: x.Name, Kind: kinds[x.Type]})
		}
		return sdk.JSON(out)

	case "messages", "reply", "react", "unreact", "pin_message", "unpin_message", "create_thread", "archive_thread":
		if err := needBot(); err != nil {
			return sdk.Result{}, err
		}
		return m.channelAction(ctx, c, call, p)

	case "threads", "members", "timeout_member", "remove_timeout", "kick_member", "ban_member", "unban_member":
		if err := needGuild(); err != nil {
			return sdk.Result{}, err
		}
		if call.Action == "threads" {
			return m.threads(ctx, c)
		}
		return m.guildAction(ctx, c, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

var kinds = map[int]string{0: "text", 2: "voice", 4: "category", 5: "announcement", 10: "announcement thread", 11: "thread", 12: "private thread", 13: "stage", 15: "forum", 16: "media"}

type channel struct {
	ID       string `json:"id"`
	GuildID  string `json:"guild_id"`
	Name     string `json:"name"`
	Type     int    `json:"type"`
	ParentID string `json:"parent_id"`
	OwnerID  string `json:"owner_id"`
	Messages int    `json:"message_count"`
	Members  int    `json:"member_count"`
	Meta     *struct {
		Archived bool   `json:"archived"`
		Locked   bool   `json:"locked"`
		Created  string `json:"create_timestamp"`
		Minutes  int    `json:"auto_archive_duration"`
	} `json:"thread_metadata"`
}

func (m *Module) guildChannels(ctx context.Context, c *conn) ([]channel, error) {
	var chs []channel
	err := m.do(ctx, c.bot, http.MethodGet, seg("guilds", c.cfg.Guild, "channels"), nil, nil, &chs)
	return chs, err
}

// label is "#name" for a preview, or the id when it has no name.
func (ch channel) label() string {
	if ch.Name != "" {
		return "#" + ch.Name
	}
	return "channel " + ch.ID
}

// inServer reads a channel or thread and, when the settings name a server,
// checks that it's in that server: an instance set up for one server can't
// reach another server the bot is in, or the bot's direct messages.
func (m *Module) inServer(ctx context.Context, c *conn, id string) (channel, error) {
	var ch channel
	if err := m.do(ctx, c.bot, http.MethodGet, seg("channels", id), nil, nil, &ch); err != nil {
		return channel{}, err
	}
	if ch.ID == "" {
		ch.ID = id
	}
	if c.cfg.Guild != "" && ch.GuildID != c.cfg.Guild {
		return channel{}, fmt.Errorf("channel %s isn't in this instance's server", id)
	}
	return ch, nil
}

type user struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	GlobalName string `json:"global_name"`
	Bot        bool   `json:"bot"`
}

// display is the name people see.
func (u user) display() string {
	if u.GlobalName != "" {
		return u.GlobalName
	}
	return u.Username
}

// myID is the bot's own user id.
func (m *Module) myID(ctx context.Context, c *conn) (string, error) {
	c.mu.Lock()
	id := c.botID
	c.mu.Unlock()
	if id != "" {
		return id, nil
	}
	var u user
	if err := m.do(ctx, c.bot, http.MethodGet, "/users/@me", nil, nil, &u); err != nil {
		return "", err
	}
	if u.ID == "" {
		return "", errors.New("Discord didn't say who the bot is")
	}
	c.mu.Lock()
	c.botID = u.ID
	c.mu.Unlock()
	return u.ID, nil
}
