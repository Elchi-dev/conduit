// Package slack posts to Slack through a bot or an incoming webhook and
// reads channels and recent messages with the bot.
package slack

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Slack connection's settings. Either or both may be set.
type Config struct {
	BotToken string `json:"botToken"` // secret:// bot token (xoxb-…)
	Webhook  string `json:"webhook"`  // secret:// incoming webhook URL
	Channel  string `json:"channel"`  // default channel id for the bot
	API      string `json:"api"`      // default https://slack.com/api (tests)
}

type conn struct {
	cfg  Config
	bot  *rest.Client
	host sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Slack module.
func New() *Module { return &Module{} }

var (
	channelRe = regexp.MustCompile(`^[CGD][A-Z0-9]{6,20}$`)
	tsRe      = regexp.MustCompile(`^\d{9,11}\.\d{1,8}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "slack", Name: "Slack", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "Post to channels through a bot or a webhook, and read what's been said.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"botToken":{"type":"string","x-secret":true,"description":"A bot token (xoxb-…) from your Slack app, to post anywhere the bot is invited and read channels"},
			"webhook":{"type":"string","x-secret":true,"description":"An incoming webhook URL; enough for posting to one channel"},
			"channel":{"type":"string","description":"Default channel id for the bot (right-click a channel, Copy link; the id starts with C)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "send", Title: "Post a message", Description: "With the bot to a channel, or through the webhook.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["message"],"properties":{"message":{"type":"string","format":"textarea","maxLength":4000},"channel":{"type":"string","description":"Channel id (bot); empty uses the default channel or the webhook"},"thread":{"type":"string","description":"Reply in the thread of this message ts (bot)"}}}`)},
			{Name: "delete_message", Title: "Delete a message", Description: "Only messages the bot posted.", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["channel","ts"],"properties":{"channel":{"type":"string"},"ts":{"type":"string"}}}`)},
			{Name: "channels", Title: "Channels", Description: "Public and private channels the bot can see.", Risk: sdk.RiskRead},
			{Name: "history", Title: "Recent messages", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"channel":{"type":"string"},"limit":{"type":"integer","default":20,"maximum":200}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.BotToken == "" && c.Webhook == "" {
		return errors.New("add a bot token, a webhook URL, or both (stored in the vault)")
	}
	if c.Channel != "" && !channelRe.MatchString(c.Channel) {
		return errors.New("the channel is an id like C0123ABCD, not a name")
	}
	if c.API == "" {
		c.API = "https://slack.com/api"
	}
	cn := &conn{cfg: c, host: h}
	if c.BotToken != "" {
		tok := c.BotToken
		cn.bot = rest.New(c.API, func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, tok)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+t)
			return nil
		})
		if m.HTTP != nil {
			cn.bot.HTTP = m.HTTP
		}
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// call runs a Web API method. Slack answers HTTP 200 with ok:false on
// errors, so the envelope is checked here.
func (c *conn) call(ctx context.Context, method string, q url.Values, body, out any) error {
	if c.bot == nil {
		return errors.New("this needs a bot token in the settings")
	}
	var raw json.RawMessage
	verb := "GET"
	if body != nil {
		verb = "POST"
	}
	if _, err := c.bot.Do(ctx, verb, "/"+method, q, body, &raw); err != nil {
		return err
	}
	var env struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("unexpected answer from Slack: %w", err)
	}
	if !env.OK {
		return fmt.Errorf("Slack: %s", explain(env.Error))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func explain(code string) string {
	switch code {
	case "not_in_channel":
		return "the bot isn't in that channel; invite it with /invite"
	case "channel_not_found":
		return "no such channel, or the bot can't see it"
	case "invalid_auth", "not_authed", "token_revoked":
		return "the bot token isn't valid any more"
	case "missing_scope":
		return "the bot is missing a permission (scope) for this"
	case "cant_delete_message", "message_not_found":
		return "the bot can only delete its own messages"
	case "":
		return "unknown error"
	}
	return code
}

// quiet stops a message from pinging everyone: Slack treats "<!channel>",
// "<!here>", "<!everyone>" and group mentions as broadcasts.
func quiet(s string) string { return strings.ReplaceAll(s, "<!", "&lt;!") }

func (c *conn) webhook(ctx context.Context, client *http.Client) (*rest.Client, error) {
	if c.cfg.Webhook == "" {
		return nil, errors.New("no webhook is set; add one, or name a channel for the bot")
	}
	u, err := c.host.Secret(ctx, c.cfg.Webhook)
	if err != nil {
		return nil, err
	}
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" && p.Scheme != "http" || p.Host == "" {
		return nil, errors.New("the webhook isn't a URL")
	}
	r := rest.New(strings.TrimRight(u, "/"), nil)
	if client != nil {
		r.HTTP = client
	}
	return r, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if c.bot == nil {
		return sdk.Health{Status: "ok", Message: "Webhook only (posting)"}
	}
	var a struct {
		Team string `json:"team"`
		User string `json:"user"`
	}
	if err := c.call(ctx, "auth.test", nil, map[string]any{}, &a); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: a.User + " in " + a.Team}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Message string `json:"message"`
		Channel string `json:"channel"`
		Thread  string `json:"thread"`
		TS      string `json:"ts"`
		Limit   int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	channel := p.Channel
	if channel == "" {
		channel = c.cfg.Channel
	}
	checkChannel := func() error {
		if !channelRe.MatchString(channel) {
			return errors.New("give a channel id like C0123ABCD")
		}
		return nil
	}
	switch call.Action {
	case "send":
		msg := strings.TrimSpace(p.Message)
		if msg == "" || len(msg) > 4000 {
			return sdk.Result{}, errors.New("a message is 1 to 4000 characters")
		}
		if channel == "" || c.bot == nil {
			if p.Channel != "" {
				return sdk.Result{}, errors.New("posting to a channel needs a bot token in the settings")
			}
			w, err := c.webhook(ctx, m.HTTP)
			if err != nil {
				return sdk.Result{}, err
			}
			if _, err := w.Do(ctx, "POST", "", nil, map[string]any{"text": quiet(msg)}, nil); err != nil {
				return sdk.Result{}, err
			}
			// Webhook posts can't be deleted through the API, so no undo.
			return sdk.JSON(map[string]string{"posted": "webhook"})
		}
		if err := checkChannel(); err != nil {
			return sdk.Result{}, err
		}
		body := map[string]any{"channel": channel, "text": quiet(msg), "link_names": false, "unfurl_links": false}
		if p.Thread != "" {
			if !tsRe.MatchString(p.Thread) {
				return sdk.Result{}, errors.New("the thread is a message ts like 1730600000.123456")
			}
			body["thread_ts"] = p.Thread
		}
		var out struct {
			Channel string `json:"channel"`
			TS      string `json:"ts"`
		}
		if err := c.call(ctx, "chat.postMessage", nil, body, &out); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"channel": out.Channel, "ts": out.TS})
		r.Undo = sdk.UndoWith("delete_message", map[string]string{"channel": out.Channel, "ts": out.TS}, "Delete the message")
		return r, nil

	case "delete_message":
		if err := checkChannel(); err != nil {
			return sdk.Result{}, err
		}
		if !tsRe.MatchString(p.TS) {
			return sdk.Result{}, errors.New("the message is identified by its ts, like 1730600000.123456")
		}
		if err := c.call(ctx, "chat.delete", nil, map[string]string{"channel": channel, "ts": p.TS}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.TS})

	case "channels":
		var out struct {
			Channels []struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				IsPrivate bool   `json:"is_private"`
				IsMember  bool   `json:"is_member"`
				Members   int    `json:"num_members"`
			} `json:"channels"`
		}
		q := url.Values{"types": {"public_channel,private_channel"}, "exclude_archived": {"true"}, "limit": {"200"}}
		if err := c.call(ctx, "conversations.list", q, nil, &out); err != nil {
			return sdk.Result{}, err
		}
		type ch struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Private bool   `json:"private"`
			BotIn   bool   `json:"botIn"`
			Members int    `json:"members"`
		}
		list := []ch{}
		for _, x := range out.Channels {
			list = append(list, ch{x.ID, x.Name, x.IsPrivate, x.IsMember, x.Members})
		}
		return sdk.JSON(list)

	case "history":
		if err := checkChannel(); err != nil {
			return sdk.Result{}, err
		}
		limit := p.Limit
		if limit <= 0 {
			limit = 20
		}
		if limit > 200 {
			limit = 200
		}
		var out struct {
			Messages []struct {
				TS      string `json:"ts"`
				User    string `json:"user"`
				BotID   string `json:"bot_id"`
				Text    string `json:"text"`
				Replies int    `json:"reply_count"`
			} `json:"messages"`
		}
		if err := c.call(ctx, "conversations.history", url.Values{"channel": {channel}, "limit": {strconv.Itoa(limit)}}, nil, &out); err != nil {
			return sdk.Result{}, err
		}
		type msg struct {
			TS      string `json:"ts"`
			From    string `json:"from"`
			Text    string `json:"text"`
			Replies int    `json:"replies,omitempty"`
		}
		list := []msg{}
		for _, x := range out.Messages {
			from := x.User
			if from == "" {
				from = "bot " + x.BotID
			}
			list = append(list, msg{x.TS, from, x.Text, x.Replies})
		}
		return sdk.JSON(list)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
