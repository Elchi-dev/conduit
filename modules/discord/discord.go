// Package discord posts to Discord through a webhook or a bot, and reads a
// server's status with the bot.
package discord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Discord connection's settings. Either or both may be set.
type Config struct {
	Webhook  string `json:"webhook"`  // secret:// webhook URL
	BotToken string `json:"botToken"` // secret:// bot token
	Guild    string `json:"guild"`    // server id for status and channels
	API      string `json:"api"`      // default https://discord.com/api/v10 (tests)
}

type conn struct {
	cfg  Config
	bot  *rest.Client
	hook *rest.Client
	host sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Discord module.
func New() *Module { return &Module{} }

var idRe = regexp.MustCompile(`^\d{5,25}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "discord", Name: "Discord", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "Post to a channel through a webhook or bot, and see how your server is doing.",
		Presets:     []string{"gamer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"webhook":{"type":"string","x-secret":true,"description":"A channel webhook URL (Channel settings, Integrations); enough for posting"},
			"botToken":{"type":"string","x-secret":true,"description":"A bot token, to post anywhere the bot can and read server status"},
			"guild":{"type":"string","description":"Server id (Developer Mode, right-click the server, Copy ID)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "send", Title: "Post a message", Description: "Through the webhook, or with the bot when a channel is given.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["message"],"properties":{"message":{"type":"string","format":"textarea","maxLength":2000},"channel":{"type":"string","description":"Channel id (bot only)"}}}`)},
			{Name: "delete_message", Title: "Delete a message", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"channel":{"type":"string"}}}`)},
			{Name: "server", Title: "Server status", Description: "Members and how many are online.", Risk: sdk.RiskRead},
			{Name: "channels", Title: "Channels", Risk: sdk.RiskRead},
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
	if c.Guild != "" && !idRe.MatchString(c.Guild) {
		return errors.New("the server id is a long number")
	}
	if c.API == "" {
		c.API = "https://discord.com/api/v10"
	}
	cn := &conn{cfg: c, host: h}
	if c.BotToken != "" {
		tok := c.BotToken
		cn.bot = rest.New(c.API, func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, tok)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bot "+t)
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

// webhook resolves the webhook URL into a client for it.
func (c *conn) webhook(ctx context.Context, client *http.Client) (*rest.Client, error) {
	if c.cfg.Webhook == "" {
		return nil, errors.New("no webhook is set; add one, or name a channel for the bot")
	}
	u, err := c.host.Secret(ctx, c.cfg.Webhook)
	if err != nil {
		return nil, err
	}
	p, err := url.Parse(u)
	if err != nil || !strings.Contains(p.Path, "/webhooks/") {
		return nil, errors.New("the webhook isn't a Discord webhook URL")
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
	if c.bot != nil {
		var u struct {
			Username string `json:"username"`
		}
		if _, err := c.bot.Do(ctx, "GET", "/users/@me", nil, nil, &u); err != nil {
			return sdk.Health{Status: "down", Message: "Bot: " + err.Error()}
		}
		return sdk.Health{Status: "ok", Message: "Bot " + u.Username}
	}
	w, err := c.webhook(ctx, m.HTTP)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var info struct {
		Name string `json:"name"`
	}
	if _, err := w.Do(ctx, "GET", "", nil, nil, &info); err != nil {
		return sdk.Health{Status: "down", Message: "Webhook: " + err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "Webhook " + info.Name}
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
		ID      string `json:"id"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	needBot := func() error {
		if c.bot == nil {
			return errors.New("this needs a bot token in the settings")
		}
		return nil
	}
	switch call.Action {
	case "send":
		msg := strings.TrimSpace(p.Message)
		if msg == "" || len(msg) > 2000 {
			return sdk.Result{}, errors.New("a message is 1 to 2000 characters")
		}
		body := map[string]any{"content": msg, "allowed_mentions": map[string]any{"parse": []string{}}}
		var out struct {
			ID        string `json:"id"`
			ChannelID string `json:"channel_id"`
		}
		if p.Channel != "" {
			if err := needBot(); err != nil {
				return sdk.Result{}, err
			}
			if !idRe.MatchString(p.Channel) {
				return sdk.Result{}, errors.New("the channel id is a long number")
			}
			if _, err := c.bot.Do(ctx, "POST", "/channels/"+p.Channel+"/messages", nil, body, &out); err != nil {
				return sdk.Result{}, err
			}
		} else {
			w, err := c.webhook(ctx, m.HTTP)
			if err != nil {
				return sdk.Result{}, err
			}
			if _, err := w.Do(ctx, "POST", "", url.Values{"wait": {"true"}}, body, &out); err != nil {
				return sdk.Result{}, err
			}
			out.ChannelID = ""
		}
		r, _ := sdk.JSON(map[string]string{"id": out.ID})
		r.Undo = sdk.UndoWith("delete_message", map[string]string{"id": out.ID, "channel": p.Channel}, "Delete the message")
		return r, nil

	case "delete_message":
		if !idRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("message id required")
		}
		if p.Channel != "" {
			if err := needBot(); err != nil {
				return sdk.Result{}, err
			}
			_, err = c.bot.Do(ctx, "DELETE", "/channels/"+p.Channel+"/messages/"+p.ID, nil, nil, nil)
		} else {
			w, werr := c.webhook(ctx, m.HTTP)
			if werr != nil {
				return sdk.Result{}, werr
			}
			_, err = w.Do(ctx, "DELETE", "/messages/"+p.ID, nil, nil, nil)
		}
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.ID})

	case "server", "channels":
		if err := needBot(); err != nil {
			return sdk.Result{}, err
		}
		if c.cfg.Guild == "" {
			return sdk.Result{}, errors.New("set the server id in the settings")
		}
		if call.Action == "server" {
			var g struct {
				Name     string `json:"name"`
				Members  int    `json:"approximate_member_count"`
				Presence int    `json:"approximate_presence_count"`
			}
			if _, err := c.bot.Do(ctx, "GET", "/guilds/"+c.cfg.Guild, url.Values{"with_counts": {"true"}}, nil, &g); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"name": g.Name, "members": g.Members, "online": g.Presence})
		}
		var chs []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Type int    `json:"type"`
		}
		if _, err := c.bot.Do(ctx, "GET", "/guilds/"+c.cfg.Guild+"/channels", nil, nil, &chs); err != nil {
			return sdk.Result{}, err
		}
		type ch struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Kind string `json:"kind"`
		}
		kinds := map[int]string{0: "text", 2: "voice", 4: "category", 5: "announcement", 13: "stage", 15: "forum"}
		out := []ch{}
		for _, x := range chs {
			out = append(out, ch{ID: x.ID, Name: x.Name, Kind: kinds[x.Type]})
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
