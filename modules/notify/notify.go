// Package notify sends notifications to a phone, chat or any webhook: ntfy,
// Telegram, Discord, Slack, a signed webhook, or the desktop app. Approval
// requests can be forwarded so people can decide from anywhere.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one channel's settings.
type Config struct {
	Channel string `json:"channel"` // ntfy, telegram, discord, slack, webhook, desktop

	Server string `json:"server"` // ntfy server, default https://ntfy.sh
	Topic  string `json:"topic"`  // ntfy topic
	Token  string `json:"token"`  // secret:// — ntfy access token or Telegram bot token
	ChatID string `json:"chatId"` // Telegram
	URL    string `json:"url"`    // secret:// — Discord/Slack webhook URL, or plain webhook URL
	Secret string `json:"secret"` // secret:// — HMAC key for the generic webhook

	// Approvals forwards every approval request to this channel.
	Approvals bool `json:"approvals"`
	// AppURL is where the Conduit app is reachable from this channel's
	// devices, used for links in notifications.
	AppURL string `json:"appUrl"`
	// MinPriority drops messages below this level.
	MinPriority string `json:"minPriority"`
}

// Module implements sdk.Module.
type Module struct {
	mu   sync.Mutex
	cfgs map[string]Config
	host map[string]sdk.Host
	http *http.Client
}

// New returns the notifications module.
func New() *Module {
	return &Module{cfgs: map[string]Config{}, host: map[string]sdk.Host{}, http: &http.Client{Timeout: 15 * time.Second}}
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "notify", Name: "Notifications", Version: "0.1.0", Category: "Communication", Icon: "bell",
		Description: "Send alerts and approval requests to your phone, a chat or any webhook.",
		Presets:     []string{"developer", "gamer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["channel"],"properties":{
			"channel":{"type":"string","enum":["ntfy","telegram","discord","slack","webhook","desktop"],"default":"ntfy","description":"ntfy is free and has phone apps; desktop shows a notification from the Conduit app"},
			"server":{"type":"string","description":"ntfy server (default https://ntfy.sh)"},
			"topic":{"type":"string","description":"ntfy topic; pick something hard to guess"},
			"token":{"type":"string","x-secret":true,"description":"ntfy access token, or the Telegram bot token"},
			"chatId":{"type":"string","title":"Telegram chat ID"},
			"url":{"type":"string","x-secret":true,"title":"Webhook URL","description":"Discord or Slack webhook (vault reference), or your own endpoint"},
			"secret":{"type":"string","x-secret":true,"title":"Signing key","description":"Signs webhook bodies (X-Conduit-Signature: sha256=…)"},
			"approvals":{"type":"boolean","title":"Send approval requests here"},
			"appUrl":{"type":"string","title":"Conduit address","description":"Link target in notifications, e.g. http://my-pc:7600"},
			"minPriority":{"type":"string","enum":["low","normal","high","urgent"],"default":"low"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "send", Title: "Send a notification", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["message"],"properties":{"title":{"type":"string"},"message":{"type":"string","x-multiline":true},"priority":{"type":"string","enum":["low","normal","high","urgent"],"default":"normal"},"link":{"type":"string"}}}`)},
			{Name: "test", Title: "Send a test", Description: "Check this channel works.", Risk: sdk.RiskWrite},
		},
		Events: []sdk.EventSpec{{Type: "notify.desktop", Description: "A notification for the desktop app to show"}},
	}
}

var levels = map[string]int{"low": 1, "normal": 2, "high": 3, "urgent": 4}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	switch c.Channel {
	case "ntfy":
		if c.Topic == "" {
			return errors.New("ntfy needs a topic")
		}
	case "telegram":
		if c.Token == "" || c.ChatID == "" {
			return errors.New("Telegram needs a bot token and a chat ID")
		}
	case "discord", "slack", "webhook":
		if c.URL == "" {
			return errors.New("a webhook URL is required")
		}
	case "desktop":
	default:
		return fmt.Errorf("unknown channel %q", c.Channel)
	}
	m.mu.Lock()
	m.cfgs[id], m.host[id] = c, h
	m.mu.Unlock()
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error {
	m.mu.Lock()
	delete(m.cfgs, id)
	delete(m.host, id)
	m.mu.Unlock()
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(_ context.Context, id string) sdk.Health {
	m.mu.Lock()
	c, ok := m.cfgs[id]
	m.mu.Unlock()
	if !ok {
		return sdk.Health{Status: "unconfigured"}
	}
	msg := "Sends to " + c.Channel
	if c.Approvals {
		msg += ", including approval requests"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// ForwardsApprovals reports whether an instance wants approval requests.
func (m *Module) ForwardsApprovals(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfgs[id].Approvals
}

// AppURL returns an instance's configured app address.
func (m *Module) AppURL(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return strings.TrimRight(m.cfgs[id].AppURL, "/")
}

// Note is one notification.
type Note struct {
	Title    string `json:"title"`
	Message  string `json:"message"`
	Priority string `json:"priority"`
	Link     string `json:"link"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	m.mu.Lock()
	c, ok := m.cfgs[call.Instance]
	h := m.host[call.Instance]
	m.mu.Unlock()
	if !ok {
		return sdk.Result{}, errors.New("channel is not configured")
	}
	var n Note
	switch call.Action {
	case "send":
		if err := sdk.Decode(call, &n); err != nil {
			return sdk.Result{}, err
		}
	case "test":
		n = Note{Title: "Conduit", Message: "Notifications work. You'll get alerts here.", Priority: "normal"}
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	if n.Message == "" {
		return sdk.Result{}, errors.New("message is required")
	}
	if n.Priority == "" {
		n.Priority = "normal"
	}
	if levels[n.Priority] < levels[c.MinPriority] {
		return sdk.JSON(map[string]any{"sent": false, "reason": "below this channel's minimum priority"})
	}
	if err := m.deliver(ctx, c, h, call.Instance, n); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"sent": true, "channel": c.Channel})
}

func (m *Module) secret(ctx context.Context, h sdk.Host, ref string) (string, error) {
	if !strings.HasPrefix(ref, "secret://") {
		return ref, nil // plain value (e.g. a public ntfy server URL)
	}
	return h.Secret(ctx, ref)
}

func (m *Module) deliver(ctx context.Context, c Config, h sdk.Host, id string, n Note) error {
	switch c.Channel {
	case "desktop":
		h.Publish(ctx, sdk.Event{Type: "notify.desktop", Instance: id, Data: mustJSON(n)})
		return nil

	case "ntfy":
		server := c.Server
		if server == "" {
			server = "https://ntfy.sh"
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(server, "/")+"/"+url.PathEscape(c.Topic), strings.NewReader(n.Message))
		if n.Title != "" {
			req.Header.Set("Title", n.Title)
		}
		req.Header.Set("Priority", strconv.Itoa(map[string]int{"low": 2, "normal": 3, "high": 4, "urgent": 5}[n.Priority]))
		if n.Link != "" {
			req.Header.Set("Click", n.Link)
		}
		if c.Token != "" {
			tok, err := m.secret(ctx, h, c.Token)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		return m.do(req)

	case "telegram":
		tok, err := m.secret(ctx, h, c.Token)
		if err != nil {
			return err
		}
		text := n.Message
		if n.Title != "" {
			text = "*" + escapeMD(n.Title) + "*\n" + escapeMD(n.Message)
		} else {
			text = escapeMD(text)
		}
		if n.Link != "" {
			text += "\n" + escapeMD(n.Link)
		}
		body := mustJSON(map[string]any{"chat_id": c.ChatID, "text": text, "parse_mode": "MarkdownV2", "disable_web_page_preview": true})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+tok+"/sendMessage", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		return m.do(req)

	case "discord", "slack":
		hook, err := m.secret(ctx, h, c.URL)
		if err != nil {
			return err
		}
		text := n.Message
		if n.Title != "" {
			text = "**" + n.Title + "**\n" + text
		}
		if n.Link != "" {
			text += "\n" + n.Link
		}
		var body []byte
		if c.Channel == "discord" {
			body = mustJSON(map[string]any{"content": truncate(text, 1900), "allowed_mentions": map[string]any{"parse": []string{}}})
		} else {
			body = mustJSON(map[string]any{"text": strings.ReplaceAll(text, "**", "*")})
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, hook, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		return m.do(req)

	case "webhook":
		hook, err := m.secret(ctx, h, c.URL)
		if err != nil {
			return err
		}
		body := mustJSON(map[string]any{"type": "notification", "title": n.Title, "message": n.Message, "priority": n.Priority, "link": n.Link, "sentAt": time.Now().UTC()})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, hook, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if c.Secret != "" {
			key, err := m.secret(ctx, h, c.Secret)
			if err != nil {
				return err
			}
			req.Header.Set("X-Conduit-Signature", Sign(key, body))
		}
		return m.do(req)
	}
	return fmt.Errorf("unknown channel %q", c.Channel)
}

// Sign returns the X-Conduit-Signature value for a webhook body.
func Sign(key string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (m *Module) do(req *http.Request) error {
	res, err := m.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("the channel answered %s: %s", res.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

var mdReplacer = strings.NewReplacer("_", `\_`, "*", `\*`, "[", `\[`, "]", `\]`, "(", `\(`, ")", `\)`, "~", `\~`, "`", "\\`", ">", `\>`,
	"#", `\#`, "+", `\+`, "-", `\-`, "=", `\=`, "|", `\|`, "{", `\{`, "}", `\}`, ".", `\.`, "!", `\!`)

func escapeMD(s string) string { return mdReplacer.Replace(s) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
