package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// briefModule is the daily brief (signature feature 10): one summary of
// what needs attention across everything connected. It reads other modules
// through the engine as Conduit itself, so every read is audited.
type briefModule struct{ app *App }

const briefID = "brief"

type briefConfig struct {
	// Channels are notification instance ids the brief is sent to.
	Channels []string `json:"channels"`
}

func (b *briefModule) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "brief", Name: "Daily brief", Version: "0.1.0", Category: "Conduit", Icon: "sun",
		Description: "Unread mail, today's events and weather, anything down, approvals waiting and keys expiring, in one summary.",
		Presets:     []string{"developer", "gamer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"channels":{"type":"array","items":{"type":"string"},"description":"Notification channels (their IDs) to send the brief to"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "brief", Title: "Brief", Description: "What needs attention right now.", Risk: sdk.RiskRead},
			{Name: "send", Title: "Send the brief", Description: "To the notification channels in settings.", Risk: sdk.RiskWrite},
		},
	}
}

func (b *briefModule) Configure(_ context.Context, _ sdk.Host, _ string, raw json.RawMessage) error {
	var c briefConfig
	if len(raw) > 0 {
		return json.Unmarshal(raw, &c)
	}
	return nil
}

func (b *briefModule) Health(context.Context, string) sdk.Health { return sdk.Health{Status: "ok"} }
func (b *briefModule) Close(string) error                        { return nil }

// Brief is the structured summary.
type Brief struct {
	Date      string       `json:"date"`
	Attention []string     `json:"attention"`
	Mail      []briefMail  `json:"mail"`
	Agenda    []briefEvent `json:"agenda"`
	Approvals int          `json:"approvalsWaiting"`
	Failures  []string     `json:"failuresLast24h"`
	Keys      []string     `json:"keysExpiringSoon"`
	Weather   []string     `json:"weather"`
}

type briefMail struct {
	Account string   `json:"account"`
	Unread  int      `json:"unread"`
	Latest  []string `json:"latest"`
}

type briefEvent struct {
	Calendar string `json:"calendar"`
	Time     string `json:"time"`
	Title    string `json:"title"`
}

func (b *briefModule) read(ctx context.Context, instance, action string, input any, out any) error {
	in, _ := json.Marshal(input)
	res, err := b.app.Engine.Invoke(ctx, systemActor, sdk.Call{Instance: instance, Action: action, Input: in}, core.InvokeOptions{NoWait: true})
	if err != nil {
		return err
	}
	return json.Unmarshal(res.Result.Output, out)
}

func (b *briefModule) build(ctx context.Context) Brief {
	e := b.app.Engine
	br := Brief{Date: time.Now().Format("Monday 2 January"), Attention: []string{}, Mail: []briefMail{}, Agenda: []briefEvent{}, Failures: []string{}, Keys: []string{}, Weather: []string{}}

	for _, in := range e.Instances("") {
		if !in.Enabled || in.Module == "brief" {
			continue
		}
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		h := e.Health(hctx, in.ID)
		cancel()
		if h.Status == "down" || h.Status == "degraded" {
			msg := in.Name + " is " + h.Status
			if h.Message != "" {
				msg += ": " + h.Message
			}
			br.Attention = append(br.Attention, msg)
		}
		switch in.Module {
		case "mail":
			var list []struct {
				From    string `json:"from"`
				Subject string `json:"subject"`
			}
			if b.read(ctx, in.ID, "inbox", map[string]any{"unreadOnly": true, "limit": 50}, &list) == nil {
				m := briefMail{Account: in.Name, Unread: len(list), Latest: []string{}}
				for i, x := range list {
					if i == 5 {
						break
					}
					from := x.From
					if j := strings.Index(from, " <"); j > 0 {
						from = from[:j]
					}
					m.Latest = append(m.Latest, from+": "+x.Subject)
				}
				br.Mail = append(br.Mail, m)
			}
		case "weather":
			var w struct {
				Places []struct {
					Place   string `json:"place"`
					Summary string `json:"summary"`
				} `json:"places"`
			}
			if b.read(ctx, in.ID, "today", nil, &w) == nil {
				for _, p := range w.Places {
					if p.Summary != "" {
						br.Weather = append(br.Weather, p.Place+": "+p.Summary)
					}
				}
			}
		case "calendar":
			var evs []struct {
				Title  string `json:"title"`
				Start  string `json:"start"`
				AllDay bool   `json:"allDay"`
			}
			if b.read(ctx, in.ID, "today", nil, &evs) == nil {
				for _, x := range evs {
					t := "all day"
					if !x.AllDay {
						if ts, err := time.Parse(time.RFC3339, x.Start); err == nil {
							t = ts.Local().Format("15:04")
						}
					}
					br.Agenda = append(br.Agenda, briefEvent{Calendar: in.Name, Time: t, Title: x.Title})
				}
			}
		}
	}
	if p, err := e.Approvals.List(ctx, "pending"); err == nil {
		br.Approvals = len(p)
	}
	if entries, err := e.Audit.List(ctx, core.Query{Since: time.Now().Add(-24 * time.Hour), Limit: 500}); err == nil {
		seen := map[string]bool{}
		for _, x := range entries {
			if x.Status == "error" && !seen[x.Module+x.Action] {
				seen[x.Module+x.Action] = true
				br.Failures = append(br.Failures, fmt.Sprintf("%s %s: %s", x.Module, x.Action, x.Error))
			}
		}
	}
	if keys, err := b.app.Auth.ListKeys(ctx, ""); err == nil {
		soon := time.Now().Add(7 * 24 * time.Hour)
		for _, k := range keys {
			if k.Active(time.Now()) && k.ExpiresAt != nil && k.ExpiresAt.Before(soon) {
				br.Keys = append(br.Keys, fmt.Sprintf("%s expires %s", k.Name, k.ExpiresAt.Local().Format("Mon 2 Jan")))
			}
		}
	}
	return br
}

func (br Brief) text() string {
	var sb strings.Builder
	if len(br.Attention) == 0 && br.Approvals == 0 && len(br.Failures) == 0 {
		sb.WriteString("Everything is running.\n")
	}
	for _, a := range br.Attention {
		sb.WriteString("• " + a + "\n")
	}
	if br.Approvals > 0 {
		fmt.Fprintf(&sb, "• %d approvals waiting for you\n", br.Approvals)
	}
	for _, m := range br.Mail {
		fmt.Fprintf(&sb, "\n%s: %d unread\n", m.Account, m.Unread)
		for _, l := range m.Latest {
			sb.WriteString("  " + l + "\n")
		}
	}
	if len(br.Weather) > 0 {
		sb.WriteString("\nWeather\n")
		for _, w := range br.Weather {
			sb.WriteString("  " + w + "\n")
		}
	}
	if len(br.Agenda) > 0 {
		sb.WriteString("\nToday\n")
		for _, ev := range br.Agenda {
			sb.WriteString("  " + ev.Time + "  " + ev.Title + "\n")
		}
	}
	if len(br.Failures) > 0 {
		sb.WriteString("\nFailed in the last 24 hours\n")
		for _, f := range br.Failures {
			sb.WriteString("  " + f + "\n")
		}
	}
	for _, k := range br.Keys {
		sb.WriteString("\nKey " + k + "\n")
	}
	return strings.TrimSpace(sb.String())
}

func (b *briefModule) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	switch c.Action {
	case "brief":
		return sdk.JSON(b.build(ctx))
	case "send":
		in, ok := b.app.Engine.Instance(c.Instance)
		if !ok {
			return sdk.Result{}, errors.New("no such instance")
		}
		var cfg briefConfig
		_ = json.Unmarshal(in.Config, &cfg)
		if len(cfg.Channels) == 0 {
			for _, n := range b.app.Engine.Instances("notify") {
				cfg.Channels = append(cfg.Channels, n.ID)
			}
		}
		if len(cfg.Channels) == 0 {
			return sdk.Result{}, errors.New("connect a notification channel first")
		}
		br := b.build(ctx)
		note, _ := json.Marshal(map[string]string{"title": "Your brief for " + br.Date, "message": br.text(), "priority": "normal"})
		var sent []string
		for _, ch := range cfg.Channels {
			if _, err := b.app.Engine.Invoke(ctx, systemActor, sdk.Call{Instance: ch, Action: "send", Input: note}, core.InvokeOptions{NoWait: true}); err == nil {
				sent = append(sent, ch)
			}
		}
		return sdk.JSON(map[string]any{"sentTo": sent, "brief": br})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}
