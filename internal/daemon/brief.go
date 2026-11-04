package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/modules/notify"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// briefModule is the daily brief (signature feature 10): one summary of
// what needs attention across everything connected. It reads other modules
// through the engine as whoever asked for it (the person who set up a
// scheduled brief), so it never shows more than they could read themselves,
// and every read is audited under their name.
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
			{Name: "send", Title: "Send the brief", Description: "To the notification channels in settings. The preview shows the exact text each channel gets.", Risk: sdk.RiskWrite, DryRun: true},
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

// briefViewer is who a brief is built for: the caller of the brief's
// action, or, for an automation a person saved, that person. Every read the
// brief makes is made as this actor, so it never shows more than the caller
// could read itself.
type briefViewer struct {
	actor core.Actor
	// scopes are the API scopes of the person or key behind the actor, for
	// the parts that aren't module reads (approvals, the audit log, keys).
	scopes []string
	// user is the person whose keys the brief lists.
	user string
}

func (v briefViewer) allows(scope string) bool { return auth.Allows(v.scopes, scope) }

// viewer works out who the brief is for from the call's context, where the
// engine put the caller.
func (b *briefModule) viewer(ctx context.Context) (briefViewer, error) {
	a, ok := core.ActorFrom(ctx)
	if !ok {
		return briefViewer{}, errors.New("the brief runs only through Conduit's engine")
	}
	person := func(id string) (briefViewer, bool) {
		if b.app.Auth == nil {
			return briefViewer{}, false
		}
		u, err := b.app.Auth.GetUser(ctx, id)
		if err != nil || u.Disabled {
			return briefViewer{}, false
		}
		return briefViewer{actor: core.Actor{ID: u.ID, Kind: core.ActorUser, Name: u.Name}, scopes: roleScopes(u.Role), user: u.ID}, true
	}
	switch a.Kind {
	case core.ActorAutomation:
		// A scheduled brief a person set up acts as that person (who saved
		// it last, which is what made it trusted). Any other automation
		// acts as itself, under its own rules, and sees no audit log.
		if b.app.Automations != nil {
			if au, err := b.app.Automations.Get(ctx, a.ID); err == nil && au.Trusted {
				if kind, id, _ := strings.Cut(au.UpdatedBy, ":"); kind == string(core.ActorUser) {
					if v, ok := person(id); ok {
						return v, nil
					}
				}
			}
		}
		return briefViewer{actor: a}, nil
	case core.ActorSystem:
		return briefViewer{actor: a, scopes: []string{"admin:*:*"}}, nil
	}
	// A call over the API or MCP carries the principal that made it. The
	// built-in assistant acts as an agent for the signed-in person and has
	// that person's scopes, as its own tools do.
	if p, ok := ctx.Value(ctxKey{}).(Principal); ok {
		if p.Actor.Subject() == a.Subject() || (a.Kind == core.ActorAgent && p.User.ID != "" && a.ID == "assistant-"+p.User.ID) {
			return briefViewer{actor: a, scopes: p.Scopes, user: p.User.ID}, nil
		}
	}
	if a.Kind == core.ActorUser {
		if v, ok := person(a.ID); ok {
			return v, nil
		}
	}
	return briefViewer{actor: a}, nil
}

// may says whether the policy lets the viewer run a read action outright.
// A read that would ask is left out rather than filed as an approval.
func (b *briefModule) may(ctx context.Context, v briefViewer, in core.Instance, action string) bool {
	d, err := b.app.Engine.Policy.Decide(ctx, v.actor, in.Module, in.ID, action, sdk.RiskRead)
	return err == nil && d.Effect == core.Allow
}

// mayReadAny says whether the viewer may run any read action of the
// instance, which is what showing its health needs.
func (b *briefModule) mayReadAny(ctx context.Context, v briefViewer, in core.Instance) bool {
	m, ok := b.app.Engine.Module(in.Module)
	if !ok {
		return false
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk == sdk.RiskRead && b.may(ctx, v, in, a.Name) {
			return true
		}
	}
	return false
}

// read runs a read action of another module as the viewer.
func (b *briefModule) read(ctx context.Context, v briefViewer, in core.Instance, action string, input any, out any) error {
	if !b.may(ctx, v, in, action) {
		return core.ErrForbidden
	}
	raw, _ := json.Marshal(input)
	res, err := b.app.Engine.Invoke(ctx, v.actor, sdk.Call{Instance: in.ID, Action: action, Input: raw}, core.InvokeOptions{NoWait: true})
	if err != nil {
		return err
	}
	return json.Unmarshal(res.Result.Output, out)
}

func (b *briefModule) build(ctx context.Context, v briefViewer) Brief {
	e := b.app.Engine
	br := Brief{Date: time.Now().Format("Monday 2 January"), Attention: []string{}, Mail: []briefMail{}, Agenda: []briefEvent{}, Failures: []string{}, Keys: []string{}, Weather: []string{}}

	for _, in := range e.Instances("") {
		if !in.Enabled || in.Module == "brief" {
			continue
		}
		// Sections the policy doesn't let the viewer read are left out,
		// health included.
		if !b.mayReadAny(ctx, v, in) {
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
			if b.read(ctx, v, in, "inbox", map[string]any{"unreadOnly": true, "limit": 50}, &list) == nil {
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
			if b.read(ctx, v, in, "today", nil, &w) == nil {
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
			if b.read(ctx, v, in, "today", nil, &evs) == nil {
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
	if v.allows("approvals:*:read") {
		if p, err := e.Approvals.List(ctx, "pending"); err == nil {
			br.Approvals = len(p)
		}
	}
	// Failures come from the audit log, so only for a viewer who may read
	// it, and only as module and action: an error can quote what failed.
	if v.allows("audit:*:read") {
		if entries, err := e.Audit.List(ctx, core.Query{Since: time.Now().Add(-24 * time.Hour), Limit: 500}); err == nil {
			seen := map[string]bool{}
			for _, x := range entries {
				k := x.Module + " " + x.Action
				if x.Status == "error" && !seen[k] {
					seen[k] = true
					br.Failures = append(br.Failures, k)
				}
			}
		}
	}
	// Keys: the viewer's person's own, for whoever may manage keys.
	if v.allows("keys:*:manage") && (v.user != "" || v.actor.Kind == core.ActorSystem) && b.app.Auth != nil {
		if keys, err := b.app.Auth.ListKeys(ctx, v.user); err == nil {
			soon := time.Now().Add(7 * 24 * time.Hour)
			for _, k := range keys {
				if k.Active(time.Now()) && k.ExpiresAt != nil && k.ExpiresAt.Before(soon) {
					br.Keys = append(br.Keys, fmt.Sprintf("%s expires %s", k.Name, k.ExpiresAt.Local().Format("Mon 2 Jan")))
				}
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
	v, err := b.viewer(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "brief":
		return sdk.JSON(b.build(ctx, v))
	case "send":
		return b.send(ctx, v, c)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

// briefChannel is one notification channel the brief goes to.
type briefChannel struct {
	in   core.Instance
	note notify.Note
}

// channels are the notification instances in settings (or every one), each
// with the exact note it would send: a channel set to hide details gets the
// generic line, as the notify module sends it.
func (b *briefModule) channels(c sdk.Call, br Brief) ([]briefChannel, error) {
	in, ok := b.app.Engine.Instance(c.Instance)
	if !ok {
		return nil, errors.New("no such instance")
	}
	var cfg briefConfig
	_ = json.Unmarshal(in.Config, &cfg)
	if len(cfg.Channels) == 0 {
		for _, n := range b.app.Engine.Instances("notify") {
			cfg.Channels = append(cfg.Channels, n.ID)
		}
	}
	full := notify.Note{Title: "Your brief for " + br.Date, Message: br.text(), Priority: "normal"}
	var out []briefChannel
	for _, id := range cfg.Channels {
		n, ok := b.app.Engine.Instance(id)
		if !ok || !n.Enabled || n.Module != "notify" {
			continue
		}
		note := full
		if b.app.Notify != nil && b.app.Notify.HidesDetails(n.ID) {
			note.Title, note.Message = notify.PrivateNote.Title, notify.PrivateNote.Message
		}
		out = append(out, briefChannel{in: n, note: note})
	}
	if len(out) == 0 {
		return nil, errors.New("connect a notification channel first")
	}
	return out, nil
}

// send delivers the brief through each channel's own send action, made as
// the viewer, so the viewer's rules on notifications apply as they would to
// a direct call (a channel it may not use is refused, one that asks files
// an approval).
func (b *briefModule) send(ctx context.Context, v briefViewer, c sdk.Call) (sdk.Result, error) {
	br := b.build(ctx, v)
	chans, err := b.channels(c, br)
	if err != nil {
		return sdk.Result{}, err
	}
	if c.DryRun {
		plan := &sdk.Plan{Summary: fmt.Sprintf("Send the brief for %s to %d notification channel(s)", br.Date, len(chans)), Changes: []sdk.Change{}}
		for _, ch := range chans {
			after, _ := json.Marshal(map[string]string{"title": ch.note.Title, "message": ch.note.Message})
			plan.Changes = append(plan.Changes, sdk.Change{Op: "send", Target: ch.in.Name + " (" + ch.in.ID + ")", After: after})
		}
		return sdk.Result{Plan: plan}, nil
	}
	sent, pending, refused, failed := []string{}, []string{}, []string{}, []string{}
	for _, ch := range chans {
		note, _ := json.Marshal(map[string]string{"title": ch.note.Title, "message": ch.note.Message, "priority": ch.note.Priority})
		_, err := b.app.Engine.Invoke(ctx, v.actor, sdk.Call{Instance: ch.in.ID, Action: "send", Input: note}, core.InvokeOptions{NoWait: true})
		switch {
		case err == nil:
			sent = append(sent, ch.in.ID)
		case errors.Is(err, core.ErrPending):
			pending = append(pending, ch.in.ID)
		case errors.Is(err, core.ErrForbidden):
			refused = append(refused, ch.in.ID)
		default:
			failed = append(failed, ch.in.ID)
		}
	}
	return sdk.JSON(map[string]any{"date": br.Date, "sentTo": sent, "waitingForApproval": pending, "refused": refused, "failed": failed})
}
