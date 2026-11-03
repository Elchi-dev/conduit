// Package ai turns Conduit into tools for AI agents: a catalog built from
// every connected module's actions, an MCP server that exposes it, AI
// providers, and the built-in agent. Every tool call is an ordinary engine
// call made as an agent, so the agent rules, approvals and audit log apply.
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Tool is one callable tool, in the shape MCP and model APIs share.
type Tool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations *Annotations    `json:"annotations,omitempty"`

	// For module tools: which instance and action this calls.
	instance string
	action   string
	risk     sdk.Risk
	dryRun   bool
}

// Annotations are MCP tool hints.
type Annotations struct {
	ReadOnlyHint    bool `json:"readOnlyHint"`
	DestructiveHint bool `json:"destructiveHint"`
	IdempotentHint  bool `json:"idempotentHint"`
	OpenWorldHint   bool `json:"openWorldHint"`
}

// Toolbox builds and runs tools for one caller.
type Toolbox struct {
	Engine *core.Engine
	Actor  core.Actor
	// Allows reports whether the caller holds a scope ("actions:mail:invoke").
	Allows func(scope string) bool
	// Panic pulls the emergency stop with the caller's identity; nil hides
	// the tool.
	Panic func(ctx context.Context) error
}

var nameClean = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func toolName(instance, action string) string {
	n := nameClean.ReplaceAllString(instance, "_") + "__" + nameClean.ReplaceAllString(action, "_")
	if len(n) > 64 {
		n = n[:64]
	}
	return n
}

var emptySchema = json.RawMessage(`{"type":"object","properties":{}}`)

// Tools lists every tool the caller may use, sorted by name. Conduit's own
// tools come first.
func (t *Toolbox) Tools() []Tool {
	tools := t.metaTools()
	var mods []Tool
	for _, in := range t.Engine.Instances("") {
		if !in.Enabled || !t.Allows("actions:"+in.Module+":invoke") {
			continue
		}
		m, ok := t.Engine.Module(in.Module)
		if !ok {
			continue
		}
		man := m.Manifest()
		for _, a := range man.Actions {
			schema := a.Input
			if len(schema) == 0 {
				schema = emptySchema
			}
			title := a.Title
			if title == "" {
				title = a.Name
			}
			desc := fmt.Sprintf("%s on %q (%s). %s", title, in.Name, man.Name, a.Description)
			switch a.Risk {
			case sdk.RiskWrite:
				desc += " Changes something; may need the owner's approval."
			case sdk.RiskDestructive:
				desc += " Destructive; usually needs the owner's approval."
			}
			if a.DryRun {
				desc += " Supports conduit_preview to show exactly what would change first."
			}
			mods = append(mods, Tool{
				Name: toolName(in.ID, a.Name), Title: in.Name + ": " + title, Description: strings.TrimSpace(desc), InputSchema: schema,
				Annotations: &Annotations{ReadOnlyHint: a.Risk == sdk.RiskRead, DestructiveHint: a.Risk == sdk.RiskDestructive, OpenWorldHint: true},
				instance:    in.ID, action: a.Name, risk: a.Risk, dryRun: a.DryRun,
			})
		}
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Name < mods[j].Name })
	return append(tools, mods...)
}

func (t *Toolbox) metaTools() []Tool {
	ro := &Annotations{ReadOnlyHint: true}
	tools := []Tool{
		{Name: "conduit_overview", Title: "Overview", Annotations: ro,
			Description: "Everything connected to Conduit with its live health, plus approvals waiting. Start here.",
			InputSchema: emptySchema},
		{Name: "conduit_preview", Title: "Preview a change", Annotations: ro,
			Description: "Dry-run a tool that supports previews and get the exact list of changes it would make, without making them. Show this to the user before risky changes.",
			InputSchema: json.RawMessage(`{"type":"object","required":["tool"],"properties":{"tool":{"type":"string"},"arguments":{"type":"object"}}}`)},
		{Name: "conduit_approval_status", Title: "Check an approval", Annotations: ro,
			Description: "Whether the owner approved or denied a request. An approved request runs by itself; this reports how it went.",
			InputSchema: json.RawMessage(`{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}`)},
	}
	if t.Allows("audit:*:read") {
		tools = append(tools,
			Tool{Name: "conduit_what_changed", Title: "What changed?", Annotations: ro,
				Description: "Everything that happened around a moment, across all systems: actions, failures, configuration changes, by whom. Use it to explain an outage or a surprise.",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"at":{"type":"string","description":"RFC 3339 time; default now"},"minutes":{"type":"integer","default":60,"description":"How far before 'at' to look"}}}`)},
			Tool{Name: "conduit_timeline", Title: "Timeline", Annotations: ro,
				Description: "Recent entries of the audit log, optionally for one module or matching text.",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"module":{"type":"string"},"search":{"type":"string"},"limit":{"type":"integer","default":30}}}`)})
	}
	if t.Allows("audit:*:undo") {
		tools = append(tools, Tool{Name: "conduit_undo", Title: "Undo",
			Description: "Undo an earlier action by its timeline entry number, if it is reversible.",
			InputSchema: json.RawMessage(`{"type":"object","required":["entry"],"properties":{"entry":{"type":"integer"}}}`)})
	}
	if t.Panic != nil {
		tools = append(tools, Tool{Name: "conduit_emergency_stop", Title: "Emergency stop", Annotations: &Annotations{DestructiveHint: true},
			Description: "Freeze every agent, key and automation and revoke agent keys, including your own. Use only if something is going badly wrong.",
			InputSchema: json.RawMessage(`{"type":"object","required":["reason"],"properties":{"reason":{"type":"string"}}}`)})
	}
	return tools
}

// Result is a tool call's outcome as text for the model, plus structured data.
type Result struct {
	Text    string `json:"text"`
	IsError bool   `json:"isError"`
	// Pending is set when the call waits for the owner's approval.
	Pending *core.Approval `json:"pending,omitempty"`
	Audit   int64          `json:"audit,omitempty"`
}

func textJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func errResult(format string, a ...any) Result {
	return Result{Text: fmt.Sprintf(format, a...), IsError: true}
}

// Call runs a tool by name.
func (t *Toolbox) Call(ctx context.Context, name string, args json.RawMessage) Result {
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage(`{}`)
	}
	switch name {
	case "conduit_overview":
		return t.overview(ctx)
	case "conduit_preview":
		var in struct {
			Tool      string          `json:"tool"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if json.Unmarshal(args, &in) != nil {
			return errResult("invalid arguments")
		}
		tool, ok := t.find(in.Tool)
		if !ok {
			return errResult("no tool named %q", in.Tool)
		}
		if !tool.dryRun {
			return errResult("%s does not support previews; describe the change to the user instead", in.Tool)
		}
		return t.invoke(ctx, tool, in.Arguments, true)
	case "conduit_approval_status":
		var in struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(args, &in)
		a, err := t.Engine.Approvals.Get(ctx, in.ID)
		if err != nil {
			return errResult("no approval %q", in.ID)
		}
		if a.Actor.Subject() != t.Actor.Subject() {
			return errResult("that approval belongs to someone else")
		}
		msg := map[string]string{"pending": "Still waiting for the owner.", "approved": "Approved; it is running.", "denied": "Denied by the owner. Don't retry; ask what they'd like instead.", "expired": "Expired without a decision."}[a.Status]
		if a.Status == "approved" && a.ResultSeq != nil {
			if e, err := t.Engine.Audit.Get(ctx, *a.ResultSeq); err == nil {
				msg = fmt.Sprintf("Approved and ran: %s (timeline entry %d).", e.Status, e.Seq)
				if e.Error != "" {
					msg += " Error: " + e.Error
				} else if len(e.Output) > 0 {
					msg += "\nOutput:\n" + textJSON(e.Output)
				}
			}
		}
		return Result{Text: fmt.Sprintf("%s (%s %s on %s)", msg, a.Action, a.Instance, a.Module)}
	case "conduit_what_changed":
		if !t.Allows("audit:*:read") {
			return errResult("missing scope audit:*:read")
		}
		var in struct {
			At      string `json:"at"`
			Minutes int    `json:"minutes"`
		}
		_ = json.Unmarshal(args, &in)
		return t.whatChanged(ctx, in.At, in.Minutes)
	case "conduit_timeline":
		if !t.Allows("audit:*:read") {
			return errResult("missing scope audit:*:read")
		}
		var in struct {
			Module string `json:"module"`
			Search string `json:"search"`
			Limit  int    `json:"limit"`
		}
		_ = json.Unmarshal(args, &in)
		if in.Limit <= 0 || in.Limit > 100 {
			in.Limit = 30
		}
		list, err := t.Engine.Audit.List(ctx, core.Query{Module: in.Module, Search: in.Search, Limit: in.Limit})
		if err != nil {
			return errResult("%v", err)
		}
		return Result{Text: textJSON(summarizeEntries(list))}
	case "conduit_undo":
		if !t.Allows("audit:*:undo") {
			return errResult("missing scope audit:*:undo")
		}
		var in struct {
			Entry int64 `json:"entry"`
		}
		_ = json.Unmarshal(args, &in)
		out, err := t.Engine.Undo(ctx, t.Actor, in.Entry, core.InvokeOptions{NoWait: true})
		return t.outcome(out, err)
	case "conduit_emergency_stop":
		if t.Panic == nil {
			return errResult("not available")
		}
		if err := t.Panic(ctx); err != nil {
			return errResult("%v", err)
		}
		return Result{Text: "Emergency stop is on. Everything automated is frozen; tell the user what you saw."}
	}
	tool, ok := t.find(name)
	if !ok {
		return errResult("no tool named %q (the system may have been disconnected; call conduit_overview)", name)
	}
	return t.invoke(ctx, tool, args, false)
}

func (t *Toolbox) find(name string) (Tool, bool) {
	for _, tl := range t.Tools() {
		if tl.Name == name && tl.instance != "" {
			return tl, true
		}
	}
	return Tool{}, false
}

func (t *Toolbox) invoke(ctx context.Context, tool Tool, args json.RawMessage, dryRun bool) Result {
	out, err := t.Engine.Invoke(ctx, t.Actor, sdk.Call{Instance: tool.instance, Action: tool.action, Input: args, DryRun: dryRun}, core.InvokeOptions{NoWait: true})
	return t.outcome(out, err)
}

func (t *Toolbox) outcome(out core.Outcome, err error) Result {
	switch {
	case errors.Is(err, core.ErrPending):
		a := out.Approval
		text := fmt.Sprintf("Waiting for the owner's approval (id %s). They have been notified. If they approve, it runs by itself; don't call the tool again. Tell the user what you asked to do and why; check the outcome later with conduit_approval_status.", a.ID)
		if a.Plan != nil {
			text += "\nPlanned changes:\n" + textJSON(a.Plan)
		}
		return Result{Text: text, Pending: a}
	case errors.Is(err, core.ErrForbidden):
		return errResult("Not allowed by the owner's rules: %v. Don't try to work around it; tell the user.", err)
	case err != nil:
		return Result{Text: "Failed: " + err.Error(), IsError: true, Audit: out.Audit.Seq}
	}
	r := Result{Audit: out.Audit.Seq}
	switch {
	case out.Result.Plan != nil:
		r.Text = "Preview (nothing changed yet):\n" + textJSON(out.Result.Plan)
	case len(out.Result.Output) > 0:
		var v any
		_ = json.Unmarshal(out.Result.Output, &v)
		r.Text = truncate(textJSON(v), 60000)
	default:
		r.Text = "Done."
	}
	if out.Audit.Undo != nil {
		r.Text += fmt.Sprintf("\n(Timeline entry %d; can be undone: %s.)", out.Audit.Seq, out.Audit.Undo.Description)
	}
	return r
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n…(truncated)"
}

func (t *Toolbox) overview(ctx context.Context) Result {
	type sys struct {
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		Health string `json:"health"`
		Detail string `json:"detail,omitempty"`
		Tools  string `json:"toolPrefix"`
	}
	var out []sys
	for _, in := range t.Engine.Instances("") {
		if !in.Enabled {
			continue
		}
		hctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		h := t.Engine.Health(hctx, in.ID)
		cancel()
		m, _ := t.Engine.Module(in.Module)
		kind := in.Module
		if m != nil {
			kind = m.Manifest().Name
		}
		out = append(out, sys{Name: in.Name, Kind: kind, Health: h.Status, Detail: h.Message, Tools: nameClean.ReplaceAllString(in.ID, "_") + "__"})
	}
	pending, _ := t.Engine.Approvals.List(ctx, "pending")
	frozen, _ := t.Engine.Policy.Frozen(ctx)
	preset, _ := t.Engine.Policy.Preset(ctx)
	return Result{Text: textJSON(map[string]any{"systems": out, "approvalsWaiting": len(pending), "emergencyStop": frozen, "agentRules": preset, "time": time.Now().Format(time.RFC3339)})}
}

type entrySummary struct {
	Entry  int64  `json:"entry"`
	At     string `json:"at"`
	Who    string `json:"who"`
	What   string `json:"what"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Undo   string `json:"undo,omitempty"`
}

func summarizeEntries(list []core.Entry) []entrySummary {
	out := make([]entrySummary, 0, len(list))
	for _, e := range list {
		who := e.Actor.Name
		if who == "" {
			who = e.Actor.Subject()
		}
		s := entrySummary{Entry: e.Seq, At: e.At.Format(time.RFC3339), Who: who, What: e.Module + "/" + e.Instance + " " + e.Action, Status: e.Status, Error: e.Error}
		if e.Undo != nil && e.UndoneBy == nil {
			s.Undo = e.Undo.Description
		}
		out = append(out, s)
	}
	return out
}

// whatChanged gathers everything around a moment: changes and failures in
// the audit log, grouped, newest first (signature feature 4).
func (t *Toolbox) whatChanged(ctx context.Context, at string, minutes int) Result {
	end := time.Now()
	if at != "" {
		if p, err := time.Parse(time.RFC3339, at); err == nil {
			end = p
		}
	}
	if minutes <= 0 || minutes > 7*24*60 {
		minutes = 60
	}
	start := end.Add(-time.Duration(minutes) * time.Minute)
	list, err := t.Engine.Audit.List(ctx, core.Query{Since: start, Until: end.Add(5 * time.Minute), Limit: 500})
	if err != nil {
		return errResult("%v", err)
	}
	r := WhatChanged(list)
	r.From, r.To = start.Format(time.RFC3339), end.Format(time.RFC3339)
	return Result{Text: textJSON(r)}
}

// Changes is the answer to "what changed?".
type Changes struct {
	From     string         `json:"from"`
	To       string         `json:"to"`
	Changes  []entrySummary `json:"changes"`
	Failures []entrySummary `json:"failures"`
	Blocked  []entrySummary `json:"blocked"`
	Reads    int            `json:"readsOmitted"`
}

// WhatChanged sorts audit entries into changes, failures and blocked
// attempts, leaving out successful reads, which don't change anything.
func WhatChanged(list []core.Entry) Changes {
	c := Changes{Changes: []entrySummary{}, Failures: []entrySummary{}, Blocked: []entrySummary{}}
	for _, e := range list {
		s := summarizeEntries([]core.Entry{e})[0]
		switch {
		case e.Status == "error":
			c.Failures = append(c.Failures, s)
		case e.Status == "denied":
			c.Blocked = append(c.Blocked, s)
		case e.Risk == sdk.RiskRead || e.DryRun:
			c.Reads++
		default:
			c.Changes = append(c.Changes, s)
		}
	}
	return c
}
