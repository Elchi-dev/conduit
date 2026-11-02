// Package sdk is the public contract between Conduit and its modules.
//
// A module is anything Conduit can manage: a mailbox, a vault, a fleet of
// servers, a game launcher. Built-in modules implement Module directly and are
// compiled into the daemon. External modules speak the same contract as
// JSON-RPC over stdio (see docs/protocol/external-modules.md), so they can be
// written in any language.
//
// Module authors import this package and nothing else from Conduit.
package sdk

import (
	"context"
	"encoding/json"
)

// Risk classifies what an action can do. The permission engine uses it as the
// coarsest input when deciding allow / ask / deny.
type Risk string

const (
	// RiskRead never changes state (list mail, read metrics).
	RiskRead Risk = "read"
	// RiskWrite changes state in a way that is usually reversible
	// (send a draft, toggle a light, create a DNS record).
	RiskWrite Risk = "write"
	// RiskDestructive may lose data or disrupt service
	// (delete, restart, kill, reveal a secret).
	RiskDestructive Risk = "destructive"
)

// Manifest describes a module. It is static: everything Conduit needs to show
// the module in the UI, build its settings form and expose its actions to
// agents is derived from it.
type Manifest struct {
	ID          string `json:"id"`          // stable, lowercase, e.g. "mail"
	Name        string `json:"name"`        // human name, e.g. "Mail"
	Version     string `json:"version"`     // semver of the module
	Description string `json:"description"` // one line
	Icon        string `json:"icon,omitempty"`
	Category    string `json:"category,omitempty"` // "communication", "infrastructure", ...

	// ConfigSchema is a JSON Schema for one instance's settings. Fields that
	// hold credentials are strings in the form "secret://<name>" and are
	// resolved by the vault at call time.
	ConfigSchema json.RawMessage `json:"configSchema,omitempty"`

	Actions   []ActionSpec   `json:"actions"`
	Resources []ResourceSpec `json:"resources,omitempty"`
	Events    []EventSpec    `json:"events,omitempty"`

	// Presets lists the onboarding presets that enable this module by default
	// ("developer", "gamer", "homelab", "team").
	Presets []string `json:"presets,omitempty"`
}

// ActionSpec declares one callable action.
type ActionSpec struct {
	Name        string          `json:"name"` // e.g. "send_message"
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Risk        Risk            `json:"risk"`
	Input       json.RawMessage `json:"input,omitempty"`  // JSON Schema
	Output      json.RawMessage `json:"output,omitempty"` // JSON Schema
	// Reversible actions return an Undo token in their Result.
	Reversible bool `json:"reversible,omitempty"`
	// DryRun actions accept Call.DryRun and return a Plan instead of acting.
	DryRun bool `json:"dryRun,omitempty"`
}

// ResourceSpec declares a kind of thing the module can list and open.
type ResourceSpec struct {
	Kind       string          `json:"kind"` // e.g. "mailbox", "server"
	Title      string          `json:"title"`
	Schema     json.RawMessage `json:"schema,omitempty"`
	ListAction string          `json:"listAction,omitempty"`
	GetAction  string          `json:"getAction,omitempty"`
	ViewHint   string          `json:"viewHint,omitempty"` // "table", "log", "chart", "detail"
}

// EventSpec declares an event type the module emits.
type EventSpec struct {
	Type        string          `json:"type"` // e.g. "mail.received"
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema,omitempty"`
}

// Call is one invocation of an action.
type Call struct {
	Instance string          `json:"instance"` // configured instance id, e.g. "work-mail"
	Action   string          `json:"action"`
	Input    json.RawMessage `json:"input,omitempty"`
	DryRun   bool            `json:"dryRun,omitempty"`
}

// Result is what an action returns.
type Result struct {
	Output json.RawMessage `json:"output,omitempty"`
	// Plan is set instead of Output when the call was a dry run.
	Plan *Plan `json:"plan,omitempty"`
	// Undo, when set, can be passed back to the module to reverse this call.
	Undo *Undo `json:"undo,omitempty"`
}

// Plan describes what an action would do, as a list of human-readable changes
// with optional before/after values for rendering a diff.
type Plan struct {
	Summary string   `json:"summary"`
	Changes []Change `json:"changes"`
}

// Change is one line of a Plan.
type Change struct {
	Target string          `json:"target"` // e.g. "nginx.service on web-2"
	Op     string          `json:"op"`     // "create", "update", "delete", "restart", ...
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
}

// Undo is an opaque token plus the action that reverses a call.
type Undo struct {
	Action string          `json:"action"`
	Input  json.RawMessage `json:"input"`
	// Description is shown on the Undo button, e.g. "Restore 3 DNS records".
	Description string `json:"description"`
}

// Event is something that happened, published on the event bus.
type Event struct {
	Type     string          `json:"type"`
	Module   string          `json:"module"`
	Instance string          `json:"instance,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
}

// Host is what Conduit gives a module: access to secrets, event publishing and
// logging. Modules never touch storage, the network policy or other modules
// directly.
type Host interface {
	// Secret resolves a "secret://name" reference. The value must not be
	// logged or returned in action output.
	Secret(ctx context.Context, ref string) (string, error)
	// Publish emits an event on the bus.
	Publish(ctx context.Context, e Event)
	// Log writes a structured log line attributed to the module.
	Log(level, msg string, kv ...any)
}

// Module is implemented by every built-in module.
type Module interface {
	Manifest() Manifest
	// Configure validates and applies one instance's settings. It is called
	// once per instance at start and again whenever settings change.
	Configure(ctx context.Context, host Host, instance string, config json.RawMessage) error
	// Invoke runs an action. The permission engine has already approved it.
	Invoke(ctx context.Context, call Call) (Result, error)
	// Health reports whether an instance is reachable and working.
	Health(ctx context.Context, instance string) Health
	// Close releases everything held for an instance.
	Close(instance string) error
}

// Health is a module instance's status.
type Health struct {
	Status  string `json:"status"` // "ok", "degraded", "down", "unconfigured"
	Message string `json:"message,omitempty"`
}
