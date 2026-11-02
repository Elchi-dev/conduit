package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Effect is a policy decision.
type Effect string

const (
	Allow Effect = "allow"
	Ask   Effect = "ask"
	Deny  Effect = "deny"
)

// ActorKind is who is making a call.
type ActorKind string

const (
	// ActorUser is a signed-in human acting directly in a Conduit client.
	ActorUser ActorKind = "user"
	// ActorAgent is an AI agent (built-in, MCP client or API-connected).
	ActorAgent ActorKind = "agent"
	// ActorKey is a program using an API key.
	ActorKey ActorKind = "key"
	// ActorAutomation is a trigger or scheduled automation.
	ActorAutomation ActorKind = "automation"
	// ActorSystem is Conduit itself (health checks, undo replays).
	ActorSystem ActorKind = "system"
)

// Actor identifies the caller of an action.
type Actor struct {
	ID   string    `json:"id"`
	Kind ActorKind `json:"kind"`
	Name string    `json:"name,omitempty"`
}

// Subject returns the policy subject string, e.g. "agent:claude-desktop".
func (a Actor) Subject() string { return string(a.Kind) + ":" + a.ID }

// Rule is one policy rule. "*" matches anything. Subject may be "*",
// "kind:<actor kind>" or "<kind>:<id>".
type Rule struct {
	ID        string     `json:"id"`
	Position  int        `json:"position"`
	Subject   string     `json:"subject"`
	Module    string     `json:"module"`
	Instance  string     `json:"instance"`
	Action    string     `json:"action"`
	Risk      string     `json:"risk"`
	Effect    Effect     `json:"effect"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Note      string     `json:"note,omitempty"`
}

func (r Rule) matches(a Actor, module, instance, action string, risk sdk.Risk, now time.Time) bool {
	if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
		return false
	}
	switch r.Subject {
	case "*", a.Subject(), "kind:" + string(a.Kind):
	default:
		return false
	}
	return wild(r.Module, module) && wild(r.Instance, instance) && wild(r.Action, action) && wild(r.Risk, string(risk))
}

func wild(pattern, v string) bool { return pattern == "*" || pattern == v }

// Preset is the baseline autonomy for non-human callers, applied when no rule
// matches.
type Preset string

const (
	PresetReadOnly       Preset = "read-only"
	PresetAskWrites      Preset = "ask-writes"      // default
	PresetAskDestructive Preset = "ask-destructive" // writes allowed
	PresetFullAutonomy   Preset = "full-autonomy"
)

// Presets lists the presets in order of increasing autonomy.
var Presets = []Preset{PresetReadOnly, PresetAskWrites, PresetAskDestructive, PresetFullAutonomy}

func (p Preset) decide(risk sdk.Risk) Effect {
	switch p {
	case PresetReadOnly:
		if risk == sdk.RiskRead {
			return Allow
		}
		return Deny
	case PresetAskDestructive:
		if risk == sdk.RiskDestructive {
			return Ask
		}
		return Allow
	case PresetFullAutonomy:
		return Allow
	default: // ask-writes
		if risk == sdk.RiskRead {
			return Allow
		}
		return Ask
	}
}

// Decision is the outcome of evaluating the policy, with the reason shown to
// people and recorded in the audit log.
type Decision struct {
	Effect Effect `json:"effect"`
	Reason string `json:"reason"`
	RuleID string `json:"ruleId,omitempty"`
}

// Policy evaluates rules stored in the database.
type Policy struct {
	store *Store
	now   func() time.Time
}

// NewPolicy returns a policy engine backed by store.
func NewPolicy(s *Store) *Policy { return &Policy{store: s, now: time.Now} }

const (
	settingPreset = "policy.preset"
	settingFrozen = "policy.frozen"
)

// Decide returns allow, ask or deny for a call.
//
// Order: the panic freeze first, then rules by position (first match wins),
// then the baseline: humans acting directly are allowed, everyone else gets
// the active preset.
func (p *Policy) Decide(ctx context.Context, a Actor, module, instance, action string, risk sdk.Risk) (Decision, error) {
	frozen, err := p.Frozen(ctx)
	if err != nil {
		return Decision{}, err
	}
	if frozen && a.Kind != ActorUser && a.Kind != ActorSystem {
		return Decision{Effect: Deny, Reason: "panic mode is on: all agents, keys and automations are frozen"}, nil
	}
	rules, err := p.Rules(ctx)
	if err != nil {
		return Decision{}, err
	}
	now := p.now()
	for _, r := range rules {
		if r.matches(a, module, instance, action, risk, now) {
			reason := "rule " + r.ID
			if r.Note != "" {
				reason += ": " + r.Note
			}
			return Decision{Effect: r.Effect, Reason: reason, RuleID: r.ID}, nil
		}
	}
	if a.Kind == ActorUser || a.Kind == ActorSystem {
		return Decision{Effect: Allow, Reason: "direct action by " + string(a.Kind)}, nil
	}
	preset, err := p.Preset(ctx)
	if err != nil {
		return Decision{}, err
	}
	return Decision{Effect: preset.decide(risk), Reason: "preset " + string(preset)}, nil
}

// Rules returns all rules in evaluation order.
func (p *Policy) Rules(ctx context.Context) ([]Rule, error) {
	rows, err := p.store.DB.QueryContext(ctx, `SELECT id, position, subject, module, instance, action, risk, effect, expires_at, note FROM policy_rules ORDER BY position, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var exp sql.NullString
		if err := rows.Scan(&r.ID, &r.Position, &r.Subject, &r.Module, &r.Instance, &r.Action, &r.Risk, &r.Effect, &exp, &r.Note); err != nil {
			return nil, err
		}
		if exp.Valid {
			t, err := time.Parse(time.RFC3339Nano, exp.String)
			if err == nil {
				r.ExpiresAt = &t
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PutRule inserts or replaces a rule.
func (p *Policy) PutRule(ctx context.Context, r Rule) error {
	if r.ID == "" {
		r.ID = NewID("rule")
	}
	for _, f := range []*string{&r.Subject, &r.Module, &r.Instance, &r.Action, &r.Risk} {
		if *f == "" {
			*f = "*"
		}
	}
	switch r.Effect {
	case Allow, Ask, Deny:
	default:
		return fmt.Errorf("invalid effect %q", r.Effect)
	}
	var exp any
	if r.ExpiresAt != nil {
		exp = r.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	_, err := p.store.DB.ExecContext(ctx, `INSERT OR REPLACE INTO policy_rules (id, position, subject, module, instance, action, risk, effect, expires_at, note) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Position, r.Subject, r.Module, r.Instance, r.Action, r.Risk, r.Effect, exp, r.Note)
	return err
}

// DeleteRule removes a rule.
func (p *Policy) DeleteRule(ctx context.Context, id string) error {
	_, err := p.store.DB.ExecContext(ctx, `DELETE FROM policy_rules WHERE id = ?`, id)
	return err
}

// Preset returns the active baseline preset.
func (p *Policy) Preset(ctx context.Context) (Preset, error) {
	v, err := getSetting(ctx, p.store, settingPreset)
	if err != nil {
		return "", err
	}
	if v == "" {
		return PresetAskWrites, nil
	}
	return Preset(v), nil
}

// SetPreset changes the baseline preset.
func (p *Policy) SetPreset(ctx context.Context, preset Preset) error {
	for _, known := range Presets {
		if known == preset {
			return setSetting(ctx, p.store, settingPreset, string(preset))
		}
	}
	return fmt.Errorf("unknown preset %q", preset)
}

// Frozen reports whether panic mode is on.
func (p *Policy) Frozen(ctx context.Context) (bool, error) {
	v, err := getSetting(ctx, p.store, settingFrozen)
	return v == "1", err
}

// SetFrozen turns panic mode on or off. Only humans may turn it off; that
// check happens in the API layer.
func (p *Policy) SetFrozen(ctx context.Context, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return setSetting(ctx, p.store, settingFrozen, v)
}

func getSetting(ctx context.Context, s *Store, key string) (string, error) {
	var v string
	err := s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func setSetting(ctx context.Context, s *Store, key, value string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
