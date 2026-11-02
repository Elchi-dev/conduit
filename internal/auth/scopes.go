package auth

import (
	"fmt"
	"strings"
)

// Scopes have the form "<area>:<target>:<access>", each part a word or "*".
//
//	actions:*:invoke        call any action on any module (policy still applies)
//	actions:mail:invoke     call actions on the mail module only
//	modules:*:read          list modules, instances and health
//	audit:*:read            read the audit log and timeline
//	audit:*:undo            undo audited actions
//	approvals:*:read        see pending approvals
//	approvals:*:decide      approve or deny (never granted to agent keys)
//	events:*:read           subscribe to the event stream
//	policy:*:read / manage  read or change policy rules and presets
//	keys:*:manage           create, rotate and revoke keys
//	instances:*:manage      create, change and delete module instances
//	admin:*:*               everything above
//
// A scope grants nothing the policy engine forbids: an agent key with
// actions:*:invoke still has to pass the agent policy for every call.
var knownAreas = map[string][]string{
	"actions":   {"invoke"},
	"modules":   {"read"},
	"audit":     {"read", "undo"},
	"approvals": {"read", "decide"},
	"events":    {"read"},
	"policy":    {"read", "manage"},
	"keys":      {"manage"},
	"instances": {"manage"},
	"admin":     {"*"},
}

// ValidateScope checks a scope string.
func ValidateScope(s string) error {
	p := strings.Split(s, ":")
	if len(p) != 3 {
		return fmt.Errorf("invalid scope %q: want area:target:access", s)
	}
	accesses, ok := knownAreas[p[0]]
	if !ok {
		return fmt.Errorf("invalid scope %q: unknown area %q", s, p[0])
	}
	if p[1] == "" {
		return fmt.Errorf("invalid scope %q: empty target", s)
	}
	if p[2] == "*" {
		return nil
	}
	for _, a := range accesses {
		if a == p[2] || a == "*" {
			return nil
		}
	}
	return fmt.Errorf("invalid scope %q: unknown access %q", s, p[2])
}

// Allows reports whether any granted scope covers need ("area:target:access").
func Allows(granted []string, need string) bool {
	n := strings.Split(need, ":")
	if len(n) != 3 {
		return false
	}
	for _, g := range granted {
		p := strings.Split(g, ":")
		if len(p) != 3 {
			continue
		}
		if p[0] == "admin" {
			return true
		}
		if p[0] == n[0] && (p[1] == "*" || p[1] == n[1]) && (p[2] == "*" || p[2] == n[2]) {
			return true
		}
	}
	return false
}
