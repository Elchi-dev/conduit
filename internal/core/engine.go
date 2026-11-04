package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Errors returned by Engine.Invoke.
var (
	ErrNotFound  = errors.New("not found")
	ErrForbidden = errors.New("forbidden by policy")
	// ErrPending is returned with an approval when the caller asked not to wait.
	ErrPending = errors.New("waiting for approval")
)

// SecretResolver resolves "secret://name" references. The vault implements it.
type SecretResolver interface {
	Resolve(ctx context.Context, ref string) (string, error)
}

// Instance is a configured instance of a module.
type Instance struct {
	ID      string          `json:"id"`
	Module  string          `json:"module"`
	Name    string          `json:"name"`
	Config  json.RawMessage `json:"config"`
	Enabled bool            `json:"enabled"`
	// Network is the daemon network (internal/wgnet) the instance's
	// outbound connections go through; "" for none.
	Network   string    `json:"network,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Engine is the heart of the daemon: it owns the modules and runs every call
// through policy, approval, execution, audit and events.
type Engine struct {
	Store     *Store
	Bus       *Bus
	Policy    *Policy
	Audit     *Audit
	Approvals *Approvals
	Log       *slog.Logger

	// Guard, when set, is asked before the policy for every call and can
	// refuse it (the daemon uses it for restricted vault folders). A
	// refusal is audited as denied.
	Guard func(ctx context.Context, actor Actor, in Instance, call sdk.Call) error

	mu        sync.RWMutex
	modules   map[string]sdk.Module
	instances map[string]Instance
	secrets   SecretResolver
	networks  Networks
}

// Networks carries instances' connections through the daemon's networks
// (userspace WireGuard tunnels, internal/wgnet).
type Networks interface {
	// Dial connects to addr through network id: destinations inside the
	// network go through its tunnel, others directly if direct allows
	// them (nil allows all).
	Dial(ctx context.Context, id, network, addr string, direct func(netip.Addr) bool) (net.Conn, error)
}

// SetNetworks installs the daemon's networks.
func (e *Engine) SetNetworks(n Networks) {
	e.mu.Lock()
	e.networks = n
	e.mu.Unlock()
}

// NewEngine assembles an engine on top of an open store.
func NewEngine(store *Store, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	bus := NewBus()
	return &Engine{
		Store:     store,
		Bus:       bus,
		Policy:    NewPolicy(store),
		Audit:     NewAudit(store),
		Approvals: NewApprovals(store, bus, 15*time.Minute),
		Log:       log,
		modules:   map[string]sdk.Module{},
		instances: map[string]Instance{},
	}
}

// SetSecrets installs the secret resolver (the vault).
func (e *Engine) SetSecrets(r SecretResolver) {
	e.mu.Lock()
	e.secrets = r
	e.mu.Unlock()
}

// Register adds a built-in or external module.
func (e *Engine) Register(m sdk.Module) error {
	id := m.Manifest().ID
	if id == "" {
		return errors.New("module manifest has no id")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, dup := e.modules[id]; dup {
		return fmt.Errorf("module %q already registered", id)
	}
	e.modules[id] = m
	return nil
}

// Unregister removes a module (used when an MCP server is unmounted).
func (e *Engine) Unregister(id string) {
	e.mu.Lock()
	delete(e.modules, id)
	e.mu.Unlock()
}

// Modules returns the manifests of every registered module, sorted by name.
func (e *Engine) Modules() []sdk.Manifest {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]sdk.Manifest, 0, len(e.modules))
	for _, m := range e.modules {
		out = append(out, m.Manifest())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Module returns one module.
func (e *Engine) Module(id string) (sdk.Module, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	m, ok := e.modules[id]
	return m, ok
}

// Start loads stored instances and configures each enabled one. A failing
// instance is logged and left unhealthy; it does not stop the daemon.
func (e *Engine) Start(ctx context.Context) error {
	rows, err := e.Store.DB.QueryContext(ctx, `SELECT id, module, name, config, enabled, network, created_at, updated_at FROM instances`)
	if err != nil {
		return err
	}
	var list []Instance
	for rows.Next() {
		var in Instance
		var cfg, c, u string
		if err := rows.Scan(&in.ID, &in.Module, &in.Name, &cfg, &in.Enabled, &in.Network, &c, &u); err != nil {
			rows.Close()
			return err
		}
		in.Config = json.RawMessage(cfg)
		in.CreatedAt, _ = time.Parse(time.RFC3339Nano, c)
		in.UpdatedAt, _ = time.Parse(time.RFC3339Nano, u)
		list = append(list, in)
	}
	rows.Close()
	for _, in := range list {
		e.mu.Lock()
		e.instances[in.ID] = in
		e.mu.Unlock()
		if in.Enabled {
			if err := e.configure(ctx, in); err != nil {
				e.Log.Warn("instance failed to configure", "instance", in.ID, "module", in.Module, "err", err)
			}
		}
	}
	return nil
}

func (e *Engine) configure(ctx context.Context, in Instance) error {
	m, ok := e.Module(in.Module)
	if !ok {
		return fmt.Errorf("%w: module %q", ErrNotFound, in.Module)
	}
	return m.Configure(ctx, &host{e: e, module: in.Module, instance: in.ID}, in.ID, in.Config)
}

// Instances returns all instances, optionally for one module.
func (e *Engine) Instances(module string) []Instance {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []Instance
	for _, in := range e.instances {
		if module == "" || in.Module == module {
			out = append(out, in)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Instance returns one instance.
func (e *Engine) Instance(id string) (Instance, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	in, ok := e.instances[id]
	return in, ok
}

// SaveInstance creates or updates an instance and (re)configures it.
func (e *Engine) SaveInstance(ctx context.Context, in Instance) (Instance, error) {
	if _, ok := e.Module(in.Module); !ok {
		return in, fmt.Errorf("%w: module %q", ErrNotFound, in.Module)
	}
	if in.ID == "" {
		in.ID = NewID(in.Module)
	}
	if len(in.Config) == 0 {
		in.Config = json.RawMessage("{}")
	}
	if in.Name == "" {
		in.Name = in.Module
	}
	now := time.Now().UTC()
	in.UpdatedAt = now
	if old, ok := e.Instance(in.ID); ok {
		in.CreatedAt = old.CreatedAt
	} else {
		in.CreatedAt = now
	}
	if in.Enabled {
		if err := e.configure(ctx, in); err != nil {
			return in, fmt.Errorf("configure: %w", err)
		}
	} else if m, ok := e.Module(in.Module); ok {
		_ = m.Close(in.ID)
	}
	_, err := e.Store.DB.ExecContext(ctx, `INSERT INTO instances (id, module, name, config, enabled, network, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, config = excluded.config, enabled = excluded.enabled, network = excluded.network, updated_at = excluded.updated_at`,
		in.ID, in.Module, in.Name, string(in.Config), in.Enabled, in.Network, in.CreatedAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return in, err
	}
	e.mu.Lock()
	e.instances[in.ID] = in
	e.mu.Unlock()
	data, _ := json.Marshal(map[string]string{"id": in.ID, "module": in.Module})
	e.Bus.Publish(sdk.Event{Type: "instance.saved", Module: "core", Instance: in.ID, Data: data})
	return in, nil
}

// DeleteInstance closes and removes an instance.
func (e *Engine) DeleteInstance(ctx context.Context, id string) error {
	in, ok := e.Instance(id)
	if !ok {
		return ErrNotFound
	}
	if m, ok := e.Module(in.Module); ok {
		_ = m.Close(id)
	}
	if _, err := e.Store.DB.ExecContext(ctx, `DELETE FROM instances WHERE id = ?`, id); err != nil {
		return err
	}
	e.mu.Lock()
	delete(e.instances, id)
	e.mu.Unlock()
	e.Bus.Publish(sdk.Event{Type: "instance.deleted", Module: "core", Instance: id})
	return nil
}

// Health checks one instance.
func (e *Engine) Health(ctx context.Context, id string) sdk.Health {
	in, ok := e.Instance(id)
	if !ok {
		return sdk.Health{Status: "down", Message: "no such instance"}
	}
	if !in.Enabled {
		return sdk.Health{Status: "unconfigured", Message: "disabled"}
	}
	m, ok := e.Module(in.Module)
	if !ok {
		return sdk.Health{Status: "down", Message: "module not installed"}
	}
	return m.Health(ctx, id)
}

// InvokeOptions tunes one call.
type InvokeOptions struct {
	// NoWait returns ErrPending with the approval instead of blocking. The
	// call then runs in the background as soon as a person approves it; its
	// audit entry is recorded on the approval (ResultSeq).
	NoWait bool
	// undoes links this call to the audit entry it reverses.
	undoes *int64
}

// Outcome is the full result of an invocation.
type Outcome struct {
	Result   sdk.Result `json:"result"`
	Decision Decision   `json:"decision"`
	Audit    Entry      `json:"audit"`
	Approval *Approval  `json:"approval,omitempty"`
}

// Invoke runs one action for actor. It is the only path into a module.
func (e *Engine) Invoke(ctx context.Context, actor Actor, call sdk.Call, opt InvokeOptions) (Outcome, error) {
	in, ok := e.Instance(call.Instance)
	if !ok {
		return Outcome{}, fmt.Errorf("%w: instance %q", ErrNotFound, call.Instance)
	}
	m, ok := e.Module(in.Module)
	if !ok {
		return Outcome{}, fmt.Errorf("%w: module %q", ErrNotFound, in.Module)
	}
	spec, ok := findAction(m.Manifest(), call.Action)
	if !ok {
		return Outcome{}, fmt.Errorf("%w: action %q on module %q", ErrNotFound, call.Action, in.Module)
	}
	if !in.Enabled {
		return Outcome{}, fmt.Errorf("instance %q is disabled", in.ID)
	}
	if call.DryRun && !spec.DryRun {
		return Outcome{}, fmt.Errorf("action %q does not support dry runs", spec.Name)
	}

	base := Entry{Actor: actor, Module: in.Module, Instance: in.ID, Action: spec.Name, Risk: spec.Risk, DryRun: call.DryRun, Input: redact(spec, call.Input), Undoes: opt.undoes}

	if e.Guard != nil {
		if err := e.Guard(ctx, actor, in, call); err != nil {
			base.Status, base.Error, base.Decision = "denied", err.Error(), Deny
			out := Outcome{Decision: Decision{Effect: Deny, Reason: err.Error()}}
			out.Audit, _ = e.Audit.Append(ctx, base)
			return out, fmt.Errorf("%w: %s", ErrForbidden, err.Error())
		}
	}

	decision, err := e.Policy.Decide(ctx, actor, in.Module, in.ID, spec.Name, spec.Risk)
	if err != nil {
		return Outcome{}, err
	}
	base.Decision = decision.Effect
	out := Outcome{Decision: decision}

	// Dry runs never change anything, so they only need "not denied"
	// (allow or ask). A preview can quote what the module's reads would
	// return, though, so a caller denied any of them gets it redacted.
	if decision.Effect == Deny {
		base.Status, base.Error = "denied", decision.Reason
		out.Audit, _ = e.Audit.Append(ctx, base)
		return out, fmt.Errorf("%w: %s", ErrForbidden, decision.Reason)
	}

	if call.DryRun {
		readDenied, err := e.deniesAnyRead(ctx, actor, m.Manifest(), in.ID)
		if err != nil {
			return Outcome{}, err
		}
		return e.run(ctx, m, spec, in, call, base, out, "", readDenied)
	}

	if decision.Effect == Ask {
		var plan *sdk.Plan
		private := spec.Sensitive
		if spec.DryRun {
			dry := call
			dry.DryRun = true
			if r, err := m.Invoke(ctx, dry); err == nil {
				plan = r.Plan
				if plan != nil && plan.Changes == nil {
					plan.Changes = []sdk.Change{}
				}
			}
			if plan != nil && !private {
				if private, err = e.deniesAnyRead(ctx, actor, m.Manifest(), in.ID); err != nil {
					return out, err
				}
			}
		}
		appr, err := e.Approvals.Request(ctx, Approval{Actor: actor, Module: in.Module, Instance: in.ID, Action: spec.Name, Risk: spec.Risk, Input: redact(spec, call.Input), Plan: plan, PlanPrivate: private})
		if err != nil {
			return out, err
		}
		// The caller gets the approval as everyone who can't decide sees it.
		view := appr.View()
		out.Approval = &view
		if opt.NoWait {
			go e.runWhenApproved(actor, m, spec, in, call, base, appr)
			return out, ErrPending
		}
		if err := e.Approvals.Wait(ctx, appr.ID); err != nil {
			base.Status, base.Error = "denied", err.Error()
			out.Audit, _ = e.Audit.Append(ctx, base)
			return out, err
		}
		return e.run(ctx, m, spec, in, call, base, out, appr.ID, false)
	}
	return e.run(ctx, m, spec, in, call, base, out, "", false)
}

// deniesAnyRead says whether the policy denies actor any read action of
// the module on this instance. Such a caller's dry runs get their plans
// redacted: a preview often quotes the very data those reads return (the
// message a redact removes, the transaction a delete drops).
func (e *Engine) deniesAnyRead(ctx context.Context, actor Actor, mf sdk.Manifest, instance string) (bool, error) {
	for _, a := range mf.Actions {
		if a.Risk != sdk.RiskRead {
			continue
		}
		d, err := e.Policy.Decide(ctx, actor, mf.ID, instance, a.Name, a.Risk)
		if err != nil {
			return false, err
		}
		if d.Effect == Deny {
			return true, nil
		}
	}
	return false, nil
}

// runWhenApproved waits for a person's decision on a call whose caller
// didn't wait, then runs it (or audits the refusal). The policy is checked
// again first, so a freeze or a rule change in the meantime still applies.
func (e *Engine) runWhenApproved(actor Actor, m sdk.Module, spec sdk.ActionSpec, in Instance, call sdk.Call, base Entry, appr Approval) {
	ctx := context.Background()
	if err := e.Approvals.Wait(ctx, appr.ID); err != nil {
		base.Status, base.Error = "denied", err.Error()
		_, _ = e.Audit.Append(ctx, base)
		return
	}
	d, err := e.Policy.Decide(ctx, actor, in.Module, in.ID, spec.Name, spec.Risk)
	if err != nil || d.Effect == Deny {
		reason := "the rules changed before it ran"
		if err == nil {
			reason = d.Reason
		}
		base.Status, base.Error, base.Decision = "denied", reason, Deny
		if entry, err := e.Audit.Append(ctx, base); err == nil {
			_ = e.Approvals.SetResult(ctx, appr.ID, entry.Seq)
		}
		return
	}
	cur, ok := e.Instance(in.ID)
	if !ok || !cur.Enabled {
		base.Status, base.Error = "error", "the instance was removed or disabled before it ran"
		if entry, err := e.Audit.Append(ctx, base); err == nil {
			_ = e.Approvals.SetResult(ctx, appr.ID, entry.Seq)
		}
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	_, _ = e.run(cctx, m, spec, cur, call, base, Outcome{Decision: d}, appr.ID, false)
}

// run calls the module and audits the result. hidePlan redacts a dry
// run's plan for the caller too (it is denied some of the module's reads);
// a sensitive action's plan is always redacted in the log and events.
func (e *Engine) run(ctx context.Context, m sdk.Module, spec sdk.ActionSpec, in Instance, call sdk.Call, base Entry, out Outcome, approval string, hidePlan bool) (Outcome, error) {
	res, err := m.Invoke(ctx, call)
	if res.Plan != nil && res.Plan.Changes == nil {
		res.Plan.Changes = []sdk.Change{}
	}
	if hidePlan && res.Plan != nil {
		res.Plan = RedactPlan(spec.Name, res.Plan)
	}
	out.Result = res
	switch {
	case err != nil:
		base.Status, base.Error = "error", err.Error()
	case call.DryRun:
		base.Status = "planned"
		if res.Plan != nil {
			plan := res.Plan
			if spec.Sensitive {
				plan = RedactPlan(spec.Name, plan)
			}
			base.Output, _ = json.Marshal(plan)
		}
	default:
		base.Status = "ok"
		base.Output = redact(spec, res.Output)
		if keepUndo(m, spec, res.Undo) {
			base.Undo = res.Undo
		}
	}
	entry, aerr := e.Audit.Append(ctx, base)
	out.Audit = entry
	if aerr != nil {
		e.Log.Error("audit append failed", "err", aerr)
	} else if approval != "" {
		_ = e.Approvals.SetResult(context.WithoutCancel(ctx), approval, entry.Seq)
	}
	data, _ := json.Marshal(entry)
	e.Bus.Publish(sdk.Event{Type: "action." + base.Status, Module: in.Module, Instance: in.ID, Data: data})
	if err != nil {
		return out, err
	}
	return out, aerr
}

// Undo reverses an audited call. The reversal is itself a call: it goes
// through the policy and is audited, linked to the entry it undoes.
func (e *Engine) Undo(ctx context.Context, actor Actor, seq int64, opt InvokeOptions) (Outcome, error) {
	entry, err := e.Audit.Get(ctx, seq)
	if errors.Is(err, sql.ErrNoRows) {
		return Outcome{}, ErrNotFound
	}
	if err != nil {
		return Outcome{}, err
	}
	if entry.Undo == nil {
		return Outcome{}, fmt.Errorf("entry %d cannot be undone", seq)
	}
	if entry.UndoneBy != nil {
		return Outcome{}, fmt.Errorf("entry %d was already undone by entry %d", seq, *entry.UndoneBy)
	}
	opt.undoes = &seq
	return e.Invoke(ctx, actor, sdk.Call{Instance: entry.Instance, Action: entry.Undo.Action, Input: entry.Undo.Input}, opt)
}

// Panic freezes every non-human caller and denies all pending approvals.
// Revoking API keys and ending sessions is done by the daemon layer, which
// owns them, after calling this.
func (e *Engine) Panic(ctx context.Context, by Actor) (int, error) {
	if err := e.Policy.SetFrozen(ctx, true); err != nil {
		return 0, err
	}
	n, err := e.Approvals.DenyAllPending(ctx, by.Subject())
	data, _ := json.Marshal(map[string]any{"by": by, "deniedApprovals": n})
	e.Bus.Publish(sdk.Event{Type: "panic.on", Module: "core", Data: data})
	_, _ = e.Audit.Append(ctx, Entry{Actor: by, Module: "core", Instance: "core", Action: "panic", Risk: sdk.RiskDestructive, Decision: Allow, Status: "ok", Output: data})
	return n, err
}

// Unpanic lifts the freeze. Only a human may call it (enforced by the API).
func (e *Engine) Unpanic(ctx context.Context, by Actor) error {
	if err := e.Policy.SetFrozen(ctx, false); err != nil {
		return err
	}
	e.Bus.Publish(sdk.Event{Type: "panic.off", Module: "core"})
	_, err := e.Audit.Append(ctx, Entry{Actor: by, Module: "core", Instance: "core", Action: "unpanic", Risk: sdk.RiskWrite, Decision: Allow, Status: "ok"})
	return err
}

// Close closes every configured instance.
func (e *Engine) Close() {
	for _, in := range e.Instances("") {
		if m, ok := e.Module(in.Module); ok {
			_ = m.Close(in.ID)
		}
	}
}

// redacted replaces secret material in the audit log, approvals and events.
var redacted = json.RawMessage(`"[redacted]"`)

// redact keeps the field names of a sensitive action's JSON object (so the
// log still says which secret was touched) but drops every value except
// those under the keys "name" and "names".
func redact(spec sdk.ActionSpec, b json.RawMessage) json.RawMessage {
	if !spec.Sensitive || len(b) == 0 || string(b) == "null" {
		return b
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return redacted
	}
	for k := range m {
		if k != "name" && k != "names" {
			m[k] = redacted
		}
	}
	out, _ := json.Marshal(m)
	return out
}

// RedactPlan returns a copy of a plan with nothing but its shape: the
// summary becomes "Change to <action> (details hidden)", and every change
// keeps its op while its target, before and after become "[redacted]".
// It's what the audit log, events and approvals (for anyone who can't
// decide them) hold for a sensitive action, and what a caller denied some of
// a module's reads gets from a dry run.
func RedactPlan(action string, p *sdk.Plan) *sdk.Plan {
	if p == nil {
		return nil
	}
	out := &sdk.Plan{Summary: "Change to " + action + " (details hidden)", Changes: make([]sdk.Change, 0, len(p.Changes))}
	for _, c := range p.Changes {
		r := sdk.Change{Target: "[redacted]", Op: c.Op}
		if len(c.Before) > 0 {
			r.Before = redacted
		}
		if len(c.After) > 0 {
			r.After = redacted
		}
		out.Changes = append(out.Changes, r)
	}
	return out
}

// keepUndo says whether an action's undo token may go in the audit log. A
// sensitive action's token is kept only when it reverses through an action
// of the same module that isn't sensitive itself: that action's input is
// logged in the clear whenever it runs, so its contract is that it carries
// no secret (kv_delete takes a key, restore_version a version number). The
// one exception is a token that holds nothing but identifiers ("id",
// "name" or "names" with scalar values, or record numbers in refKeys),
// which are no secret even when the action it calls is sensitive (a
// transaction deleted by its id, a note by its ticket's number and its
// own). An undo that would replay a secret value (put the old value back)
// is dropped, and such actions don't declare themselves reversible.
func keepUndo(m sdk.Module, spec sdk.ActionSpec, u *sdk.Undo) bool {
	if u == nil || !spec.Sensitive {
		return true
	}
	target, ok := findAction(m.Manifest(), u.Action)
	return ok && (!target.Sensitive || idOnly(u.Input))
}

// refKeys are the keys besides "id" under which an undo token names a
// record by its number: a note is deleted by its ticket's and its own id.
// Their values must be positive integers (a number or a string of digits),
// so nothing but a reference fits.
var refKeys = map[string]bool{"ticket": true, "conversation": true, "note": true, "article": true}

// refIDRe matches a record number for refKeys.
var refIDRe = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

// idOnly says whether an undo input is an object holding only identifiers:
// the keys "id", "name" and "names", with numbers or short strings, and the
// record references in refKeys, with positive integers.
func idOnly(b json.RawMessage) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil || len(m) == 0 {
		return false
	}
	scalar := func(v json.RawMessage) bool {
		var n json.Number
		var s string
		return json.Unmarshal(v, &n) == nil || (json.Unmarshal(v, &s) == nil && len(s) <= 200)
	}
	for k, v := range m {
		if refKeys[k] {
			var n json.Number
			var s string
			switch {
			case json.Unmarshal(v, &n) == nil && refIDRe.MatchString(n.String()):
			case json.Unmarshal(v, &s) == nil && refIDRe.MatchString(s):
			default:
				return false
			}
			continue
		}
		switch k {
		case "id", "name":
			if !scalar(v) {
				return false
			}
		case "names":
			var list []json.RawMessage
			if json.Unmarshal(v, &list) != nil {
				return false
			}
			for _, x := range list {
				if !scalar(x) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func findAction(m sdk.Manifest, name string) (sdk.ActionSpec, bool) {
	for _, a := range m.Actions {
		if a.Name == name {
			return a, true
		}
	}
	return sdk.ActionSpec{}, false
}

// host implements sdk.Host for one module instance.
type host struct {
	e        *Engine
	module   string
	instance string
}

// Secret resolves a vault reference for a module. A module may only resolve
// references that appear in its own instance's configuration, so a
// compromised or buggy module cannot read arbitrary secrets.
func (h *host) Secret(ctx context.Context, ref string) (string, error) {
	h.e.mu.RLock()
	r := h.e.secrets
	in, ok := h.e.instances[h.instance]
	h.e.mu.RUnlock()
	if r == nil {
		return "", errors.New("vault is not available")
	}
	if !ok || !ConfigRefs(in.Config)[ref] {
		return "", fmt.Errorf("%s is not referenced by this instance's settings", ref)
	}
	return r.Resolve(ctx, ref)
}

// configRefs collects every "secret://…" string in a JSON document.
// ConfigRefs returns every secret:// reference in decoded module settings.
func ConfigRefs(cfg json.RawMessage) map[string]bool {
	out := map[string]bool{}
	var v any
	if json.Unmarshal(cfg, &v) != nil {
		return out
	}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if strings.HasPrefix(t, "secret://") {
				out[t] = true
			}
		case []any:
			for _, x := range t {
				walk(x)
			}
		case map[string]any:
			for _, x := range t {
				walk(x)
			}
		}
	}
	walk(v)
	return out
}

// Network implements sdk.NetHost: the network the instance is attached to.
func (h *host) Network() string {
	h.e.mu.RLock()
	defer h.e.mu.RUnlock()
	return h.e.instances[h.instance].Network
}

// DialContext implements sdk.NetHost. The instance's network is looked up
// on every dial, so a client made at Configure time follows later changes.
func (h *host) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return h.DialFiltered(ctx, network, addr, nil)
}

// DialFiltered dials like DialContext; destinations outside the instance's
// network (or every destination, without one) are dialled directly only if
// direct allows them (nil allows all). The sandbox uses it to keep its
// reserved-address checks for everything but the network's own ranges.
func (h *host) DialFiltered(ctx context.Context, network, addr string, direct func(netip.Addr) bool) (net.Conn, error) {
	h.e.mu.RLock()
	nets := h.e.networks
	id := h.e.instances[h.instance].Network
	h.e.mu.RUnlock()
	if id != "" {
		if nets == nil {
			return nil, fmt.Errorf("network %s is not available", id)
		}
		return nets.Dial(ctx, id, network, addr, direct)
	}
	return dialDirect(ctx, network, addr, direct)
}

// dialDirect resolves addr and dials the first address direct allows.
func dialDirect(ctx context.Context, network, addr string, direct func(netip.Addr) bool) (net.Conn, error) {
	d := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if direct == nil {
		return d.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if !direct(ip.Unmap()) {
			return nil, fmt.Errorf("%s resolves to a local or reserved address", host)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s has no address", host)
	}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
}

func (h *host) Publish(_ context.Context, ev sdk.Event) {
	ev.Module = h.module
	if ev.Instance == "" {
		ev.Instance = h.instance
	}
	h.e.Bus.Publish(ev)
}

func (h *host) Log(level, msg string, kv ...any) {
	kv = append([]any{"module", h.module, "instance", h.instance}, kv...)
	switch level {
	case "debug":
		h.e.Log.Debug(msg, kv...)
	case "warn":
		h.e.Log.Warn(msg, kv...)
	case "error":
		h.e.Log.Error(msg, kv...)
	default:
		h.e.Log.Info(msg, kv...)
	}
}
