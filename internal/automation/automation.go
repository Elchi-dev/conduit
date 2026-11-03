// Package automation runs chains of actions on a schedule, on an event, on
// an incoming webhook, or on demand. Every step is an ordinary call through
// the engine, made as an "automation" actor, so the permission policy and the
// audit log apply exactly as they do to people and agents.
package automation

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Trigger says when an automation runs.
type Trigger struct {
	// Kind is "schedule", "event", "webhook" or "manual".
	Kind string `json:"kind"`
	// Cron is a 5-field schedule ("30 7 * * 1-5"), for kind schedule.
	Cron string `json:"cron,omitempty"`
	// Timezone for the schedule, e.g. "Europe/Zurich" (default: local).
	Timezone string `json:"timezone,omitempty"`
	// Event is an event type or prefix ("mail.received", "web."), for kind event.
	Event string `json:"event,omitempty"`
	// Match requires event data fields to equal these values ("data.name": "Shop").
	Match map[string]string `json:"match,omitempty"`
}

// Step is one action in the chain. String values in Input may contain
// {{trigger.<path>}} and {{steps.<n>.<path>}} placeholders.
type Step struct {
	Instance        string          `json:"instance"`
	Action          string          `json:"action"`
	Input           json.RawMessage `json:"input,omitempty"`
	ContinueOnError bool            `json:"continueOnError,omitempty"`
}

// Automation is a saved automation.
type Automation struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Enabled   bool    `json:"enabled"`
	Trigger   Trigger `json:"trigger"`
	Steps     []Step  `json:"steps"`
	HookURL   string  `json:"hookPath,omitempty"` // for webhook triggers: /hooks/<token>
	CreatedBy string  `json:"createdBy"`
	// UpdatedBy is who saved it last (an actor subject, like CreatedBy).
	// Restricted vault folders check this person too.
	UpdatedBy string    `json:"updatedBy,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	// Trusted is true when a person saved or enabled it, which granted its
	// steps permission to run without asking.
	Trusted bool `json:"trusted"`
}

type spec struct {
	Trigger   Trigger `json:"trigger"`
	Steps     []Step  `json:"steps"`
	Trusted   bool    `json:"trusted"`
	UpdatedBy string  `json:"updatedBy,omitempty"`
}

// Run is one execution.
type Run struct {
	ID         string          `json:"id"`
	Automation string          `json:"automation"`
	StartedAt  time.Time       `json:"startedAt"`
	FinishedAt *time.Time      `json:"finishedAt,omitempty"`
	Trigger    json.RawMessage `json:"trigger"`
	Status     string          `json:"status"` // running, ok, error, denied
	Steps      []StepResult    `json:"steps"`
	Error      string          `json:"error,omitempty"`
}

// StepResult is the outcome of one step.
type StepResult struct {
	Action string          `json:"action"`
	Status string          `json:"status"`
	Output json.RawMessage `json:"output,omitempty"`
	Error  string          `json:"error,omitempty"`
	Audit  int64           `json:"audit,omitempty"`
}

// Service stores and runs automations.
type Service struct {
	engine *core.Engine
	db     *sql.DB
	log    *slog.Logger

	mu      sync.Mutex
	cron    *cron.Cron
	cronIDs map[string]cron.EntryID
	lastRun map[string]time.Time
	ctx     context.Context
}

// New returns the automation service.
func New(e *core.Engine) *Service {
	return &Service{engine: e, db: e.Store.DB, log: e.Log, cronIDs: map[string]cron.EntryID{}, lastRun: map[string]time.Time{}}
}

func newToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Start loads schedules and listens for events until ctx ends.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	s.ctx = ctx
	s.cron = cron.New()
	s.mu.Unlock()
	list, err := s.List(ctx)
	if err != nil {
		return err
	}
	for _, a := range list {
		s.schedule(a)
	}
	s.cron.Start()
	go s.listen(ctx)
	go func() {
		<-ctx.Done()
		s.cron.Stop()
	}()
	return nil
}

func (s *Service) schedule(a Automation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cron == nil {
		return
	}
	if id, ok := s.cronIDs[a.ID]; ok {
		s.cron.Remove(id)
		delete(s.cronIDs, a.ID)
	}
	if !a.Enabled || a.Trigger.Kind != "schedule" {
		return
	}
	expr := a.Trigger.Cron
	if a.Trigger.Timezone != "" {
		expr = "CRON_TZ=" + a.Trigger.Timezone + " " + expr
	}
	id, err := s.cron.AddFunc(expr, func() {
		_, _ = s.Run(s.ctx, a.ID, json.RawMessage(`{"kind":"schedule"}`))
	})
	if err != nil {
		s.log.Warn("automation schedule rejected", "automation", a.ID, "err", err)
		return
	}
	s.cronIDs[a.ID] = id
}

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// Validate checks an automation before it is saved.
func (s *Service) Validate(a Automation) error {
	if strings.TrimSpace(a.Name) == "" {
		return errors.New("give the automation a name")
	}
	switch a.Trigger.Kind {
	case "schedule":
		if _, err := cronParser.Parse(a.Trigger.Cron); err != nil {
			return fmt.Errorf("schedule %q is not valid: use five fields, e.g. \"30 7 * * 1-5\" for 7:30 on weekdays", a.Trigger.Cron)
		}
		if a.Trigger.Timezone != "" {
			if _, err := time.LoadLocation(a.Trigger.Timezone); err != nil {
				return fmt.Errorf("unknown time zone %q", a.Trigger.Timezone)
			}
		}
	case "event":
		if a.Trigger.Event == "" {
			return errors.New("an event trigger needs an event type, e.g. mail.received")
		}
	case "webhook", "manual":
	default:
		return fmt.Errorf("unknown trigger %q", a.Trigger.Kind)
	}
	if len(a.Steps) == 0 {
		return errors.New("add at least one step")
	}
	if len(a.Steps) > 20 {
		return errors.New("an automation can have at most 20 steps")
	}
	for i, st := range a.Steps {
		in, ok := s.engine.Instance(st.Instance)
		if !ok {
			return fmt.Errorf("step %d: no connected system %q", i+1, st.Instance)
		}
		m, _ := s.engine.Module(in.Module)
		found := false
		for _, act := range m.Manifest().Actions {
			if act.Name == st.Action {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("step %d: %s has no action %q", i+1, in.Name, st.Action)
		}
	}
	return nil
}

// Save creates or updates an automation. When a person saves it (trust is
// true), its steps are allowed to run without asking, through policy rules
// scoped to this automation and these exact actions. When an agent or key
// saves it, it is stored disabled and untrusted: a person must review and
// enable it.
func (s *Service) Save(ctx context.Context, a Automation, by core.Actor) (Automation, error) {
	if err := s.Validate(a); err != nil {
		return a, err
	}
	trust := by.Kind == core.ActorUser
	now := time.Now().UTC()
	old, err := s.Get(ctx, a.ID)
	isNew := a.ID == "" || errors.Is(err, sql.ErrNoRows)
	if a.ID == "" {
		a.ID = core.NewID("auto")
	}
	if !trust {
		a.Enabled = false
	}
	a.Trusted = trust
	a.UpdatedAt, a.UpdatedBy = now, by.Subject()
	if isNew {
		a.CreatedAt, a.CreatedBy = now, by.Subject()
	} else {
		a.CreatedAt, a.CreatedBy = old.CreatedAt, old.CreatedBy
	}
	var token any
	if a.Trigger.Kind == "webhook" {
		if !isNew && old.HookURL != "" {
			token = strings.TrimPrefix(old.HookURL, "/hooks/")
		} else {
			token = newToken()
		}
		a.HookURL = "/hooks/" + token.(string)
	} else {
		a.HookURL = ""
	}
	sp, _ := json.Marshal(spec{Trigger: a.Trigger, Steps: a.Steps, Trusted: trust, UpdatedBy: a.UpdatedBy})
	_, err = s.db.ExecContext(ctx, `INSERT INTO automations (id, name, enabled, spec, hook_token, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, enabled = excluded.enabled, spec = excluded.spec, hook_token = excluded.hook_token, updated_at = excluded.updated_at`,
		a.ID, a.Name, a.Enabled, string(sp), token, a.CreatedBy, a.CreatedAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return a, err
	}
	if err := s.grant(ctx, a); err != nil {
		return a, err
	}
	s.schedule(a)
	return a, nil
}

// grant replaces this automation's policy rules.
func (s *Service) grant(ctx context.Context, a Automation) error {
	rules, err := s.engine.Policy.Rules(ctx)
	if err != nil {
		return err
	}
	prefix := "auto_" + a.ID + "_"
	for _, r := range rules {
		if strings.HasPrefix(r.ID, prefix) {
			if err := s.engine.Policy.DeleteRule(ctx, r.ID); err != nil {
				return err
			}
		}
	}
	if !a.Trusted {
		return nil
	}
	for i, st := range a.Steps {
		in, _ := s.engine.Instance(st.Instance)
		r := core.Rule{ID: prefix + strconv.Itoa(i), Position: -1000, Subject: "automation:" + a.ID, Module: in.Module, Instance: st.Instance, Action: st.Action,
			Effect: core.Allow, Note: "set by a person for automation " + a.Name}
		if err := s.engine.Policy.PutRule(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// SetEnabled turns an automation on or off. Only a person enabling it makes
// it trusted.
func (s *Service) SetEnabled(ctx context.Context, id string, on bool, by core.Actor) (Automation, error) {
	a, err := s.Get(ctx, id)
	if err != nil {
		return a, err
	}
	if on && !a.Trusted && by.Kind != core.ActorUser {
		return a, errors.New("an automation drafted by an agent must be reviewed and enabled by a person")
	}
	a.Enabled = on
	return s.Save(ctx, a, by)
}

// Delete removes an automation and its rules.
func (s *Service) Delete(ctx context.Context, id string) error {
	a, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	a.Trusted, a.Enabled = false, false
	_ = s.grant(ctx, a)
	s.schedule(a)
	_, err = s.db.ExecContext(ctx, `DELETE FROM automations WHERE id = ?`, id)
	return err
}

const cols = `id, name, enabled, spec, hook_token, created_by, created_at, updated_at`

func scan(row interface{ Scan(...any) error }) (Automation, error) {
	var a Automation
	var sp, c, u string
	var tok sql.NullString
	if err := row.Scan(&a.ID, &a.Name, &a.Enabled, &sp, &tok, &a.CreatedBy, &c, &u); err != nil {
		return a, err
	}
	var x spec
	_ = json.Unmarshal([]byte(sp), &x)
	a.Trigger, a.Steps, a.Trusted, a.UpdatedBy = x.Trigger, x.Steps, x.Trusted, x.UpdatedBy
	if a.UpdatedBy == "" {
		a.UpdatedBy = a.CreatedBy
	}
	if tok.Valid {
		a.HookURL = "/hooks/" + tok.String
	}
	a.CreatedAt, _ = time.Parse(time.RFC3339Nano, c)
	a.UpdatedAt, _ = time.Parse(time.RFC3339Nano, u)
	return a, nil
}

// Get returns one automation.
func (s *Service) Get(ctx context.Context, id string) (Automation, error) {
	return scan(s.db.QueryRowContext(ctx, `SELECT `+cols+` FROM automations WHERE id = ?`, id))
}

// List returns all automations, by name.
func (s *Service) List(ctx context.Context) ([]Automation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cols+` FROM automations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Automation{}
	for rows.Next() {
		a, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ByHookToken finds the automation behind a webhook URL.
func (s *Service) ByHookToken(ctx context.Context, token string) (Automation, error) {
	return scan(s.db.QueryRowContext(ctx, `SELECT `+cols+` FROM automations WHERE hook_token = ?`, token))
}

// Runs returns an automation's most recent runs.
func (s *Service) Runs(ctx context.Context, id string, limit int) ([]Run, error) {
	if limit <= 0 || limit > 200 {
		limit = 30
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, automation, started_at, finished_at, trigger, status, steps, error FROM automation_runs WHERE automation = ? ORDER BY started_at DESC LIMIT ?`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		var r Run
		var st, trig, steps string
		var fin sql.NullString
		if err := rows.Scan(&r.ID, &r.Automation, &st, &fin, &trig, &r.Status, &steps, &r.Error); err != nil {
			return nil, err
		}
		r.StartedAt, _ = time.Parse(time.RFC3339Nano, st)
		if fin.Valid {
			t, _ := time.Parse(time.RFC3339Nano, fin.String)
			r.FinishedAt = &t
		}
		r.Trigger = json.RawMessage(trig)
		_ = json.Unmarshal([]byte(steps), &r.Steps)
		out = append(out, r)
	}
	return out, rows.Err()
}

// minGap stops runaway loops: an automation runs at most once per gap.
const minGap = 5 * time.Second

// Run executes an automation now with the given trigger data.
func (s *Service) Run(ctx context.Context, id string, trigger json.RawMessage) (Run, error) {
	a, err := s.Get(ctx, id)
	if err != nil {
		return Run{}, err
	}
	s.mu.Lock()
	if last, ok := s.lastRun[id]; ok && time.Since(last) < minGap {
		s.mu.Unlock()
		return Run{}, errors.New("this automation ran less than 5 seconds ago")
	}
	s.lastRun[id] = time.Now()
	s.mu.Unlock()
	if len(trigger) == 0 {
		trigger = json.RawMessage(`{"kind":"manual"}`)
	}
	run := Run{ID: core.NewID("run"), Automation: id, StartedAt: time.Now().UTC(), Trigger: trigger, Status: "running", Steps: []StepResult{}}
	_, _ = s.db.ExecContext(ctx, `INSERT INTO automation_runs (id, automation, started_at, trigger, status) VALUES (?,?,?,?,?)`,
		run.ID, id, run.StartedAt.Format(time.RFC3339Nano), string(trigger), run.Status)

	actor := core.Actor{ID: a.ID, Kind: core.ActorAutomation, Name: a.Name}
	var trig any
	_ = json.Unmarshal(trigger, &trig)
	scope := map[string]any{"trigger": trig, "steps": []any{}}
	run.Status = "ok"
	for i, st := range a.Steps {
		input := render(st.Input, scope)
		sctx, cancel := context.WithTimeout(ctx, 20*time.Minute) // includes waiting for an approval
		out, err := s.engine.Invoke(sctx, actor, sdk.Call{Instance: st.Instance, Action: st.Action, Input: input}, core.InvokeOptions{})
		cancel()
		res := StepResult{Action: st.Action, Status: "ok", Output: out.Result.Output, Audit: out.Audit.Seq}
		var outVal any
		_ = json.Unmarshal(out.Result.Output, &outVal)
		scope["steps"] = append(scope["steps"].([]any), map[string]any{"output": outVal})
		if err != nil {
			res.Status, res.Error = "error", err.Error()
			if errors.Is(err, core.ErrForbidden) || errors.Is(err, core.ErrDenied) {
				res.Status = "denied"
			}
		}
		run.Steps = append(run.Steps, res)
		if err != nil && !st.ContinueOnError {
			run.Status, run.Error = res.Status, fmt.Sprintf("step %d (%s): %s", i+1, st.Action, err)
			break
		}
	}
	fin := time.Now().UTC()
	run.FinishedAt = &fin
	steps, _ := json.Marshal(run.Steps)
	_, _ = s.db.ExecContext(context.WithoutCancel(ctx), `UPDATE automation_runs SET finished_at = ?, status = ?, steps = ?, error = ? WHERE id = ?`,
		fin.Format(time.RFC3339Nano), run.Status, string(steps), run.Error, run.ID)
	data, _ := json.Marshal(map[string]any{"automation": a.ID, "name": a.Name, "status": run.Status, "error": run.Error})
	s.engine.Bus.Publish(sdk.Event{Type: "automation.run." + run.Status, Module: "automations", Data: data})
	return run, nil
}

// listen starts event-triggered automations.
func (s *Service) listen(ctx context.Context) {
	events, stop := s.engine.Bus.Subscribe("", 512)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			// Never trigger on automation bookkeeping, and never on actions an
			// automation itself caused, so automations can't loop.
			if strings.HasPrefix(ev.Type, "automation.") || causedByAutomation(ev) {
				continue
			}
			list, err := s.List(ctx)
			if err != nil {
				continue
			}
			payload, _ := json.Marshal(ev)
			var obj map[string]any
			_ = json.Unmarshal(payload, &obj)
			for _, a := range list {
				if !a.Enabled || a.Trigger.Kind != "event" || !strings.HasPrefix(ev.Type, a.Trigger.Event) {
					continue
				}
				if !matches(obj, a.Trigger.Match) {
					continue
				}
				go func(id string) { _, _ = s.Run(ctx, id, payload) }(a.ID)
			}
		}
	}
}

func causedByAutomation(ev core.Envelope) bool {
	if !strings.HasPrefix(ev.Type, "action.") {
		return false
	}
	var e struct {
		Actor core.Actor `json:"actor"`
	}
	_ = json.Unmarshal(ev.Data, &e)
	return e.Actor.Kind == core.ActorAutomation
}

func matches(obj map[string]any, match map[string]string) bool {
	for path, want := range match {
		if fmt.Sprint(lookup(obj, path)) != want {
			return false
		}
	}
	return true
}

// lookup follows a dotted path ("data.messages.0.subject") through JSON values.
func lookup(v any, path string) any {
	for _, p := range strings.Split(path, ".") {
		switch t := v.(type) {
		case map[string]any:
			v = t[p]
		case []any:
			i, err := strconv.Atoi(p)
			if err != nil || i < 0 || i >= len(t) {
				return nil
			}
			v = t[i]
		default:
			return nil
		}
	}
	return v
}

var placeholder = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}`)

// render fills {{…}} placeholders in every string of a JSON document. A
// string that is exactly one placeholder takes the referenced value's type.
func render(in json.RawMessage, scope map[string]any) json.RawMessage {
	if len(in) == 0 {
		return in
	}
	var v any
	if json.Unmarshal(in, &v) != nil {
		return in
	}
	var walk func(any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case string:
			if m := placeholder.FindStringSubmatch(t); m != nil && m[0] == strings.TrimSpace(t) {
				return lookup(scope, m[1])
			}
			return placeholder.ReplaceAllStringFunc(t, func(s string) string {
				m := placeholder.FindStringSubmatch(s)
				val := lookup(scope, m[1])
				if val == nil {
					return ""
				}
				if b, ok := val.(string); ok {
					return b
				}
				b, _ := json.Marshal(val)
				return string(b)
			})
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
		case map[string]any:
			for k := range t {
				t[k] = walk(t[k])
			}
		}
		return v
	}
	out, _ := json.Marshal(walk(v))
	return out
}
