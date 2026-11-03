package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Approval is a call waiting for a human decision.
type Approval struct {
	ID        string          `json:"id"`
	CreatedAt time.Time       `json:"createdAt"`
	Actor     Actor           `json:"actor"`
	Module    string          `json:"module"`
	Instance  string          `json:"instance"`
	Action    string          `json:"action"`
	Risk      sdk.Risk        `json:"risk"`
	Input     json.RawMessage `json:"input"`
	Plan      *sdk.Plan       `json:"plan,omitempty"`
	Status    string          `json:"status"` // pending, approved, denied, expired
	DecidedBy string          `json:"decidedBy,omitempty"`
	DecidedAt *time.Time      `json:"decidedAt,omitempty"`
	ExpiresAt time.Time       `json:"expiresAt"`
}

// ErrDenied is returned when an approval is denied or expires.
var ErrDenied = errors.New("denied")

// Approvals is the approval queue. Waiting callers block on Wait until a
// person decides in a client (app, desktop notification, phone).
type Approvals struct {
	store   *Store
	bus     *Bus
	ttl     time.Duration
	mu      sync.Mutex
	waiters map[string][]chan string
}

// NewApprovals returns the approval queue. Pending approvals expire after ttl.
func NewApprovals(s *Store, bus *Bus, ttl time.Duration) *Approvals {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &Approvals{store: s, bus: bus, ttl: ttl, waiters: map[string][]chan string{}}
}

// Request creates a pending approval and announces it on the bus.
func (q *Approvals) Request(ctx context.Context, a Approval) (Approval, error) {
	a.ID = NewID("appr")
	a.CreatedAt = time.Now().UTC()
	a.ExpiresAt = a.CreatedAt.Add(q.ttl)
	a.Status = "pending"
	a.Input = orNull(a.Input)
	actor, _ := json.Marshal(a.Actor)
	var plan any
	if a.Plan != nil {
		b, _ := json.Marshal(a.Plan)
		plan = string(b)
	}
	_, err := q.store.DB.ExecContext(ctx, `INSERT INTO approvals (id, created_at, actor, actor_kind, module, instance, action, risk, input, plan, status, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.CreatedAt.Format(time.RFC3339Nano), string(actor), a.Actor.Kind, a.Module, a.Instance, a.Action, a.Risk, string(a.Input), plan, a.Status, a.ExpiresAt.Format(time.RFC3339Nano))
	if err != nil {
		return a, err
	}
	data, _ := json.Marshal(a)
	q.bus.Publish(sdk.Event{Type: "approval.requested", Module: "core", Data: data})
	return a, nil
}

// Wait blocks until the approval is decided, it expires, or ctx ends.
func (q *Approvals) Wait(ctx context.Context, id string) error {
	ch := make(chan string, 1)
	q.mu.Lock()
	q.waiters[id] = append(q.waiters[id], ch)
	q.mu.Unlock()

	// It may have been decided before we registered.
	if a, err := q.Get(ctx, id); err == nil && a.Status != "pending" {
		return statusErr(a.Status)
	}
	a, err := q.Get(ctx, id)
	if err != nil {
		return err
	}
	timer := time.NewTimer(time.Until(a.ExpiresAt))
	defer timer.Stop()
	select {
	case s := <-ch:
		return statusErr(s)
	case <-timer.C:
		_ = q.decide(context.Background(), id, "expired", "system")
		return statusErr("expired")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func statusErr(s string) error {
	if s == "approved" {
		return nil
	}
	return fmt.Errorf("%w: approval %s", ErrDenied, s)
}

// Decide approves or denies a pending approval on behalf of decidedBy.
// Approvals past their expiry can no longer be decided.
func (q *Approvals) Decide(ctx context.Context, id string, approve bool, decidedBy string) error {
	q.ExpireStale(ctx)
	s := "denied"
	if approve {
		s = "approved"
	}
	return q.decide(ctx, id, s, decidedBy)
}

func (q *Approvals) decide(ctx context.Context, id, status, by string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := q.store.DB.ExecContext(ctx, `UPDATE approvals SET status = ?, decided_by = ?, decided_at = ? WHERE id = ? AND status = 'pending'`, status, by, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("approval %s is not pending", id)
	}
	q.mu.Lock()
	ws := q.waiters[id]
	delete(q.waiters, id)
	q.mu.Unlock()
	for _, w := range ws {
		w <- status
	}
	data, _ := json.Marshal(map[string]string{"id": id, "status": status, "decidedBy": by})
	q.bus.Publish(sdk.Event{Type: "approval.decided", Module: "core", Data: data})
	return nil
}

// DenyAllPending denies every pending approval (used by panic mode).
func (q *Approvals) DenyAllPending(ctx context.Context, by string) (int, error) {
	list, err := q.List(ctx, "pending")
	if err != nil {
		return 0, err
	}
	for _, a := range list {
		_ = q.decide(ctx, a.ID, "denied", by)
	}
	return len(list), nil
}

// Get returns one approval.
func (q *Approvals) Get(ctx context.Context, id string) (Approval, error) {
	return scanApproval(q.store.DB.QueryRowContext(ctx, `SELECT id, created_at, actor, module, instance, action, risk, input, plan, status, decided_by, decided_at, expires_at FROM approvals WHERE id = ?`, id))
}

// ExpireStale marks pending approvals past their expiry as expired. Waiters
// expire their own approvals on time; this catches approvals whose waiter is
// gone, for example after a restart.
func (q *Approvals) ExpireStale(ctx context.Context) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rows, err := q.store.DB.QueryContext(ctx, `SELECT id FROM approvals WHERE status = 'pending' AND expires_at < ?`, now)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		_ = q.decide(ctx, id, "expired", "system")
	}
}

// List returns approvals with the given status ("" for all), newest first.
func (q *Approvals) List(ctx context.Context, status string) ([]Approval, error) {
	q.ExpireStale(ctx)
	query := `SELECT id, created_at, actor, module, instance, action, risk, input, plan, status, decided_by, decided_at, expires_at FROM approvals`
	var args []any
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC LIMIT 200`
	rows, err := q.store.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func scanApproval(s scanner) (Approval, error) {
	var a Approval
	var created, actor, input, expires string
	var plan, by, decided sql.NullString
	if err := s.Scan(&a.ID, &created, &actor, &a.Module, &a.Instance, &a.Action, &a.Risk, &input, &plan, &a.Status, &by, &decided, &expires); err != nil {
		return a, err
	}
	a.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	a.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	_ = json.Unmarshal([]byte(actor), &a.Actor)
	a.Input = json.RawMessage(input)
	if plan.Valid {
		a.Plan = &sdk.Plan{}
		_ = json.Unmarshal([]byte(plan.String), a.Plan)
	}
	a.DecidedBy = by.String
	if decided.Valid {
		t, _ := time.Parse(time.RFC3339Nano, decided.String)
		a.DecidedAt = &t
	}
	return a, nil
}
