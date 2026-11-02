package core

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// genesisHash is the prev_hash of the first audit entry.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry is one audit log record.
type Entry struct {
	Seq      int64           `json:"seq"`
	At       time.Time       `json:"at"`
	Actor    Actor           `json:"actor"`
	Module   string          `json:"module"`
	Instance string          `json:"instance"`
	Action   string          `json:"action"`
	Risk     sdk.Risk        `json:"risk"`
	Decision Effect          `json:"decision"`
	Status   string          `json:"status"` // "ok", "error", "denied", "pending", "planned"
	DryRun   bool            `json:"dryRun"`
	Input    json.RawMessage `json:"input"`
	Output   json.RawMessage `json:"output"`
	Error    string          `json:"error,omitempty"`
	Undo     *sdk.Undo       `json:"undo,omitempty"`
	UndoneBy *int64          `json:"undoneBy,omitempty"`
	Undoes   *int64          `json:"undoes,omitempty"`
	PrevHash string          `json:"prevHash"`
	Hash     string          `json:"hash"`
}

// Audit is the append-only, hash-chained audit log. Each entry's hash covers
// its content and the previous entry's hash, so any edit or deletion breaks
// the chain and Verify reports where.
type Audit struct {
	store *Store
	mu    sync.Mutex // serialises appends so the chain stays linear
}

// NewAudit returns the audit log backed by store.
func NewAudit(s *Store) *Audit { return &Audit{store: s} }

// hashable is the canonical content an entry's hash covers. UndoneBy is
// excluded because it is set later when the entry is undone; the undoing
// entry records Undoes, which is covered.
type hashable struct {
	At       string          `json:"at"`
	Actor    Actor           `json:"actor"`
	Module   string          `json:"module"`
	Instance string          `json:"instance"`
	Action   string          `json:"action"`
	Risk     sdk.Risk        `json:"risk"`
	Decision Effect          `json:"decision"`
	Status   string          `json:"status"`
	DryRun   bool            `json:"dryRun"`
	Input    json.RawMessage `json:"input"`
	Output   json.RawMessage `json:"output"`
	Error    string          `json:"error"`
	Undo     *sdk.Undo       `json:"undo"`
	Undoes   *int64          `json:"undoes"`
	Prev     string          `json:"prev"`
}

func entryHash(e Entry) string {
	b, _ := json.Marshal(hashable{
		At: e.At.UTC().Format(time.RFC3339Nano), Actor: e.Actor, Module: e.Module, Instance: e.Instance,
		Action: e.Action, Risk: e.Risk, Decision: e.Decision, Status: e.Status, DryRun: e.DryRun,
		Input: orNull(e.Input), Output: orNull(e.Output), Error: e.Error, Undo: e.Undo, Undoes: e.Undoes, Prev: e.PrevHash,
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func orNull(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("null")
	}
	return b
}

// Append writes e to the log, filling Seq, At, PrevHash and Hash.
func (a *Audit) Append(ctx context.Context, e Entry) (Entry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := genesisHash
	err := a.store.DB.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Entry{}, err
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	e.Input, e.Output = orNull(e.Input), orNull(e.Output)
	e.PrevHash = prev
	e.Hash = entryHash(e)
	var undo any
	if e.Undo != nil {
		b, _ := json.Marshal(e.Undo)
		undo = string(b)
	}
	actor, _ := json.Marshal(e.Actor)
	res, err := a.store.DB.ExecContext(ctx, `INSERT INTO audit_log (at, actor, actor_kind, module, instance, action, risk, decision, status, dry_run, input, output, error, undo, undoes, prev_hash, hash)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.At.UTC().Format(time.RFC3339Nano), string(actor), e.Actor.Kind, e.Module, e.Instance, e.Action, e.Risk, e.Decision, e.Status,
		e.DryRun, string(e.Input), string(e.Output), e.Error, undo, e.Undoes, e.PrevHash, e.Hash)
	if err != nil {
		return Entry{}, err
	}
	e.Seq, _ = res.LastInsertId()
	if e.Undoes != nil {
		if _, err := a.store.DB.ExecContext(ctx, `UPDATE audit_log SET undone_by = ? WHERE seq = ?`, e.Seq, *e.Undoes); err != nil {
			return e, err
		}
	}
	return e, nil
}

// Query filters the log for the timeline view.
type Query struct {
	Module   string
	Instance string
	Actor    string // actor subject, e.g. "agent:desktop"
	Since    time.Time
	Until    time.Time
	Before   int64 // page backwards: entries with seq < Before
	Limit    int
	Search   string // substring match on action, input and output
}

const auditCols = `seq, at, actor, module, instance, action, risk, decision, status, dry_run, input, output, error, undo, undone_by, undoes, prev_hash, hash`

// List returns entries newest first.
func (a *Audit) List(ctx context.Context, q Query) ([]Entry, error) {
	var where []string
	var args []any
	if q.Module != "" {
		where, args = append(where, "module = ?"), append(args, q.Module)
	}
	if q.Instance != "" {
		where, args = append(where, "instance = ?"), append(args, q.Instance)
	}
	if q.Actor != "" {
		kind, id, _ := strings.Cut(q.Actor, ":")
		where, args = append(where, "actor_kind = ? AND json_extract(actor, '$.id') = ?"), append(args, kind, id)
	}
	if !q.Since.IsZero() {
		where, args = append(where, "at >= ?"), append(args, q.Since.UTC().Format(time.RFC3339Nano))
	}
	if !q.Until.IsZero() {
		where, args = append(where, "at <= ?"), append(args, q.Until.UTC().Format(time.RFC3339Nano))
	}
	if q.Before > 0 {
		where, args = append(where, "seq < ?"), append(args, q.Before)
	}
	if q.Search != "" {
		s := "%" + q.Search + "%"
		where, args = append(where, "(action LIKE ? OR input LIKE ? OR output LIKE ? OR module LIKE ?)"), append(args, s, s, s, s)
	}
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	sqlq := `SELECT ` + auditCols + ` FROM audit_log`
	if len(where) > 0 {
		sqlq += " WHERE " + strings.Join(where, " AND ")
	}
	sqlq += fmt.Sprintf(" ORDER BY seq DESC LIMIT %d", limit)
	rows, err := a.store.DB.QueryContext(ctx, sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Get returns one entry.
func (a *Audit) Get(ctx context.Context, seq int64) (Entry, error) {
	row := a.store.DB.QueryRowContext(ctx, `SELECT `+auditCols+` FROM audit_log WHERE seq = ?`, seq)
	return scanEntry(row)
}

type scanner interface{ Scan(...any) error }

func scanEntry(s scanner) (Entry, error) {
	var e Entry
	var at, actor, input, output string
	var undo sql.NullString
	var undoneBy, undoes sql.NullInt64
	if err := s.Scan(&e.Seq, &at, &actor, &e.Module, &e.Instance, &e.Action, &e.Risk, &e.Decision, &e.Status, &e.DryRun,
		&input, &output, &e.Error, &undo, &undoneBy, &undoes, &e.PrevHash, &e.Hash); err != nil {
		return e, err
	}
	e.At, _ = time.Parse(time.RFC3339Nano, at)
	_ = json.Unmarshal([]byte(actor), &e.Actor)
	e.Input, e.Output = json.RawMessage(input), json.RawMessage(output)
	if undo.Valid {
		e.Undo = &sdk.Undo{}
		_ = json.Unmarshal([]byte(undo.String), e.Undo)
	}
	if undoneBy.Valid {
		v := undoneBy.Int64
		e.UndoneBy = &v
	}
	if undoes.Valid {
		v := undoes.Int64
		e.Undoes = &v
	}
	return e, nil
}

// VerifyResult reports the integrity of the chain.
type VerifyResult struct {
	OK       bool   `json:"ok"`
	Entries  int64  `json:"entries"`
	BrokenAt int64  `json:"brokenAt,omitempty"`
	Problem  string `json:"problem,omitempty"`
}

// Verify walks the whole chain and reports the first broken link.
func (a *Audit) Verify(ctx context.Context) (VerifyResult, error) {
	rows, err := a.store.DB.QueryContext(ctx, `SELECT `+auditCols+` FROM audit_log ORDER BY seq`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()
	prev := genesisHash
	var n int64
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return VerifyResult{}, err
		}
		n++
		if e.PrevHash != prev {
			return VerifyResult{Entries: n, BrokenAt: e.Seq, Problem: "previous-hash link does not match (an entry before this one was removed or changed)"}, nil
		}
		if entryHash(e) != e.Hash {
			return VerifyResult{Entries: n, BrokenAt: e.Seq, Problem: "entry content does not match its hash (this entry was edited)"}, nil
		}
		prev = e.Hash
	}
	return VerifyResult{OK: true, Entries: n}, rows.Err()
}
