// Package webhooks delivers Conduit's events to outside URLs, signed so the
// receiver can tell they came from this daemon.
//
// Each delivery is a POST with a JSON body
//
//	{"id":"dlv_…","type":"action.ok","module":"docker","instance":"…","at":"…","data":{…}}
//
// and these headers:
//
//	X-Conduit-Event:     the event type
//	X-Conduit-Delivery:  the delivery id (stable across retries; use it to dedupe)
//	X-Conduit-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>
//
// Receivers recompute the HMAC with the webhook's secret, compare in
// constant time and reject timestamps more than five minutes old. Failed
// deliveries (no answer, or a status outside 2xx) are retried after 2, 20 and
// 120 seconds. A webhook that fails 25 deliveries in a row is switched off.
package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
)

// Webhook is one subscription.
type Webhook struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"` // type prefixes, e.g. "action.", "approval."; empty = everything
	Enabled   bool      `json:"enabled"`
	Failures  int       `json:"failures"`
	CreatedAt time.Time `json:"createdAt"`
	// Secret is only filled in when the webhook is created.
	Secret string `json:"secret,omitempty"`
}

// Delivery is one attempt record.
type Delivery struct {
	ID         string    `json:"id"`
	Event      string    `json:"event"`
	At         time.Time `json:"at"`
	Status     int       `json:"status"`
	Attempts   int       `json:"attempts"`
	OK         bool      `json:"ok"`
	Error      string    `json:"error,omitempty"`
	DurationMS int       `json:"durationMs"`
}

// Retries are the waits before the second, third and fourth attempt.
var Retries = []time.Duration{2 * time.Second, 20 * time.Second, 120 * time.Second}

// DisableAfter consecutive failures switches a webhook off.
const DisableAfter = 25

// Service stores webhooks and delivers events to them.
type Service struct {
	DB   *sql.DB
	Bus  *core.Bus
	HTTP *http.Client
	Log  *slog.Logger
	now  func() time.Time
	sem  chan struct{}
	// pending counts deliveries in flight or waiting to retry; past
	// maxPending, new events are dropped (and logged) instead of piling up
	// behind a slow receiver.
	pending atomic.Int64
}

const maxPending = 2000

// New returns a webhook service.
func New(db *sql.DB, bus *core.Bus, log *slog.Logger) *Service {
	return &Service{DB: db, Bus: bus, Log: log, now: time.Now,
		HTTP: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		sem:  make(chan struct{}, 8)}
}

// Sign returns the X-Conduit-Signature value for body at time t.
func Sign(secret string, t time.Time, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "."))
	m.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(m.Sum(nil))
}

// Verify checks a signature header against body, rejecting signatures older
// than maxAge. Receivers written in Go can use it directly.
func Verify(secret, header string, body []byte, now time.Time, maxAge time.Duration) error {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sig == "" {
		return errors.New("malformed signature")
	}
	t := time.Unix(n, 0)
	if now.Sub(t) > maxAge || t.Sub(now) > maxAge {
		return errors.New("signature too old")
	}
	want := Sign(secret, t, body)
	if !hmac.Equal([]byte(want), []byte("t="+ts+",v1="+sig)) {
		return errors.New("signature mismatch")
	}
	return nil
}

func validURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("the URL must start with https:// (or http:// for your own network)")
	}
	if u.User != nil {
		return errors.New("put credentials in the receiver, not in the URL; the signature authenticates Conduit")
	}
	return nil
}

func secret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "whsec_" + hex.EncodeToString(b)
}

// Create adds a webhook and returns it with its secret (shown once).
func (s *Service) Create(ctx context.Context, name, rawURL string, events []string) (Webhook, error) {
	if err := validURL(rawURL); err != nil {
		return Webhook{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = rawURL
	}
	if events == nil {
		events = []string{}
	}
	for _, e := range events {
		if strings.TrimSpace(e) == "" || len(e) > 100 {
			return Webhook{}, errors.New("event filters are type prefixes such as action. or approval.requested")
		}
	}
	w := Webhook{ID: core.NewID("whk"), Name: name, URL: rawURL, Events: events, Enabled: true, CreatedAt: s.now().UTC(), Secret: secret()}
	ev, _ := json.Marshal(events)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO webhooks (id, name, url, events, secret, enabled, created_at) VALUES (?,?,?,?,?,1,?)`,
		w.ID, w.Name, w.URL, string(ev), w.Secret, w.CreatedAt.Format(time.RFC3339Nano))
	return w, err
}

const cols = `id, name, url, events, enabled, failures, created_at`

func scan(sc interface{ Scan(...any) error }) (Webhook, error) {
	var w Webhook
	var ev, created string
	var en int
	if err := sc.Scan(&w.ID, &w.Name, &w.URL, &ev, &en, &w.Failures, &created); err != nil {
		return w, err
	}
	_ = json.Unmarshal([]byte(ev), &w.Events)
	w.Enabled = en == 1
	w.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return w, nil
}

// List returns every webhook, without secrets.
func (s *Service) List(ctx context.Context) ([]Webhook, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+cols+` FROM webhooks ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Webhook{}
	for rows.Next() {
		w, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// Get returns one webhook.
func (s *Service) Get(ctx context.Context, id string) (Webhook, error) {
	w, err := scan(s.DB.QueryRowContext(ctx, `SELECT `+cols+` FROM webhooks WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return w, core.ErrNotFound
	}
	return w, err
}

// SetEnabled switches a webhook on or off (on resets its failure count).
func (s *Service) SetEnabled(ctx context.Context, id string, on bool) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE webhooks SET enabled = ?, failures = CASE WHEN ? THEN 0 ELSE failures END WHERE id = ?`, b2i(on), on, id)
	return notFound(res, err)
}

// RotateSecret replaces a webhook's secret and returns the new one.
func (s *Service) RotateSecret(ctx context.Context, id string) (string, error) {
	sec := secret()
	res, err := s.DB.ExecContext(ctx, `UPDATE webhooks SET secret = ? WHERE id = ?`, sec, id)
	return sec, notFound(res, err)
}

// Delete removes a webhook and its delivery log.
func (s *Service) Delete(ctx context.Context, id string) error {
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM webhook_deliveries WHERE webhook_id = ?`, id)
	res, err := s.DB.ExecContext(ctx, `DELETE FROM webhooks WHERE id = ?`, id)
	return notFound(res, err)
}

// Deliveries returns the most recent deliveries of a webhook.
func (s *Service) Deliveries(ctx context.Context, id string, limit int) ([]Delivery, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, event, at, status, attempts, ok, error, duration_ms FROM webhook_deliveries WHERE webhook_id = ? ORDER BY at DESC LIMIT ?`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		var at string
		var ok int
		if err := rows.Scan(&d.ID, &d.Event, &at, &d.Status, &d.Attempts, &ok, &d.Error, &d.DurationMS); err != nil {
			return nil, err
		}
		d.At, _ = time.Parse(time.RFC3339Nano, at)
		d.OK = ok == 1
		out = append(out, d)
	}
	return out, rows.Err()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func notFound(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return core.ErrNotFound
	}
	return nil
}

func matches(prefixes []string, typ string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(typ, p) {
			return true
		}
	}
	return false
}

// Run delivers bus events until ctx ends.
func (s *Service) Run(ctx context.Context) {
	events, stop := s.Bus.Subscribe("", 512)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			s.dispatch(ctx, ev)
		}
	}
}

type target struct {
	id, url, secret string
}

func (s *Service) dispatch(ctx context.Context, ev core.Envelope) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, url, secret, events FROM webhooks WHERE enabled = 1`)
	if err != nil {
		return
	}
	var ts []target
	for rows.Next() {
		var t target
		var evs string
		if rows.Scan(&t.id, &t.url, &t.secret, &evs) != nil {
			continue
		}
		var prefixes []string
		_ = json.Unmarshal([]byte(evs), &prefixes)
		if matches(prefixes, ev.Type) {
			ts = append(ts, t)
		}
	}
	rows.Close()
	for _, t := range ts {
		if s.pending.Add(1) > maxPending {
			s.pending.Add(-1)
			if s.Log != nil {
				s.Log.Warn("webhook backlog full; event not delivered", "webhook", t.id, "event", ev.Type)
			}
			continue
		}
		go func() {
			defer s.pending.Add(-1)
			s.deliver(context.WithoutCancel(ctx), t, ev)
		}()
	}
}

// Send delivers one event to one webhook now (the API's test button) and
// returns the record.
func (s *Service) Send(ctx context.Context, id string, ev core.Envelope) (Delivery, error) {
	var t target
	err := s.DB.QueryRowContext(ctx, `SELECT id, url, secret FROM webhooks WHERE id = ?`, id).Scan(&t.id, &t.url, &t.secret)
	if errors.Is(err, sql.ErrNoRows) {
		return Delivery{}, core.ErrNotFound
	}
	if err != nil {
		return Delivery{}, err
	}
	return s.attempt(ctx, t, ev, core.NewID("dlv"), 1), nil
}

func (s *Service) deliver(ctx context.Context, t target, ev core.Envelope) {
	id := core.NewID("dlv")
	for i := 0; ; i++ {
		d := s.attempt(ctx, t, ev, id, i+1)
		if d.OK || i >= len(Retries) {
			s.settle(ctx, t.id, d.OK)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(Retries[i]):
		}
	}
}

func (s *Service) attempt(ctx context.Context, t target, ev core.Envelope, id string, n int) Delivery {
	s.sem <- struct{}{}
	defer func() { <-s.sem }()
	body, _ := json.Marshal(map[string]any{"id": id, "type": ev.Type, "module": ev.Module, "instance": ev.Instance, "at": ev.At, "data": json.RawMessage(nonEmpty(ev.Data))})
	d := Delivery{ID: id, Event: ev.Type, At: s.now().UTC(), Attempts: n}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Conduit-Webhooks/1")
		req.Header.Set("X-Conduit-Event", ev.Type)
		req.Header.Set("X-Conduit-Delivery", id)
		req.Header.Set("X-Conduit-Signature", Sign(t.secret, s.now(), body))
		var res *http.Response
		res, err = s.HTTP.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
			res.Body.Close()
			d.Status = res.StatusCode
			if res.StatusCode < 200 || res.StatusCode > 299 {
				err = fmt.Errorf("the receiver answered %s", res.Status)
			}
		}
	}
	d.DurationMS = int(time.Since(start).Milliseconds())
	d.OK = err == nil
	if err != nil {
		d.Error = err.Error()
	}
	// One row per delivery, updated by each retry.
	_, _ = s.DB.ExecContext(ctx, `INSERT INTO webhook_deliveries (id, webhook_id, event, at, status, attempts, ok, error, duration_ms) VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET at = excluded.at, status = excluded.status, attempts = excluded.attempts, ok = excluded.ok, error = excluded.error, duration_ms = excluded.duration_ms`,
		d.ID, t.id, d.Event, d.At.Format(time.RFC3339Nano), d.Status, d.Attempts, b2i(d.OK), d.Error, d.DurationMS)
	// Keep the last 500 per webhook.
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM webhook_deliveries WHERE webhook_id = ? AND id NOT IN (SELECT id FROM webhook_deliveries WHERE webhook_id = ? ORDER BY at DESC LIMIT 500)`, t.id, t.id)
	return d
}

func (s *Service) settle(ctx context.Context, id string, ok bool) {
	if ok {
		_, _ = s.DB.ExecContext(ctx, `UPDATE webhooks SET failures = 0 WHERE id = ?`, id)
		return
	}
	_, _ = s.DB.ExecContext(ctx, `UPDATE webhooks SET failures = failures + 1, enabled = CASE WHEN failures + 1 >= ? THEN 0 ELSE enabled END WHERE id = ?`, DisableAfter, id)
	var en int
	if s.DB.QueryRowContext(ctx, `SELECT enabled FROM webhooks WHERE id = ?`, id).Scan(&en) == nil && en == 0 && s.Log != nil {
		s.Log.Warn("webhook switched off after repeated failures", "webhook", id)
	}
}

func nonEmpty(b []byte) []byte {
	if len(b) == 0 {
		return []byte("null")
	}
	return b
}
