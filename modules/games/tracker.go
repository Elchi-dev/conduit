package games

import (
	"context"
	"encoding/json"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Watch records play sessions and publishes games.started and
// games.stopped while ctx lives. It idles until the module is set up.
func (m *Module) Watch(ctx context.Context) {
	iv := m.Interval
	if iv <= 0 {
		iv = 10 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.flush()
			return
		case <-t.C:
		}
		m.poll(ctx)
	}
}

func (m *Module) tracking() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.host != nil && (m.cfg.Track == nil || *m.cfg.Track)
}

// heartbeatEvery is how many polls pass between saves of the sessions in
// progress, so a crash loses at most about a minute of play.
const heartbeatEvery = 6

// poll looks at running processes once and updates sessions.
func (m *Module) poll(ctx context.Context) {
	if !m.tracking() {
		return
	}
	st, err := m.store()
	if err != nil {
		return
	}
	games, _, err := m.scan(false)
	if err != nil {
		return
	}
	procs, err := m.Procs(ctx)
	if err != nil {
		return
	}
	e := m.environment()
	matched := matchProcs(procs, games, e.GOOS, e.Home)
	byID := map[string]Game{}
	for _, g := range games {
		byID[g.ID] = g
	}
	h, inst := m.hostAndInstance()
	now := m.Now()

	type ev struct {
		typ  string
		data map[string]any
	}
	var events []ev
	changed := false

	m.mu.Lock()
	if !m.resumed {
		// Sessions open when the daemon last stopped: carry on with the ones
		// still running (same process), close the others where last seen.
		m.resumed = true
		st.mu.Lock()
		for _, o := range st.d.Open {
			o := o
			if ps, ok := matched[o.GameID]; ok && overlaps(ps, o.PIDs) {
				m.active[o.GameID] = &o
				continue
			}
			if s, ok := closeSession(o, o.LastSeen); ok {
				st.d.Sessions = append(st.d.Sessions, s)
			}
			changed = true
		}
		st.d.Open = nil
		st.mu.Unlock()
	}
	for id, ps := range matched {
		pids := pidList(ps)
		if a, ok := m.active[id]; ok {
			a.LastSeen, a.PIDs = now, pids
			continue
		}
		g := byID[id]
		start := now
		// A game that started just before this look: count from its start.
		if t := earliest(ps, now); now.Sub(t) < 2*m.Interval+time.Second {
			start = t
		}
		a := &openSession{GameID: id, Title: g.Title, Launcher: g.Launcher, Start: start, LastSeen: now, PIDs: pids}
		m.active[id] = a
		changed = true
		events = append(events, ev{"games.started", map[string]any{"id": id, "title": g.Title, "launcher": g.Launcher,
			"appId": g.AppID, "pid": ps[0].PID, "since": start.UTC().Format(time.RFC3339)}})
	}
	for id, a := range m.active {
		if _, ok := matched[id]; ok {
			continue
		}
		delete(m.active, id)
		changed = true
		s, ok := closeSession(*a, now)
		if ok {
			st.mu.Lock()
			st.d.Sessions = append(st.d.Sessions, s)
			st.mu.Unlock()
		}
		g := byID[id]
		events = append(events, ev{"games.stopped", map[string]any{"id": id, "title": a.Title, "launcher": a.Launcher,
			"appId": g.AppID, "since": a.Start.UTC().Format(time.RFC3339), "end": now.UTC().Format(time.RFC3339), "seconds": s.Seconds}})
	}
	m.polls++
	if changed || (len(m.active) > 0 && m.polls%heartbeatEvery == 0) {
		m.saveOpenLocked(st)
	}
	m.mu.Unlock()

	if h == nil {
		return
	}
	for _, e := range events {
		b, _ := json.Marshal(e.data)
		h.Publish(ctx, sdk.Event{Type: e.typ, Module: "games", Instance: inst, Data: b})
	}
}

// saveOpenLocked writes the sessions in progress. The caller holds m.mu.
func (m *Module) saveOpenLocked(st *store) {
	st.mu.Lock()
	st.d.Open = st.d.Open[:0]
	for _, a := range m.active {
		st.d.Open = append(st.d.Open, *a)
	}
	_ = st.save()
	st.mu.Unlock()
}

// flush saves the sessions in progress (on shutdown) so the next start can
// resume or close them.
func (m *Module) flush() {
	st, err := m.store()
	if err != nil {
		return
	}
	m.mu.Lock()
	if m.resumed {
		m.saveOpenLocked(st)
	}
	m.mu.Unlock()
}

func closeSession(o openSession, end time.Time) (Session, bool) {
	if !end.After(o.Start) {
		return Session{}, false
	}
	return Session{GameID: o.GameID, Title: o.Title, Launcher: o.Launcher, Start: o.Start.UTC(), End: end.UTC(),
		Seconds: int64(end.Sub(o.Start).Seconds())}, true
}

func pidList(ps []proc) []int32 {
	out := make([]int32, len(ps))
	for i, p := range ps {
		out[i] = p.PID
	}
	return out
}

func overlaps(ps []proc, pids []int32) bool {
	for _, p := range ps {
		for _, q := range pids {
			if p.PID == q {
				return true
			}
		}
	}
	return false
}
