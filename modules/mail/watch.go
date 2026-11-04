package mail

import (
	"context"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// watch polls INBOX and publishes mail.received for new messages and
// mail.unread when the unread count changes. Its position survives
// restarts, so mail that arrived while the daemon was off is announced once
// (at most 50 messages).
//
// Polling (STATUS, then a FETCH of only the new uids) is used rather than
// IDLE: it shares the account's connection, works on every server
// including Proton Bridge, and two minutes is quick enough for
// automations and the brief.
func (m *Module) watch(ctx context.Context, a *account) {
	defer close(a.done)
	every := time.Duration(a.cfg.WatchSeconds) * time.Second
	if every <= 0 {
		every = 2 * time.Minute
	}
	if every < 30*time.Second {
		every = 30 * time.Second
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		m.checkNew(ctx, a)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// checkNew runs one poll.
func (m *Module) checkNew(ctx context.Context, a *account) {
	var fresh []Summary
	var unread uint32
	ok := false
	err := m.with(ctx, a, func(cl *imapclient.Client) error {
		st, err := cl.Status("INBOX", &imap.StatusOptions{UIDNext: true, UIDValidity: true, NumUnseen: true}).Wait()
		if err != nil {
			return err
		}
		if st.NumUnseen != nil {
			unread = *st.NumUnseen
		}
		ok = true
		d := a.state.get()
		next := uint32(st.UIDNext)
		if d.Validity == 0 || d.Validity != st.UIDValidity {
			// first run, or the server renumbered the inbox: start from now
			return a.state.update(func(s *stateData) { s.LastUID, s.Validity = next-1, st.UIDValidity })
		}
		if next == 0 || next-1 <= d.LastUID {
			return nil
		}
		if _, err := cl.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
			return err
		}
		from := d.LastUID + 1
		if next-from > 50 {
			from = next - 50
		}
		set := imap.UIDSet{imap.UIDRange{Start: imap.UID(from), Stop: 0}} // from:*
		msgs, err := cl.Fetch(set, listFetch()).Collect()
		if err != nil {
			return err
		}
		max := d.LastUID
		for _, s := range summarize(msgs, "INBOX") {
			if s.UID > d.LastUID {
				fresh = append(fresh, s)
				if s.UID > max {
					max = s.UID
				}
			}
		}
		if max < next-1 {
			max = next - 1
		}
		return a.state.update(func(s *stateData) { s.LastUID = max })
	})
	if err != nil {
		a.log("warn", "checking for new mail failed", "err", err)
		return
	}
	if !ok || a.host == nil {
		return
	}
	if len(fresh) > 0 {
		a.host.Publish(ctx, sdk.Event{Type: "mail.received", Instance: a.id,
			Data: mustJSON(map[string]any{"count": len(fresh), "unread": unread, "messages": fresh})})
	}
	prev := a.state.get().Unread
	if prev == nil || *prev != unread {
		u := unread
		_ = a.state.update(func(s *stateData) { s.Unread = &u })
		if prev != nil {
			a.host.Publish(ctx, sdk.Event{Type: "mail.unread", Instance: a.id,
				Data: mustJSON(map[string]any{"unread": unread, "previous": *prev})})
		}
	}
}
