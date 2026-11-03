package hub

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/coder/websocket"
)

// The operator console: what a hub's admins (accounts with is_admin) need to
// run it. Every endpoint needs a signed-in admin person (no API keys or
// device tokens), is written to the hub's log, and tells the affected
// account by email.

// AdminStats is the console's overview.
type AdminStats struct {
	Accounts      int   `json:"accounts"`
	Verified      int   `json:"verified"`
	Admins        int   `json:"admins"`
	Disabled      int   `json:"disabled"`
	Devices       int   `json:"devices"`
	Daemons       int   `json:"daemons"`
	DaemonsOnline int   `json:"daemonsOnline"`
	Orgs          int   `json:"orgs"`
	SyncBlobs     int   `json:"syncBlobs"`
	SyncBytes     int64 `json:"syncBytes"`
	Packages      int   `json:"packages"`
	Releases      int   `json:"releases"`
}

// AdminAccount is one row of the console's account table.
type AdminAccount struct {
	Account
	Devices      int    `json:"devices"`
	LastSignInAt string `json:"lastSignInAt,omitempty"`
}

func (s *Server) adminOnly(w http.ResponseWriter, r *http.Request) (caller, bool) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return c, false
	}
	if !c.Account.Admin {
		writeErr(w, http.StatusForbidden, "only the hub's admins can do this")
		return c, false
	}
	return c, true
}

func (s *Server) adminStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminOnly(w, r); !ok {
		return
	}
	ctx := r.Context()
	var st AdminStats
	count := func(dst *int, q string) {
		_ = s.db.Row(ctx, q).Scan(dst)
	}
	count(&st.Accounts, `SELECT COUNT(*) FROM accounts`)
	count(&st.Verified, `SELECT COUNT(*) FROM accounts WHERE verified = 1`)
	count(&st.Admins, `SELECT COUNT(*) FROM accounts WHERE is_admin = 1`)
	count(&st.Disabled, `SELECT COUNT(*) FROM accounts WHERE disabled = 1`)
	count(&st.Devices, `SELECT COUNT(*) FROM devices WHERE revoked = 0`)
	count(&st.Daemons, `SELECT COUNT(*) FROM devices WHERE revoked = 0 AND kind = 'daemon'`)
	count(&st.Orgs, `SELECT COUNT(*) FROM orgs`)
	count(&st.SyncBlobs, `SELECT COUNT(*) FROM sync_blobs`)
	count(&st.Packages, `SELECT COUNT(*) FROM registry_packages`)
	count(&st.Releases, `SELECT COUNT(*) FROM releases`)
	var bytes sql.NullInt64
	_ = s.db.Row(ctx, `SELECT SUM(LENGTH(data)) FROM sync_blobs`).Scan(&bytes)
	st.SyncBytes = bytes.Int64
	s.relay.mu.Lock()
	st.DaemonsOnline = len(s.relay.daemons)
	s.relay.mu.Unlock()
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) adminAccounts(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminOnly(w, r); !ok {
		return
	}
	ctx := r.Context()
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	where, args := "", []any{}
	if q != "" {
		// LIKE wildcards in the search are matched literally.
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
		where = ` WHERE LOWER(a.email) LIKE ? ESCAPE '\' OR LOWER(a.name) LIKE ? ESCAPE '\'`
		args = append(args, "%"+esc+"%", "%"+esc+"%")
	}
	var total int
	_ = s.db.Row(ctx, `SELECT COUNT(*) FROM accounts a`+where, args...).Scan(&total)
	rows, err := s.db.Query(ctx, `SELECT a.id, a.email, a.name, a.verified, a.is_admin, a.disabled, a.created_at, a.last_sign_in_at,
		(SELECT COUNT(*) FROM devices d WHERE d.account_id = a.id AND d.revoked = 0)
		FROM accounts a`+where+` ORDER BY a.created_at DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list accounts")
		return
	}
	defer rows.Close()
	out := []AdminAccount{}
	for rows.Next() {
		var a AdminAccount
		var v, adm, dis int
		var cr string
		if err := rows.Scan(&a.ID, &a.Email, &a.Name, &v, &adm, &dis, &cr, &a.LastSignInAt, &a.Devices); err != nil {
			continue
		}
		a.Verified, a.Admin, a.Disabled, a.CreatedAt = v == 1, adm == 1, dis == 1, parseTS(cr)
		out = append(out, a)
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "items": out})
}

// target loads the account an admin acts on, refusing the admin's own.
func (s *Server) adminTarget(w http.ResponseWriter, r *http.Request, c caller) (Account, bool) {
	id := r.PathValue("id")
	if id == c.Account.ID {
		writeErr(w, http.StatusBadRequest, "you can't do this to your own account")
		return Account{}, false
	}
	a, err := s.account(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such account")
		return Account{}, false
	}
	return a, true
}

// endAccess revokes every session, device and key of an account and drops
// its daemons' relay connections.
func (s *Server) endAccess(ctx context.Context, id string) {
	_, _ = s.db.Exec(ctx, `UPDATE hub_sessions SET revoked = 1 WHERE account_id = ?`, id)
	_, _ = s.db.Exec(ctx, `UPDATE hub_keys SET revoked = 1 WHERE account_id = ?`, id)
	rows, err := s.db.Query(ctx, `SELECT id FROM devices WHERE account_id = ?`, id)
	var devs []string
	if err == nil {
		for rows.Next() {
			var d string
			if rows.Scan(&d) == nil {
				devs = append(devs, d)
			}
		}
		rows.Close()
	}
	_, _ = s.db.Exec(ctx, `UPDATE devices SET revoked = 1 WHERE account_id = ?`, id)
	s.relay.mu.Lock()
	for _, d := range devs {
		if dc := s.relay.daemons[d]; dc != nil {
			dc.ws.Close(websocket.StatusPolicyViolation, "the account was switched off")
		}
	}
	s.relay.mu.Unlock()
}

func (s *Server) adminDisable(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	a, ok := s.adminTarget(w, r, c)
	if !ok {
		return
	}
	ctx := r.Context()
	if a.Admin && s.otherActiveAdmins(ctx, a.ID) == 0 {
		writeErr(w, http.StatusConflict, "that's the last admin who can sign in; make someone else an admin first")
		return
	}
	if _, err := s.db.Exec(ctx, `UPDATE accounts SET disabled = 1 WHERE id = ?`, a.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not switch the account off")
		return
	}
	s.endAccess(ctx, a.ID)
	s.log.Warn("admin: account switched off", "account", a.Email, "by", c.Account.Email)
	go s.tell(a.Email, "Your account on "+s.cfg.Name+" was switched off",
		"An operator of "+s.cfg.Name+" switched your account off. You can't sign in, and your devices and API keys no longer work with this hub. Your daemons keep running on their own.\n\nIf you think this is a mistake, contact the hub's operator.")
	a.Disabled = true
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) adminEnable(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	a, ok := s.adminTarget(w, r, c)
	if !ok {
		return
	}
	if _, err := s.db.Exec(r.Context(), `UPDATE accounts SET disabled = 0 WHERE id = ?`, a.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not switch the account on")
		return
	}
	s.log.Info("admin: account switched on", "account", a.Email, "by", c.Account.Email)
	go s.tell(a.Email, "Your account on "+s.cfg.Name+" is back on",
		"An operator of "+s.cfg.Name+" switched your account back on. You can sign in again. Devices and API keys from before were revoked when it was switched off: pair your devices again and make new keys.")
	a.Disabled = false
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) adminDelete(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	a, ok := s.adminTarget(w, r, c)
	if !ok {
		return
	}
	ctx := r.Context()
	if a.Admin && s.otherActiveAdmins(ctx, a.ID) == 0 {
		writeErr(w, http.StatusConflict, "that's the last admin who can sign in; make someone else an admin first")
		return
	}
	s.endAccess(ctx, a.ID)
	if err := s.deleteAccountData(ctx, a.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not delete the account: "+err.Error())
		return
	}
	s.log.Warn("admin: account deleted", "account", a.Email, "by", c.Account.Email)
	go s.tell(a.Email, "Your account on "+s.cfg.Name+" was deleted",
		"An operator of "+s.cfg.Name+" deleted your account and its data on this hub: devices, keys, sync data and passkeys. Your daemons and everything on them are untouched; link them to another hub, or use them without one.")
	w.WriteHeader(http.StatusNoContent)
}

// deleteAccountData removes everything the hub stores for an account.
// Published registry packages stay (others may depend on them, and their
// signatures don't depend on the account). The author handle is kept as a
// tombstone, with its key, so nobody can take it over and publish newer
// versions of those packages.
func (s *Server) deleteAccountData(ctx context.Context, id string) error {
	for _, q := range []string{
		`DELETE FROM hub_sessions WHERE account_id = ?`,
		`DELETE FROM email_tokens WHERE account_id = ?`,
		`DELETE FROM pairing_codes WHERE account_id = ?`,
		`DELETE FROM devices WHERE account_id = ?`,
		`DELETE FROM sync_blobs WHERE account_id = ?`,
		`DELETE FROM hub_keys WHERE account_id = ?`,
		`DELETE FROM passkeys WHERE account_id = ?`,
		`DELETE FROM account_totp WHERE account_id = ?`,
		`DELETE FROM account_recovery_codes WHERE account_id = ?`,
		`UPDATE registry_authors SET account_id = 'deleted:' || account_id WHERE account_id = ?`,
		`DELETE FROM org_members WHERE account_id = ?`,
	} {
		if _, err := s.db.Exec(ctx, q, id); err != nil {
			return fmt.Errorf("%s: %w", strings.Fields(q)[2], err)
		}
	}
	// Organisations left without members go too.
	if _, err := s.db.Exec(ctx, `DELETE FROM orgs WHERE id NOT IN (SELECT org_id FROM org_members)`); err != nil {
		return err
	}
	res, err := s.db.Exec(ctx, `DELETE FROM accounts WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such account")
	}
	return nil
}

func (s *Server) otherActiveAdmins(ctx context.Context, except string) int {
	var n int
	_ = s.db.Row(ctx, `SELECT COUNT(*) FROM accounts WHERE is_admin = 1 AND disabled = 0 AND id != ?`, except).Scan(&n)
	return n
}

func (s *Server) tell(to, subject, body string) {
	_ = s.mail.Send(context.Background(), to, subject, body+"\n\n"+s.cfg.Name+" ("+s.cfg.PublicURL+")")
}
