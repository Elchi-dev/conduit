package hub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

// --- orgs ---------------------------------------------------------------------

type Org struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
}

type Member struct {
	AccountID string    `json:"accountId"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	JoinedAt  time.Time `json:"joinedAt"`
}

func personOnly(w http.ResponseWriter, c caller) bool {
	if c.Scopes != nil {
		writeErr(w, http.StatusForbidden, "this needs a signed-in person, not a device or API key")
		return false
	}
	return true
}

func (s *Server) roleIn(ctx context.Context, org, account string) string {
	var role string
	_ = s.db.Row(ctx, `SELECT role FROM org_members WHERE org_id = ? AND account_id = ?`, org, account).Scan(&role)
	return role
}

func (s *Server) listOrgs(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !c.can("orgs:read") {
		writeErr(w, http.StatusForbidden, "missing scope orgs:read")
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT o.id, o.name, m.role, o.created_at FROM orgs o JOIN org_members m ON m.org_id = o.id WHERE m.account_id = ? ORDER BY o.name`, c.Account.ID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []Org{}
	for rows.Next() {
		var o Org
		var cr string
		if rows.Scan(&o.ID, &o.Name, &o.Role, &cr) == nil {
			o.CreatedAt = parseTS(cr)
			out = append(out, o)
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	_ = readJSON(r, &req)
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 80 {
		writeErr(w, 400, "give the organisation a name of up to 80 characters")
		return
	}
	o := Org{ID: newID("org"), Name: req.Name, Role: "owner", CreatedAt: s.now().UTC()}
	ctx := r.Context()
	if _, err := s.db.Exec(ctx, `INSERT INTO orgs (id, name, created_at) VALUES (?,?,?)`, o.ID, o.Name, ts(o.CreatedAt)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_, _ = s.db.Exec(ctx, `INSERT INTO org_members (org_id, account_id, role, created_at) VALUES (?,?,?,?)`, o.ID, c.Account.ID, "owner", ts(o.CreatedAt))
	writeJSON(w, 201, o)
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	org := r.PathValue("id")
	if !c.can("orgs:read") || s.roleIn(r.Context(), org, c.Account.ID) == "" {
		writeErr(w, 404, "no such organisation")
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT a.id, a.email, a.name, m.role, m.created_at FROM org_members m JOIN accounts a ON a.id = m.account_id WHERE m.org_id = ? ORDER BY a.name`, org)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []Member{}
	for rows.Next() {
		var m Member
		var cr string
		if rows.Scan(&m.AccountID, &m.Email, &m.Name, &m.Role, &cr) == nil {
			m.JoinedAt = parseTS(cr)
			out = append(out, m)
		}
	}
	writeJSON(w, 200, out)
}

var roles = map[string]bool{"owner": true, "admin": true, "member": true}

func (s *Server) invite(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	org := r.PathValue("id")
	ctx := r.Context()
	my := s.roleIn(ctx, org, c.Account.ID)
	if my != "owner" && my != "admin" {
		writeErr(w, 403, "only owners and admins can invite people")
		return
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	_ = readJSON(r, &req)
	addr, err := mail.ParseAddress(req.Email)
	if err != nil {
		writeErr(w, 400, "enter a valid email address")
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}
	if !roles[req.Role] || (req.Role == "owner" && my != "owner") {
		writeErr(w, 400, "role must be member, admin or (for owners) owner")
		return
	}
	var name string
	_ = s.db.Row(ctx, `SELECT name FROM orgs WHERE id = ?`, org).Scan(&name)
	email := strings.ToLower(addr.Address)
	err = s.sendToken(ctx, "", email, "invite", map[string]string{"org": org, "role": req.Role, "email": email}, 7*24*time.Hour,
		c.Account.Name+" invited you to "+name+" on "+s.cfg.Name,
		c.Account.Name+" ("+c.Account.Email+") invited you to join "+name+" as "+req.Role+". Accept the invitation (create an account first if you don't have one):", "/invite")
	if err != nil {
		writeErr(w, 500, "could not send the invitation: "+err.Error())
		return
	}
	writeJSON(w, 202, map[string]string{"status": "invitation sent"})
}

func (s *Server) acceptInvite(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	_ = readJSON(r, &req)
	ctx := r.Context()
	// Check the address before consuming the token, so the wrong account
	// doesn't burn someone else's invitation.
	var data string
	if err := s.db.Row(ctx, `SELECT data FROM email_tokens WHERE token_hash = ? AND kind = 'invite'`, hash(req.Token)).Scan(&data); err != nil {
		writeErr(w, 400, "this invitation is invalid or has expired")
		return
	}
	var inv struct{ Org, Role, Email string }
	_ = json.Unmarshal([]byte(data), &inv)
	if inv.Email != c.Account.Email {
		writeErr(w, 403, "this invitation was sent to a different email address")
		return
	}
	if _, _, err := s.useToken(ctx, req.Token, "invite"); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if s.roleIn(ctx, inv.Org, c.Account.ID) == "" {
		_, _ = s.db.Exec(ctx, `INSERT INTO org_members (org_id, account_id, role, created_at) VALUES (?,?,?,?)`, inv.Org, c.Account.ID, inv.Role, ts(s.now()))
	}
	// Accepting an emailed link also proves the address.
	_, _ = s.db.Exec(ctx, `UPDATE accounts SET verified = 1 WHERE id = ?`, c.Account.ID)
	s.grantConfiguredAdmin(ctx, c.Account.ID)
	writeJSON(w, 200, map[string]string{"org": inv.Org, "role": inv.Role})
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	org, target := r.PathValue("id"), r.PathValue("account")
	ctx := r.Context()
	my := s.roleIn(ctx, org, c.Account.ID)
	their := s.roleIn(ctx, org, target)
	if their == "" {
		writeErr(w, 404, "not a member")
		return
	}
	self := target == c.Account.ID
	if !self && (my != "owner" && !(my == "admin" && their == "member")) {
		writeErr(w, 403, "you can't remove this member")
		return
	}
	if their == "owner" {
		var owners int
		_ = s.db.Row(ctx, `SELECT COUNT(*) FROM org_members WHERE org_id = ? AND role = 'owner'`, org).Scan(&owners)
		if owners <= 1 {
			writeErr(w, 409, "an organisation needs at least one owner; make someone else owner first")
			return
		}
	}
	_, _ = s.db.Exec(ctx, `DELETE FROM org_members WHERE org_id = ? AND account_id = ?`, org, target)
	w.WriteHeader(204)
}

// --- devices & pairing ---------------------------------------------------------

type Device struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	PublicKey  string    `json:"publicKey"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	Online     bool      `json:"online"`
}

// pairing codes are short so they can be typed: 8 characters from the
// unambiguous alphabet, valid 10 minutes, one use.
func (s *Server) newPairingCode(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	code := strings.ToUpper(token(5))
	exp := s.now().Add(10 * time.Minute)
	if _, err := s.db.Exec(r.Context(), `INSERT INTO pairing_codes (code_hash, account_id, expires_at) VALUES (?,?,?)`, hash(code), c.Account.ID, ts(exp)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"code": code, "expiresAt": exp.UTC()})
}

func (s *Server) pairDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code      string `json:"code"`
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		PublicKey string `json:"publicKey"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Kind != "daemon" && req.Kind != "client" {
		writeErr(w, 400, `kind must be "daemon" or "client"`)
		return
	}
	if req.Kind == "daemon" {
		if k, err := base64.RawURLEncoding.DecodeString(req.PublicKey); err != nil || len(k) != 32 {
			writeErr(w, 400, "a daemon must send its 32-byte X25519 public key (base64url)")
			return
		}
	}
	ctx := r.Context()
	code := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(req.Code), "-", ""))
	var account, exp string
	var used int
	if err := s.db.Row(ctx, `SELECT account_id, expires_at, used FROM pairing_codes WHERE code_hash = ?`, hash(code)).Scan(&account, &exp, &used); err != nil || used == 1 || s.now().After(parseTS(exp)) {
		writeErr(w, 400, "that pairing code is wrong or has expired")
		return
	}
	res, _ := s.db.Exec(ctx, `UPDATE pairing_codes SET used = 1 WHERE code_hash = ? AND used = 0`, hash(code))
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 400, "that pairing code was already used")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = req.Kind
	}
	d := Device{ID: newID("dev"), Name: truncate(name, 80), Kind: req.Kind, PublicKey: req.PublicKey, CreatedAt: s.now().UTC()}
	d.LastSeenAt = d.CreatedAt
	tok := devicePrefix + token(24)
	if _, err := s.db.Exec(ctx, `INSERT INTO devices (id, account_id, name, kind, public_key, token_hash, created_at, last_seen_at) VALUES (?,?,?,?,?,?,?,?)`,
		d.ID, account, d.Name, d.Kind, d.PublicKey, hash(tok), ts(d.CreatedAt), ts(d.CreatedAt)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	a, _ := s.account(ctx, account)
	go func() {
		_ = s.mail.Send(context.Background(), a.Email, "A new device was paired to your account",
			"\""+d.Name+"\" ("+d.Kind+") was paired to your "+s.cfg.Name+" account. If this wasn't you, remove it under Devices at "+s.cfg.PublicURL+".")
	}()
	writeJSON(w, 201, map[string]any{"device": d, "token": tok, "account": map[string]string{"id": a.ID, "email": a.Email}, "hub": s.cfg.PublicURL})
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !c.can("devices:read") && c.DeviceID == "" {
		writeErr(w, 403, "missing scope devices:read")
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT id, name, kind, public_key, created_at, last_seen_at FROM devices WHERE account_id = ? AND revoked = 0 ORDER BY created_at`, c.Account.ID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		var d Device
		var cr, ls string
		if rows.Scan(&d.ID, &d.Name, &d.Kind, &d.PublicKey, &cr, &ls) == nil {
			d.CreatedAt, d.LastSeenAt = parseTS(cr), parseTS(ls)
			d.Online = d.Kind == "daemon" && s.relay.online(d.ID)
			out = append(out, d)
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	id := r.PathValue("id")
	// People can remove any of their devices; a device can remove itself.
	if c.Scopes != nil && c.DeviceID != id {
		writeErr(w, 403, "this needs a signed-in person")
		return
	}
	res, _ := s.db.Exec(r.Context(), `UPDATE devices SET revoked = 1 WHERE id = ? AND account_id = ?`, id, c.Account.ID)
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 404, "no such device")
		return
	}
	s.relay.mu.Lock()
	if d := s.relay.daemons[id]; d != nil {
		d.ws.CloseNow()
	}
	s.relay.mu.Unlock()
	w.WriteHeader(204)
}

// --- hub API keys --------------------------------------------------------------

// HubScopes are what a hub API key can be granted.
var HubScopes = []string{"orgs:read", "devices:read", "sync", "registry:read", "registry:publish", "releases:publish"}

type HubKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Prefix    string    `json:"prefix"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *Server) listHubKeys(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT id, name, prefix, scopes, created_at FROM hub_keys WHERE account_id = ? AND revoked = 0 ORDER BY created_at`, c.Account.ID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []HubKey{}
	for rows.Next() {
		var k HubKey
		var sc, cr string
		if rows.Scan(&k.ID, &k.Name, &k.Prefix, &sc, &cr) == nil {
			_ = json.Unmarshal([]byte(sc), &k.Scopes)
			k.CreatedAt = parseTS(cr)
			out = append(out, k)
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) createHubKey(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	_ = readJSON(r, &req)
	allowed := map[string]bool{}
	for _, sc := range HubScopes {
		allowed[sc] = true
	}
	if len(req.Scopes) == 0 {
		writeErr(w, 400, "pick at least one scope: "+strings.Join(HubScopes, ", "))
		return
	}
	for _, sc := range req.Scopes {
		if !allowed[sc] {
			writeErr(w, 400, "unknown scope "+sc+"; use "+strings.Join(HubScopes, ", "))
			return
		}
		if sc == "releases:publish" && !c.Account.Admin {
			writeErr(w, 403, "only hub admins can publish releases")
			return
		}
	}
	id := token(6)
	secret := keyPrefix + id + "_" + token(24)
	k := HubKey{ID: "hk_" + id, Name: strings.TrimSpace(req.Name), Prefix: keyPrefix + id, Scopes: req.Scopes, CreatedAt: s.now().UTC()}
	if k.Name == "" {
		k.Name = "API key"
	}
	sc, _ := json.Marshal(k.Scopes)
	if _, err := s.db.Exec(r.Context(), `INSERT INTO hub_keys (id, account_id, name, prefix, secret_hash, scopes, created_at) VALUES (?,?,?,?,?,?,?)`,
		k.ID, c.Account.ID, k.Name, k.Prefix, hash(secret), string(sc), ts(k.CreatedAt)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"key": k, "secret": secret})
}

func (s *Server) revokeHubKey(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	res, _ := s.db.Exec(r.Context(), `UPDATE hub_keys SET revoked = 1 WHERE id = ? AND account_id = ?`, r.PathValue("id"), c.Account.ID)
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 404, "no such key")
		return
	}
	w.WriteHeader(204)
}

// --- sync ------------------------------------------------------------------

// Sync stores opaque blobs the client encrypted itself (settings, layouts,
// policy presets). The hub can't read them. Writes use optimistic versions:
// send the version you last saw; a mismatch answers 409 with the current one.

var blobKey = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

const (
	maxBlob  = 1 << 20
	maxBlobs = 1000
)

type Blob struct {
	Key       string    `json:"key"`
	Version   int64     `json:"version"`
	Data      string    `json:"data,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func syncAllowed(w http.ResponseWriter, c caller) bool {
	if !c.can("sync") {
		writeErr(w, 403, "missing scope sync")
		return false
	}
	return true
}

func (s *Server) listBlobs(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !syncAllowed(w, c) {
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT blob_key, version, updated_at FROM sync_blobs WHERE account_id = ? ORDER BY blob_key`, c.Account.ID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []Blob{}
	for rows.Next() {
		var b Blob
		var up string
		if rows.Scan(&b.Key, &b.Version, &up) == nil {
			b.UpdatedAt = parseTS(up)
			out = append(out, b)
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) blob(ctx context.Context, account, key string) (Blob, error) {
	b := Blob{Key: key}
	var up string
	err := s.db.Row(ctx, `SELECT version, data, updated_at FROM sync_blobs WHERE account_id = ? AND blob_key = ?`, account, key).Scan(&b.Version, &b.Data, &up)
	b.UpdatedAt = parseTS(up)
	return b, err
}

func (s *Server) getBlob(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !syncAllowed(w, c) {
		return
	}
	b, err := s.blob(r.Context(), c.Account.ID, r.PathValue("key"))
	if err != nil {
		writeErr(w, 404, "nothing stored under that key")
		return
	}
	writeJSON(w, 200, b)
}

func (s *Server) putBlob(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !syncAllowed(w, c) {
		return
	}
	key := r.PathValue("key")
	if !blobKey.MatchString(key) {
		writeErr(w, 400, "keys are lowercase letters, digits, dot, dash and underscore, up to 100 characters")
		return
	}
	var req struct {
		Version int64  `json:"version"`
		Data    string `json:"data"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(req.Data) > maxBlob {
		writeErr(w, 413, "a blob can be at most 1 MiB")
		return
	}
	ctx := r.Context()
	now := ts(s.now())
	if req.Version == 0 {
		var n int
		_ = s.db.Row(ctx, `SELECT COUNT(*) FROM sync_blobs WHERE account_id = ?`, c.Account.ID).Scan(&n)
		if n >= maxBlobs {
			writeErr(w, 413, "this account has reached 1000 sync blobs")
			return
		}
		if _, err := s.db.Exec(ctx, `INSERT INTO sync_blobs (account_id, blob_key, version, data, updated_at) VALUES (?,?,1,?,?)`, c.Account.ID, key, req.Data, now); err == nil {
			writeJSON(w, 200, Blob{Key: key, Version: 1, UpdatedAt: parseTS(now)})
			return
		}
	} else {
		res, err := s.db.Exec(ctx, `UPDATE sync_blobs SET version = version + 1, data = ?, updated_at = ? WHERE account_id = ? AND blob_key = ? AND version = ?`, req.Data, now, c.Account.ID, key, req.Version)
		if err == nil {
			if n, _ := res.RowsAffected(); n == 1 {
				writeJSON(w, 200, Blob{Key: key, Version: req.Version + 1, UpdatedAt: parseTS(now)})
				return
			}
		}
	}
	cur, err := s.blob(ctx, c.Account.ID, key)
	if err != nil {
		writeErr(w, 409, "nothing is stored under that key yet; write with version 0")
		return
	}
	writeJSON(w, 409, map[string]any{"error": "someone else changed this first; merge and retry with the current version", "current": cur})
}

func (s *Server) deleteBlob(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !syncAllowed(w, c) {
		return
	}
	_, _ = s.db.Exec(r.Context(), `DELETE FROM sync_blobs WHERE account_id = ? AND blob_key = ?`, c.Account.ID, r.PathValue("key"))
	w.WriteHeader(204)
}
