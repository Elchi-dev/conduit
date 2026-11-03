package hub

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The registry lists external modules. Each author registers an ed25519
// public key; each version is a signed payload. The hub verifies the
// signature on publish and serves the payload byte-for-byte, so daemons
// verify it again against the author's key and never have to trust the hub.

var (
	handleRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,38}$`)
	pkgNameRe = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{1,38})/([a-z0-9][a-z0-9-]{0,62})$`)
	semverRe  = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$`)
)

// VersionPayload is what an author signs when publishing.
type VersionPayload struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Homepage    string          `json:"homepage,omitempty"`
	Manifest    json.RawMessage `json:"manifest"`
	Artifacts   []Artifact      `json:"artifacts"`
}

// Artifact is one downloadable build of a module version.
type Artifact struct {
	Platform string `json:"platform"` // e.g. linux-amd64, any (scripts), wasm
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
}

type Package struct {
	Name        string    `json:"name"`
	Owner       string    `json:"owner"`
	Description string    `json:"description"`
	Homepage    string    `json:"homepage,omitempty"`
	Latest      string    `json:"latest,omitempty"`
	Downloads   int64     `json:"downloads"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type PackageVersion struct {
	Version   string    `json:"version"`
	Payload   string    `json:"payload"`   // base64 of the exact signed bytes
	Signature string    `json:"signature"` // base64 ed25519 signature
	Yanked    bool      `json:"yanked"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *Server) registerAuthor(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	if !c.Account.Verified {
		writeErr(w, 403, "confirm your email address before publishing")
		return
	}
	var req struct {
		Handle    string `json:"handle"`
		PublicKey string `json:"publicKey"`
	}
	_ = readJSON(r, &req)
	if !handleRe.MatchString(req.Handle) {
		writeErr(w, 400, "handles are 2 to 39 lowercase letters, digits and dashes")
		return
	}
	if k, err := base64.StdEncoding.DecodeString(req.PublicKey); err != nil || len(k) != ed25519.PublicKeySize {
		writeErr(w, 400, "publicKey must be a base64 ed25519 public key")
		return
	}
	ctx := r.Context()
	var existing string
	if s.db.Row(ctx, `SELECT handle FROM registry_authors WHERE account_id = ?`, c.Account.ID).Scan(&existing) == nil {
		if existing != req.Handle {
			writeErr(w, 409, "your account already publishes as "+existing)
			return
		}
		// Same handle: rotate the key.
		_, _ = s.db.Exec(ctx, `UPDATE registry_authors SET public_key = ? WHERE account_id = ?`, req.PublicKey, c.Account.ID)
		writeJSON(w, 200, map[string]string{"handle": req.Handle, "publicKey": req.PublicKey})
		return
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO registry_authors (account_id, handle, public_key, created_at) VALUES (?,?,?,?)`, c.Account.ID, req.Handle, req.PublicKey, ts(s.now())); err != nil {
		writeErr(w, 409, "that handle is taken")
		return
	}
	writeJSON(w, 201, map[string]string{"handle": req.Handle, "publicKey": req.PublicKey})
}

func (s *Server) getAuthor(w http.ResponseWriter, r *http.Request) {
	var key, cr string
	h := r.PathValue("handle")
	if err := s.db.Row(r.Context(), `SELECT public_key, created_at FROM registry_authors WHERE handle = ?`, h).Scan(&key, &cr); err != nil {
		writeErr(w, 404, "no such author")
		return
	}
	writeJSON(w, 200, map[string]any{"handle": h, "publicKey": key, "createdAt": parseTS(cr)})
}

func (s *Server) publishVersion(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !c.can("registry:publish") {
		writeErr(w, 403, "missing scope registry:publish")
		return
	}
	name := r.PathValue("name")
	// Package names contain a slash; clients send it escaped as %2F.
	m := pkgNameRe.FindStringSubmatch(name)
	if m == nil {
		writeErr(w, 400, "package names look like handle/module")
		return
	}
	ctx := r.Context()
	var handle, pub string
	if err := s.db.Row(ctx, `SELECT handle, public_key FROM registry_authors WHERE account_id = ?`, c.Account.ID).Scan(&handle, &pub); err != nil {
		writeErr(w, 403, "register as an author first (POST /v1/registry/authors)")
		return
	}
	if m[1] != handle {
		writeErr(w, 403, "you publish as "+handle+", so your packages are named "+handle+"/…")
		return
	}
	var req struct {
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	raw, err1 := base64.StdEncoding.DecodeString(req.Payload)
	sig, err2 := base64.StdEncoding.DecodeString(req.Signature)
	key, _ := base64.StdEncoding.DecodeString(pub)
	if err1 != nil || err2 != nil || !ed25519.Verify(ed25519.PublicKey(key), raw, sig) {
		writeErr(w, 400, "the signature doesn't match your registered author key")
		return
	}
	var p VersionPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		writeErr(w, 400, "payload: "+err.Error())
		return
	}
	if p.Name != name {
		writeErr(w, 400, "the signed payload names "+p.Name+", not "+name)
		return
	}
	if !semverRe.MatchString(p.Version) {
		writeErr(w, 400, "versions are semantic: 1.2.3 or 1.2.3-beta.1")
		return
	}
	if len(p.Artifacts) == 0 {
		writeErr(w, 400, "add at least one artifact")
		return
	}
	for _, a := range p.Artifacts {
		if !strings.HasPrefix(a.URL, "https://") || len(a.SHA256) != 64 || a.Platform == "" {
			writeErr(w, 400, "each artifact needs a platform, an https URL and a hex sha256")
			return
		}
	}
	var owner string
	err := s.db.Row(ctx, `SELECT owner FROM registry_packages WHERE name = ?`, name).Scan(&owner)
	now := ts(s.now())
	if err != nil {
		if _, err := s.db.Exec(ctx, `INSERT INTO registry_packages (name, owner, description, homepage, created_at, updated_at) VALUES (?,?,?,?,?,?)`,
			name, handle, truncate(p.Description, 300), p.Homepage, now, now); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	} else if owner != handle {
		writeErr(w, 403, "this package belongs to "+owner)
		return
	} else {
		_, _ = s.db.Exec(ctx, `UPDATE registry_packages SET description = ?, homepage = ?, updated_at = ? WHERE name = ?`, truncate(p.Description, 300), p.Homepage, now, name)
	}
	arts, _ := json.Marshal(p.Artifacts)
	if _, err := s.db.Exec(ctx, `INSERT INTO registry_versions (name, version, payload, artifacts, signature, created_at) VALUES (?,?,?,?,?,?)`,
		name, p.Version, req.Payload, string(arts), req.Signature, now); err != nil {
		writeErr(w, 409, "version "+p.Version+" already exists; versions are immutable, publish a new one")
		return
	}
	writeJSON(w, 201, map[string]string{"name": name, "version": p.Version})
}

func (s *Server) yankVersion(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !c.can("registry:publish") {
		writeErr(w, 403, "missing scope registry:publish")
		return
	}
	name := r.PathValue("name")
	ctx := r.Context()
	var handle, owner string
	_ = s.db.Row(ctx, `SELECT handle FROM registry_authors WHERE account_id = ?`, c.Account.ID).Scan(&handle)
	_ = s.db.Row(ctx, `SELECT owner FROM registry_packages WHERE name = ?`, name).Scan(&owner)
	if owner == "" || owner != handle {
		writeErr(w, 404, "no such package of yours")
		return
	}
	res, _ := s.db.Exec(ctx, `UPDATE registry_versions SET yanked = 1 WHERE name = ? AND version = ?`, name, r.PathValue("version"))
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 404, "no such version")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) searchPackages(w http.ResponseWriter, r *http.Request) {
	q := "%" + strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))) + "%"
	rows, err := s.db.Query(r.Context(), `SELECT name, owner, description, homepage, downloads, updated_at FROM registry_packages
		WHERE LOWER(name) LIKE ? OR LOWER(description) LIKE ? ORDER BY downloads DESC, name LIMIT 100`, q, q)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []Package{}
	for rows.Next() {
		var p Package
		var up string
		if rows.Scan(&p.Name, &p.Owner, &p.Description, &p.Homepage, &p.Downloads, &up) == nil {
			p.UpdatedAt = parseTS(up)
			out = append(out, p)
		}
	}
	rows.Close()
	for i := range out {
		vs := s.versions(r, out[i].Name)
		if l := latest(vs); l != "" {
			out[i].Latest = l
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) versions(r *http.Request, name string) []PackageVersion {
	rows, err := s.db.Query(r.Context(), `SELECT version, payload, signature, yanked, created_at FROM registry_versions WHERE name = ?`, name)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []PackageVersion
	for rows.Next() {
		var v PackageVersion
		var y int
		var cr string
		if rows.Scan(&v.Version, &v.Payload, &v.Signature, &y, &cr) == nil {
			v.Yanked, v.CreatedAt = y == 1, parseTS(cr)
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return semverLess(out[j].Version, out[i].Version) })
	return out
}

func latest(vs []PackageVersion) string {
	for _, v := range vs {
		if !v.Yanked && !strings.Contains(v.Version, "-") {
			return v.Version
		}
	}
	for _, v := range vs {
		if !v.Yanked {
			return v.Version
		}
	}
	return ""
}

func (s *Server) getPackage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var p Package
	var up string
	if err := s.db.Row(r.Context(), `SELECT name, owner, description, homepage, downloads, updated_at FROM registry_packages WHERE name = ?`, name).
		Scan(&p.Name, &p.Owner, &p.Description, &p.Homepage, &p.Downloads, &up); err != nil {
		writeErr(w, 404, "no such package")
		return
	}
	p.UpdatedAt = parseTS(up)
	vs := s.versions(r, name)
	p.Latest = latest(vs)
	var key string
	_ = s.db.Row(r.Context(), `SELECT public_key FROM registry_authors WHERE handle = ?`, p.Owner).Scan(&key)
	if r.URL.Query().Get("download") == "1" {
		_, _ = s.db.Exec(r.Context(), `UPDATE registry_packages SET downloads = downloads + 1 WHERE name = ?`, name)
	}
	if vs == nil {
		vs = []PackageVersion{}
	}
	writeJSON(w, 200, map[string]any{"package": p, "authorKey": key, "versions": vs})
}

// semverLess orders versions; a pre-release sorts before its release.
func semverLess(a, b string) bool {
	pa, pb := semverRe.FindStringSubmatch(a), semverRe.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		return a < b
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	switch {
	case pa[4] == pb[4]:
		return false
	case pa[4] == "":
		return false
	case pb[4] == "":
		return true
	}
	return pa[4] < pb[4]
}

// --- update feed -------------------------------------------------------------

// ReleasePayload is what the release key signs. Clients verify the signature
// with the release key compiled into them, so a compromised hub can't push a
// malicious update.
type ReleasePayload struct {
	Component string `json:"component"` // daemon, desktop, android, hub
	Channel   string `json:"channel"`   // stable, beta
	Platform  string `json:"platform"`  // linux-amd64, windows-amd64, darwin-arm64, android, …
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Notes     string `json:"notes,omitempty"`
}

var components = map[string]bool{"daemon": true, "desktop": true, "android": true, "hub": true}

func (s *Server) publishRelease(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !c.Account.Admin || !c.can("releases:publish") {
		writeErr(w, 403, "only hub admins can publish releases")
		return
	}
	if s.cfg.ReleaseKey == "" {
		writeErr(w, 409, "this hub has no release key configured (CONDUIT_HUB_RELEASE_KEY)")
		return
	}
	var req struct {
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	raw, err1 := base64.StdEncoding.DecodeString(req.Payload)
	sig, err2 := base64.StdEncoding.DecodeString(req.Signature)
	key, err3 := base64.StdEncoding.DecodeString(s.cfg.ReleaseKey)
	if err1 != nil || err2 != nil || err3 != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(key), raw, sig) {
		writeErr(w, 400, "the signature doesn't match this hub's release key")
		return
	}
	var p ReleasePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !components[p.Component] || p.Channel == "" || p.Platform == "" || !semverRe.MatchString(p.Version) || len(p.SHA256) != 64 || !strings.HasPrefix(p.URL, "https://") {
		writeErr(w, 400, "a release needs a known component, channel, platform, semantic version, https URL and sha256")
		return
	}
	if _, err := s.db.Exec(r.Context(), `INSERT INTO releases (component, channel, platform, version, payload, sha256, signature, notes, created_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		p.Component, p.Channel, p.Platform, p.Version, req.Payload, p.SHA256, req.Signature, p.Notes, ts(s.now())); err != nil {
		writeErr(w, 409, "that release already exists")
		return
	}
	writeJSON(w, 201, p)
}

// latestRelease answers the newest release, or 204 when the caller is current
// (pass ?current=1.2.3).
func (s *Server) latestRelease(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `SELECT version, payload, signature, created_at FROM releases WHERE component = ? AND channel = ? AND platform = ?`,
		r.PathValue("component"), r.PathValue("channel"), r.PathValue("platform"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	var best struct{ version, payload, sig, created string }
	for rows.Next() {
		var v, p, sg, cr string
		if rows.Scan(&v, &p, &sg, &cr) == nil && (best.version == "" || semverLess(best.version, v)) {
			best.version, best.payload, best.sig, best.created = v, p, sg, cr
		}
	}
	if best.version == "" {
		writeErr(w, 404, "no releases for that component, channel and platform")
		return
	}
	if cur := r.URL.Query().Get("current"); cur != "" && !semverLess(cur, best.version) {
		w.WriteHeader(204)
		return
	}
	writeJSON(w, 200, map[string]any{"version": best.version, "payload": best.payload, "signature": best.sig, "publishedAt": parseTS(best.created)})
}
