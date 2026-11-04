package hub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// The marketplace on top of the registry: listings (readme, categories,
// tags, links, icon, screenshots), anonymous install counts, ratings and
// reviews, reports, and the operators' moderation tools. Listing metadata
// isn't part of the signed version payload: it describes the package, not
// what runs, and authors can change it at any time. See
// docs/protocol/marketplace.md.

// Category is one of the fixed marketplace categories.
type Category struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

var categories = []Category{
	{ID: "home", Label: "Home and IoT"},
	{ID: "servers", Label: "Servers and infrastructure"},
	{ID: "dev", Label: "Developer tools"},
	{ID: "monitoring", Label: "Monitoring"},
	{ID: "communication", Label: "Mail and chat"},
	{ID: "media", Label: "Media"},
	{ID: "games", Label: "Games"},
	{ID: "productivity", Label: "Productivity"},
	{ID: "finance", Label: "Finance"},
	{ID: "security", Label: "Security"},
	{ID: "ai", Label: "AI and agents"},
	{ID: "data", Label: "Data and storage"},
	{ID: "other", Label: "Other"},
}

func knownCategory(id string) bool {
	for _, c := range categories {
		if c.ID == id {
			return true
		}
	}
	return false
}

// Reasons for reports, operator yanks, delistings and bans.
var reportReasons = map[string]bool{"malware": true, "broken": true, "spam": true, "impersonation": true, "license": true, "other": true}

const (
	maxReadme      = 64 << 10
	maxIcon        = 128 << 10
	maxScreenshot  = 1 << 20
	maxScreenshots = 6
	maxTags        = 8
	maxCategories  = 3
	maxReviewBody  = 2000
	maxReportBody  = 2000
	maxNote        = 500
)

var (
	tagRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,23}$`)
	licenseRe = regexp.MustCompile(`^[A-Za-z0-9.+() -]{1,64}$`)
	mediaIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	daemonRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

// --- reading packages ---------------------------------------------------------

const pkgColumns = `p.name, p.owner, p.description, p.homepage, p.source_url, p.license, p.downloads, p.installs,
	p.rating_count, p.rating_sum, p.tags, p.icon, p.created_at, p.updated_at, p.delisted, p.delist_reason, p.delist_note,
	COALESCE(a.verified, 0)`

type scanner interface{ Scan(...any) error }

func scanPackage(sc scanner, extra ...any) (Package, error) {
	var p Package
	var tags, cr, up string
	var del, ver int
	dst := append([]any{&p.Name, &p.Owner, &p.Description, &p.Homepage, &p.Source, &p.License, &p.Downloads, &p.Installs,
		&p.RatingCount, new(int64), &tags, &p.Icon, &cr, &up, &del, &p.DelistReason, &p.DelistNote, &ver}, extra...)
	if err := sc.Scan(dst...); err != nil {
		return p, err
	}
	sum := *(dst[9].(*int64))
	if p.RatingCount > 0 {
		p.Rating = float64(int(float64(sum)/float64(p.RatingCount)*10+0.5)) / 10
	}
	_ = json.Unmarshal([]byte(tags), &p.Tags)
	if p.Tags == nil {
		p.Tags = []string{}
	}
	p.CreatedAt, p.UpdatedAt, p.Delisted, p.Verified = parseTS(cr), parseTS(up), del == 1, ver == 1
	return p, nil
}

func (s *Server) categoriesOf(ctx context.Context, name string) []string {
	out := []string{}
	rows, err := s.db.Query(ctx, `SELECT category FROM registry_package_categories WHERE name = ? ORDER BY category`, name)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		if rows.Scan(&c) == nil {
			out = append(out, c)
		}
	}
	return out
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// searchPackages answers listed (not delisted) packages, searched by q,
// filtered by category and sorted. The total is in X-Total-Count.
func (s *Server) searchPackages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	qp := r.URL.Query()
	q := strings.ToLower(strings.TrimSpace(qp.Get("q")))
	cat := qp.Get("category")
	if cat != "" && !knownCategory(cat) {
		writeErr(w, 400, "unknown category")
		return
	}
	limit, _ := strconv.Atoi(qp.Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	offset, _ := strconv.Atoi(qp.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	sortBy := qp.Get("sort")
	if sortBy == "" {
		sortBy = "relevance"
	}
	var order string
	switch sortBy {
	case "relevance":
		order = "score DESC, p.installs DESC, p.downloads DESC, p.name"
	case "installs":
		order = "p.installs DESC, p.downloads DESC, p.name"
	case "rating":
		// A weighted average: two imaginary 3-star ratings keep a single
		// 5-star rating from topping the list.
		order = "(p.rating_sum + 6.0) / (p.rating_count + 2) DESC, p.rating_count DESC, p.name"
	case "newest":
		order = "p.created_at DESC, p.name"
	case "updated":
		order = "p.updated_at DESC, p.name"
	default:
		writeErr(w, 400, "sort is one of relevance, installs, rating, newest, updated")
		return
	}
	esc := likeEscape(q)
	like := "%" + esc + "%"
	where := ` WHERE p.delisted = 0`
	args := []any{}
	if q != "" {
		where += ` AND (LOWER(p.name) LIKE ? ESCAPE '\' OR LOWER(p.description) LIKE ? ESCAPE '\' OR LOWER(p.tags) LIKE ? ESCAPE '\')`
		args = append(args, like, like, like)
	}
	if cat != "" {
		where += ` AND p.name IN (SELECT name FROM registry_package_categories WHERE category = ?)`
		args = append(args, cat)
	}
	from := ` FROM registry_packages p LEFT JOIN registry_authors a ON a.handle = p.owner`
	var total int
	_ = s.db.Row(ctx, `SELECT COUNT(*)`+from+where, args...).Scan(&total)
	score := `(CASE WHEN LOWER(p.name) = ? OR LOWER(p.name) LIKE ? ESCAPE '\' THEN 100 ELSE 0 END
		+ CASE WHEN LOWER(p.name) LIKE ? ESCAPE '\' THEN 40 ELSE 0 END
		+ CASE WHEN LOWER(p.tags) LIKE ? ESCAPE '\' THEN 20 ELSE 0 END
		+ CASE WHEN LOWER(p.description) LIKE ? ESCAPE '\' THEN 10 ELSE 0 END) AS score`
	sargs := []any{q, "%/" + esc, like, `%"` + esc + `"%`, like}
	rows, err := s.db.Query(ctx, `SELECT `+pkgColumns+`, `+score+from+where+` ORDER BY `+order+` LIMIT ? OFFSET ?`,
		append(append(sargs, args...), limit, offset)...)
	if err != nil {
		writeErr(w, 500, "could not search")
		return
	}
	defer rows.Close()
	out := []Package{}
	for rows.Next() {
		var sc int
		if p, err := scanPackage(rows, &sc); err == nil {
			out = append(out, p)
		}
	}
	rows.Close()
	for i := range out {
		out[i].Latest = latest(s.versionsOf(ctx, out[i].Name))
		out[i].Categories = s.categoriesOf(ctx, out[i].Name)
	}
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	writeJSON(w, 200, out)
}

func (s *Server) listCategories(w http.ResponseWriter, r *http.Request) {
	counts := map[string]int{}
	rows, err := s.db.Query(r.Context(), `SELECT c.category, COUNT(*) FROM registry_package_categories c
		JOIN registry_packages p ON p.name = c.name WHERE p.delisted = 0 GROUP BY c.category`)
	if err == nil {
		for rows.Next() {
			var id string
			var n int
			if rows.Scan(&id, &n) == nil {
				counts[id] = n
			}
		}
		rows.Close()
	}
	out := make([]Category, len(categories))
	for i, c := range categories {
		c.Count = counts[c.ID]
		out[i] = c
	}
	writeJSON(w, 200, out)
}

// Screenshot is one image on a listing.
type Screenshot struct {
	ID      string `json:"id"`
	Caption string `json:"caption,omitempty"`
}

func (s *Server) getPackage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	var readme, shots string
	p, err := scanPackage(s.db.Row(ctx, `SELECT `+pkgColumns+`, p.readme, p.screenshots FROM registry_packages p
		LEFT JOIN registry_authors a ON a.handle = p.owner WHERE p.name = ?`, name), &readme, &shots)
	if err != nil {
		writeErr(w, 404, "no such package")
		return
	}
	vs := s.versionsOf(ctx, name)
	p.Latest = latest(vs)
	p.Categories = s.categoriesOf(ctx, name)
	var key, acr, banReason string
	var verified, banned int
	_ = s.db.Row(ctx, `SELECT public_key, created_at, verified, banned, ban_reason FROM registry_authors WHERE handle = ?`, p.Owner).
		Scan(&key, &acr, &verified, &banned, &banReason)
	if vs == nil {
		vs = []PackageVersion{}
	}
	sc := []Screenshot{}
	_ = json.Unmarshal([]byte(shots), &sc)
	author := map[string]any{"handle": p.Owner, "verified": verified == 1, "banned": banned == 1, "createdAt": parseTS(acr)}
	if banned == 1 {
		author["banReason"] = banReason
	}
	writeJSON(w, 200, map[string]any{"package": p, "authorKey": key, "versions": vs, "readme": readme, "screenshots": sc, "author": author})
}

// --- listings and media ---------------------------------------------------------

// ownPackage checks the caller may edit a package's listing: its author,
// with scope registry:publish, not banned.
func (s *Server) ownPackage(w http.ResponseWriter, r *http.Request) (string, bool) {
	c := callerOf(r)
	if !c.can("registry:publish") || c.DeviceID != "" {
		writeErr(w, 403, "missing scope registry:publish")
		return "", false
	}
	ctx := r.Context()
	name := r.PathValue("name")
	var handle, owner string
	_ = s.db.Row(ctx, `SELECT handle FROM registry_authors WHERE account_id = ?`, c.Account.ID).Scan(&handle)
	_ = s.db.Row(ctx, `SELECT owner FROM registry_packages WHERE name = ?`, name).Scan(&owner)
	if owner == "" || owner != handle {
		writeErr(w, 404, "no such package of yours")
		return "", false
	}
	if s.authorBanned(ctx, handle) {
		writeErr(w, 403, "this author handle is banned from publishing on this hub")
		return "", false
	}
	return name, true
}

func httpsURL(u string) bool {
	return u == "" || (strings.HasPrefix(u, "https://") && len(u) <= 300 && !strings.ContainsAny(u, " \t\r\n\"'<>"))
}

func (s *Server) putListing(w http.ResponseWriter, r *http.Request) {
	name, ok := s.ownPackage(w, r)
	if !ok {
		return
	}
	var req struct {
		Description *string  `json:"description"`
		Readme      *string  `json:"readme"`
		Categories  []string `json:"categories"`
		Tags        []string `json:"tags"`
		Homepage    *string  `json:"homepage"`
		Source      *string  `json:"source"`
		License     *string  `json:"license"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ctx := r.Context()
	set, args := []string{}, []any{}
	if req.Description != nil {
		d := strings.TrimSpace(*req.Description)
		if utf8.RuneCountInString(d) > 300 {
			writeErr(w, 400, "the description is at most 300 characters")
			return
		}
		set, args = append(set, "description = ?"), append(args, d)
	}
	if req.Readme != nil {
		if len(*req.Readme) > maxReadme || !utf8.ValidString(*req.Readme) {
			writeErr(w, 400, "the readme is UTF-8 Markdown of at most 64 KiB")
			return
		}
		set, args = append(set, "readme = ?"), append(args, *req.Readme)
	}
	for _, f := range []struct {
		v   *string
		col string
	}{{req.Homepage, "homepage"}, {req.Source, "source_url"}} {
		if f.v == nil {
			continue
		}
		if !httpsURL(*f.v) {
			writeErr(w, 400, f.col+" must be an https:// URL")
			return
		}
		set, args = append(set, f.col+" = ?"), append(args, *f.v)
	}
	if req.License != nil {
		if *req.License != "" && !licenseRe.MatchString(*req.License) {
			writeErr(w, 400, "license is an SPDX identifier or expression, like MIT or Apache-2.0")
			return
		}
		set, args = append(set, "license = ?"), append(args, *req.License)
	}
	if req.Tags != nil {
		if len(req.Tags) > maxTags {
			writeErr(w, 400, "at most 8 tags")
			return
		}
		seen := map[string]bool{}
		tags := []string{}
		for _, t := range req.Tags {
			t = strings.ToLower(strings.TrimSpace(t))
			if !tagRe.MatchString(t) {
				writeErr(w, 400, "tags are up to 24 lowercase letters, digits and dashes")
				return
			}
			if !seen[t] {
				seen[t] = true
				tags = append(tags, t)
			}
		}
		b, _ := json.Marshal(tags)
		set, args = append(set, "tags = ?"), append(args, string(b))
	}
	if req.Categories != nil {
		if len(req.Categories) > maxCategories {
			writeErr(w, 400, "at most 3 categories")
			return
		}
		for _, c := range req.Categories {
			if !knownCategory(c) {
				writeErr(w, 400, "unknown category "+c+" (see GET /v1/registry/categories)")
				return
			}
		}
		_, _ = s.db.Exec(ctx, `DELETE FROM registry_package_categories WHERE name = ?`, name)
		for _, c := range req.Categories {
			_, _ = s.db.Exec(ctx, `INSERT INTO registry_package_categories (name, category) VALUES (?, ?) ON CONFLICT DO NOTHING`, name, c)
		}
	}
	if len(set) > 0 {
		if _, err := s.db.Exec(ctx, `UPDATE registry_packages SET `+strings.Join(set, ", ")+` WHERE name = ?`, append(args, name)...); err != nil {
			writeErr(w, 500, "could not save the listing")
			return
		}
	}
	s.getPackage(w, r)
}

// imageType sniffs PNG and WebP, the only image formats the marketplace
// takes (SVG can carry scripts).
func imageType(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "image/png"
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return "image/webp"
	}
	return ""
}

type imageUpload struct {
	Data    string `json:"data"` // base64
	Caption string `json:"caption"`
}

func (s *Server) storeImage(w http.ResponseWriter, r *http.Request, name string, max int) (string, string, bool) {
	var req imageUpload
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil || len(raw) == 0 {
		writeErr(w, 400, "data must be a base64 image")
		return "", "", false
	}
	if len(raw) > max {
		writeErr(w, 413, "the image is too large (at most "+strconv.Itoa(max>>10)+" KiB)")
		return "", "", false
	}
	ct := imageType(raw)
	if ct == "" {
		writeErr(w, 415, "images must be PNG or WebP")
		return "", "", false
	}
	sum := sha256.Sum256(append([]byte(name+"\x00"), raw...))
	id := hex.EncodeToString(sum[:16])
	if _, err := s.db.Exec(r.Context(), `INSERT INTO registry_media (id, name, content_type, data, created_at) VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING`,
		id, name, ct, base64.StdEncoding.EncodeToString(raw), ts(s.now())); err != nil {
		writeErr(w, 500, "could not store the image")
		return "", "", false
	}
	return id, strings.TrimSpace(req.Caption), true
}

// dropUnusedMedia deletes a package's images no longer on its listing.
func (s *Server) dropUnusedMedia(ctx context.Context, name string) {
	var icon, shots string
	_ = s.db.Row(ctx, `SELECT icon, screenshots FROM registry_packages WHERE name = ?`, name).Scan(&icon, &shots)
	keep := map[string]bool{icon: true}
	var sc []Screenshot
	_ = json.Unmarshal([]byte(shots), &sc)
	for _, x := range sc {
		keep[x.ID] = true
	}
	rows, err := s.db.Query(ctx, `SELECT id FROM registry_media WHERE name = ?`, name)
	if err != nil {
		return
	}
	var drop []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil && !keep[id] {
			drop = append(drop, id)
		}
	}
	rows.Close()
	for _, id := range drop {
		_, _ = s.db.Exec(ctx, `DELETE FROM registry_media WHERE id = ?`, id)
	}
}

func (s *Server) putIcon(w http.ResponseWriter, r *http.Request) {
	name, ok := s.ownPackage(w, r)
	if !ok {
		return
	}
	id, _, ok := s.storeImage(w, r, name, maxIcon)
	if !ok {
		return
	}
	_, _ = s.db.Exec(r.Context(), `UPDATE registry_packages SET icon = ? WHERE name = ?`, id, name)
	s.dropUnusedMedia(r.Context(), name)
	writeJSON(w, 200, map[string]string{"icon": id})
}

func (s *Server) deleteIcon(w http.ResponseWriter, r *http.Request) {
	name, ok := s.ownPackage(w, r)
	if !ok {
		return
	}
	_, _ = s.db.Exec(r.Context(), `UPDATE registry_packages SET icon = '' WHERE name = ?`, name)
	s.dropUnusedMedia(r.Context(), name)
	w.WriteHeader(204)
}

func (s *Server) screenshotsOf(ctx context.Context, name string) []Screenshot {
	var shots string
	_ = s.db.Row(ctx, `SELECT screenshots FROM registry_packages WHERE name = ?`, name).Scan(&shots)
	sc := []Screenshot{}
	_ = json.Unmarshal([]byte(shots), &sc)
	return sc
}

func (s *Server) addScreenshot(w http.ResponseWriter, r *http.Request) {
	name, ok := s.ownPackage(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	sc := s.screenshotsOf(ctx, name)
	if len(sc) >= maxScreenshots {
		writeErr(w, 409, "a listing has at most 6 screenshots; delete one first")
		return
	}
	id, caption, ok := s.storeImage(w, r, name, maxScreenshot)
	if !ok {
		return
	}
	if utf8.RuneCountInString(caption) > 140 {
		caption = string([]rune(caption)[:140])
	}
	for _, x := range sc {
		if x.ID == id {
			writeJSON(w, 200, sc)
			return
		}
	}
	sc = append(sc, Screenshot{ID: id, Caption: caption})
	b, _ := json.Marshal(sc)
	_, _ = s.db.Exec(ctx, `UPDATE registry_packages SET screenshots = ? WHERE name = ?`, string(b), name)
	writeJSON(w, 201, sc)
}

func (s *Server) deleteScreenshot(w http.ResponseWriter, r *http.Request) {
	name, ok := s.ownPackage(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	sc := s.screenshotsOf(ctx, name)
	out := []Screenshot{}
	for _, x := range sc {
		if x.ID != r.PathValue("id") {
			out = append(out, x)
		}
	}
	if len(out) == len(sc) {
		writeErr(w, 404, "no such screenshot")
		return
	}
	b, _ := json.Marshal(out)
	_, _ = s.db.Exec(ctx, `UPDATE registry_packages SET screenshots = ? WHERE name = ?`, string(b), name)
	s.dropUnusedMedia(ctx, name)
	w.WriteHeader(204)
}

// getMedia serves an icon or screenshot. The type is sniffed again and the
// response can't run anything, whatever the bytes are.
func (s *Server) getMedia(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var data string
	if !mediaIDRe.MatchString(id) || s.db.Row(r.Context(), `SELECT data FROM registry_media WHERE id = ?`, id).Scan(&data) != nil {
		writeErr(w, 404, "no such image")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	ct := imageType(raw)
	if err != nil || ct == "" {
		writeErr(w, 404, "no such image")
		return
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("Content-Length", strconv.Itoa(len(raw)))
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}

// --- install counts -------------------------------------------------------------

// installPing counts an anonymous install, uninstall or "still installed"
// heartbeat. daemon is an opaque id the daemon derives per package, so the
// hub can't link one daemon's packages; each kind counts once per daemon per
// package per day.
func (s *Server) installPing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Event   string `json:"event"`
		Daemon  string `json:"daemon"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Event != "install" && req.Event != "uninstall" && req.Event != "heartbeat" {
		writeErr(w, 400, "event is install, uninstall or heartbeat")
		return
	}
	if !daemonRe.MatchString(req.Daemon) || (req.Version != "" && !semverRe.MatchString(req.Version)) {
		writeErr(w, 400, "daemon is an opaque id of 16 to 128 letters, digits, - and _; version is semantic")
		return
	}
	ctx := r.Context()
	var n int
	if s.db.Row(ctx, `SELECT COUNT(*) FROM registry_packages WHERE name = ?`, req.Name).Scan(&n) != nil || n == 0 {
		writeErr(w, 404, "no such package")
		return
	}
	now := s.now().UTC()
	day := now.Format("2006-01-02")
	daemon := hash(req.Name + "\x00" + req.Daemon)
	res, err := s.db.Exec(ctx, `INSERT INTO registry_install_pings (name, daemon, day, event) VALUES (?,?,?,?) ON CONFLICT DO NOTHING`, req.Name, daemon, day, req.Event)
	if err != nil {
		writeErr(w, 500, "could not count it")
		return
	}
	first, _ := res.RowsAffected()
	if req.Event == "install" && first > 0 {
		_, _ = s.db.Exec(ctx, `UPDATE registry_packages SET downloads = downloads + 1 WHERE name = ?`, req.Name)
	}
	if req.Event == "uninstall" {
		_, _ = s.db.Exec(ctx, `DELETE FROM registry_active_installs WHERE name = ? AND daemon = ?`, req.Name, daemon)
	} else {
		_, _ = s.db.Exec(ctx, `INSERT INTO registry_active_installs (name, daemon, version, updated_at) VALUES (?,?,?,?)
			ON CONFLICT (name, daemon) DO UPDATE SET version = excluded.version, updated_at = excluded.updated_at`, req.Name, daemon, req.Version, day)
	}
	// Daemons send a heartbeat at least weekly; ones silent for 45 days
	// don't count as installs any more.
	since := now.AddDate(0, 0, -45).Format("2006-01-02")
	_, _ = s.db.Exec(ctx, `UPDATE registry_packages SET installs = (SELECT COUNT(*) FROM registry_active_installs WHERE name = ? AND updated_at >= ?) WHERE name = ?`, req.Name, since, req.Name)
	if rand.IntN(50) == 0 {
		_, _ = s.db.Exec(ctx, `DELETE FROM registry_install_pings WHERE day < ?`, now.AddDate(0, 0, -2).Format("2006-01-02"))
	}
	writeJSON(w, 202, map[string]bool{"counted": first > 0})
}

// --- advisories -----------------------------------------------------------------

// Advisory tells a daemon whether an installed version is still fine.
type Advisory struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Status: ok, yanked (this version), delisted (the whole package), or
	// missing (not on this hub).
	Status string `json:"status"`
	By     string `json:"by,omitempty"`     // author or operator
	Reason string `json:"reason,omitempty"` // malware, broken, spam, impersonation, license, other
	Note   string `json:"note,omitempty"`
	Latest string `json:"latest,omitempty"`
}

func (s *Server) advisoryFor(ctx context.Context, name, version string) Advisory {
	a := Advisory{Name: name, Version: version, Status: "ok"}
	var del int
	var reason, note string
	if s.db.Row(ctx, `SELECT delisted, delist_reason, delist_note FROM registry_packages WHERE name = ?`, name).Scan(&del, &reason, &note) != nil {
		a.Status = "missing"
		return a
	}
	vs := s.versionsOf(ctx, name)
	a.Latest = latest(vs)
	for _, v := range vs {
		if v.Version == version && v.Yanked {
			a.Status, a.By, a.Reason, a.Note = "yanked", v.YankedBy, v.Reason, v.Note
		}
	}
	// An operator's yank for malware says more than a delisting.
	if del == 1 && !(a.Status == "yanked" && a.By == "operator") {
		a.Status, a.By, a.Reason, a.Note = "delisted", "operator", reason, note
	}
	return a
}

func (s *Server) advisories(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Modules []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"modules"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(req.Modules) > 200 {
		writeErr(w, 400, "at most 200 modules at a time")
		return
	}
	out := []Advisory{}
	for _, m := range req.Modules {
		if pkgNameRe.MatchString(m.Name) {
			out = append(out, s.advisoryFor(r.Context(), m.Name, m.Version))
		}
	}
	writeJSON(w, 200, out)
}

// --- ratings and reviews -----------------------------------------------------------

// Review is one account's rating of a package, with the author's reply.
type Review struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"` // the account's display name; may be empty
	Rating    int       `json:"rating"`
	Body      string    `json:"body"`
	Version   string    `json:"version,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Reply     string    `json:"reply,omitempty"`
	ReplyAt   string    `json:"replyAt,omitempty"`
}

// reviewer checks the caller may rate, review and report: a confirmed
// account, as a person, a paired daemon acting for it, or an API key with
// registry:review.
func (s *Server) reviewer(w http.ResponseWriter, r *http.Request, limiter interface{ Add(string) bool }) (caller, bool) {
	c := callerOf(r)
	if !c.can("registry:review") {
		writeErr(w, 403, "missing scope registry:review")
		return c, false
	}
	if !c.Account.Verified {
		writeErr(w, 403, "confirm your email address first")
		return c, false
	}
	if limiter != nil && !limiter.Add(c.Account.ID) {
		w.Header().Set("Retry-After", "3600")
		writeErr(w, 429, "that's a lot at once; try again later")
		return c, false
	}
	return c, true
}

func (s *Server) recountRatings(ctx context.Context, name string) {
	_, _ = s.db.Exec(ctx, `UPDATE registry_packages SET rating_count = (SELECT COUNT(*) FROM registry_reviews WHERE name = ?),
		rating_sum = (SELECT COALESCE(SUM(rating), 0) FROM registry_reviews WHERE name = ?) WHERE name = ?`, name, name, name)
}

func (s *Server) recountAllRatings(ctx context.Context) {
	_, _ = s.db.Exec(ctx, `UPDATE registry_packages SET
		rating_count = (SELECT COUNT(*) FROM registry_reviews r WHERE r.name = registry_packages.name),
		rating_sum = (SELECT COALESCE(SUM(r.rating), 0) FROM registry_reviews r WHERE r.name = registry_packages.name)`)
}

const reviewColumns = `r.id, COALESCE(a.name, ''), r.rating, r.body, r.version, r.created_at, r.updated_at, r.reply, r.reply_at`

func scanReview(sc scanner) (Review, error) {
	var v Review
	var cr, up string
	err := sc.Scan(&v.ID, &v.Author, &v.Rating, &v.Body, &v.Version, &cr, &up, &v.Reply, &v.ReplyAt)
	v.CreatedAt, v.UpdatedAt = parseTS(cr), parseTS(up)
	return v, err
}

func (s *Server) listReviews(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	var n int
	if s.db.Row(ctx, `SELECT COUNT(*) FROM registry_packages WHERE name = ?`, name).Scan(&n) != nil || n == 0 {
		writeErr(w, 404, "no such package")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	hist := []int{0, 0, 0, 0, 0}
	total, sum := 0, 0
	if rows, err := s.db.Query(ctx, `SELECT rating, COUNT(*) FROM registry_reviews WHERE name = ? GROUP BY rating`, name); err == nil {
		for rows.Next() {
			var rt, c int
			if rows.Scan(&rt, &c) == nil && rt >= 1 && rt <= 5 {
				hist[rt-1] = c
				total += c
				sum += rt * c
			}
		}
		rows.Close()
	}
	avg := 0.0
	if total > 0 {
		avg = float64(int(float64(sum)/float64(total)*10+0.5)) / 10
	}
	items := []Review{}
	rows, err := s.db.Query(ctx, `SELECT `+reviewColumns+` FROM registry_reviews r LEFT JOIN accounts a ON a.id = r.account_id
		WHERE r.name = ? ORDER BY CASE WHEN r.body = '' THEN 1 ELSE 0 END, r.updated_at DESC LIMIT ? OFFSET ?`, name, limit, offset)
	if err == nil {
		for rows.Next() {
			if v, err := scanReview(rows); err == nil {
				items = append(items, v)
			}
		}
		rows.Close()
	}
	writeJSON(w, 200, map[string]any{"average": avg, "count": total, "histogram": hist, "items": items})
}

func (s *Server) myReview(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !c.can("registry:review") {
		writeErr(w, 403, "missing scope registry:review")
		return
	}
	v, err := scanReview(s.db.Row(r.Context(), `SELECT `+reviewColumns+` FROM registry_reviews r LEFT JOIN accounts a ON a.id = r.account_id
		WHERE r.name = ? AND r.account_id = ?`, r.PathValue("name"), c.Account.ID))
	if err != nil {
		writeErr(w, 404, "you haven't rated this package")
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) putReview(w http.ResponseWriter, r *http.Request) {
	c, ok := s.reviewer(w, r, s.reviewWrites)
	if !ok {
		return
	}
	var req struct {
		Rating  int    `json:"rating"`
		Body    string `json:"body"`
		Version string `json:"version"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Body = strings.TrimSpace(req.Body)
	if req.Rating < 1 || req.Rating > 5 {
		writeErr(w, 400, "rating is 1 to 5")
		return
	}
	if utf8.RuneCountInString(req.Body) > maxReviewBody || !utf8.ValidString(req.Body) {
		writeErr(w, 400, "a review is at most 2000 characters")
		return
	}
	if req.Version != "" && !semverRe.MatchString(req.Version) {
		writeErr(w, 400, "version is semantic")
		return
	}
	ctx := r.Context()
	name := r.PathValue("name")
	var owner string
	var del int
	if s.db.Row(ctx, `SELECT owner, delisted FROM registry_packages WHERE name = ?`, name).Scan(&owner, &del) != nil {
		writeErr(w, 404, "no such package")
		return
	}
	if del == 1 {
		writeErr(w, 409, "this package was removed from the marketplace")
		return
	}
	var authorAcct string
	_ = s.db.Row(ctx, `SELECT account_id FROM registry_authors WHERE handle = ?`, owner).Scan(&authorAcct)
	if authorAcct == c.Account.ID {
		writeErr(w, 403, "authors can't rate their own packages; reply to reviews instead")
		return
	}
	now := ts(s.now())
	res, err := s.db.Exec(ctx, `UPDATE registry_reviews SET rating = ?, body = ?, version = ?, updated_at = ? WHERE name = ? AND account_id = ?`,
		req.Rating, req.Body, req.Version, now, name, c.Account.ID)
	code := 200
	if err != nil {
		writeErr(w, 500, "could not save the review")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		code = 201
		_, err = s.db.Exec(ctx, `INSERT INTO registry_reviews (id, name, account_id, rating, body, version, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)`,
			newID("rev"), name, c.Account.ID, req.Rating, req.Body, req.Version, now, now)
	}
	if err != nil {
		writeErr(w, 500, "could not save the review")
		return
	}
	s.recountRatings(ctx, name)
	v, _ := scanReview(s.db.Row(ctx, `SELECT `+reviewColumns+` FROM registry_reviews r LEFT JOIN accounts a ON a.id = r.account_id
		WHERE r.name = ? AND r.account_id = ?`, name, c.Account.ID))
	writeJSON(w, code, v)
}

func (s *Server) deleteReview(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !c.can("registry:review") {
		writeErr(w, 403, "missing scope registry:review")
		return
	}
	name := r.PathValue("name")
	res, _ := s.db.Exec(r.Context(), `DELETE FROM registry_reviews WHERE name = ? AND account_id = ?`, name, c.Account.ID)
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 404, "you haven't rated this package")
		return
	}
	s.recountRatings(r.Context(), name)
	w.WriteHeader(204)
}

// replyReview lets a package's author answer a review (an empty body
// removes the reply).
func (s *Server) replyReview(w http.ResponseWriter, r *http.Request) {
	name, ok := s.ownPackage(w, r)
	if !ok {
		return
	}
	c := callerOf(r)
	if !s.reviewWrites.Add(c.Account.ID) {
		writeErr(w, 429, "that's a lot at once; try again later")
		return
	}
	var req struct {
		Body string `json:"body"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Body = strings.TrimSpace(req.Body)
	if utf8.RuneCountInString(req.Body) > maxReviewBody {
		writeErr(w, 400, "a reply is at most 2000 characters")
		return
	}
	at := ""
	if req.Body != "" {
		at = ts(s.now())
	}
	res, _ := s.db.Exec(r.Context(), `UPDATE registry_reviews SET reply = ?, reply_at = ? WHERE name = ? AND id = ?`, req.Body, at, name, r.PathValue("id"))
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 404, "no such review")
		return
	}
	v, _ := scanReview(s.db.Row(r.Context(), `SELECT `+reviewColumns+` FROM registry_reviews r LEFT JOIN accounts a ON a.id = r.account_id
		WHERE r.id = ?`, r.PathValue("id")))
	writeJSON(w, 200, v)
}

// --- reports --------------------------------------------------------------------

func (s *Server) reportPackage(w http.ResponseWriter, r *http.Request) {
	c, ok := s.reviewer(w, r, s.reportWrites)
	if !ok {
		return
	}
	var req struct {
		Version string `json:"version"`
		Reason  string `json:"reason"`
		Details string `json:"details"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Details = strings.TrimSpace(req.Details)
	if !reportReasons[req.Reason] {
		writeErr(w, 400, "reason is one of malware, broken, spam, impersonation, license, other")
		return
	}
	if utf8.RuneCountInString(req.Details) > maxReportBody {
		writeErr(w, 400, "details are at most 2000 characters")
		return
	}
	if req.Reason == "other" && req.Details == "" {
		writeErr(w, 400, "say what's wrong in the details")
		return
	}
	ctx := r.Context()
	name := r.PathValue("name")
	var n int
	if s.db.Row(ctx, `SELECT COUNT(*) FROM registry_packages WHERE name = ?`, name).Scan(&n) != nil || n == 0 {
		writeErr(w, 404, "no such package")
		return
	}
	if req.Version != "" {
		if s.db.Row(ctx, `SELECT COUNT(*) FROM registry_versions WHERE name = ? AND version = ?`, name, req.Version).Scan(&n) != nil || n == 0 {
			writeErr(w, 404, "no such version")
			return
		}
	}
	if s.db.Row(ctx, `SELECT COUNT(*) FROM registry_reports WHERE name = ? AND account_id = ? AND status = 'open'`, name, c.Account.ID).Scan(&n) == nil && n > 0 {
		writeErr(w, 409, "you already reported this package; the hub's operators are looking at it")
		return
	}
	id := newID("rep")
	if _, err := s.db.Exec(ctx, `INSERT INTO registry_reports (id, name, version, account_id, reason, details, created_at) VALUES (?,?,?,?,?,?,?)`,
		id, name, req.Version, c.Account.ID, req.Reason, req.Details, ts(s.now())); err != nil {
		writeErr(w, 409, "you already reported this package; the hub's operators are looking at it")
		return
	}
	s.log.Warn("registry: package reported", "package", name, "version", req.Version, "reason", req.Reason)
	if req.Reason == "malware" {
		go s.tellAdmins("Malware report: "+name, "Someone reported "+name+" "+req.Version+" as malware on "+s.cfg.Name+".\n\n"+req.Details+
			"\n\nReview it in the operator console: "+s.cfg.PublicURL+"/account/admin/")
	}
	writeJSON(w, 201, map[string]string{"id": id, "status": "open"})
}

func (s *Server) tellAdmins(subject, body string) {
	rows, err := s.db.Query(context.Background(), `SELECT email FROM accounts WHERE is_admin = 1 AND disabled = 0`)
	if err != nil {
		return
	}
	var to []string
	for rows.Next() {
		var e string
		if rows.Scan(&e) == nil {
			to = append(to, e)
		}
	}
	rows.Close()
	for _, e := range to {
		s.tell(e, subject, body)
	}
}

// --- moderation (operator console) ------------------------------------------------

// AdminReport is a report as operators see it.
type AdminReport struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Version     string    `json:"version,omitempty"`
	Reason      string    `json:"reason"`
	Details     string    `json:"details"`
	Status      string    `json:"status"` // open, dismissed, actioned
	Action      string    `json:"action,omitempty"`
	Note        string    `json:"note,omitempty"`
	Reporter    string    `json:"reporter"` // email, or empty when the account is gone
	ResolvedBy  string    `json:"resolvedBy,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	ResolvedAt  string    `json:"resolvedAt,omitempty"`
	Owner       string    `json:"owner"`
	Delisted    bool      `json:"delisted"`
	AuthorState string    `json:"authorState"` // ok, verified, banned
	OpenReports int       `json:"openReports"` // open reports about the same package
}

func (s *Server) adminReports(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminOnly(w, r); !ok {
		return
	}
	ctx := r.Context()
	status := r.URL.Query().Get("status")
	where, args := "", []any{}
	switch status {
	case "", "open":
		where = ` WHERE rp.status = 'open'`
	case "resolved":
		where = ` WHERE rp.status != 'open'`
	case "all":
	default:
		writeErr(w, 400, "status is open, resolved or all")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	var total int
	_ = s.db.Row(ctx, `SELECT COUNT(*) FROM registry_reports rp`+where, args...).Scan(&total)
	rows, err := s.db.Query(ctx, `SELECT rp.id, rp.name, rp.version, rp.reason, rp.details, rp.status, rp.action, rp.note,
		COALESCE(a.email, ''), rp.resolved_by, rp.created_at, rp.resolved_at, COALESCE(p.owner, ''), COALESCE(p.delisted, 0),
		COALESCE(au.verified, 0), COALESCE(au.banned, 0),
		(SELECT COUNT(*) FROM registry_reports o WHERE o.name = rp.name AND o.status = 'open')
		FROM registry_reports rp LEFT JOIN accounts a ON a.id = rp.account_id
		LEFT JOIN registry_packages p ON p.name = rp.name LEFT JOIN registry_authors au ON au.handle = p.owner`+where+`
		ORDER BY CASE WHEN rp.reason = 'malware' AND rp.status = 'open' THEN 0 ELSE 1 END, rp.created_at DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		writeErr(w, 500, "could not list reports")
		return
	}
	defer rows.Close()
	out := []AdminReport{}
	for rows.Next() {
		var x AdminReport
		var cr string
		var del, ver, ban int
		if rows.Scan(&x.ID, &x.Name, &x.Version, &x.Reason, &x.Details, &x.Status, &x.Action, &x.Note, &x.Reporter, &x.ResolvedBy,
			&cr, &x.ResolvedAt, &x.Owner, &del, &ver, &ban, &x.OpenReports) != nil {
			continue
		}
		x.CreatedAt, x.Delisted = parseTS(cr), del == 1
		x.AuthorState = "ok"
		if ver == 1 {
			x.AuthorState = "verified"
		}
		if ban == 1 {
			x.AuthorState = "banned"
		}
		out = append(out, x)
	}
	writeJSON(w, 200, map[string]any{"total": total, "items": out})
}

type moderation struct {
	Reason string `json:"reason"`
	Note   string `json:"note"`
}

func readModeration(w http.ResponseWriter, r *http.Request, def string) (moderation, bool) {
	var m moderation
	if err := readJSON(r, &m); err != nil {
		writeErr(w, 400, err.Error())
		return m, false
	}
	if m.Reason == "" {
		m.Reason = def
	}
	m.Note = strings.TrimSpace(m.Note)
	if !reportReasons[m.Reason] {
		writeErr(w, 400, "reason is one of malware, broken, spam, impersonation, license, other")
		return m, false
	}
	if utf8.RuneCountInString(m.Note) > maxNote {
		writeErr(w, 400, "the note is at most 500 characters")
		return m, false
	}
	return m, true
}

// closeReports marks open reports about a package as handled.
func (s *Server) closeReports(ctx context.Context, name, status, action, note, by string) {
	_, _ = s.db.Exec(ctx, `UPDATE registry_reports SET status = ?, action = ?, note = ?, resolved_by = ?, resolved_at = ? WHERE name = ? AND status = 'open'`,
		status, action, note, by, ts(s.now()), name)
}

// tellAuthor emails the account behind a handle, if it still exists.
func (s *Server) tellAuthor(ctx context.Context, handle, subject, body string) {
	var email string
	if s.db.Row(ctx, `SELECT a.email FROM registry_authors ra JOIN accounts a ON a.id = ra.account_id WHERE ra.handle = ?`, handle).Scan(&email) == nil {
		go s.tell(email, subject, body)
	}
}

func (s *Server) delist(ctx context.Context, name string, m moderation) (string, bool) {
	var owner string
	if s.db.Row(ctx, `SELECT owner FROM registry_packages WHERE name = ?`, name).Scan(&owner) != nil {
		return "", false
	}
	_, _ = s.db.Exec(ctx, `UPDATE registry_packages SET delisted = 1, delist_reason = ?, delist_note = ?, delisted_at = ? WHERE name = ?`, m.Reason, m.Note, ts(s.now()), name)
	return owner, true
}

func (s *Server) yankByOperator(ctx context.Context, name, version string, m moderation) bool {
	res, _ := s.db.Exec(ctx, `UPDATE registry_versions SET yanked = 1, yanked_by = 'operator', yank_reason = ?, yank_note = ?, yanked_at = ? WHERE name = ? AND version = ?`,
		m.Reason, m.Note, ts(s.now()), name, version)
	n, _ := res.RowsAffected()
	return n > 0
}

// ban stops an author publishing and delists all their packages. The
// handle and key stay, so nobody can register the handle and daemons that
// pinned the key keep refusing anyone else's builds.
func (s *Server) ban(ctx context.Context, handle string, m moderation, by string) bool {
	res, _ := s.db.Exec(ctx, `UPDATE registry_authors SET banned = 1, ban_reason = ?, banned_at = ?, verified = 0 WHERE handle = ?`, m.Reason, ts(s.now()), handle)
	if n, _ := res.RowsAffected(); n == 0 {
		return false
	}
	note := m.Note
	if note == "" {
		note = "The author was banned from this hub."
	}
	var names []string
	if rows, err := s.db.Query(ctx, `SELECT name FROM registry_packages WHERE owner = ?`, handle); err == nil {
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				names = append(names, n)
			}
		}
		rows.Close()
	}
	for _, n := range names {
		_, _ = s.delist(ctx, n, moderation{Reason: m.Reason, Note: note})
		s.closeReports(ctx, n, "actioned", "ban", m.Note, by)
	}
	return true
}

func (s *Server) adminResolveReport(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var rep struct{ name, version, reason, status string }
	if s.db.Row(ctx, `SELECT name, version, reason, status FROM registry_reports WHERE id = ?`, r.PathValue("id")).
		Scan(&rep.name, &rep.version, &rep.reason, &rep.status) != nil {
		writeErr(w, 404, "no such report")
		return
	}
	if rep.status != "open" {
		writeErr(w, 409, "this report is already resolved")
		return
	}
	var req struct {
		Action  string `json:"action"` // dismiss, yank, delist, ban
		Reason  string `json:"reason"`
		Note    string `json:"note"`
		Version string `json:"version"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Reason == "" {
		req.Reason = rep.reason
	}
	m := moderation{Reason: req.Reason, Note: strings.TrimSpace(req.Note)}
	if !reportReasons[m.Reason] || utf8.RuneCountInString(m.Note) > maxNote {
		writeErr(w, 400, "reason is one of malware, broken, spam, impersonation, license, other; the note is at most 500 characters")
		return
	}
	by := c.Account.Email
	id := r.PathValue("id")
	var owner string
	_ = s.db.Row(ctx, `SELECT owner FROM registry_packages WHERE name = ?`, rep.name).Scan(&owner)
	switch req.Action {
	case "dismiss":
		_, _ = s.db.Exec(ctx, `UPDATE registry_reports SET status = 'dismissed', action = 'dismiss', note = ?, resolved_by = ?, resolved_at = ? WHERE id = ?`,
			m.Note, by, ts(s.now()), id)
	case "yank":
		v := req.Version
		if v == "" {
			v = rep.version
		}
		if v == "" || !s.yankByOperator(ctx, rep.name, v, m) {
			writeErr(w, 400, "say which version to yank")
			return
		}
		_, _ = s.db.Exec(ctx, `UPDATE registry_reports SET status = 'actioned', action = 'yank', note = ?, resolved_by = ?, resolved_at = ? WHERE id = ?`,
			m.Note, by, ts(s.now()), id)
		s.tellAuthor(ctx, owner, "A version of "+rep.name+" was yanked", "An operator of "+s.cfg.Name+" yanked "+rep.name+" "+v+" ("+m.Reason+"). "+m.Note+
			"\n\nDaemons that have it are told to remove it. Publish a fixed version, or contact the hub's operator if you think this is a mistake.")
		s.log.Warn("admin: version yanked", "package", rep.name, "version", v, "reason", m.Reason, "by", by)
	case "delist":
		if _, ok := s.delist(ctx, rep.name, m); !ok {
			writeErr(w, 404, "the package is gone")
			return
		}
		s.closeReports(ctx, rep.name, "actioned", "delist", m.Note, by)
		s.tellAuthor(ctx, owner, rep.name+" was removed from the marketplace", "An operator of "+s.cfg.Name+" removed "+rep.name+" from the marketplace ("+m.Reason+"). "+m.Note+
			"\n\nIt no longer shows in search, and daemons that have it are told. Contact the hub's operator if you think this is a mistake.")
		s.log.Warn("admin: package delisted", "package", rep.name, "reason", m.Reason, "by", by)
	case "ban":
		if owner == "" || !s.ban(ctx, owner, m, by) {
			writeErr(w, 404, "the author is gone")
			return
		}
		_, _ = s.db.Exec(ctx, `UPDATE registry_reports SET status = 'actioned', action = 'ban', note = ?, resolved_by = ?, resolved_at = ? WHERE id = ?`,
			m.Note, by, ts(s.now()), id)
		s.tellAuthor(ctx, owner, "Your author handle "+owner+" was banned", "An operator of "+s.cfg.Name+" banned the author handle "+owner+" ("+m.Reason+"). "+m.Note+
			"\n\nIts packages were removed from the marketplace and it can't publish any more.")
		s.log.Warn("admin: author banned", "handle", owner, "reason", m.Reason, "by", by)
	default:
		writeErr(w, 400, "action is dismiss, yank, delist or ban")
		return
	}
	writeJSON(w, 200, map[string]string{"id": id, "action": req.Action})
}

func (s *Server) adminDelist(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	m, ok := readModeration(w, r, "other")
	if !ok {
		return
	}
	name := r.PathValue("name")
	owner, ok := s.delist(r.Context(), name, m)
	if !ok {
		writeErr(w, 404, "no such package")
		return
	}
	s.closeReports(r.Context(), name, "actioned", "delist", m.Note, c.Account.Email)
	s.tellAuthor(r.Context(), owner, name+" was removed from the marketplace", "An operator of "+s.cfg.Name+" removed "+name+" from the marketplace ("+m.Reason+"). "+m.Note)
	s.log.Warn("admin: package delisted", "package", name, "reason", m.Reason, "by", c.Account.Email)
	w.WriteHeader(204)
}

func (s *Server) adminRelist(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	res, _ := s.db.Exec(r.Context(), `UPDATE registry_packages SET delisted = 0, delist_reason = '', delist_note = '', delisted_at = '' WHERE name = ?`, name)
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 404, "no such package")
		return
	}
	s.log.Info("admin: package listed again", "package", name, "by", c.Account.Email)
	w.WriteHeader(204)
}

func (s *Server) adminYank(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	m, ok := readModeration(w, r, "other")
	if !ok {
		return
	}
	name, v := r.PathValue("name"), r.PathValue("version")
	if !s.yankByOperator(r.Context(), name, v, m) {
		writeErr(w, 404, "no such version")
		return
	}
	var owner string
	_ = s.db.Row(r.Context(), `SELECT owner FROM registry_packages WHERE name = ?`, name).Scan(&owner)
	s.tellAuthor(r.Context(), owner, "A version of "+name+" was yanked", "An operator of "+s.cfg.Name+" yanked "+name+" "+v+" ("+m.Reason+"). "+m.Note)
	s.log.Warn("admin: version yanked", "package", name, "version", v, "reason", m.Reason, "by", c.Account.Email)
	w.WriteHeader(204)
}

func (s *Server) adminUnyank(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	name, v := r.PathValue("name"), r.PathValue("version")
	res, _ := s.db.Exec(r.Context(), `UPDATE registry_versions SET yanked = 0, yanked_by = '', yank_reason = '', yank_note = '', yanked_at = ''
		WHERE name = ? AND version = ? AND yanked_by = 'operator'`, name, v)
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 404, "no version yanked by an operator by that name")
		return
	}
	s.log.Info("admin: version restored", "package", name, "version", v, "by", c.Account.Email)
	w.WriteHeader(204)
}

func (s *Server) adminBan(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	m, ok := readModeration(w, r, "other")
	if !ok {
		return
	}
	h := r.PathValue("handle")
	if !s.ban(r.Context(), h, m, c.Account.Email) {
		writeErr(w, 404, "no such author")
		return
	}
	s.tellAuthor(r.Context(), h, "Your author handle "+h+" was banned", "An operator of "+s.cfg.Name+" banned the author handle "+h+" ("+m.Reason+"). "+m.Note+
		"\n\nIts packages were removed from the marketplace and it can't publish any more.")
	s.log.Warn("admin: author banned", "handle", h, "reason", m.Reason, "by", c.Account.Email)
	w.WriteHeader(204)
}

// adminUnban lets an author publish again. Their packages stay delisted
// until an operator lists each one again.
func (s *Server) adminUnban(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	h := r.PathValue("handle")
	res, _ := s.db.Exec(r.Context(), `UPDATE registry_authors SET banned = 0, ban_reason = '', banned_at = '' WHERE handle = ?`, h)
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 404, "no such author")
		return
	}
	s.log.Info("admin: author unbanned", "handle", h, "by", c.Account.Email)
	w.WriteHeader(204)
}

func (s *Server) adminVerify(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	var req struct {
		Verified bool `json:"verified"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	h := r.PathValue("handle")
	if req.Verified && s.authorBanned(r.Context(), h) {
		writeErr(w, 409, "a banned author can't be verified")
		return
	}
	res, _ := s.db.Exec(r.Context(), `UPDATE registry_authors SET verified = ? WHERE handle = ?`, b2i(req.Verified), h)
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 404, "no such author")
		return
	}
	s.log.Info("admin: author verification", "handle", h, "verified", req.Verified, "by", c.Account.Email)
	writeJSON(w, 200, map[string]any{"handle": h, "verified": req.Verified})
}
