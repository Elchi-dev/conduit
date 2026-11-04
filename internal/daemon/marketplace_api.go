package daemon

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// The marketplace side of installing from a hub (docs/protocol/marketplace.md):
// listings, ratings and reviews, reports, anonymous install counts, and the
// periodic check that warns when an installed version was yanked or its
// package removed from the marketplace. Rating, reviewing and reporting use
// this daemon's hub device token, so they count for the account it's paired
// to; only people can do them.

const (
	regAdvisorySetting = "registry.advisories"
	regPingSetting     = "registry.ping_secret"
	// regPingsSetting = "off" stops the anonymous install counts.
	regPingsSetting = "registry.pings"
)

var regMediaRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// regAdvisory is the hub's word on an installed version.
type regAdvisory struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Status  string `json:"status"` // ok, yanked, delisted, missing
	By      string `json:"by,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Note    string `json:"note,omitempty"`
	Latest  string `json:"latest,omitempty"`
}

type regAdvisories struct {
	CheckedAt  time.Time              `json:"checkedAt"`
	Modules    map[string]regAdvisory `json:"modules"`
	Heartbeats map[string]string      `json:"heartbeats"` // name -> day of the last heartbeat
}

// reasonText is the English for a moderation reason.
func reasonText(code string) string {
	switch code {
	case "malware":
		return "malware"
	case "broken":
		return "broken"
	case "spam":
		return "spam"
	case "impersonation":
		return "impersonation"
	case "license":
		return "license problem"
	case "":
		return "no reason given"
	}
	return "other"
}

func listingOf(pkg regPackage) map[string]any {
	p := pkg.Package
	shots := []map[string]string{}
	for _, s := range pkg.Screenshots {
		if regMediaRe.MatchString(s.ID) {
			shots = append(shots, map[string]string{"id": s.ID, "caption": s.Caption})
		}
	}
	icon := ""
	if regMediaRe.MatchString(p.Icon) {
		icon = p.Icon
	}
	return map[string]any{"owner": p.Owner, "readme": pkg.Readme, "screenshots": shots, "categories": nonNilStrings(p.Categories),
		"tags": nonNilStrings(p.Tags), "rating": p.Rating, "ratingCount": p.RatingCount, "installs": p.Installs, "downloads": p.Downloads,
		"verified": p.Verified && !pkg.Author.Banned, "license": p.License, "source": httpsOnly(p.Source), "icon": icon}
}

func httpsOnly(u string) string {
	if strings.HasPrefix(u, "https://") {
		return u
	}
	return ""
}

// registryHub is the registry and, when it's the hub this daemon is paired
// with, the device token to act for the account.
func (s *Server) registryHub(ctx context.Context) (string, string, error) {
	base, err := s.registryBase(ctx)
	if err != nil {
		return "", "", err
	}
	tok := ""
	if s.Remote != nil {
		if hub, t := s.Remote.HubCredentials(); strings.TrimRight(hub, "/") == base {
			tok = t
		}
	}
	return base, tok, nil
}

// hubCall sends a JSON request to the registry and answers the status and
// body (at most 1 MiB).
func hubCall(ctx context.Context, method, rawURL, tok string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := regHTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, b, err
}

// passOn answers the hub's response: JSON successes as they are, errors with
// the hub's message.
func passOn(w http.ResponseWriter, code int, b []byte, err error) {
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if code == http.StatusNoContent {
		w.WriteHeader(code)
		return
	}
	if code >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("the hub answered %d", code)
		}
		if code >= 500 {
			code = http.StatusBadGateway
		}
		writeErr(w, code, e.Error)
		return
	}
	if !json.Valid(b) {
		writeErr(w, http.StatusBadGateway, "the hub sent something that isn't JSON")
		return
	}
	writeJSON(w, code, json.RawMessage(b))
}

func pkgPath(name string) string { return "/v1/registry/packages/" + url.PathEscape(name) }

func (s *Server) registryCategories(w http.ResponseWriter, r *http.Request) {
	base, err := s.registryBase(r.Context())
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	code, b, err := hubCall(r.Context(), http.MethodGet, base+"/v1/registry/categories", "", nil)
	passOn(w, code, b, err)
}

// registryMedia passes an icon or screenshot through, only if it really is
// PNG or WebP, so the page never loads anything from the hub directly.
func (s *Server) registryMedia(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !regMediaRe.MatchString(id) {
		writeErr(w, http.StatusNotFound, "no such image")
		return
	}
	base, err := s.registryBase(r.Context())
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	b, err := regGet(r.Context(), base+"/v1/registry/media/"+id, 1<<20, nil)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	var ct string
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		ct = "image/png"
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		ct = "image/webp"
	default:
		writeErr(w, http.StatusBadGateway, "the hub sent something that isn't a PNG or WebP image")
		return
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cache-Control", "private, max-age=86400")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (s *Server) registryReviews(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.URL.Query().Get("name")
	if !regNameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "module names look like author/module")
		return
	}
	base, tok, err := s.registryHub(ctx)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	q := url.Values{}
	for _, k := range []string{"limit", "offset"} {
		if v := r.URL.Query().Get(k); v != "" {
			q.Set(k, v)
		}
	}
	code, b, err := hubCall(ctx, http.MethodGet, base+pkgPath(name)+"/reviews?"+q.Encode(), "", nil)
	if err != nil || code != http.StatusOK {
		passOn(w, code, b, err)
		return
	}
	var out map[string]any
	if json.Unmarshal(b, &out) != nil {
		writeErr(w, http.StatusBadGateway, "the hub sent something that isn't JSON")
		return
	}
	out["canReview"] = tok != ""
	out["mine"] = nil
	if tok != "" {
		if c, mb, err := hubCall(ctx, http.MethodGet, base+pkgPath(name)+"/reviews/mine", tok, nil); err == nil && c == http.StatusOK {
			var mine map[string]any
			if json.Unmarshal(mb, &mine) == nil {
				out["mine"] = mine
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

var errNotPaired = errors.New("pair this daemon with an account on its hub (Settings, Remote access) to rate, review and report modules")

// reviewHub is registryHub for actions that need the account.
func (s *Server) reviewHub(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	if !s.humanOnly(w, r) {
		return "", "", false
	}
	base, tok, err := s.registryHub(r.Context())
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return "", "", false
	}
	if tok == "" {
		writeErr(w, http.StatusConflict, errNotPaired.Error())
		return "", "", false
	}
	return base, tok, true
}

func (s *Server) registryRate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Rating  int    `json:"rating"`
		Body    string `json:"body"`
		Version string `json:"version"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !regNameRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "module names look like author/module")
		return
	}
	base, tok, ok := s.reviewHub(w, r)
	if !ok {
		return
	}
	code, b, err := hubCall(r.Context(), http.MethodPut, base+pkgPath(req.Name)+"/reviews/mine", tok,
		map[string]any{"rating": req.Rating, "body": req.Body, "version": req.Version})
	if err == nil && code < 300 {
		s.auditConfig(r, "module_rated", "", map[string]any{"name": req.Name, "rating": req.Rating})
	}
	passOn(w, code, b, err)
}

func (s *Server) registryUnrate(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if !regNameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "module names look like author/module")
		return
	}
	base, tok, ok := s.reviewHub(w, r)
	if !ok {
		return
	}
	code, b, err := hubCall(r.Context(), http.MethodDelete, base+pkgPath(name)+"/reviews/mine", tok, nil)
	if err == nil && code < 300 {
		s.auditConfig(r, "module_unrated", "", map[string]any{"name": name})
	}
	passOn(w, code, b, err)
}

func (s *Server) registryReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Reason  string `json:"reason"`
		Details string `json:"details"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !regNameRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "module names look like author/module")
		return
	}
	base, tok, ok := s.reviewHub(w, r)
	if !ok {
		return
	}
	code, b, err := hubCall(r.Context(), http.MethodPost, base+pkgPath(req.Name)+"/reports", tok,
		map[string]string{"version": req.Version, "reason": req.Reason, "details": req.Details})
	if err == nil && code < 300 {
		s.auditConfig(r, "module_reported", "", map[string]string{"name": req.Name, "version": req.Version, "reason": req.Reason})
	}
	passOn(w, code, b, err)
}

// --- install counts -------------------------------------------------------------

// pingID is this daemon's opaque id for one package: an HMAC of the name
// under a random secret, so the hub can count installs per daemon without
// linking one daemon's packages together.
func (s *Server) pingID(ctx context.Context, name string) string {
	var secret string
	_ = s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, regPingSetting).Scan(&secret)
	if secret == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		secret = base64.RawURLEncoding.EncodeToString(b)
		_, _ = s.DB.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`, regPingSetting, secret)
		_ = s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, regPingSetting).Scan(&secret)
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(name))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// installPing tells the registry, anonymously and in the background, that a
// package was installed, removed or is still installed.
func (s *Server) installPing(name, version, event string) {
	ctx := context.Background()
	var off string
	_ = s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, regPingsSetting).Scan(&off)
	if off == "off" {
		return
	}
	base, err := s.registryBase(ctx)
	if err != nil {
		return
	}
	id := s.pingID(ctx, name)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _, _ = hubCall(ctx, http.MethodPost, base+"/v1/registry/installs", "", map[string]string{"name": name, "version": version, "event": event, "daemon": id})
	}()
}

// --- advisories -----------------------------------------------------------------

func (s *Server) storedAdvisories(ctx context.Context) regAdvisories {
	var a regAdvisories
	var raw string
	if s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, regAdvisorySetting).Scan(&raw) == nil {
		_ = json.Unmarshal([]byte(raw), &a)
	}
	if a.Modules == nil {
		a.Modules = map[string]regAdvisory{}
	}
	if a.Heartbeats == nil {
		a.Heartbeats = map[string]string{}
	}
	return a
}

func (s *Server) saveAdvisories(ctx context.Context, a regAdvisories) {
	b, _ := json.Marshal(a)
	_, _ = s.DB.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, regAdvisorySetting, string(b))
}

func (s *Server) forgetAdvisory(ctx context.Context, name string) {
	a := s.storedAdvisories(ctx)
	delete(a.Modules, name)
	delete(a.Heartbeats, name)
	s.saveAdvisories(ctx, a)
}

// checkAdvisories asks the registry about every installed module, keeps
// the answers for the installed list, raises a registry.advisory event (and
// so a notification) for each newly yanked or delisted one, and sends the
// weekly still-installed heartbeats.
func (s *Server) checkAdvisories(ctx context.Context) error {
	installed := s.installedModules(ctx)
	prev := s.storedAdvisories(ctx)
	if len(installed) == 0 {
		return nil
	}
	base, err := s.registryBase(ctx)
	if err != nil {
		return err
	}
	mods := []map[string]string{}
	for _, m := range installed {
		mods = append(mods, map[string]string{"name": m.Name, "version": m.Version})
	}
	code, b, err := hubCall(ctx, http.MethodPost, base+"/v1/registry/advisories", "", map[string]any{"modules": mods})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("the registry answered %d", code)
	}
	var got []regAdvisory
	if err := json.Unmarshal(b, &got); err != nil {
		return err
	}
	next := regAdvisories{CheckedAt: time.Now().UTC(), Modules: map[string]regAdvisory{}, Heartbeats: prev.Heartbeats}
	for _, a := range got {
		next.Modules[a.Name] = a
		if a.Status != "yanked" && a.Status != "delisted" {
			continue
		}
		if old, ok := prev.Modules[a.Name]; ok && old.Status == a.Status && old.Version == a.Version && old.Reason == a.Reason {
			continue
		}
		data, _ := json.Marshal(a)
		s.Engine.Bus.Publish(sdk.Event{Type: "registry.advisory", Module: "core", Data: data})
		s.Log.Warn("an installed module was flagged by its registry", "name", a.Name, "version", a.Version, "status", a.Status, "reason", a.Reason)
	}
	today := time.Now().UTC().Format("2006-01-02")
	weekAgo := time.Now().UTC().AddDate(0, 0, -7).Format("2006-01-02")
	for _, m := range installed {
		if last := next.Heartbeats[m.Name]; last == "" || last <= weekAgo {
			s.installPing(m.Name, m.Version, "heartbeat")
			next.Heartbeats[m.Name] = today
		}
	}
	s.saveAdvisories(ctx, next)
	return nil
}

// runRegistryChecks checks installed modules a few minutes after start and
// every six hours.
func runRegistryChecks(ctx context.Context, s *Server) {
	wait := time.After(3 * time.Minute)
	tick := time.NewTicker(6 * time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-wait:
		case <-tick.C:
		}
		if err := s.checkAdvisories(ctx); err != nil && s.Log != nil {
			s.Log.Debug("registry check", "err", err)
		}
	}
}
