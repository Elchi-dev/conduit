// Package hub implements conduit-hub: accounts, orgs, device pairing, the
// end-to-end encrypted relay, encrypted sync, the module registry, the update
// feed and hub API keys. Anyone can run a hub; daemons work without one.
package hub

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/internal/version"
)

// Config holds hub settings, usually from environment variables (see
// docs/self-hosting).
type Config struct {
	Listen      string
	DatabaseURL string
	// PublicURL is how people reach this hub, used in emails and QR codes.
	PublicURL string
	// Name is shown in emails and the hub's info endpoint.
	Name string
	// OpenRegistration lets anyone create an account; otherwise only the
	// admin email and invited people can.
	OpenRegistration bool
	// AdminEmail becomes an admin when it registers.
	AdminEmail string
	// ReleaseKey is the base64 ed25519 public key that release manifests must
	// be signed with.
	ReleaseKey string
	Mail       MailConfig
	// SiteDir, if set, is served at / (the public website build).
	SiteDir string
}

// DefaultConfig reads CONDUIT_HUB_* environment variables.
func DefaultConfig() Config {
	env := func(k, d string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return d
	}
	return Config{
		Listen:           env("CONDUIT_HUB_LISTEN", ":7700"),
		DatabaseURL:      env("CONDUIT_HUB_DB", "hub.db"),
		PublicURL:        strings.TrimRight(env("CONDUIT_HUB_URL", "http://localhost:7700"), "/"),
		Name:             env("CONDUIT_HUB_NAME", "Conduit hub"),
		OpenRegistration: env("CONDUIT_HUB_OPEN_REGISTRATION", "true") == "true",
		AdminEmail:       strings.ToLower(env("CONDUIT_HUB_ADMIN_EMAIL", "")),
		ReleaseKey:       env("CONDUIT_HUB_RELEASE_KEY", ""),
		SiteDir:          env("CONDUIT_HUB_SITE_DIR", ""),
		Mail: MailConfig{
			Driver:    env("CONDUIT_HUB_MAIL", "console"),
			From:      env("CONDUIT_HUB_MAIL_FROM", ""),
			ResendKey: env("CONDUIT_HUB_RESEND_KEY", ""),
			SMTPHost:  env("CONDUIT_HUB_SMTP_HOST", ""),
			SMTPPort:  atoiDefault(env("CONDUIT_HUB_SMTP_PORT", "587"), 587),
			SMTPUser:  env("CONDUIT_HUB_SMTP_USER", ""),
			SMTPPass:  env("CONDUIT_HUB_SMTP_PASSWORD", ""),
		},
	}
}

// Server is a running hub.
type Server struct {
	cfg   Config
	db    *DB
	mail  Mailer
	log   *slog.Logger
	relay *relayHub
	now   func() time.Time

	limitMu sync.Mutex
	limits  map[string][]time.Time
}

// New opens the database and prepares a hub.
func New(ctx context.Context, cfg Config, log *slog.Logger) (*Server, error) {
	db, err := OpenDB(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	m, err := NewMailer(cfg.Mail, log)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Server{cfg: cfg, db: db, mail: m, log: log, relay: newRelayHub(), now: time.Now, limits: map[string][]time.Time{}}, nil
}

// Close releases the database.
func (s *Server) Close() error { return s.db.Close() }

// Run starts the hub and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	s, err := New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer s.Close()
	srv := &http.Server{Addr: cfg.Listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("conduit-hub listening", "addr", cfg.Listen, "url", cfg.PublicURL, "mail", s.mail.Name(), "version", version.Version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shut); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

type route struct {
	pattern string
	h       http.HandlerFunc
}

// Handler returns the hub's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, r := range s.routes() {
		mux.HandleFunc(r.pattern, r.h)
	}
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, _ *http.Request) { writeErr(w, http.StatusNotFound, "no such endpoint") })
	if s.cfg.SiteDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(s.cfg.SiteDir)))
	}
	return headers(mux)
}

func headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		// The hub API is used cross-origin by the website and by apps.
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			hd.Set("Access-Control-Allow-Origin", "*")
			hd.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-Match")
			hd.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			hd.Set("Access-Control-Expose-Headers", "ETag")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) routes() []route {
	return []route{
		{"GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) }},
		{"GET /v1/version", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, version.Get()) }},
		{"GET /v1/info", s.info},

		{"POST /v1/accounts", s.limited("register", 10, s.register)},
		{"POST /v1/accounts/verify", s.verifyEmail},
		{"POST /v1/accounts/password-reset", s.limited("reset", 5, s.requestReset)},
		{"POST /v1/accounts/password-reset/confirm", s.confirmReset},
		{"POST /v1/sessions", s.limited("login", 20, s.login)},
		{"DELETE /v1/sessions", s.auth(s.logout)},
		{"GET /v1/me", s.auth(s.me)},
		{"POST /v1/me/resend-verification", s.auth(s.resendVerification)},

		{"GET /v1/orgs", s.auth(s.listOrgs)},
		{"POST /v1/orgs", s.auth(s.createOrg)},
		{"GET /v1/orgs/{id}/members", s.auth(s.listMembers)},
		{"POST /v1/orgs/{id}/invites", s.auth(s.invite)},
		{"DELETE /v1/orgs/{id}/members/{account}", s.auth(s.removeMember)},
		{"POST /v1/invites/accept", s.auth(s.acceptInvite)},

		{"POST /v1/pairing-codes", s.auth(s.newPairingCode)},
		{"POST /v1/devices/pair", s.limited("pair", 20, s.pairDevice)},
		{"GET /v1/devices", s.auth(s.listDevices)},
		{"DELETE /v1/devices/{id}", s.auth(s.revokeDevice)},

		{"GET /v1/relay/daemon", s.relayDaemon},
		{"GET /v1/relay/connect/{daemon}", s.relayClient},

		{"GET /v1/sync", s.auth(s.listBlobs)},
		{"GET /v1/sync/{key}", s.auth(s.getBlob)},
		{"PUT /v1/sync/{key}", s.auth(s.putBlob)},
		{"DELETE /v1/sync/{key}", s.auth(s.deleteBlob)},

		{"GET /v1/keys", s.auth(s.listHubKeys)},
		{"POST /v1/keys", s.auth(s.createHubKey)},
		{"DELETE /v1/keys/{id}", s.auth(s.revokeHubKey)},

		{"GET /v1/registry/packages", s.searchPackages},
		{"GET /v1/registry/packages/{name}", s.getPackage},
		{"POST /v1/registry/authors", s.auth(s.registerAuthor)},
		{"GET /v1/registry/authors/{handle}", s.getAuthor},
		{"POST /v1/registry/packages/{name}/versions", s.auth(s.publishVersion)},
		{"POST /v1/registry/packages/{name}/versions/{version}/yank", s.auth(s.yankVersion)},

		{"GET /v1/updates/{component}/{channel}/{platform}", s.latestRelease},
		{"POST /v1/releases", s.auth(s.publishRelease)},
	}
}

func (s *Server) info(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name": s.cfg.Name, "url": s.cfg.PublicURL, "openRegistration": s.cfg.OpenRegistration,
		"mail": s.mail.Name() != "console", "version": version.Version, "relayVersion": 1,
		"releaseKey": s.cfg.ReleaseKey,
	})
}

// --- helpers -----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, v); err != nil {
		return errors.New("invalid JSON: " + err.Error())
	}
	return nil
}

var tokenEnc = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

func token(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return tokenEnc.EncodeToString(b)
}

func newID(prefix string) string { return prefix + "_" + token(10) }

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limited allows each client IP n requests per 10 minutes on an endpoint.
func (s *Server) limited(name string, n int, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := name + "|" + clientIP(r)
		now := s.now()
		s.limitMu.Lock()
		var keep []time.Time
		for _, t := range s.limits[key] {
			if now.Sub(t) < 10*time.Minute {
				keep = append(keep, t)
			}
		}
		if len(keep) >= n {
			s.limits[key] = keep
			s.limitMu.Unlock()
			w.Header().Set("Retry-After", "600")
			writeErr(w, http.StatusTooManyRequests, "too many attempts; try again in a few minutes")
			return
		}
		s.limits[key] = append(keep, now)
		s.limitMu.Unlock()
		h(w, r)
	}
}
