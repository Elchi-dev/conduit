package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/internal/ai"
	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/automation"
	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/internal/remote"
	"github.com/elchi-dev/conduit/internal/vault"
)

// Server is the daemon's HTTP API.
type Server struct {
	Engine *core.Engine
	Auth   *auth.Service
	Vault  *vault.Vault
	// Automations may be nil in tests that don't use them.
	Automations *automation.Service
	Providers   *ai.Providers
	Assistant   *ai.Agent
	Bridge      *ai.Bridge
	// Remote may be nil in tests that don't use remote access.
	Remote *remote.Service
	Log    *slog.Logger
	// SetupToken must be presented to create the owner account. It is printed
	// to the log and written to <data>/setup-token on first start.
	SetupToken string
	// UI serves the web app; nil in tests.
	UI http.Handler
}

// Principal is the authenticated caller of a request.
type Principal struct {
	Actor   core.Actor
	User    auth.User
	Session *auth.Session
	Key     *auth.Key
	Scopes  []string
}

type ctxKey struct{}

func principal(r *http.Request) (Principal, bool) {
	p, ok := r.Context().Value(ctxKey{}).(Principal)
	return p, ok
}

// SessionCookie is the name of the browser session cookie.
const SessionCookie = "conduit_session"

func roleScopes(r auth.Role) []string {
	switch r {
	case auth.RoleOwner, auth.RoleAdmin:
		return []string{"admin:*:*"}
	case auth.RoleMember:
		return []string{"actions:*:invoke", "modules:*:read", "audit:*:read", "audit:*:undo", "approvals:*:read", "approvals:*:decide", "events:*:read", "policy:*:read"}
	default:
		return []string{"modules:*:read", "audit:*:read", "approvals:*:read", "events:*:read", "policy:*:read"}
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func bearer(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if c, err := r.Cookie(SessionCookie); err == nil {
		return c.Value
	}
	return ""
}

// authenticate resolves the caller. It never rejects; handlers decide.
func (s *Server) authenticate(r *http.Request) (Principal, error) {
	tok := bearer(r)
	if tok == "" {
		return Principal{}, auth.ErrUnauthenticated
	}
	ctx := r.Context()
	if strings.HasPrefix(tok, auth.SessionPrefix) {
		u, se, err := s.Auth.SessionUser(ctx, tok)
		if err != nil {
			return Principal{}, err
		}
		return Principal{Actor: core.Actor{ID: u.ID, Kind: core.ActorUser, Name: u.Name}, User: u, Session: &se, Scopes: roleScopes(u.Role)}, nil
	}
	if strings.HasPrefix(tok, auth.KeyPrefix) {
		k, err := s.Auth.LookupKey(ctx, tok, clientIP(r))
		if err != nil {
			return Principal{}, err
		}
		u, err := s.Auth.GetUser(ctx, k.OwnerID)
		if err != nil || u.Disabled {
			return Principal{}, auth.ErrUnauthenticated
		}
		kind := core.ActorKey
		if k.Kind == auth.KeyAgent {
			kind = core.ActorAgent
		}
		// A key can never exceed its owner's role.
		scopes := intersect(k.Scopes, roleScopes(u.Role))
		return Principal{Actor: core.Actor{ID: k.ID, Kind: kind, Name: k.Name}, User: u, Key: &k, Scopes: scopes}, nil
	}
	return Principal{}, auth.ErrUnauthenticated
}

func intersect(keyScopes, roleScopes []string) []string {
	var out []string
	for _, k := range keyScopes {
		if auth.Allows(roleScopes, k) {
			out = append(out, k)
		}
	}
	return out
}

// statusRecorder captures the response code for key usage logging.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (w *statusRecorder) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }
func (w *statusRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// need wraps a handler with authentication and a scope check. Scope targets
// containing "{module}" are filled from the request path.
func (s *Server) need(scope string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r)
		if err != nil {
			var ke *auth.KeyError
			if errors.As(err, &ke) {
				code := http.StatusUnauthorized
				if ke.Reason == "rate limit exceeded" {
					code = http.StatusTooManyRequests
					w.Header().Set("Retry-After", "10")
				}
				writeErr(w, code, ke.Reason)
				return
			}
			writeErr(w, http.StatusUnauthorized, "sign in or present an API key")
			return
		}
		if scope != "" && !auth.Allows(p.Scopes, scope) {
			writeErr(w, http.StatusForbidden, "missing scope "+scope)
			return
		}
		// Mutations from browsers must be JSON, which a cross-site form cannot
		// send without a CORS preflight; together with SameSite=Strict cookies
		// this blocks CSRF.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && p.Session != nil && r.ContentLength != 0 &&
			!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeErr(w, http.StatusUnsupportedMediaType, "send JSON")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, p)
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		h(rec, r.WithContext(ctx))
		if p.Key != nil {
			s.Auth.RecordUsage(context.WithoutCancel(r.Context()), p.Key.ID, auth.Usage{At: time.Now().UTC(), Method: r.Method, Path: r.URL.Path, Status: rec.code, IP: clientIP(r)})
		}
	}
}

type apiError struct {
	Error string `json:"error"`
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, apiError{Error: msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	if r.ContentLength == 0 {
		return nil
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body: " + err.Error())
	}
	return nil
}

// engineErr maps engine errors to HTTP responses.
func engineErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, core.ErrNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, core.ErrForbidden), errors.Is(err, core.ErrDenied):
		writeErr(w, http.StatusForbidden, err.Error())
	default:
		writeErr(w, http.StatusBadRequest, err.Error())
	}
}
