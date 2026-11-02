package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/internal/vault"
	"github.com/elchi-dev/conduit/internal/version"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Handler returns the full HTTP surface of the daemon. Every route here is
// listed in api/openapi/daemon.yaml; a test enforces it.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	routes := s.routes()
	if s.Automations != nil {
		routes = append(routes, s.automationRoutes()...)
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pattern, rt.h)
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusNotFound, "no such endpoint")
	})
	if s.UI != nil {
		mux.Handle("/", s.UI)
	}
	return securityHeaders(mux)
}

type route struct {
	pattern string
	h       http.HandlerFunc
}

func (s *Server) routes() []route {
	return []route{
		{"GET /healthz", s.healthz},
		{"GET /api/v1/version", s.version},

		// Setup and sessions
		{"GET /api/v1/setup", s.setupStatus},
		{"POST /api/v1/setup", s.setup},
		{"POST /api/v1/auth/login", s.login},
		{"POST /api/v1/auth/logout", s.need("", s.logout)},
		{"GET /api/v1/me", s.need("", s.me)},
		{"POST /api/v1/me/password", s.need("", s.changePassword)},
		{"GET /api/v1/me/sessions", s.need("", s.listSessions)},
		{"DELETE /api/v1/me/sessions/{id}", s.need("", s.revokeSession)},
		{"GET /api/v1/users", s.need("admin:*:*", s.listUsers)},
		{"POST /api/v1/users", s.need("admin:*:*", s.createUser)},

		// Modules and instances
		{"GET /api/v1/modules", s.need("modules:*:read", s.listModules)},
		{"GET /api/v1/modules/{id}", s.need("modules:*:read", s.getModule)},
		{"GET /api/v1/instances", s.need("modules:*:read", s.listInstances)},
		{"POST /api/v1/instances", s.need("instances:*:manage", s.saveInstance)},
		{"GET /api/v1/instances/{id}", s.need("modules:*:read", s.getInstance)},
		{"PUT /api/v1/instances/{id}", s.need("instances:*:manage", s.saveInstance)},
		{"DELETE /api/v1/instances/{id}", s.need("instances:*:manage", s.deleteInstance)},
		{"GET /api/v1/instances/{id}/health", s.need("modules:*:read", s.instanceHealth)},
		{"POST /api/v1/instances/{id}/actions/{action}", s.need("", s.invoke)},

		// Audit, timeline and undo
		{"GET /api/v1/audit", s.need("audit:*:read", s.listAudit)},
		{"GET /api/v1/audit/verify", s.need("audit:*:read", s.verifyAudit)},
		{"GET /api/v1/audit/{seq}", s.need("audit:*:read", s.getAudit)},
		{"POST /api/v1/audit/{seq}/undo", s.need("audit:*:undo", s.undo)},

		// Approvals
		{"GET /api/v1/approvals", s.need("approvals:*:read", s.listApprovals)},
		{"GET /api/v1/approvals/{id}", s.need("approvals:*:read", s.getApproval)},
		{"POST /api/v1/approvals/{id}/approve", s.need("approvals:*:decide", s.decide(true))},
		{"POST /api/v1/approvals/{id}/deny", s.need("approvals:*:decide", s.decide(false))},

		// Policy
		{"GET /api/v1/policy", s.need("policy:*:read", s.getPolicy)},
		{"PUT /api/v1/policy/preset", s.need("policy:*:manage", s.setPreset)},
		{"POST /api/v1/policy/rules", s.need("policy:*:manage", s.putRule)},
		{"DELETE /api/v1/policy/rules/{id}", s.need("policy:*:manage", s.deleteRule)},

		// Panic
		{"GET /api/v1/panic", s.need("", s.panicStatus)},
		{"POST /api/v1/panic", s.need("", s.panic)},
		{"DELETE /api/v1/panic", s.need("admin:*:*", s.unpanic)},

		// Vault
		{"GET /api/v1/vault", s.need("modules:*:read", s.vaultStatus)},
		{"POST /api/v1/vault/setup", s.need("admin:*:*", s.vaultSetup)},
		{"POST /api/v1/vault/unlock", s.need("admin:*:*", s.vaultUnlock)},
		{"POST /api/v1/vault/lock", s.need("", s.vaultLock)},

		// API keys
		{"GET /api/v1/keys", s.need("keys:*:manage", s.listKeys)},
		{"POST /api/v1/keys", s.need("keys:*:manage", s.createKey)},
		{"GET /api/v1/keys/{id}", s.need("keys:*:manage", s.getKey)},
		{"POST /api/v1/keys/{id}/rotate", s.need("keys:*:manage", s.rotateKey)},
		{"DELETE /api/v1/keys/{id}", s.need("keys:*:manage", s.revokeKey)},
		{"GET /api/v1/keys/{id}/usage", s.need("keys:*:manage", s.keyUsage)},

		// Live events (server-sent events)
		{"GET /api/v1/events", s.need("events:*:read", s.events)},
	}
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, version.Get())
}

// --- setup and sessions ---------------------------------------------------

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.Auth.UserCount(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needsSetup": n == 0})
}

type setupReq struct {
	Token    string `json:"token"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Device   string `json:"device"`
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var req setupReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.SetupToken == "" || !constantEq(req.Token, s.SetupToken) {
		writeErr(w, http.StatusForbidden, "invalid setup token (see the daemon log or <data>/setup-token)")
		return
	}
	u, err := s.Auth.Setup(r.Context(), req.Name, req.Email, req.Password)
	if errors.Is(err, auth.ErrSetupDone) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.startSession(w, r, u, req.Device, http.StatusCreated)
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Device   string `json:"device"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.Auth.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, auth.ErrInvalidCredentials.Error())
		return
	}
	s.startSession(w, r, u, req.Device, http.StatusOK)
}

type sessionResp struct {
	User    auth.User    `json:"user"`
	Session auth.Session `json:"session"`
	// Token is for native clients that cannot use cookies. Browsers get an
	// HttpOnly cookie as well and should ignore it.
	Token string `json:"token"`
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u auth.User, device string, code int) {
	if device == "" {
		device = r.UserAgent()
	}
	se, tok, err := s.Auth.CreateSession(r.Context(), u.ID, device)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil, Expires: se.ExpiresAt})
	writeJSON(w, code, sessionResp{User: u, Session: se, Token: tok})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	if p.Session != nil {
		_ = s.Auth.RevokeSession(r.Context(), p.User.ID, p.Session.ID)
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

type meResp struct {
	User   auth.User  `json:"user"`
	Actor  core.Actor `json:"actor"`
	Scopes []string   `json:"scopes"`
	Key    *auth.Key  `json:"key,omitempty"`
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	writeJSON(w, http.StatusOK, meResp{User: p.User, Actor: p.Actor, Scopes: p.Scopes, Key: p.Key})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	if p.Session == nil {
		writeErr(w, http.StatusForbidden, "passwords can only be changed from a signed-in session")
		return
	}
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Auth.ChangePassword(r.Context(), p.User.ID, req.Current, req.New, p.Session.ID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	list, err := s.Auth.ListSessions(r.Context(), p.User.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nonNil(list))
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	if err := s.Auth.RevokeSession(r.Context(), p.User.ID, r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	list, err := s.Auth.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nonNil(list))
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string    `json:"name"`
		Email    string    `json:"email"`
		Password string    `json:"password"`
		Role     auth.Role `json:"role"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Role == auth.RoleOwner {
		writeErr(w, http.StatusBadRequest, "there is exactly one owner")
		return
	}
	u, err := s.Auth.CreateUser(r.Context(), req.Name, req.Email, req.Password, req.Role)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

// --- modules and instances --------------------------------------------------

func (s *Server) listModules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, nonNil(s.Engine.Modules()))
}

func (s *Server) getModule(w http.ResponseWriter, r *http.Request) {
	m, ok := s.Engine.Module(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such module")
		return
	}
	writeJSON(w, http.StatusOK, m.Manifest())
}

type instanceView struct {
	core.Instance
	Health *sdk.Health `json:"health,omitempty"`
}

func (s *Server) listInstances(w http.ResponseWriter, r *http.Request) {
	list := s.Engine.Instances(r.URL.Query().Get("module"))
	out := make([]instanceView, 0, len(list))
	for _, in := range list {
		out = append(out, instanceView{Instance: in})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getInstance(w http.ResponseWriter, r *http.Request) {
	in, ok := s.Engine.Instance(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such instance")
		return
	}
	h := s.Engine.Health(r.Context(), in.ID)
	writeJSON(w, http.StatusOK, instanceView{Instance: in, Health: &h})
}

func (s *Server) saveInstance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Module  string          `json:"module"`
		Name    string          `json:"name"`
		Config  json.RawMessage `json:"config"`
		Enabled *bool           `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	in := core.Instance{Module: req.Module, Name: req.Name, Config: req.Config, Enabled: true}
	code := http.StatusCreated
	if id := r.PathValue("id"); id != "" {
		old, ok := s.Engine.Instance(id)
		if !ok {
			writeErr(w, http.StatusNotFound, "no such instance")
			return
		}
		in.ID, in.Module, in.Enabled, code = id, old.Module, old.Enabled, http.StatusOK
		if in.Name == "" {
			in.Name = old.Name
		}
		if len(in.Config) == 0 {
			in.Config = old.Config
		}
	}
	if req.Enabled != nil {
		in.Enabled = *req.Enabled
	}
	saved, err := s.Engine.SaveInstance(r.Context(), in)
	if err != nil {
		engineErr(w, err)
		return
	}
	writeJSON(w, code, saved)
}

func (s *Server) deleteInstance(w http.ResponseWriter, r *http.Request) {
	if err := s.Engine.DeleteInstance(r.Context(), r.PathValue("id")); err != nil {
		engineErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) instanceHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Engine.Health(r.Context(), r.PathValue("id")))
}

type invokeReq struct {
	Input  json.RawMessage `json:"input"`
	DryRun bool            `json:"dryRun"`
	// Wait blocks until a required approval is decided (default true for
	// people and false for programs, which poll the approval instead).
	Wait *bool `json:"wait"`
}

func (s *Server) invoke(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	in, ok := s.Engine.Instance(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such instance")
		return
	}
	if !auth.Allows(p.Scopes, "actions:"+in.Module+":invoke") {
		writeErr(w, http.StatusForbidden, "missing scope actions:"+in.Module+":invoke")
		return
	}
	var req invokeReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	wait := p.Actor.Kind == core.ActorUser
	if req.Wait != nil {
		wait = *req.Wait
	}
	out, err := s.Engine.Invoke(r.Context(), p.Actor, sdk.Call{Instance: in.ID, Action: r.PathValue("action"), Input: req.Input, DryRun: req.DryRun}, core.InvokeOptions{NoWait: !wait})
	if errors.Is(err, core.ErrPending) {
		writeJSON(w, http.StatusAccepted, out)
		return
	}
	if err != nil {
		if out.Audit.Seq > 0 && out.Audit.Status == "error" {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "audit": out.Audit})
			return
		}
		engineErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// --- audit -----------------------------------------------------------------

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := core.Query{Module: q.Get("module"), Instance: q.Get("instance"), Actor: q.Get("actor"), Search: q.Get("q")}
	query.Limit, _ = strconv.Atoi(q.Get("limit"))
	query.Before, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	if v := q.Get("since"); v != "" {
		query.Since, _ = time.Parse(time.RFC3339, v)
	}
	if v := q.Get("until"); v != "" {
		query.Until, _ = time.Parse(time.RFC3339, v)
	}
	list, err := s.Engine.Audit.List(r.Context(), query)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nonNil(list))
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	v, err := s.Engine.Audit.Verify(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func seqParam(r *http.Request) (int64, error) {
	n, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid sequence number")
	}
	return n, nil
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	seq, err := seqParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	e, err := s.Engine.Audit.Get(r.Context(), seq)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such entry")
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) undo(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	seq, err := seqParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.Engine.Undo(r.Context(), p.Actor, seq, core.InvokeOptions{NoWait: p.Actor.Kind != core.ActorUser})
	if errors.Is(err, core.ErrPending) {
		writeJSON(w, http.StatusAccepted, out)
		return
	}
	if err != nil {
		engineErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// --- approvals ---------------------------------------------------------------

func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request) {
	list, err := s.Engine.Approvals.List(r.Context(), r.URL.Query().Get("status"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nonNil(list))
}

func (s *Server) getApproval(w http.ResponseWriter, r *http.Request) {
	a, err := s.Engine.Approvals.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such approval")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) decide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := principal(r)
		// Only people decide. Keys never can, even with an admin scope, so a
		// leaked key cannot approve its own (or anyone's) requests.
		if p.Actor.Kind != core.ActorUser {
			writeErr(w, http.StatusForbidden, "approvals can only be decided by a signed-in person")
			return
		}
		if err := s.Engine.Approvals.Decide(r.Context(), r.PathValue("id"), approve, p.Actor.Subject()); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		a, _ := s.Engine.Approvals.Get(r.Context(), r.PathValue("id"))
		writeJSON(w, http.StatusOK, a)
	}
}

// --- policy -------------------------------------------------------------------

type policyResp struct {
	Preset  core.Preset   `json:"preset"`
	Presets []core.Preset `json:"presets"`
	Frozen  bool          `json:"frozen"`
	Rules   []core.Rule   `json:"rules"`
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	preset, err1 := s.Engine.Policy.Preset(ctx)
	frozen, err2 := s.Engine.Policy.Frozen(ctx)
	rules, err3 := s.Engine.Policy.Rules(ctx)
	if err := errors.Join(err1, err2, err3); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, policyResp{Preset: preset, Presets: core.Presets, Frozen: frozen, Rules: nonNil(rules)})
}

func (s *Server) setPreset(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req struct {
		Preset core.Preset `json:"preset"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Engine.Policy.SetPreset(r.Context(), req.Preset); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.getPolicy(w, r)
}

func (s *Server) putRule(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var rule core.Rule
	if err := readJSON(r, &rule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if rule.ID == "" {
		rule.ID = core.NewID("rule")
	}
	if err := s.Engine.Policy.PutRule(r.Context(), rule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	if err := s.Engine.Policy.DeleteRule(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// humanOnly blocks programs from changing who may do what.
func (s *Server) humanOnly(w http.ResponseWriter, r *http.Request) bool {
	p, _ := principal(r)
	if p.Actor.Kind != core.ActorUser {
		writeErr(w, http.StatusForbidden, "only a signed-in person can change policy")
		return false
	}
	return true
}

// --- panic -------------------------------------------------------------------

func (s *Server) panicStatus(w http.ResponseWriter, r *http.Request) {
	frozen, err := s.Engine.Policy.Frozen(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"frozen": frozen})
}

type panicResp struct {
	Frozen           bool  `json:"frozen"`
	DeniedApprovals  int   `json:"deniedApprovals"`
	RevokedAgentKeys int64 `json:"revokedAgentKeys"`
	EndedSessions    int64 `json:"endedSessions"`
}

// panic is the one-tap emergency stop: freeze every agent, key and
// automation, deny everything pending, revoke all agent keys and sign out
// every other session. Anyone signed in (or any key) may pull it.
func (s *Server) panic(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	ctx := r.Context()
	n, err := s.Engine.Panic(ctx, p.Actor)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	keys, _ := s.Auth.RevokeKind(ctx, auth.KeyAgent, "panic mode")
	keep := ""
	if p.Session != nil {
		keep = p.Session.ID
	}
	sessions, _ := s.Auth.RevokeSessions(ctx, "", keep)
	if s.Vault != nil {
		_ = s.Vault.Lock(false)
	}
	s.Log.Warn("PANIC MODE ON", "by", p.Actor.Subject(), "deniedApprovals", n, "revokedAgentKeys", keys, "endedSessions", sessions)
	writeJSON(w, http.StatusOK, panicResp{Frozen: true, DeniedApprovals: n, RevokedAgentKeys: keys, EndedSessions: sessions})
}

func (s *Server) unpanic(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	p, _ := principal(r)
	if err := s.Engine.Unpanic(r.Context(), p.Actor); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"frozen": false})
}

// --- vault -------------------------------------------------------------------

func (s *Server) vaultStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.Vault.Status(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) vaultSetup(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Vault.Setup(r.Context(), req.Passphrase); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditVault(r, "vault_setup")
	s.vaultStatus(w, r)
}

func (s *Server) vaultUnlock(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req struct {
		Passphrase string `json:"passphrase"`
		Remember   bool   `json:"remember"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Vault.Unlock(r.Context(), req.Passphrase, req.Remember); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, vault.ErrBadPassphrase) {
			code = http.StatusUnauthorized
		}
		writeErr(w, code, err.Error())
		return
	}
	s.auditVault(r, "vault_unlock")
	s.vaultStatus(w, r)
}

// vaultLock is open to any authenticated caller: locking only ever reduces
// access, so an agent noticing something wrong may do it.
func (s *Server) vaultLock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Forget bool `json:"forget"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Vault.Lock(req.Forget); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditVault(r, "vault_lock")
	s.vaultStatus(w, r)
}

func (s *Server) auditVault(r *http.Request, action string) {
	p, _ := principal(r)
	_, _ = s.Engine.Audit.Append(context.WithoutCancel(r.Context()), core.Entry{Actor: p.Actor, Module: "vault", Instance: "vault", Action: action, Risk: sdk.RiskWrite, Decision: core.Allow, Status: "ok"})
	s.Engine.Bus.Publish(sdk.Event{Type: "instance.saved", Module: "vault", Instance: "vault"})
}

// --- API keys ------------------------------------------------------------------

type createdKey struct {
	Key auth.Key `json:"key"`
	// Secret is the full key. It is shown exactly once.
	Secret string `json:"secret"`
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	owner := p.User.ID
	if r.URL.Query().Get("all") == "1" && auth.Allows(p.Scopes, "admin:*:*") {
		owner = ""
	}
	list, err := s.Auth.ListKeys(r.Context(), owner)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nonNil(list))
}

func (s *Server) ownKey(w http.ResponseWriter, r *http.Request) (auth.Key, bool) {
	p, _ := principal(r)
	k, err := s.Auth.GetKey(r.Context(), r.PathValue("id"))
	if err != nil || (k.OwnerID != p.User.ID && !auth.Allows(p.Scopes, "admin:*:*")) {
		writeErr(w, http.StatusNotFound, "no such key")
		return k, false
	}
	return k, true
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	p, _ := principal(r)
	var req auth.NewKey
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	k, secret, err := s.Auth.CreateKey(r.Context(), p.User.ID, req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, createdKey{Key: k, Secret: secret})
}

func (s *Server) getKey(w http.ResponseWriter, r *http.Request) {
	if k, ok := s.ownKey(w, r); ok {
		writeJSON(w, http.StatusOK, k)
	}
}

func (s *Server) rotateKey(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	k, ok := s.ownKey(w, r)
	if !ok {
		return
	}
	var req struct {
		GraceSeconds int `json:"graceSeconds"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	grace := 24 * time.Hour
	if req.GraceSeconds > 0 {
		grace = time.Duration(req.GraceSeconds) * time.Second
	}
	nk, secret, err := s.Auth.RotateKey(r.Context(), k.ID, grace)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, createdKey{Key: nk, Secret: secret})
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request) {
	k, ok := s.ownKey(w, r)
	if !ok {
		return
	}
	if err := s.Auth.RevokeKey(r.Context(), k.ID, "revoked by "+mustPrincipal(r).Actor.Subject()); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) keyUsage(w http.ResponseWriter, r *http.Request) {
	k, ok := s.ownKey(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.Auth.KeyUsage(r.Context(), k.ID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nonNil(list))
}

func mustPrincipal(r *http.Request) Principal { p, _ := principal(r); return p }

// --- events -------------------------------------------------------------------

// events streams the event bus as server-sent events. Each message's event
// name is the event type; data is the JSON envelope.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	ch, stop := s.Engine.Bus.Subscribe(r.URL.Query().Get("prefix"), 256)
	defer stop()
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, b)
			fl.Flush()
		}
	}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
