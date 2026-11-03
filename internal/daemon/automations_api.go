package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/internal/automation"
	"github.com/elchi-dev/conduit/internal/core"
)

func (s *Server) automationRoutes() []route {
	return []route{
		{"GET /api/v1/automations", s.need("modules:*:read", s.listAutomations)},
		{"POST /api/v1/automations", s.need("instances:*:manage", s.saveAutomation)},
		{"GET /api/v1/automations/{id}", s.need("modules:*:read", s.getAutomation)},
		{"PUT /api/v1/automations/{id}", s.need("instances:*:manage", s.saveAutomation)},
		{"DELETE /api/v1/automations/{id}", s.need("instances:*:manage", s.deleteAutomation)},
		{"POST /api/v1/automations/{id}/run", s.need("actions:*:invoke", s.runAutomation)},
		{"GET /api/v1/automations/{id}/runs", s.need("modules:*:read", s.automationRuns)},
		{"POST /hooks/{token}", s.hook},
	}
}

func (s *Server) listAutomations(w http.ResponseWriter, r *http.Request) {
	list, err := s.Automations.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if p, _ := principal(r); p.Actor.Kind != core.ActorUser {
		for i := range list {
			list[i].HookURL = "" // webhook addresses are secrets for people
		}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) getAutomation(w http.ResponseWriter, r *http.Request) {
	a, err := s.Automations.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "no such automation")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if p, _ := principal(r); p.Actor.Kind != core.ActorUser {
		a.HookURL = ""
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) saveAutomation(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	var a automation.Automation
	if err := readJSON(r, &a); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	code := http.StatusCreated
	if id := r.PathValue("id"); id != "" {
		if _, err := s.Automations.Get(r.Context(), id); err != nil {
			writeErr(w, http.StatusNotFound, "no such automation")
			return
		}
		a.ID, code = id, http.StatusOK
	} else {
		a.ID = ""
	}
	saved, err := s.Automations.Save(r.Context(), a, p.Actor)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditConfig(r, "automation_saved", saved.ID, map[string]any{"name": saved.Name, "enabled": saved.Enabled, "trusted": saved.Trusted, "steps": len(saved.Steps)})
	writeJSON(w, code, saved)
}

func (s *Server) deleteAutomation(w http.ResponseWriter, r *http.Request) {
	if err := s.Automations.Delete(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, "no such automation")
		return
	}
	s.auditConfig(r, "automation_deleted", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) runAutomation(w http.ResponseWriter, r *http.Request) {
	a, err := s.Automations.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such automation")
		return
	}
	if !a.Enabled {
		writeErr(w, http.StatusConflict, "this automation is turned off")
		return
	}
	p, _ := principal(r)
	trig, _ := json.Marshal(map[string]string{"kind": "manual", "by": p.Actor.Subject()})
	run, err := s.Automations.Run(r.Context(), a.ID, trig)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) automationRuns(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := s.Automations.Runs(r.Context(), r.PathValue("id"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, runs)
}

// hookLimiter allows each webhook a burst of 10 and 1 request every 6 seconds.
var hookLimiter = struct {
	sync.Mutex
	last map[string][]time.Time
}{last: map[string][]time.Time{}}

func hookAllowed(token string) bool {
	hookLimiter.Lock()
	defer hookLimiter.Unlock()
	now := time.Now()
	var keep []time.Time
	for _, t := range hookLimiter.last[token] {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= 10 {
		hookLimiter.last[token] = keep
		return false
	}
	hookLimiter.last[token] = append(keep, now)
	return true
}

// hook starts a webhook-triggered automation. The unguessable token in the
// path is the credential; the body (JSON, up to 256 KiB) becomes the
// trigger data. It answers before the automation finishes.
func (s *Server) hook(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	if len(tok) < 32 || !hookAllowed(tok) {
		writeErr(w, http.StatusNotFound, "no such hook")
		return
	}
	a, err := s.Automations.ByHookToken(r.Context(), tok)
	if err != nil || !a.Enabled || a.Trigger.Kind != "webhook" {
		writeErr(w, http.StatusNotFound, "no such hook")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 256<<10))
	var payload any
	if len(body) > 0 && json.Unmarshal(body, &payload) != nil {
		payload = string(body)
	}
	trig, _ := json.Marshal(map[string]any{"kind": "webhook", "body": payload, "headers": map[string]string{"content-type": r.Header.Get("Content-Type"), "user-agent": r.UserAgent()}})
	go func() { _, _ = s.Automations.Run(context.WithoutCancel(r.Context()), a.ID, trig) }()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}
