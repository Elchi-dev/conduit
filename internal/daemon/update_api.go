package daemon

import (
	"context"
	"net/http"
	"time"

	"github.com/elchi-dev/conduit/internal/update"
)

// Self-update of a standalone daemon (internal/update). Installing is a
// person's decision; agents and keys can only look.
func (s *Server) updateRoutes() []route {
	return []route{
		{"GET /api/v1/system/update", s.need("admin:*:*", s.updateStatus)},
		{"POST /api/v1/system/update/check", s.need("admin:*:*", s.updateCheck)},
		{"POST /api/v1/system/update/apply", s.need("admin:*:*", s.updateApply)},
	}
}

func (s *Server) updateStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Updates.Status())
}

func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if _, err := s.Updates.Check(ctx); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Updates.Status())
}

func (s *Server) updateApply(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	p, err := s.Updates.Apply(r.Context())
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.auditConfig(r, "update_installed", "", map[string]any{"from": s.Updates.Current, "to": p.Version})
	writeJSON(w, http.StatusAccepted, s.Updates.Status())
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	exe := s.Updates.Exe
	go func() {
		time.Sleep(500 * time.Millisecond)
		if err := update.Restart(exe); err != nil {
			s.Log.Error("update: restart failed; restart conduitd yourself", "err", err)
		}
	}()
}
