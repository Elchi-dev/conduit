package daemon

import (
	"net/http"
)

// Remote access through a hub (internal/remote). Only people may change it:
// linking exposes this daemon through someone's hub account, and a pairing
// code lets a new device in.
func (s *Server) remoteRoutes() []route {
	return []route{
		{"GET /api/v1/remote", s.need("admin:*:*", s.remoteStatus)},
		{"POST /api/v1/remote/link", s.need("admin:*:*", s.remoteLink)},
		{"DELETE /api/v1/remote/link", s.need("admin:*:*", s.remoteUnlink)},
		{"POST /api/v1/remote/pairings", s.need("admin:*:*", s.remotePairing)},
		{"DELETE /api/v1/remote/clients/{id}", s.need("admin:*:*", s.remoteRevoke)},
	}
}

func (s *Server) remoteStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Remote.Status(r.Context()))
}

func (s *Server) remoteLink(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req struct {
		Hub  string `json:"hub"`
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	l, err := s.Remote.LinkHub(r.Context(), req.Hub, req.Code)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.auditConfig(r, "remote_linked", "", map[string]any{"hub": l.Hub, "device": l.DeviceID, "account": l.Account})
	writeJSON(w, http.StatusOK, s.Remote.Status(r.Context()))
}

func (s *Server) remoteUnlink(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	if err := s.Remote.Unlink(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditConfig(r, "remote_unlinked", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) remotePairing(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	p, err := s.Remote.NewPairing()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.auditConfig(r, "remote_pairing_created", "", map[string]any{"expiresAt": p.ExpiresAt})
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) remoteRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	if err := s.Remote.RevokeClient(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	s.auditConfig(r, "remote_client_removed", "", map[string]any{"client": r.PathValue("id")})
	w.WriteHeader(http.StatusNoContent)
}
