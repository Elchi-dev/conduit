package daemon

import (
	"encoding/json"
	"net/http"

	"github.com/elchi-dev/conduit/internal/ai"
	"github.com/elchi-dev/conduit/internal/core"
)

func (s *Server) assistantRoutes() []route {
	return []route{
		{"GET /api/v1/ai/providers", s.need("modules:*:read", s.listProviders)},
		{"POST /api/v1/ai/providers", s.need("admin:*:*", s.saveProvider)},
		{"PUT /api/v1/ai/providers/{id}", s.need("admin:*:*", s.saveProvider)},
		{"DELETE /api/v1/ai/providers/{id}", s.need("admin:*:*", s.deleteProvider)},
		{"GET /api/v1/ai/presets", s.need("", s.providerPresets)},
		{"GET /api/v1/ai/detect", s.need("admin:*:*", s.detectProviders)},
		{"GET /api/v1/assistant/conversations", s.need("", s.listConversations)},
		{"GET /api/v1/assistant/conversations/{id}", s.need("", s.getConversation)},
		{"DELETE /api/v1/assistant/conversations/{id}", s.need("", s.deleteConversation)},
		{"POST /api/v1/assistant/chat", s.need("actions:*:invoke", s.chat)},
		{"GET /api/v1/mcp-servers", s.need("modules:*:read", s.listMCPServers)},
		{"POST /api/v1/mcp-servers", s.need("admin:*:*", s.saveMCPServer)},
		{"PUT /api/v1/mcp-servers/{id}", s.need("admin:*:*", s.saveMCPServer)},
		{"DELETE /api/v1/mcp-servers/{id}", s.need("admin:*:*", s.deleteMCPServer)},
	}
}

func (s *Server) listMCPServers(w http.ResponseWriter, r *http.Request) {
	list, err := s.Bridge.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// saveMCPServer mounts an outside MCP server. Only people may add one: a
// stdio server runs a command on this machine.
func (s *Server) saveMCPServer(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var m ai.MCPServer
	if err := readJSON(r, &m); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if id := r.PathValue("id"); id != "" {
		m.ID = id
	}
	saved, err := s.Bridge.Save(r.Context(), m)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditConfig(r, "mcp_server_saved", saved.ModuleID(), map[string]any{"name": saved.Name, "transport": saved.Transport, "command": saved.Command, "url": saved.URL})
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) deleteMCPServer(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	if err := s.Bridge.Delete(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditConfig(r, "mcp_server_deleted", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listProviders(w http.ResponseWriter, r *http.Request) {
	list, err := s.Providers.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) saveProvider(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var pr ai.Provider
	if err := readJSON(r, &pr); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	pr.ID = r.PathValue("id")
	saved, err := s.Providers.Save(r.Context(), pr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) deleteProvider(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	if err := s.Providers.Delete(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) providerPresets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, ai.Presets)
}

func (s *Server) detectProviders(w http.ResponseWriter, r *http.Request) {
	found := s.Providers.Detect(r.Context())
	if found == nil {
		found = []ai.Provider{}
	}
	writeJSON(w, http.StatusOK, found)
}

func (s *Server) listConversations(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	list, err := s.Assistant.List(r.Context(), p.User.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) getConversation(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	c, err := s.Assistant.Get(r.Context(), p.User.ID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) deleteConversation(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	if err := s.Assistant.Delete(r.Context(), p.User.ID, r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// chat runs one assistant turn and streams its steps as newline-delimited
// JSON. The assistant acts as an agent ("assistant:<user>"), so the agent
// rules decide what it may do without asking, even though a person is
// talking to it.
func (s *Server) chat(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	if p.Actor.Kind != core.ActorUser {
		writeErr(w, http.StatusForbidden, "the built-in assistant is for people; agents connect over MCP")
		return
	}
	var req struct {
		Conversation string `json:"conversation"`
		Message      string `json:"message"`
	}
	if err := readJSON(r, &req); err != nil || req.Message == "" {
		writeErr(w, http.StatusBadRequest, "send a message")
		return
	}
	tb := s.toolbox(r)
	tb.Actor = core.Actor{ID: "assistant-" + p.User.ID, Kind: core.ActorAgent, Name: "Assistant"}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	fl, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	emit := func(st ai.Step) {
		_ = enc.Encode(st)
		if fl != nil {
			fl.Flush()
		}
	}
	if err := s.Assistant.Chat(r.Context(), tb, p.User.ID, p.User.Name, req.Conversation, req.Message, emit); err != nil {
		emit(ai.Step{Type: "error", Text: err.Error()})
		emit(ai.Step{Type: "done"})
	}
}
