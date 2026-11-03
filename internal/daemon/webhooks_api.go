package daemon

import (
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/internal/webhooks"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Outbound webhooks (internal/webhooks). Only signed-in people add, change
// or remove them: a webhook sends every matching event to a URL, so a key
// that could add one could watch everything.
func (s *Server) webhookRoutes() []route {
	return []route{
		{"GET /api/v1/webhooks", s.need("admin:*:*", s.listWebhooks)},
		{"POST /api/v1/webhooks", s.need("admin:*:*", s.createWebhook)},
		{"GET /api/v1/webhooks/{id}", s.need("admin:*:*", s.getWebhook)},
		{"PATCH /api/v1/webhooks/{id}", s.need("admin:*:*", s.patchWebhook)},
		{"DELETE /api/v1/webhooks/{id}", s.need("admin:*:*", s.deleteWebhook)},
		{"POST /api/v1/webhooks/{id}/rotate", s.need("admin:*:*", s.rotateWebhook)},
		{"POST /api/v1/webhooks/{id}/test", s.need("admin:*:*", s.testWebhook)},
		{"GET /api/v1/webhooks/{id}/deliveries", s.need("admin:*:*", s.webhookDeliveries)},
	}
}

func (s *Server) listWebhooks(w http.ResponseWriter, r *http.Request) {
	list, err := s.Webhooks.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range list {
		list[i] = redactWebhook(r, list[i])
	}
	writeJSON(w, http.StatusOK, list)
}

// redactWebhook hides a webhook URL's path and query from keys and agents:
// receivers often put their own credentials there (Slack and Discord
// hooks, ?token=).
func redactWebhook(r *http.Request, wh webhooks.Webhook) webhooks.Webhook {
	if p, _ := principal(r); p.Actor.Kind == core.ActorUser {
		return wh
	}
	if u, err := url.Parse(wh.URL); err == nil {
		wh.URL = u.Scheme + "://" + u.Host + "/…"
	}
	return wh
}

func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req struct {
		Name   string   `json:"name"`
		URL    string   `json:"url"`
		Events []string `json:"events"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	wh, err := s.Webhooks.Create(r.Context(), req.Name, req.URL, req.Events)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditConfig(r, "webhook.create", wh.ID, map[string]any{"name": wh.Name, "url": wh.URL, "events": wh.Events})
	writeJSON(w, http.StatusCreated, wh)
}

func (s *Server) getWebhook(w http.ResponseWriter, r *http.Request) {
	wh, err := s.Webhooks.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		engineErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, redactWebhook(r, wh))
}

func (s *Server) patchWebhook(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil || req.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "send {\"enabled\": true|false}")
		return
	}
	if err := s.Webhooks.SetEnabled(r.Context(), r.PathValue("id"), *req.Enabled); err != nil {
		engineErr(w, err)
		return
	}
	s.getWebhook(w, r)
}

func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.Webhooks.Delete(r.Context(), id); err != nil {
		engineErr(w, err)
		return
	}
	s.auditConfig(r, "webhook.delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotateWebhook(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	id := r.PathValue("id")
	sec, err := s.Webhooks.RotateSecret(r.Context(), id)
	if err != nil {
		engineErr(w, err)
		return
	}
	s.auditConfig(r, "webhook.rotate", id, nil)
	writeJSON(w, http.StatusOK, map[string]string{"secret": sec})
}

func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) {
	ev := core.Envelope{Event: sdk.Event{Type: "webhook.test", Module: "core", Data: []byte(`{"message":"This is a test delivery from Conduit."}`)}, At: time.Now().UTC()}
	d, err := s.Webhooks.Send(r.Context(), r.PathValue("id"), ev)
	if err != nil {
		engineErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) webhookDeliveries(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	ds, err := s.Webhooks.Deliveries(r.Context(), r.PathValue("id"), n)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ds)
}
