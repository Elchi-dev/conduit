package daemon

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Phone notifications without Google services: the daemon sends approvals
// and alerts to an ntfy topic, and the phone's ntfy app (F-Droid or Play)
// shows them even when Conduit isn't open. The topic name is random and is
// the only thing that guards it on a public server, so the default is to
// send no details there.

func (s *Server) phoneRoutes() []route {
	return []route{
		{"POST /api/v1/notify/phone", s.need("admin:*:*", s.setupPhonePush)},
	}
}

type phonePushReq struct {
	Server  string `json:"server"`  // default https://ntfy.sh
	Private *bool  `json:"private"` // default true
	AppURL  string `json:"appUrl"`  // where the phone opens Conduit; default conduit:// deep links
}

type phonePushResp struct {
	Instance  core.Instance `json:"instance"`
	Topic     string        `json:"topic"`
	Subscribe string        `json:"subscribe"` // ntfy://host/topic, opens the ntfy app
	Web       string        `json:"web"`       // https://host/topic
}

func (s *Server) setupPhonePush(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req phonePushReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	server := strings.TrimRight(strings.TrimSpace(req.Server), "/")
	if server == "" {
		server = "https://ntfy.sh"
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.Path != "" {
		writeErr(w, http.StatusBadRequest, "the ntfy server is an address like https://ntfy.sh")
		return
	}
	private := req.Private == nil || *req.Private
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	topic := "conduit-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	appURL := req.AppURL
	if appURL == "" {
		appURL = "conduit://open"
	}
	cfg, _ := json.Marshal(map[string]any{"channel": "ntfy", "server": server, "topic": topic, "approvals": true, "private": private, "appUrl": appURL, "minPriority": "normal"})
	in, err := s.Engine.SaveInstance(r.Context(), core.Instance{Module: "notify", Name: "Phone (" + u.Host + ")", Config: cfg, Enabled: true})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditConfig(r, "phone_push_set_up", in.ID, map[string]any{"server": server, "private": private})
	// A first message, so the phone shows something as soon as it subscribes.
	p, _ := principal(r)
	_, _ = s.Engine.Invoke(r.Context(), p.Actor, sdk.Call{Instance: in.ID, Action: "test"}, core.InvokeOptions{NoWait: true})
	host := u.Host
	writeJSON(w, http.StatusCreated, phonePushResp{Instance: in, Topic: topic, Subscribe: "ntfy://" + host + "/" + topic, Web: server + "/" + topic})
}
