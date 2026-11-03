package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/automation"
	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/internal/ratelimit"
	"github.com/elchi-dev/conduit/internal/syncer"
	"github.com/elchi-dev/conduit/internal/vault"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// syncActor is who changes arrive from, in the audit log.
var syncActor = core.Actor{ID: "sync", Kind: core.ActorSystem, Name: "Sync"}

// --- collections -----------------------------------------------------------------

type vaultCollection struct {
	v   *vault.Vault
	app *App
}

func (vaultCollection) Name() string { return "vault" }

type syncedSecret struct {
	Kind        vault.Kind `json:"kind"`
	Description string     `json:"description,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	Value       string     `json:"value"`
}

func (c vaultCollection) Export(ctx context.Context) (map[string]json.RawMessage, bool, error) {
	metas, vals, err := c.v.Export(ctx)
	if errors.Is(err, vault.ErrLocked) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	out := map[string]json.RawMessage{}
	for name, m := range metas {
		b, _ := json.Marshal(syncedSecret{Kind: m.Kind, Description: m.Description, Tags: m.Tags, Value: vals[name]})
		out[name] = b
	}
	return out, true, nil
}

func (c vaultCollection) Apply(ctx context.Context, name string, data json.RawMessage) error {
	if data == nil {
		err := c.v.Delete(ctx, name)
		if errors.Is(err, vault.ErrNoSecret) {
			err = nil
		}
		c.app.auditSync(ctx, "vault", "delete", name, err)
		return err
	}
	var s syncedSecret
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	err := c.v.Put(ctx, vault.Meta{Name: name, Kind: s.Kind, Description: s.Description, Tags: s.Tags}, s.Value)
	c.app.auditSync(ctx, "vault", "set", name, err)
	return err
}

type policyCollection struct {
	p   *core.Policy
	app *App
}

func (policyCollection) Name() string { return "policy" }

func (c policyCollection) Export(ctx context.Context) (map[string]json.RawMessage, bool, error) {
	out := map[string]json.RawMessage{}
	preset, err := c.p.Preset(ctx)
	if err != nil {
		return nil, false, err
	}
	out["preset"], _ = json.Marshal(map[string]string{"preset": string(preset)})
	rules, err := c.p.Rules(ctx)
	if err != nil {
		return nil, false, err
	}
	for _, r := range rules {
		// Each daemon makes the rules for its own trusted automations; they
		// follow from the automation's trust there, so they don't sync.
		if strings.HasPrefix(r.ID, "auto_") {
			continue
		}
		out["rule:"+r.ID], _ = json.Marshal(r)
	}
	return out, true, nil
}

func (c policyCollection) Apply(ctx context.Context, id string, data json.RawMessage) error {
	var err error
	switch {
	case id == "preset":
		if data == nil {
			return nil
		}
		var p struct {
			Preset core.Preset `json:"preset"`
		}
		if err = json.Unmarshal(data, &p); err == nil {
			err = c.p.SetPreset(ctx, p.Preset)
		}
	case strings.HasPrefix(id, "rule:auto_"):
		return nil // never applied from elsewhere
	case len(id) > 5 && id[:5] == "rule:":
		if data == nil {
			err = c.p.DeleteRule(ctx, id[5:])
		} else {
			var r core.Rule
			if err = json.Unmarshal(data, &r); err == nil {
				r.ID = id[5:]
				err = c.p.PutRule(ctx, r)
			}
		}
	default:
		return nil
	}
	c.app.auditSync(ctx, "policy", "set", id, err)
	return err
}

// automationCollection syncs definitions only. A synced automation arrives
// switched off and untrusted on the other daemons (it would otherwise run on
// every one of them); a person there switches it on.
type automationCollection struct {
	s   *automation.Service
	app *App
}

func (automationCollection) Name() string { return "automations" }

type syncedAutomation struct {
	Name    string             `json:"name"`
	Trigger automation.Trigger `json:"trigger"`
	Steps   []automation.Step  `json:"steps"`
}

func (c automationCollection) Export(ctx context.Context) (map[string]json.RawMessage, bool, error) {
	list, err := c.s.List(ctx)
	if err != nil {
		return nil, false, err
	}
	out := map[string]json.RawMessage{}
	for _, a := range list {
		out[a.ID], _ = json.Marshal(syncedAutomation{Name: a.Name, Trigger: a.Trigger, Steps: a.Steps})
	}
	return out, true, nil
}

func (c automationCollection) Apply(ctx context.Context, id string, data json.RawMessage) error {
	if data == nil {
		err := c.s.Delete(ctx, id)
		c.app.auditSync(ctx, "automations", "delete", id, err)
		return err
	}
	var x syncedAutomation
	if err := json.Unmarshal(data, &x); err != nil {
		return err
	}
	a := automation.Automation{ID: id, Name: x.Name, Trigger: x.Trigger, Steps: x.Steps}
	if old, err := c.s.Get(ctx, id); err == nil {
		a.Enabled = old.Enabled
	}
	_, err := c.s.Save(ctx, a, syncActor) // not a person: saved off and untrusted
	c.app.auditSync(ctx, "automations", "save", id, err)
	return err
}

func (a *App) auditSync(ctx context.Context, module, action, id string, err error) {
	in, _ := json.Marshal(map[string]string{"id": id})
	e := core.Entry{Actor: syncActor, Module: module, Instance: "sync", Action: "sync_" + action, Risk: sdk.RiskWrite, Decision: core.Allow, Status: "ok", Input: in}
	if err != nil {
		e.Status, e.Error = "error", err.Error()
	}
	_, _ = a.Engine.Audit.Append(context.WithoutCancel(ctx), e)
}

// newSync wires the sync service to this daemon's data and transports.
func newSync(app *App) *syncer.Service {
	s := &syncer.Service{
		DB: app.Store.DB,
		Collections: map[string]syncer.Collection{
			"vault":       vaultCollection{v: app.Vault, app: app},
			"policy":      policyCollection{p: app.Engine.Policy, app: app},
			"automations": automationCollection{s: app.Automations, app: app},
		},
		Info: []syncer.CollectionInfo{
			{Name: "vault", Description: "Secrets, including their values. Needs the vault unlocked on both sides."},
			{Name: "policy", Description: "The agent rules and the autonomy preset."},
			{Name: "automations", Description: "Automation definitions. They arrive switched off; switch them on where they should run."},
		},
		Peer: func(base string) syncer.Transport { return &syncer.PeerTransport{Base: base} },
	}
	s.Hub = func() syncer.Transport {
		if app.Remote == nil {
			return nil
		}
		hub, tok := app.Remote.HubCredentials()
		if hub == "" {
			return nil
		}
		return &syncer.HubTransport{Base: hub, Token: tok}
	}
	return s
}

// runSync does a round every 5 minutes and soon after local changes.
func runSync(ctx context.Context, app *App) {
	changes, stop := app.Engine.Bus.Subscribe("", 256)
	defer stop()
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	var soon <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-changes:
			if !ok {
				return
			}
			if soon == nil && syncRelevant(ev) {
				soon = time.After(10 * time.Second)
			}
		case <-soon:
			soon = nil
			app.Sync.Run(ctx)
		case <-tick.C:
			app.Sync.Run(ctx)
		}
	}
}

// syncRelevant: settings changes made through the API, and vault changes
// made through the vault module.
func syncRelevant(ev core.Envelope) bool {
	if ev.Type == "config.changed" {
		var d struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(ev.Data, &d)
		return !strings.HasPrefix(d.Action, "sync_")
	}
	return ev.Type == "action.ok" && ev.Module == "vault"
}

// --- peer endpoint -------------------------------------------------------------

var syncExchangeLimit = ratelimit.New(60, time.Minute, 10000)

// syncExchange answers another daemon in the sync group. It needs no
// session: only a group member can make a document that decrypts, and
// the answer is encrypted for the group too.
func (s *Server) syncExchange(w http.ResponseWriter, r *http.Request) {
	if s.Sync == nil || s.Sync.Key(r.Context()) == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !syncExchangeLimit.Add(requestSource(r)) {
		writeErr(w, http.StatusTooManyRequests, "too many sync requests")
		return
	}
	// One exchange at a time is plenty for a handful of daemons, and keeps
	// unauthenticated bodies from piling up in memory.
	select {
	case syncExchangeSlot <- struct{}{}:
		defer func() { <-syncExchangeSlot }()
	default:
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusTooManyRequests, "busy")
		return
	}
	var req struct {
		Collection string `json:"collection"`
		Doc        string `json:"doc"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeBody)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	out, err := s.Sync.Exchange(r.Context(), req.Collection, req.Doc)
	if errors.Is(err, syncer.ErrRefused) {
		writeErr(w, http.StatusForbidden, "refused")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"doc": out})
}

// A sealed document of 8 MiB holds tens of thousands of secrets; hub blobs
// are capped at 1 MiB.
const maxExchangeBody = 8 << 20

var syncExchangeSlot = make(chan struct{}, 2)

// --- API -------------------------------------------------------------------------

func (s *Server) syncRoutes() []route {
	return []route{
		{"GET /api/v1/sync", s.need("admin:*:*", s.syncStatus)},
		{"POST /api/v1/sync/group", s.need("admin:*:*", s.syncCreate)},
		{"POST /api/v1/sync/join", s.need("admin:*:*", s.syncJoin)},
		{"GET /api/v1/sync/code", s.need("admin:*:*", s.syncCode)},
		{"PUT /api/v1/sync/settings", s.need("admin:*:*", s.syncSettings)},
		{"POST /api/v1/sync/run", s.need("admin:*:*", s.syncRun)},
		{"DELETE /api/v1/sync/group", s.need("admin:*:*", s.syncLeave)},
	}
}

// vaultSyncOK: with restricted vault folders, only the owner may set up or
// change a group that syncs the vault, or see its join code (a joined daemon
// gets every secret, restricted folders included).
func (s *Server) vaultSyncOK(w http.ResponseWriter, r *http.Request, collections []string) bool {
	if len(s.vaultFolders(r.Context())) == 0 || !slices.Contains(collections, "vault") {
		return true
	}
	if p, _ := principal(r); p.User.Role == auth.RoleOwner {
		return true
	}
	writeErr(w, http.StatusForbidden, "the vault has restricted folders, so only the owner can sync it")
	return false
}

func (s *Server) syncStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Sync.Status(r.Context()))
}

type syncSetup struct {
	Code        string   `json:"code"`
	Collections []string `json:"collections"`
	Peers       []string `json:"peers"`
}

func (s *Server) syncCreate(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req syncSetup
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.vaultSyncOK(w, r, req.Collections) {
		return
	}
	code, err := s.Sync.Create(r.Context(), req.Collections)
	if err == nil && req.Peers != nil {
		err = s.Sync.SetPeers(r.Context(), req.Peers)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditConfig(r, "sync_group_created", "", map[string]any{"collections": req.Collections})
	writeJSON(w, http.StatusCreated, map[string]any{"code": code, "status": s.Sync.Status(r.Context())})
}

func (s *Server) syncJoin(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req syncSetup
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.vaultSyncOK(w, r, req.Collections) {
		return
	}
	err := s.Sync.Join(r.Context(), req.Code, req.Collections)
	if err == nil && req.Peers != nil {
		err = s.Sync.SetPeers(r.Context(), req.Peers)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditConfig(r, "sync_group_joined", "", map[string]any{"collections": req.Collections})
	go s.Sync.Run(context.WithoutCancel(r.Context()))
	writeJSON(w, http.StatusOK, s.Sync.Status(r.Context()))
}

func (s *Server) syncCode(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	if !s.vaultSyncOK(w, r, s.Sync.Status(r.Context()).Collections) {
		return
	}
	code, err := s.Sync.JoinCode(r.Context())
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	s.auditConfig(r, "sync_code_shown", "", nil)
	writeJSON(w, http.StatusOK, map[string]string{"code": code})
}

func (s *Server) syncSettings(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req syncSetup
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Collections != nil {
		// Adding the vault needs the owner; keeping or removing it doesn't.
		if !slices.Contains(s.Sync.Status(r.Context()).Collections, "vault") && !s.vaultSyncOK(w, r, req.Collections) {
			return
		}
		if err := s.Sync.SetCollections(r.Context(), req.Collections); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.Peers != nil {
		if err := s.Sync.SetPeers(r.Context(), req.Peers); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	s.auditConfig(r, "sync_settings_changed", "", req)
	writeJSON(w, http.StatusOK, s.Sync.Status(r.Context()))
}

func (s *Server) syncRun(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	res := s.Sync.Run(r.Context())
	if res == nil {
		res = []syncer.CollectionRun{}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) syncLeave(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	if err := s.Sync.Leave(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditConfig(r, "sync_group_left", "", nil)
	w.WriteHeader(http.StatusNoContent)
}
