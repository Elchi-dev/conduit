package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/internal/vault"
	"github.com/elchi-dev/conduit/internal/wgnet"
)

// Networks (docs/architecture/networks.md): userspace WireGuard tunnels that
// module instances can be attached to. Admins only; creating and changing
// one is for people only, since a network decides where an instance's
// traffic (and the credentials in it) goes.
func (s *Server) networkRoutes() []route {
	return []route{
		{"GET /api/v1/networks", s.need("admin:*:*", s.listNetworks)},
		{"POST /api/v1/networks", s.need("admin:*:*", s.saveNetwork)},
		{"GET /api/v1/networks/{id}", s.need("admin:*:*", s.getNetwork)},
		{"PUT /api/v1/networks/{id}", s.need("admin:*:*", s.saveNetwork)},
		{"DELETE /api/v1/networks/{id}", s.need("admin:*:*", s.deleteNetwork)},
		{"GET /api/v1/networks/{id}/status", s.need("admin:*:*", s.networkStatus)},
		{"POST /api/v1/networks/{id}/restart", s.need("admin:*:*", s.restartNetwork)},
	}
}

// networkView is a network with the instances attached to it.
type networkView struct {
	wgnet.Config
	Instances []string `json:"instances"`
}

func (s *Server) networkInstances(id string) []string {
	out := []string{}
	for _, in := range s.Engine.Instances("") {
		if in.Network == id {
			out = append(out, in.ID)
		}
	}
	return out
}

func (s *Server) listNetworks(w http.ResponseWriter, r *http.Request) {
	list, err := s.Networks.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]networkView, 0, len(list))
	for _, c := range list {
		out = append(out, networkView{Config: c, Instances: s.networkInstances(c.ID)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getNetwork(w http.ResponseWriter, r *http.Request) {
	c, err := s.Networks.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, wgnet.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, networkView{Config: c, Instances: s.networkInstances(c.ID)})
}

// networkPeerInput is a peer as sent by a client. PresharedKey is either a
// secret:// reference or a raw key, which is moved into the vault.
type networkPeerInput struct {
	Name                string   `json:"name"`
	PublicKey           string   `json:"publicKey"`
	PresharedKey        string   `json:"presharedKey"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive"`
}

// networkInput creates or changes a network. Either Conf (a wg-quick file,
// whose keys are moved into the vault) or the fields. PrivateKey is a
// secret:// reference or a raw key (moved into the vault); left empty on a
// change it keeps the current key, and GenerateKey makes a new one.
type networkInput struct {
	Name        string             `json:"name"`
	Conf        string             `json:"conf"`
	PrivateKey  string             `json:"privateKey"`
	GenerateKey bool               `json:"generateKey"`
	Addresses   []string           `json:"addresses"`
	DNS         []string           `json:"dns"`
	MTU         int                `json:"mtu"`
	ListenPort  int                `json:"listenPort"`
	Peers       []networkPeerInput `json:"peers"`
}

func (s *Server) saveNetwork(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req networkInput
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	id, code := r.PathValue("id"), http.StatusOK
	var old *wgnet.Config
	if id == "" {
		id, code = core.NewID("net"), http.StatusCreated
	} else {
		c, err := s.Networks.Get(ctx, id)
		if err != nil {
			writeErr(w, http.StatusNotFound, "no such network")
			return
		}
		old = &c
	}
	cfg := wgnet.Config{ID: id, Name: req.Name, Addresses: req.Addresses, DNS: req.DNS, MTU: req.MTU, ListenPort: req.ListenPort}
	// Raw keys to store once everything else checks out.
	pending := map[string]string{}
	privRaw := strings.TrimSpace(req.PrivateKey)
	var pskRaw []string
	if strings.TrimSpace(req.Conf) != "" {
		p, err := wgnet.ParseWGQuick(req.Conf)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "the WireGuard file: "+err.Error())
			return
		}
		p.Config.ID, p.Config.Name = id, req.Name
		if p.Config.Name == "" && old != nil {
			p.Config.Name = old.Name
		}
		cfg, privRaw, pskRaw = p.Config, p.PrivateKey, p.PresharedKeys
	} else {
		for _, p := range req.Peers {
			cfg.Peers = append(cfg.Peers, wgnet.Peer{Name: p.Name, PublicKey: p.PublicKey, Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs, PersistentKeepalive: p.PersistentKeepalive})
			pskRaw = append(pskRaw, p.PresharedKey)
		}
	}
	if cfg.Name == "" && old != nil {
		cfg.Name = old.Name
	}
	switch {
	case req.GenerateKey:
		k, err := wgnet.GenerateKey()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		privRaw = k
		fallthrough
	case privRaw != "" && !strings.HasPrefix(privRaw, "secret://"):
		pub, err := wgnet.PublicKey(privRaw)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "private key: "+err.Error())
			return
		}
		name := "networks/" + id + "/private-key"
		pending[name] = privRaw
		cfg.PrivateKey, cfg.PublicKey = "secret://"+name, pub
	case privRaw != "":
		cfg.PrivateKey = privRaw
		if old != nil && old.PrivateKey == privRaw {
			cfg.PublicKey = old.PublicKey
		} else if v, err := s.Vault.Resolve(ctx, privRaw); err == nil {
			cfg.PublicKey, _ = wgnet.PublicKey(v)
		}
	case old != nil:
		cfg.PrivateKey, cfg.PublicKey = old.PrivateKey, old.PublicKey
	default:
		writeErr(w, http.StatusBadRequest, "paste a WireGuard file, give the private key, or ask for a new key")
		return
	}
	for i := range cfg.Peers {
		if i >= len(pskRaw) || strings.TrimSpace(pskRaw[i]) == "" {
			continue
		}
		k := strings.TrimSpace(pskRaw[i])
		if strings.HasPrefix(k, "secret://") {
			cfg.Peers[i].PresharedKey = k
			continue
		}
		if _, err := wgnet.ParseKey(k); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("peer %d preshared key: %v", i+1, err))
			return
		}
		sum := sha256.Sum256([]byte(cfg.Peers[i].PublicKey))
		name := "networks/" + id + "/psk-" + hex.EncodeToString(sum[:6])
		pending[name] = k
		cfg.Peers[i].PresharedKey = "secret://" + name
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// References to existing secrets must be ones this person may use.
	refs, _ := json.Marshal(cfg)
	if err := s.checkConfigRefs(r, refs); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	for name, v := range pending {
		if err := s.Vault.Put(ctx, vault.Meta{Name: name, Kind: vault.KindToken, Description: "WireGuard key for the network " + cfg.Name, Tags: []string{"network"}}, v); err != nil {
			writeErr(w, http.StatusBadRequest, "store the key in the vault: "+err.Error())
			return
		}
	}
	saved, err := s.Networks.Save(ctx, cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	peers := []string{}
	for _, p := range saved.Peers {
		peers = append(peers, p.PublicKey)
	}
	action := "network_saved"
	if code == http.StatusCreated {
		action = "network_created"
	}
	s.auditConfig(r, action, saved.ID, map[string]any{"name": saved.Name, "addresses": saved.Addresses, "peers": peers, "fromFile": req.Conf != ""})
	writeJSON(w, code, networkView{Config: saved, Instances: s.networkInstances(saved.ID)})
}

func (s *Server) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	id := r.PathValue("id")
	if used := s.networkInstances(id); len(used) > 0 {
		writeErr(w, http.StatusConflict, "still used by "+strings.Join(used, ", ")+"; move those connections off this network first")
		return
	}
	ctx := r.Context()
	c, err := s.Networks.Get(ctx, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such network")
		return
	}
	if err := s.Networks.Delete(ctx, id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Keys Conduit stored for this network go with it; references to other
	// secrets are left alone.
	s.dropNetworkKeys(ctx, id)
	s.auditConfig(r, "network_deleted", id, map[string]any{"name": c.Name})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) dropNetworkKeys(ctx context.Context, id string) {
	list, err := s.Vault.List(ctx)
	if err != nil {
		return
	}
	for _, m := range list {
		if strings.HasPrefix(m.Name, "networks/"+id+"/") {
			_ = s.Vault.Delete(ctx, m.Name)
		}
	}
}

func (s *Server) networkStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.Networks.Status(r.Context(), r.PathValue("id"), r.URL.Query().Get("connect") == "1")
	if errors.Is(err, wgnet.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) restartNetwork(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	id := r.PathValue("id")
	if _, err := s.Networks.Get(r.Context(), id); err != nil {
		writeErr(w, http.StatusNotFound, "no such network")
		return
	}
	err := s.Networks.Restart(r.Context(), id)
	s.auditConfig(r, "network_restarted", id, nil)
	st, serr := s.Networks.Status(r.Context(), id, false)
	if serr != nil {
		writeErr(w, http.StatusInternalServerError, serr.Error())
		return
	}
	if err != nil && st.Error == "" {
		st.Error = err.Error()
	}
	writeJSON(w, http.StatusOK, st)
}
