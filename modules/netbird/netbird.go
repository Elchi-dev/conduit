// Package netbird works with a NetBird network through its management API
// and a personal access token: peers (connected, OS, version), groups,
// access policies, routes and setup keys (never their values), and
// approving or disabling peers.
package netbird

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one NetBird account.
type Config struct {
	URL                string `json:"url"`   // default https://api.netbird.io; self-hosted: the management address
	Token              string `json:"token"` // secret:// personal access token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the NetBird module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	peerRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	peer := `{"type":"object","required":["peer"],"properties":{"peer":{"type":"string","description":"Peer id (from peers)"}}}`
	return sdk.Manifest{
		ID: "netbird", Name: "NetBird", Version: "0.1.0", Category: "Network", Icon: "network",
		Description: "NetBird: peers (connected, OS, version), groups, access policies, routes and setup keys; approve or disable peers.",
		Presets:     []string{"homelab", "team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"url":{"type":"string","default":"https://api.netbird.io","description":"NetBird Cloud, or your management server's address, e.g. https://netbird.example.com"},
			"token":{"type":"string","x-secret":true,"description":"A personal access token (Team, Users or Service Users, Create token); it acts with its user's role"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "peers", Title: "Peers", Description: "Every peer: name, address, connected, last seen, OS, NetBird version, groups, and whether it waits for approval or its login expired.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"connected":{"type":"boolean","description":"Only connected (true) or disconnected (false) peers"}}}`)},
			{Name: "groups", Title: "Groups", Description: "Groups with their peers and resource counts and where they come from (API, JWT, integration).", Risk: sdk.RiskRead},
			{Name: "policies", Title: "Access policies", Description: "Policies and their rules: action, protocol, ports, and source and destination groups.", Risk: sdk.RiskRead},
			{Name: "routes", Title: "Routes", Description: "Network routes: the network or domains, routing peer or peer groups, distribution groups, metric, masquerade and whether it's on.", Risk: sdk.RiskRead},
			{Name: "setup_keys", Title: "Setup keys", Description: "Setup keys: name, type, state, uses, expiry and auto-assigned groups. Never the key itself.", Risk: sdk.RiskRead},
			{Name: "approve_peer", Title: "Approve a peer", Description: "Lets a peer waiting for approval join the network (peer approval is a NetBird Cloud feature). Undo disables it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(peer)},
			{Name: "disable_peer", Title: "Disable a peer", Description: "Sends the peer back to waiting for approval, cutting it off from the network until it's approved. Undo approves it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(peer)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = "https://api.netbird.io"
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://netbird.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	ref := c.Token
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Token "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("NetBird refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token's user isn't allowed to do this in NetBird")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, out)
	return friendly(err)
}

type ref struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type peer struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Hostname             string `json:"hostname"`
	IP                   string `json:"ip"`
	DNSLabel             string `json:"dns_label"`
	Connected            bool   `json:"connected"`
	LastSeen             string `json:"last_seen"`
	OS                   string `json:"os"`
	Version              string `json:"version"`
	Groups               []ref  `json:"groups"`
	SSHEnabled           bool   `json:"ssh_enabled"`
	LoginExpirationOn    bool   `json:"login_expiration_enabled"`
	InactivityExpiration *bool  `json:"inactivity_expiration_enabled"`
	LoginExpired         bool   `json:"login_expired"`
	ApprovalRequired     bool   `json:"approval_required"`
	AccessiblePeersCount *int   `json:"accessible_peers_count"`
	// Location, serial number and user id aren't decoded: they'd end up
	// in the audit log.
}

func (p peer) label() string {
	if p.Name != "" {
		return p.Name
	}
	return p.ID
}

func names(rs []ref) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return out
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var ps []peer
	if err := c.get(ctx, "/peers", &ps); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no NetBird management API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	on, waiting := 0, 0
	for _, p := range ps {
		if p.Connected {
			on++
		}
		if p.ApprovalRequired {
			waiting++
		}
	}
	msg := fmt.Sprintf("%d peers, %d connected", len(ps), on)
	if waiting > 0 {
		msg += fmt.Sprintf(", %d waiting for approval", waiting)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Peer      string `json:"peer"`
		Connected *bool  `json:"connected"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "peers":
		var ps []peer
		if err := c.get(ctx, "/peers", &ps); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ps {
			if p.Connected != nil && x.Connected != *p.Connected {
				continue
			}
			row := map[string]any{"id": x.ID, "name": x.label(), "hostname": x.Hostname, "ip": x.IP, "dnsName": x.DNSLabel, "connected": x.Connected,
				"lastSeen": x.LastSeen, "os": x.OS, "version": x.Version, "groups": names(x.Groups), "sshEnabled": x.SSHEnabled,
				"loginExpirationEnabled": x.LoginExpirationOn, "loginExpired": x.LoginExpired, "approvalRequired": x.ApprovalRequired}
			if x.AccessiblePeersCount != nil {
				row["reachablePeers"] = *x.AccessiblePeersCount
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	case "groups":
		var gs []struct {
			ID             string `json:"id"`
			Name           string `json:"name"`
			PeersCount     int    `json:"peers_count"`
			ResourcesCount int    `json:"resources_count"`
			Issued         string `json:"issued"`
			Peers          []ref  `json:"peers"`
		}
		if err := c.get(ctx, "/groups", &gs); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, g := range gs {
			out = append(out, map[string]any{"id": g.ID, "name": g.Name, "peers": g.PeersCount, "peerNames": names(g.Peers), "resources": g.ResourcesCount, "issued": g.Issued})
		}
		return sdk.JSON(out)
	case "policies":
		return c.policies(ctx)
	case "routes":
		return c.routes(ctx)
	case "setup_keys":
		return c.setupKeys(ctx)
	case "approve_peer", "disable_peer":
		p.Peer = strings.TrimSpace(p.Peer)
		if !peerRe.MatchString(p.Peer) {
			return sdk.Result{}, errors.New("a peer is its id from peers")
		}
		return c.setApproval(ctx, call, p.Peer)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) policies(ctx context.Context) (sdk.Result, error) {
	var ps []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Enabled     bool   `json:"enabled"`
		Rules       []struct {
			Name          string   `json:"name"`
			Enabled       bool     `json:"enabled"`
			Action        string   `json:"action"`
			Bidirectional bool     `json:"bidirectional"`
			Protocol      string   `json:"protocol"`
			Ports         []string `json:"ports"`
			PortRanges    []struct {
				Start int `json:"start"`
				End   int `json:"end"`
			} `json:"port_ranges"`
			Sources      []ref `json:"sources"`
			Destinations []ref `json:"destinations"`
		} `json:"rules"`
		PostureChecks []string `json:"source_posture_checks"`
	}
	if err := c.get(ctx, "/policies", &ps); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, p := range ps {
		rules := []map[string]any{}
		for _, r := range p.Rules {
			ports := append([]string{}, r.Ports...)
			for _, pr := range r.PortRanges {
				ports = append(ports, fmt.Sprintf("%d-%d", pr.Start, pr.End))
			}
			rules = append(rules, map[string]any{"name": r.Name, "enabled": r.Enabled, "action": r.Action, "bidirectional": r.Bidirectional,
				"protocol": r.Protocol, "ports": ports, "sources": names(r.Sources), "destinations": names(r.Destinations)})
		}
		row := map[string]any{"id": p.ID, "name": p.Name, "enabled": p.Enabled, "rules": rules}
		if p.Description != "" {
			row["description"] = p.Description
		}
		if len(p.PostureChecks) > 0 {
			row["postureChecks"] = len(p.PostureChecks)
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

// groupNames maps group ids to names, for the API answers that carry ids.
func (c *conn) groupNames(ctx context.Context) map[string]string {
	var gs []ref
	out := map[string]string{}
	if c.get(ctx, "/groups", &gs) == nil {
		for _, g := range gs {
			out[g.ID] = g.Name
		}
	}
	return out
}

func named(ids []string, by map[string]string) []string {
	out := []string{}
	for _, id := range ids {
		if n := by[id]; n != "" {
			out = append(out, n)
		} else {
			out = append(out, id)
		}
	}
	return out
}

func (c *conn) routes(ctx context.Context) (sdk.Result, error) {
	var rs []struct {
		ID          string   `json:"id"`
		NetworkID   string   `json:"network_id"`
		Description string   `json:"description"`
		Enabled     bool     `json:"enabled"`
		Peer        string   `json:"peer"`
		PeerGroups  []string `json:"peer_groups"`
		Network     string   `json:"network"`
		Domains     []string `json:"domains"`
		Metric      int      `json:"metric"`
		Masquerade  bool     `json:"masquerade"`
		Groups      []string `json:"groups"`
		ACLGroups   []string `json:"access_control_groups"`
	}
	if err := c.get(ctx, "/routes", &rs); err != nil {
		return sdk.Result{}, err
	}
	gn := c.groupNames(ctx)
	pn := map[string]string{}
	var ps []peer
	if c.get(ctx, "/peers", &ps) == nil {
		for _, p := range ps {
			pn[p.ID] = p.label()
		}
	}
	out := []map[string]any{}
	for _, r := range rs {
		row := map[string]any{"id": r.ID, "name": r.NetworkID, "enabled": r.Enabled, "metric": r.Metric, "masquerade": r.Masquerade,
			"distributionGroups": named(r.Groups, gn)}
		if r.Network != "" {
			row["network"] = r.Network
		}
		if len(r.Domains) > 0 {
			row["domains"] = r.Domains
		}
		if r.Description != "" {
			row["description"] = r.Description
		}
		if r.Peer != "" {
			row["peer"] = named([]string{r.Peer}, pn)[0]
		}
		if len(r.PeerGroups) > 0 {
			row["peerGroups"] = named(r.PeerGroups, gn)
		}
		if len(r.ACLGroups) > 0 {
			row["accessControlGroups"] = named(r.ACLGroups, gn)
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

func (c *conn) setupKeys(ctx context.Context) (sdk.Result, error) {
	// Decoded field by field: the key (masked or not) is never read.
	var ks []struct {
		ID         string   `json:"id"`
		Name       string   `json:"name"`
		Type       string   `json:"type"`
		Valid      bool     `json:"valid"`
		Revoked    bool     `json:"revoked"`
		State      string   `json:"state"`
		Expires    string   `json:"expires"`
		UsedTimes  int      `json:"used_times"`
		UsageLimit int      `json:"usage_limit"`
		LastUsed   string   `json:"last_used"`
		Ephemeral  bool     `json:"ephemeral"`
		AutoGroups []string `json:"auto_groups"`
	}
	if err := c.get(ctx, "/setup-keys", &ks); err != nil {
		return sdk.Result{}, err
	}
	gn := c.groupNames(ctx)
	out := []map[string]any{}
	for _, k := range ks {
		row := map[string]any{"id": k.ID, "name": k.Name, "type": k.Type, "valid": k.Valid, "revoked": k.Revoked, "state": k.State,
			"expires": k.Expires, "usedTimes": k.UsedTimes, "ephemeral": k.Ephemeral, "autoGroups": named(k.AutoGroups, gn)}
		if k.UsageLimit > 0 {
			row["usageLimit"] = k.UsageLimit
		}
		if k.LastUsed != "" && !strings.HasPrefix(k.LastUsed, "0001-") {
			row["lastUsed"] = k.LastUsed
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

func (c *conn) setApproval(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	approve := call.Action == "approve_peer"
	var p peer
	if err := c.get(ctx, "/peers/"+id, &p); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no peer %s", id)
		}
		return sdk.Result{}, err
	}
	if p.ID == "" {
		return sdk.Result{}, fmt.Errorf("there's no peer %s", id)
	}
	if p.ApprovalRequired != approve {
		return sdk.JSON(map[string]any{"peer": p.ID, "name": p.label(), "approved": approve, "note": "nothing to change"})
	}
	verb, back := "Disable", "approve_peer"
	if approve {
		verb, back = "Approve", "disable_peer"
	}
	target := fmt.Sprintf("peer %s (%s, %s)", p.label(), p.IP, strings.Join(names(p.Groups), ", "))
	if call.DryRun {
		b, _ := json.Marshal(map[string]bool{"approvalRequired": p.ApprovalRequired})
		a, _ := json.Marshal(map[string]bool{"approvalRequired": !approve})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + p.label(), Changes: []sdk.Change{{Target: target, Op: strings.ToLower(verb), Before: b, After: a}}}}, nil
	}
	// The update replaces the peer's settings: send back what it has.
	body := map[string]any{"name": p.Name, "ssh_enabled": p.SSHEnabled, "login_expiration_enabled": p.LoginExpirationOn, "approval_required": !approve}
	if p.InactivityExpiration != nil {
		body["inactivity_expiration_enabled"] = *p.InactivityExpiration
	}
	var after peer
	if _, err := c.api.Do(ctx, http.MethodPut, "/peers/"+p.ID, nil, body, &after); err != nil {
		return sdk.Result{}, friendly(err)
	}
	if after.ID != "" && after.ApprovalRequired != !approve {
		return sdk.Result{}, errors.New("NetBird kept the peer's approval as it was (peer approval needs NetBird Cloud with approval turned on)")
	}
	res, err := sdk.JSON(map[string]any{"peer": p.ID, "name": p.label(), "approved": approve})
	undo := "Disable " + p.label() + " again"
	if !approve {
		undo = "Approve " + p.label() + " again"
	}
	res.Undo = sdk.UndoWith(back, map[string]string{"peer": p.ID}, undo)
	return res, err
}
