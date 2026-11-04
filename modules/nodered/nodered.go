// Package nodered works with Node-RED through its admin API: the flows (tabs
// and subflows by name and id, never their nodes' settings, which can hold
// credentials), enabling and disabling a flow, and the installed node
// modules. It signs in with a user's name and password (adminAuth), uses a
// token, or calls an admin API without authentication.
package nodered

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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Node-RED instance. Give a username with a password, a
// token, or neither when the admin API has no authentication.
type Config struct {
	URL                string `json:"url"`      // e.g. http://nodered.local:1880
	Username           string `json:"username"` // adminAuth user
	Password           string `json:"password"` // secret://
	Token              string `json:"token"`    // secret://, a bearer token (adminAuth.tokens)
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
	now func() time.Time

	// Session login (with a username).
	login    *rest.Client
	user     string
	password string // secret:// reference
	host     sdk.Host
	mu       sync.Mutex
	session  string
	expires  time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces the clock (tests).
	Now func() time.Time
}

// New returns the Node-RED module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	flowRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	flow := `{"type":"object","required":["flow"],"properties":{"flow":{"type":"string","maxLength":64,"description":"Flow id (from flows)"}}}`
	return sdk.Manifest{
		ID: "nodered", Name: "Node-RED", Version: "0.1.0", Category: "Smart home", Icon: "workflow",
		Description: "Node-RED flows by name, enabling or disabling a flow, and the installed node modules.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Node-RED's address, e.g. http://nodered.local:1880 (with httpAdminRoot if it's set, e.g. /admin)"},
			"username":{"type":"string","description":"An adminAuth user (with password); leave empty when the admin API has no login"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"token":{"type":"string","x-secret":true,"description":"Or a bearer token accepted by adminAuth.tokens (instead of username and password)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "flows", Title: "Flows", Description: "Each flow (tab) and subflow: id, name, whether it's disabled and how many nodes it has. Node settings are never returned.", Risk: sdk.RiskRead},
			{Name: "nodes", Title: "Node modules", Description: "Installed node modules with version, whether they're enabled, and the node types they add.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","maxLength":100,"description":"Only modules or node types containing this"}}}`)},
			{Name: "disable_flow", Title: "Disable a flow", Description: "Disables a flow: its nodes stop, so the automations it runs stop until it's enabled again. Undo enables it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(flow)},
			{Name: "enable_flow", Title: "Enable a flow", Description: "Enables a disabled flow, so its nodes run again (with whatever they trigger). Undo disables it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(flow)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like http://nodered.local:1880")
	}
	user := strings.TrimSpace(c.Username)
	switch {
	case c.Token != "" && (user != "" || c.Password != ""):
		return errors.New("give a username and password or a token, not both")
	case c.Token != "":
		if !strings.HasPrefix(c.Token, "secret://") {
			return errors.New("store the token in the vault and enter its secret:// reference")
		}
	case (user == "") != (c.Password == ""):
		return errors.New("signing in takes both a username and a password")
	case c.Password != "" && !strings.HasPrefix(c.Password, "secret://"):
		return errors.New("store the password in the vault and enter its secret:// reference")
	case len(user) > 128 || strings.ContainsAny(user, "\x00\r\n"):
		return errors.New("the username is a Node-RED adminAuth user")
	}
	if u.Scheme == "http" && (c.Fingerprint != "" || c.InsecureSkipVerify) {
		return errors.New("the certificate settings need an https address")
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
	client = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	base := u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
	cn := &conn{now: now, user: user, password: c.Password, host: h}
	tokenRef := c.Token
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		switch {
		case tokenRef != "":
			t, err := h.Secret(ctx, tokenRef)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+strings.TrimPrefix(strings.TrimSpace(t), "Bearer "))
		case cn.user != "":
			t, err := cn.sessionToken(ctx)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+t)
		}
		return nil
	})
	cn.api.HTTP = client
	if user != "" {
		cn.login = rest.New(base, nil)
		cn.login.HTTP = client
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errLogin = errors.New("Node-RED refused the username or password")

// sessionToken signs in when there's no token or it's about to end.
func (c *conn) sessionToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != "" && c.now().Add(time.Minute).Before(c.expires) {
		return c.session, nil
	}
	pw, err := c.host.Secret(ctx, c.password)
	if err != nil {
		return "", err
	}
	var res struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	_, err = c.login.Do(ctx, http.MethodPost, "/auth/token", nil, map[string]string{
		"client_id": "node-red-admin", "grant_type": "password", "scope": "*", "username": c.user, "password": pw}, &res)
	if err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusForbidden) {
			return "", errLogin
		}
		if rest.IsStatus(err, http.StatusNotFound) {
			return "", errors.New("Node-RED has no login (adminAuth isn't set): leave the username and password empty")
		}
		return "", fmt.Errorf("couldn't sign in to Node-RED: %w", err)
	}
	t := strings.TrimSpace(res.AccessToken)
	if t == "" || strings.ContainsAny(t, " \r\n") {
		return "", errors.New("Node-RED's sign-in gave no access token")
	}
	c.session = t
	c.expires = c.now().Add(time.Duration(res.ExpiresIn) * time.Second)
	if res.ExpiresIn <= 0 {
		c.expires = c.now().Add(time.Hour)
	}
	return t, nil
}

func (c *conn) do(ctx context.Context, method, path string, body, out any) error {
	_, err := c.api.Do(ctx, method, path, nil, body, out)
	if c.login != nil && rest.IsStatus(err, http.StatusUnauthorized) {
		// The token ended early (revoked, server restart): sign in again once.
		c.mu.Lock()
		c.session = ""
		c.mu.Unlock()
		_, err = c.api.Do(ctx, method, path, nil, body, out)
	}
	switch {
	case errors.Is(err, errLogin):
		return err
	case rest.IsStatus(err, http.StatusUnauthorized):
		if c.login == nil {
			return errors.New("Node-RED refused the request: set a username and password or a token")
		}
		return errors.New("Node-RED refused the session")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the Node-RED user isn't allowed to do this (it needs the * or flows.write permission)")
	}
	return err
}

// node holds only what's needed to group nodes by flow: never their settings.
type node struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Z        string `json:"z"`
	Label    string `json:"label"`
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
}

// clip redacts server text, then shortens it.
func clip(s string, n int) string {
	s = rest.Redact(strings.TrimSpace(s))
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

func (c *conn) allNodes(ctx context.Context) ([]node, error) {
	var ns []node
	if err := c.do(ctx, http.MethodGet, "/flows", nil, &ns); err != nil {
		return nil, err
	}
	return ns, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s struct {
		Version string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "/settings", nil, &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Node-RED admin API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	ns, err := c.allNodes(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	flows, off := 0, 0
	for _, n := range ns {
		if n.Type == "tab" {
			flows++
			if n.Disabled {
				off++
			}
		}
	}
	msg := fmt.Sprintf("Node-RED %s, %d flows", clip(s.Version, 20), flows)
	if off > 0 {
		msg += fmt.Sprintf(", %d disabled", off)
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
		Flow   string `json:"flow"`
		Search string `json:"search"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "flows":
		ns, err := c.allNodes(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		count := map[string]int{}
		for _, n := range ns {
			if n.Z != "" {
				count[n.Z]++
			}
		}
		flows, subflows := []map[string]any{}, []map[string]any{}
		config := 0
		for _, n := range ns {
			switch {
			case n.Type == "tab":
				flows = append(flows, map[string]any{"id": n.ID, "name": clip(n.Label, 200), "disabled": n.Disabled, "nodes": count[n.ID]})
			case n.Type == "subflow":
				subflows = append(subflows, map[string]any{"id": n.ID, "name": clip(n.Name, 200), "nodes": count[n.ID]})
			case n.Z == "":
				config++
			}
		}
		return sdk.JSON(map[string]any{"flows": flows, "subflows": subflows, "configNodes": config})
	case "nodes":
		var sets []struct {
			ID      string   `json:"id"`
			Module  string   `json:"module"`
			Version string   `json:"version"`
			Enabled bool     `json:"enabled"`
			Types   []string `json:"types"`
			Err     string   `json:"err"`
		}
		if err := c.do(ctx, http.MethodGet, "/nodes", nil, &sets); err != nil {
			return sdk.Result{}, err
		}
		type mod struct {
			Version string
			Enabled bool
			Types   []string
			Errors  []string
		}
		mods := map[string]*mod{}
		q := strings.ToLower(strings.TrimSpace(p.Search))
		for _, s := range sets {
			if q != "" && !strings.Contains(strings.ToLower(s.Module+" "+strings.Join(s.Types, " ")), q) {
				continue
			}
			x := mods[s.Module]
			if x == nil {
				x = &mod{Version: s.Version}
				mods[s.Module] = x
			}
			if s.Enabled {
				x.Enabled = true
			}
			x.Types = append(x.Types, s.Types...)
			if s.Err != "" {
				x.Errors = append(x.Errors, clip(s.Err, 200))
			}
		}
		names := make([]string, 0, len(mods))
		for n := range mods {
			names = append(names, n)
		}
		sort.Strings(names)
		out := []map[string]any{}
		for _, n := range names {
			x := mods[n]
			sort.Strings(x.Types)
			row := map[string]any{"module": n, "version": x.Version, "enabled": x.Enabled, "types": x.Types}
			if len(x.Errors) > 0 {
				row["errors"] = x.Errors
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	case "disable_flow", "enable_flow":
		p.Flow = strings.TrimSpace(p.Flow)
		if !flowRe.MatchString(p.Flow) || p.Flow == "global" {
			return sdk.Result{}, errors.New("a flow is its id from flows")
		}
		return c.setFlow(ctx, call, p.Flow)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// setFlow enables or disables a flow. The flow's configuration goes back to
// Node-RED as it came, with only "disabled" changed; it's never returned.
func (c *conn) setFlow(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	disable := call.Action == "disable_flow"
	var f map[string]json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/flow/"+url.PathEscape(id), nil, &f); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no flow %s", id)
		}
		return sdk.Result{}, err
	}
	var head struct {
		ID       string `json:"id"`
		Label    string `json:"label"`
		Disabled bool   `json:"disabled"`
		Nodes    []any  `json:"nodes"`
	}
	b, _ := json.Marshal(f)
	if json.Unmarshal(b, &head) != nil || head.ID == "" {
		return sdk.Result{}, fmt.Errorf("there's no flow %s", id)
	}
	if head.ID != id {
		// The id goes into the update's path and the undo.
		return sdk.Result{}, fmt.Errorf("Node-RED answered with another flow for %s", id)
	}
	name := clip(head.Label, 200)
	if head.Disabled == disable {
		return sdk.JSON(map[string]any{"flow": id, "name": name, "disabled": disable, "note": "nothing to change"})
	}
	verb, back, undo := "Enable", "disable_flow", "Disable "+name+" again"
	if disable {
		verb, back, undo = "Disable", "enable_flow", "Enable "+name+" again"
	}
	if call.DryRun {
		bb, _ := json.Marshal(map[string]bool{"disabled": head.Disabled})
		ab, _ := json.Marshal(map[string]bool{"disabled": disable})
		sum := fmt.Sprintf("%s the flow %s (%d nodes)", verb, name, len(head.Nodes))
		if disable {
			sum += "; the automations it runs stop"
		} else {
			sum += "; its nodes run again"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "flow " + name, Op: strings.ToLower(verb), Before: bb, After: ab}}}}, nil
	}
	f["disabled"], _ = json.Marshal(disable)
	if err := c.do(ctx, http.MethodPut, "/flow/"+url.PathEscape(id), f, nil); err != nil {
		return sdk.Result{}, err
	}
	var after struct {
		Disabled bool `json:"disabled"`
	}
	if err := c.do(ctx, http.MethodGet, "/flow/"+url.PathEscape(id), nil, &after); err == nil && after.Disabled != disable {
		return sdk.Result{}, errors.New("Node-RED kept the flow as it was")
	}
	res, err := sdk.JSON(map[string]any{"flow": id, "name": name, "disabled": disable})
	res.Undo = sdk.UndoWith(back, map[string]string{"flow": id}, undo)
	return res, err
}
