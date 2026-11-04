// Package headscale works with a Headscale control server through its API
// key: nodes (online, last seen, addresses, routes), users, pre-auth keys
// (never their values), expiring and renaming nodes, and approving or
// withdrawing subnet and exit routes.
package headscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Headscale server.
type Config struct {
	URL                string `json:"url"`    // e.g. https://headscale.example.com
	APIKey             string `json:"apiKey"` // secret:// key from `headscale apikeys create`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client

	mu sync.Mutex
	// keysByName: this server lists pre-auth keys by user name (before
	// 0.26) rather than by user id.
	keysByName bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	now  func() time.Time
}

// New returns the Headscale module.
func New() *Module { return &Module{now: time.Now} }

var (
	pathRe  = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	nodeRe  = regexp.MustCompile(`^[0-9]{1,19}$`)
	labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Exit routes come in a pair; approving one without the other leaves the
// node half an exit node.
var exitRoutes = []string{"0.0.0.0/0", "::/0"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	node := `"node":{"type":"string","description":"Node id (from nodes)"}`
	route := `"route":{"type":"string","description":"The route's prefix, e.g. 10.0.0.0/24, or 0.0.0.0/0 for an exit node"}`
	return sdk.Manifest{
		ID: "headscale", Name: "Headscale", Version: "0.1.0", Category: "Network", Icon: "network",
		Description: "Headscale: nodes (online, last seen, routes), users and pre-auth keys; expire or rename nodes and approve or withdraw routes.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://headscale.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"An API key (headscale apikeys create --expiration 90d); it has full control of the server"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "nodes", Title: "Nodes", Description: "Every node: name, user, addresses, online, last seen, key expiry, tags, and its routes (advertised and approved).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"user":{"type":"string","description":"Only this user's nodes (name)"}}}`)},
			{Name: "users", Title: "Users", Description: "Users with their display name, provider and node count.", Risk: sdk.RiskRead},
			{Name: "routes", Title: "Routes", Description: "Subnet and exit routes by node: advertised, approved and serving.", Risk: sdk.RiskRead},
			{Name: "preauth_keys", Title: "Pre-auth keys", Description: "Each user's pre-auth keys: reusable, ephemeral, used, expiry and tags. Never the key itself.", Risk: sdk.RiskRead},
			{Name: "rename_node", Title: "Rename a node", Description: "Sets the node's name in the tailnet (its MagicDNS name). Undo puts the old name back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["node","name"],"properties":{` + node + `,"name":{"type":"string","description":"Lowercase letters, digits and dashes"}}}`)},
			{Name: "expire_node", Title: "Expire a node", Description: "Logs the node out: it has to authenticate again before it can reach the tailnet.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["node"],"properties":{` + node + `}}`)},
			{Name: "enable_route", Title: "Approve a route", Description: "Lets a node serve a route it advertises (a subnet, or both exit routes). Undo withdraws it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["node","route"],"properties":{` + node + `,` + route + `}}`)},
			{Name: "disable_route", Title: "Withdraw a route", Description: "Stops a node serving a route; clients using it lose that network. Undo approves it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["node","route"],"properties":{` + node + `,` + route + `}}`)},
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
		return errors.New("the address is like https://headscale.example.com")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
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
	ref := c.APIKey
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api/v1", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
		return errors.New("Headscale refused the API key")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

type user struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	CreatedAt   string `json:"createdAt"`
	Provider    string `json:"provider"`
}

type node struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	GivenName       string   `json:"givenName"`
	User            user     `json:"user"`
	IPAddresses     []string `json:"ipAddresses"`
	LastSeen        string   `json:"lastSeen"`
	Expiry          string   `json:"expiry"`
	CreatedAt       string   `json:"createdAt"`
	RegisterMethod  string   `json:"registerMethod"`
	Online          bool     `json:"online"`
	ForcedTags      []string `json:"forcedTags"`
	ValidTags       []string `json:"validTags"`
	Tags            []string `json:"tags"`
	ApprovedRoutes  []string `json:"approvedRoutes"`
	AvailableRoutes []string `json:"availableRoutes"`
	SubnetRoutes    []string `json:"subnetRoutes"`
}

func (n node) label() string {
	if n.GivenName != "" {
		return n.GivenName
	}
	if n.Name != "" {
		return n.Name
	}
	return "node " + n.ID
}

// oldRoute is a route as Headscale before 0.26 lists it (/api/v1/routes).
type oldRoute struct {
	ID         string `json:"id"`
	Node       node   `json:"node"`
	Prefix     string `json:"prefix"`
	Advertised bool   `json:"advertised"`
	Enabled    bool   `json:"enabled"`
	IsPrimary  bool   `json:"isPrimary"`
}

func (c *conn) nodes(ctx context.Context, q url.Values) ([]node, error) {
	var res struct {
		Nodes []node `json:"nodes"`
	}
	err := c.do(ctx, http.MethodGet, "/node", q, nil, &res)
	return res.Nodes, err
}

func (c *conn) node(ctx context.Context, id string) (node, error) {
	var res struct {
		Node node `json:"node"`
	}
	err := c.do(ctx, http.MethodGet, "/node/"+id, nil, nil, &res)
	if rest.IsStatus(err, http.StatusNotFound) {
		return node{}, fmt.Errorf("there's no node %s", id)
	}
	if err == nil && res.Node.ID == "" {
		return node{}, fmt.Errorf("there's no node %s", id)
	}
	return res.Node, err
}

// oldRoutes lists routes from the routes API Headscale had before 0.26. It
// answers ok=false on a server without it.
func (c *conn) oldRoutes(ctx context.Context) ([]oldRoute, bool, error) {
	var res struct {
		Routes []oldRoute `json:"routes"`
	}
	err := c.do(ctx, http.MethodGet, "/routes", nil, nil, &res)
	if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusNotImplemented) || rest.IsStatus(err, http.StatusMethodNotAllowed) {
		return nil, false, nil
	}
	return res.Routes, err == nil, err
}

func zeroTime(s string) bool { return s == "" || strings.HasPrefix(s, "0001-01-01") }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ns, err := c.nodes(ctx, nil)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Headscale API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	online := 0
	for _, n := range ns {
		if n.Online {
			online++
		}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d nodes, %d online", len(ns), online)}
}

type input struct {
	User  string `json:"user"`
	Node  string `json:"node"`
	Name  string `json:"name"`
	Route string `json:"route"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "nodes":
		return m.listNodes(ctx, c, p)
	case "users":
		return c.users(ctx)
	case "routes":
		return c.routes(ctx)
	case "preauth_keys":
		return m.preauthKeys(ctx, c)
	case "rename_node", "expire_node", "enable_route", "disable_route":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}

	// Everything below acts on one node: check the input before any request.
	p.Node = strings.TrimSpace(p.Node)
	if !nodeRe.MatchString(p.Node) {
		return sdk.Result{}, errors.New("a node is its numeric id from nodes")
	}
	var prefix netip.Prefix
	switch call.Action {
	case "rename_node":
		p.Name = strings.TrimSpace(p.Name)
		if !labelRe.MatchString(p.Name) {
			return sdk.Result{}, errors.New("a node name is lowercase letters, digits and dashes (at most 63), not starting or ending with a dash")
		}
	case "enable_route", "disable_route":
		pf, err := netip.ParsePrefix(strings.TrimSpace(p.Route))
		if err != nil || pf.Masked() != pf {
			return sdk.Result{}, errors.New("a route is a network prefix like 10.0.0.0/24 (with the host bits zero), or 0.0.0.0/0 for an exit node")
		}
		prefix = pf
	}
	n, err := c.node(ctx, p.Node)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "rename_node":
		return c.rename(ctx, call, n, p.Name)
	case "expire_node":
		return c.expire(ctx, call, n)
	}
	return c.setRoute(ctx, call, n, prefix)
}

func (m *Module) expired(n node) bool {
	if zeroTime(n.Expiry) {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, n.Expiry)
	return err == nil && t.Before(m.now())
}

func (m *Module) listNodes(ctx context.Context, c *conn, p input) (sdk.Result, error) {
	q := url.Values{}
	if u := strings.TrimSpace(p.User); u != "" {
		if len(u) > 200 || strings.ContainsAny(u, "\r\n\x00") {
			return sdk.Result{}, errors.New("the user is one line of at most 200 characters")
		}
		q.Set("user", u)
	}
	ns, err := c.nodes(ctx, q)
	if err != nil {
		return sdk.Result{}, err
	}
	// Before 0.26 a node doesn't carry its routes: read them from the
	// routes API.
	byNode := map[string][]oldRoute{}
	if !hasRouteFields(ns) {
		if rs, ok, err := c.oldRoutes(ctx); err == nil && ok {
			for _, r := range rs {
				byNode[r.Node.ID] = append(byNode[r.Node.ID], r)
			}
		}
	}
	out := []map[string]any{}
	for _, n := range ns {
		row := map[string]any{"id": n.ID, "name": n.label(), "hostname": n.Name, "user": n.User.Name, "addresses": nonNil(n.IPAddresses),
			"online": n.Online, "lastSeen": n.LastSeen, "created": n.CreatedAt, "tags": tags(n)}
		if zeroTime(n.Expiry) {
			row["keyExpires"] = "never"
		} else {
			row["keyExpires"] = n.Expiry
			if m.expired(n) {
				row["expired"] = true
			}
		}
		if rs, ok := byNode[n.ID]; ok {
			adv, appr := []string{}, []string{}
			for _, r := range rs {
				if r.Advertised {
					adv = append(adv, r.Prefix)
				}
				if r.Enabled {
					appr = append(appr, r.Prefix)
				}
			}
			row["advertisedRoutes"], row["approvedRoutes"] = adv, appr
		} else if len(n.AvailableRoutes)+len(n.ApprovedRoutes) > 0 {
			row["advertisedRoutes"], row["approvedRoutes"] = nonNil(n.AvailableRoutes), nonNil(n.ApprovedRoutes)
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

func hasRouteFields(ns []node) bool {
	for _, n := range ns {
		if n.AvailableRoutes != nil || n.ApprovedRoutes != nil || n.SubnetRoutes != nil {
			return true
		}
	}
	return false
}

func tags(n node) []string {
	set := map[string]bool{}
	for _, l := range [][]string{n.Tags, n.ForcedTags, n.ValidTags} {
		for _, t := range l {
			set[t] = true
		}
	}
	out := []string{}
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (c *conn) listUsers(ctx context.Context) ([]user, error) {
	var res struct {
		Users []user `json:"users"`
	}
	err := c.do(ctx, http.MethodGet, "/user", nil, nil, &res)
	return res.Users, err
}

func (c *conn) users(ctx context.Context) (sdk.Result, error) {
	us, err := c.listUsers(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	ns, err := c.nodes(ctx, nil)
	if err != nil {
		return sdk.Result{}, err
	}
	count := map[string]int{}
	for _, n := range ns {
		count[n.User.ID]++
	}
	// Email and profile picture stay out: what's returned here is logged.
	out := []map[string]any{}
	for _, u := range us {
		row := map[string]any{"id": u.ID, "name": u.Name, "created": u.CreatedAt, "nodes": count[u.ID]}
		if u.DisplayName != "" {
			row["displayName"] = u.DisplayName
		}
		if u.Provider != "" {
			row["provider"] = u.Provider
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

func (c *conn) routes(ctx context.Context) (sdk.Result, error) {
	ns, err := c.nodes(ctx, nil)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	if !hasRouteFields(ns) {
		rs, ok, err := c.oldRoutes(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if ok {
			for _, r := range rs {
				out = append(out, map[string]any{"node": r.Node.ID, "nodeName": r.Node.label(), "route": r.Prefix, "advertised": r.Advertised,
					"approved": r.Enabled, "serving": r.Enabled && r.IsPrimary, "exit": slices.Contains(exitRoutes, r.Prefix), "online": r.Node.Online})
			}
			return sdk.JSON(out)
		}
	}
	for _, n := range ns {
		seen := map[string]bool{}
		for _, l := range [][]string{n.AvailableRoutes, n.ApprovedRoutes} {
			for _, pf := range l {
				if seen[pf] {
					continue
				}
				seen[pf] = true
				out = append(out, map[string]any{"node": n.ID, "nodeName": n.label(), "route": pf, "advertised": slices.Contains(n.AvailableRoutes, pf),
					"approved": slices.Contains(n.ApprovedRoutes, pf), "serving": slices.Contains(n.SubnetRoutes, pf), "exit": slices.Contains(exitRoutes, pf), "online": n.Online})
			}
		}
	}
	return sdk.JSON(out)
}

type preauthKey struct {
	User       json.RawMessage `json:"user"` // a name before 0.26, a user object since
	ID         string          `json:"id"`
	Reusable   bool            `json:"reusable"`
	Ephemeral  bool            `json:"ephemeral"`
	Used       bool            `json:"used"`
	Expiration string          `json:"expiration"`
	CreatedAt  string          `json:"createdAt"`
	ACLTags    []string        `json:"aclTags"`
	// The key itself is never decoded.
}

func (c *conn) keysOf(ctx context.Context, u user) ([]preauthKey, error) {
	var res struct {
		Keys []preauthKey `json:"preAuthKeys"`
	}
	c.mu.Lock()
	byName := c.keysByName
	c.mu.Unlock()
	get := func(byName bool) error {
		v := u.ID
		if byName {
			v = u.Name
		}
		return c.do(ctx, http.MethodGet, "/preauthkey", url.Values{"user": {v}}, nil, &res)
	}
	err := get(byName)
	var re *rest.Error
	if err != nil && errors.As(err, &re) && re.Status >= 400 && re.Status != http.StatusUnauthorized && re.Status != http.StatusForbidden {
		// The other version's way of naming the user.
		if err2 := get(!byName); err2 == nil {
			c.mu.Lock()
			c.keysByName = !byName
			c.mu.Unlock()
			err = nil
		}
	}
	return res.Keys, err
}

func (m *Module) preauthKeys(ctx context.Context, c *conn) (sdk.Result, error) {
	us, err := c.listUsers(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, u := range us {
		keys, err := c.keysOf(ctx, u)
		if err != nil {
			return sdk.Result{}, err
		}
		for _, k := range keys {
			row := map[string]any{"id": k.ID, "user": u.Name, "reusable": k.Reusable, "ephemeral": k.Ephemeral, "used": k.Used,
				"expires": k.Expiration, "created": k.CreatedAt, "tags": nonNil(k.ACLTags)}
			if t, err := time.Parse(time.RFC3339Nano, k.Expiration); err == nil && !zeroTime(k.Expiration) {
				row["expired"] = t.Before(m.now())
			}
			out = append(out, row)
		}
	}
	return sdk.JSON(out)
}

func (c *conn) rename(ctx context.Context, call sdk.Call, n node, name string) (sdk.Result, error) {
	old := n.GivenName
	if old == name {
		return sdk.JSON(map[string]any{"node": n.ID, "name": name, "note": "nothing to change"})
	}
	if call.DryRun {
		b, _ := json.Marshal(old)
		a, _ := json.Marshal(name)
		return sdk.Result{Plan: &sdk.Plan{Summary: "Rename " + n.label() + " to " + name, Changes: []sdk.Change{{Target: "node " + n.ID, Op: "rename", Before: b, After: a}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, "/node/"+n.ID+"/rename/"+url.PathEscape(name), nil, map[string]any{}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"node": n.ID, "name": name, "was": old})
	if old != "" && labelRe.MatchString(old) {
		res.Undo = sdk.UndoWith("rename_node", map[string]string{"node": n.ID, "name": old}, "Rename it back to "+old)
	}
	return res, err
}

func (c *conn) expire(ctx context.Context, call sdk.Call, n node) (sdk.Result, error) {
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Expire " + n.label() + " (user " + n.User.Name + "): it has to log in again", Changes: []sdk.Change{{Target: "node " + n.ID + " (" + n.label() + ")", Op: "expire"}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, "/node/"+n.ID+"/expire", nil, map[string]any{}, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"node": n.ID, "name": n.label(), "expired": true})
}

// affected is the prefix and, for an exit route, its pair.
func affected(pf netip.Prefix) []string {
	s := pf.String()
	if slices.Contains(exitRoutes, s) {
		return exitRoutes
	}
	return []string{s}
}

func (c *conn) setRoute(ctx context.Context, call sdk.Call, n node, pf netip.Prefix) (sdk.Result, error) {
	enable := call.Action == "enable_route"
	want := affected(pf)
	rs, old, err := c.oldRoutes(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	// The routes this node advertises and the ones approved, either way.
	var adv, appr []string
	ids := map[string]string{}
	if old && !hasRouteFields([]node{n}) {
		for _, r := range rs {
			if r.Node.ID != n.ID {
				continue
			}
			if r.Advertised {
				adv = append(adv, r.Prefix)
			}
			if r.Enabled {
				appr = append(appr, r.Prefix)
			}
			ids[r.Prefix] = r.ID
		}
	} else {
		old = false
		adv, appr = n.AvailableRoutes, n.ApprovedRoutes
	}
	var change []string
	for _, w := range want {
		switch {
		case enable && !slices.Contains(adv, w):
			if w == pf.String() {
				return sdk.Result{}, fmt.Errorf("%s doesn't advertise %s", n.label(), w)
			}
		case enable && !slices.Contains(appr, w), !enable && slices.Contains(appr, w):
			change = append(change, w)
		}
	}
	verb, back, op := "Withdraw", "enable_route", "disable"
	if enable {
		verb, back, op = "Approve", "disable_route", "enable"
	}
	if len(change) == 0 {
		return sdk.JSON(map[string]any{"node": n.ID, "route": pf.String(), "approved": enable, "note": "nothing to change"})
	}
	target := "node " + n.ID + " (" + n.label() + ")"
	if call.DryRun {
		var cs []sdk.Change
		for _, r := range change {
			cs = append(cs, sdk.Change{Target: r + " on " + target, Op: op})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + strings.Join(change, " and ") + " on " + n.label(), Changes: cs}}, nil
	}
	if old {
		for _, r := range change {
			id := ids[r]
			if !nodeRe.MatchString(id) {
				return sdk.Result{}, fmt.Errorf("Headscale gave no usable id for %s", r)
			}
			if err := c.do(ctx, http.MethodPost, "/routes/"+id+"/"+op, nil, map[string]any{}, nil); err != nil {
				return sdk.Result{}, err
			}
		}
	} else {
		next := []string{}
		for _, r := range appr {
			if enable || !slices.Contains(change, r) {
				next = append(next, r)
			}
		}
		if enable {
			next = append(next, change...)
		}
		if err := c.do(ctx, http.MethodPost, "/node/"+n.ID+"/approve_routes", nil, map[string][]string{"routes": next}, nil); err != nil {
			return sdk.Result{}, err
		}
	}
	res, err := sdk.JSON(map[string]any{"node": n.ID, "name": n.label(), "routes": change, "approved": enable})
	undo := "Withdraw " + pf.String() + " again"
	if !enable {
		undo = "Approve " + pf.String() + " again"
	}
	res.Undo = sdk.UndoWith(back, map[string]string{"node": n.ID, "route": pf.String()}, undo)
	return res, err
}
