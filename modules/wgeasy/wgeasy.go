// Package wgeasy works with a wg-easy WireGuard server through its HTTP
// API: clients with their addresses, last handshake and traffic, turning
// clients on and off, creating and deleting them, and (only when asked, as
// a sensitive action) a client's configuration with its private key.
package wgeasy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one wg-easy server.
type Config struct {
	URL                string `json:"url"`      // e.g. https://vpn.example.com:51821
	Version            string `json:"version"`  // "15" (default) or "14" for wg-easy 14 and earlier
	Username           string `json:"username"` // wg-easy 15
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	legacy bool // wg-easy 14 and earlier: /api/wireguard, password session
	host   sdk.Host
	pass   string

	mu       sync.Mutex
	loggedIn bool
	now      func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the wg-easy module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// Client ids are integers in wg-easy 15 and UUIDs before.
	idRe   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	nameRe = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	client := `{"type":"object","required":["client"],"properties":{"client":{"type":"string","description":"Client name or id"}}}`
	return sdk.Manifest{
		ID: "wgeasy", Name: "wg-easy", Version: "0.1.0", Category: "Network", Icon: "shield",
		Description: "wg-easy WireGuard clients: addresses, handshakes and traffic, turn clients on or off, create and delete them. Private keys are never shown except by the sensitive config action.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","password"],"properties":{
			"url":{"type":"string","description":"The wg-easy web UI address, e.g. https://vpn.example.com or http://server:51821"},
			"version":{"type":"string","enum":["15","14"],"default":"15","description":"15 for wg-easy 15 and later (username and password); 14 for wg-easy 14 and earlier (password only)"},
			"username":{"type":"string","description":"The admin username (wg-easy 15)"},
			"password":{"type":"string","x-secret":true,"description":"The admin password (wg-easy 15: two-factor must be off for this user, as the API takes basic auth)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "clients", Title: "Clients", Description: "Every client with on/off, addresses, public key, last handshake, whether it's connected, traffic and expiry. Never private or preshared keys.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string"},"online":{"type":"boolean","description":"Only clients with a handshake in the last 3 minutes"}}}`)},
			{Name: "traffic", Title: "Traffic", Description: "Bytes received and sent per client, largest first, with totals and how many are connected.", Risk: sdk.RiskRead},
			{Name: "enable_client", Title: "Turn a client on", Description: "Gives a turned-off client its network access back. Destructive: an admin may have turned it off to revoke a lost or compromised device. Undo turns it off again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(client)},
			{Name: "disable_client", Title: "Turn a client off", Description: "The client can't connect until it's turned on. Undo turns it on again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(client)},
			{Name: "create_client", Title: "Create a client", Description: "Adds a client with new keys and the next free address. The answer never includes its private key (use config, which is destructive), so creating one grants nobody access by itself. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["name"],"properties":{"name":{"type":"string","maxLength":64},"expiresAt":{"type":"string","format":"date","description":"Optional expiry date, e.g. 2026-12-31"}}}`)},
			{Name: "delete_client", Title: "Delete a client", Description: "Removes the client and its keys; the device can't connect again with its configuration. Can't be undone.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(client)},
			{Name: "config", Title: "Client configuration", Description: "The client's WireGuard configuration file, including its private key.", Risk: sdk.RiskDestructive, Sensitive: true, Input: sdk.Schema(client)},
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
		return errors.New("the address is like https://vpn.example.com")
	}
	legacy := false
	switch c.Version {
	case "", "15":
	case "14":
		legacy = true
	default:
		return errors.New("the version is 15 (wg-easy 15 and later) or 14 (wg-easy 14 and earlier)")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	user := strings.TrimSpace(c.Username)
	if !legacy && (user == "" || strings.ContainsAny(user, ":\r\n")) {
		return errors.New("enter the admin username (wg-easy 15)")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	client = rest.SameHostOnly(client)
	if legacy {
		jar, _ := cookiejar.New(nil) // the session cookie
		client.Jar = jar
	}
	cn := &conn{legacy: legacy, host: h, pass: c.Password, now: time.Now}
	var auth func(context.Context, *http.Request) error
	if !legacy {
		auth = func(ctx context.Context, r *http.Request) error {
			pw, err := h.Secret(ctx, c.Password)
			if err != nil {
				return err
			}
			r.SetBasicAuth(user, pw)
			return nil
		}
	}
	cn.api = rest.New(u.Scheme+"://"+u.Host+strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")+"/api", auth)
	cn.api.HTTP = client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errRefused = errors.New("wg-easy refused the username or password")

// login starts a session (wg-easy 14 and earlier).
func (c *conn) login(ctx context.Context) error {
	pw, err := c.host.Secret(ctx, c.pass)
	if err != nil {
		return err
	}
	_, err = c.api.Do(ctx, http.MethodPost, "/session", nil, map[string]string{"password": pw}, nil)
	if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
		return errRefused
	}
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.loggedIn = true
	c.mu.Unlock()
	return nil
}

func (c *conn) do(ctx context.Context, method, path string, body, out any) error {
	if c.legacy {
		c.mu.Lock()
		in := c.loggedIn
		c.mu.Unlock()
		if !in {
			if err := c.login(ctx); err != nil {
				return err
			}
		}
	}
	_, err := c.api.Do(ctx, method, path, nil, body, out)
	if c.legacy && rest.IsStatus(err, http.StatusUnauthorized) {
		if err := c.login(ctx); err != nil {
			return err
		}
		_, err = c.api.Do(ctx, method, path, nil, body, out)
	}
	if rest.IsStatus(err, http.StatusUnauthorized) {
		return errRefused
	}
	if rest.IsStatus(err, http.StatusForbidden) {
		return errors.New("wg-easy refused the request: this needs an admin")
	}
	return err
}

func (c *conn) base() string {
	if c.legacy {
		return "/wireguard/client"
	}
	return "/client"
}

// client is what the module reads from wg-easy. Keys other than the public
// key are deliberately not decoded.
type client struct {
	ID         json.RawMessage `json:"id"`
	Name       string          `json:"name"`
	Enabled    bool            `json:"enabled"`
	Address    string          `json:"address"`     // 14
	IPv4       string          `json:"ipv4Address"` // 15
	IPv6       string          `json:"ipv6Address"`
	PublicKey  string          `json:"publicKey"`
	CreatedAt  string          `json:"createdAt"`
	ExpiresAt  *string         `json:"expiresAt"`
	ExpiredAt  *string         `json:"expiredAt"`
	Handshake  *string         `json:"latestHandshakeAt"`
	Endpoint   *string         `json:"endpoint"`
	TransferRx *float64        `json:"transferRx"`
	TransferTx *float64        `json:"transferTx"`
}

func (k client) id() string {
	var s string
	if json.Unmarshal(k.ID, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(k.ID, &n) == nil {
		return n.String()
	}
	return ""
}

func (k client) addr() string {
	if k.IPv4 != "" {
		return k.IPv4
	}
	return k.Address
}

func (k client) expiry() string {
	for _, s := range []*string{k.ExpiresAt, k.ExpiredAt} {
		if s != nil && *s != "" {
			return *s
		}
	}
	return ""
}

func (c *conn) online(k client) bool {
	if k.Handshake == nil || *k.Handshake == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, *k.Handshake)
	return err == nil && c.now().Sub(t) < 3*time.Minute
}

func num(f *float64) int64 {
	if f == nil {
		return 0
	}
	return int64(*f)
}

func (c *conn) clientOut(k client) map[string]any {
	e := map[string]any{"id": k.id(), "name": k.Name, "enabled": k.Enabled, "address": k.addr(), "publicKey": k.PublicKey,
		"online": c.online(k), "receivedBytes": num(k.TransferRx), "sentBytes": num(k.TransferTx)}
	if k.IPv6 != "" {
		e["ipv6Address"] = k.IPv6
	}
	if k.Handshake != nil && *k.Handshake != "" {
		e["latestHandshake"] = *k.Handshake
	}
	if k.Endpoint != nil && *k.Endpoint != "" {
		e["endpoint"] = *k.Endpoint
	}
	if k.CreatedAt != "" {
		e["createdAt"] = k.CreatedAt
	}
	if x := k.expiry(); x != "" {
		e["expiresAt"] = x
	}
	return e
}

func (c *conn) clients(ctx context.Context) ([]client, error) {
	var list []client
	if err := c.do(ctx, http.MethodGet, c.base(), nil, &list); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			if c.legacy {
				return nil, errors.New("no wg-easy 14 API at this address (for wg-easy 15, set the version to 15)")
			}
			return nil, errors.New("no wg-easy 15 API at this address (for wg-easy 14 and earlier, set the version to 14)")
		}
		return nil, err
	}
	return list, nil
}

func (c *conn) find(ctx context.Context, ref string) (client, error) {
	ref = strings.TrimSpace(ref)
	if !nameRe.MatchString(ref) {
		return client{}, errors.New("enter the client's name or id")
	}
	list, err := c.clients(ctx)
	if err != nil {
		return client{}, err
	}
	var hits []client
	for _, k := range list {
		if k.id() == ref {
			hits = []client{k}
			break
		}
		if k.Name == ref {
			hits = append(hits, k)
		}
	}
	if len(hits) == 0 {
		for _, k := range list {
			if strings.EqualFold(k.Name, ref) {
				hits = append(hits, k)
			}
		}
	}
	switch {
	case len(hits) == 0:
		return client{}, fmt.Errorf("there's no client %s", ref)
	case len(hits) > 1:
		return client{}, fmt.Errorf("%d clients are called %s; use the id", len(hits), ref)
	}
	if !idRe.MatchString(hits[0].id()) {
		return client{}, errors.New("unexpected client id from wg-easy")
	}
	return hits[0], nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	list, err := c.clients(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	online := 0
	for _, k := range list {
		if c.online(k) {
			online++
		}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d clients · %d connected", len(list), online)}
}

type input struct {
	Client    string `json:"client"`
	Search    string `json:"search"`
	Online    *bool  `json:"online"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expiresAt"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
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
	case "clients":
		list, err := c.clients(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.SliceStable(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
		s := strings.ToLower(strings.TrimSpace(p.Search))
		out := []map[string]any{}
		for _, k := range list {
			if s != "" && !strings.Contains(strings.ToLower(k.Name), s) && !strings.Contains(k.addr(), s) {
				continue
			}
			if p.Online != nil && c.online(k) != *p.Online {
				continue
			}
			out = append(out, c.clientOut(k))
		}
		return sdk.JSON(out)

	case "traffic":
		list, err := c.clients(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.SliceStable(list, func(i, j int) bool {
			return num(list[i].TransferRx)+num(list[i].TransferTx) > num(list[j].TransferRx)+num(list[j].TransferTx)
		})
		var rx, tx int64
		online := 0
		out := []map[string]any{}
		for _, k := range list {
			rx, tx = rx+num(k.TransferRx), tx+num(k.TransferTx)
			if c.online(k) {
				online++
			}
			e := map[string]any{"name": k.Name, "receivedBytes": num(k.TransferRx), "sentBytes": num(k.TransferTx), "online": c.online(k)}
			if k.Handshake != nil && *k.Handshake != "" {
				e["latestHandshake"] = *k.Handshake
			}
			out = append(out, e)
		}
		return sdk.JSON(map[string]any{"clients": out, "receivedBytes": rx, "sentBytes": tx, "connected": online, "total": len(list)})

	case "enable_client", "disable_client":
		k, err := c.find(ctx, p.Client)
		if err != nil {
			return sdk.Result{}, err
		}
		want := call.Action == "enable_client"
		word := map[bool]string{true: "on", false: "off"}
		if k.Enabled == want {
			return sdk.Result{}, fmt.Errorf("%s is already %s", k.Name, word[want])
		}
		if call.DryRun {
			sum := "Turn client " + k.Name + " (" + k.addr() + ") " + word[want]
			if !want && c.online(k) {
				sum += "; it's connected now and will be cut off"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "client " + k.Name, Op: "update", Before: mustJSON(map[string]bool{"enabled": k.Enabled}), After: mustJSON(map[string]bool{"enabled": want})}}}}, nil
		}
		verb := map[bool]string{true: "enable", false: "disable"}[want]
		if err := c.do(ctx, http.MethodPost, c.base()+"/"+k.id()+"/"+verb, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"client": k.Name, "enabled": want})
		back := map[bool]string{true: "disable_client", false: "enable_client"}[want]
		res.Undo = sdk.UndoWith(back, map[string]string{"client": k.id()}, "Turn "+k.Name+" "+word[!want])
		return res, err

	case "create_client":
		return c.create(ctx, call, p)

	case "delete_client":
		k, err := c.find(ctx, p.Client)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			sum := "Delete client " + k.Name + " (" + k.addr() + ") and its keys; this can't be undone"
			if c.online(k) {
				sum += "; it's connected now"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "client " + k.Name, Op: "delete", Before: mustJSON(c.clientOut(k))}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, c.base()+"/"+k.id(), nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": k.Name, "id": k.id()})

	case "config":
		k, err := c.find(ctx, p.Client)
		if err != nil {
			return sdk.Result{}, err
		}
		text, err := c.configText(ctx, k.id())
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"client": k.Name, "filename": safeFile(k.Name) + ".conf", "config": text})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func safeFile(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 128 && (r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "client"
	}
	return b.String()
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	name := strings.TrimSpace(p.Name)
	if !nameRe.MatchString(name) {
		return sdk.Result{}, errors.New("the name is 1 to 64 characters")
	}
	var exp any
	if p.ExpiresAt != "" {
		d, err := time.Parse("2006-01-02", p.ExpiresAt)
		if err != nil || !d.After(c.now()) {
			return sdk.Result{}, errors.New("expiresAt is a future date like 2026-12-31")
		}
		exp = p.ExpiresAt
	}
	list, err := c.clients(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	seen := map[string]bool{}
	for _, k := range list {
		seen[k.id()] = true
		if strings.EqualFold(k.Name, name) {
			return sdk.Result{}, fmt.Errorf("there's already a client called %s", k.Name)
		}
	}
	if call.DryRun {
		after := map[string]any{"name": name}
		if exp != nil {
			after["expiresAt"] = exp
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: "Create WireGuard client " + name + " with new keys and the next free address",
			Changes: []sdk.Change{{Target: "client " + name, Op: "create", After: mustJSON(after)}}}}, nil
	}
	body := map[string]any{"name": name, "expiresAt": exp}
	if c.legacy {
		body = map[string]any{"name": name}
		if exp != nil {
			body["expiredDate"] = exp
		}
	}
	var raw json.RawMessage // never returned: it may hold keys
	if err := c.do(ctx, http.MethodPost, c.base(), body, &raw); err != nil {
		return sdk.Result{}, err
	}
	var created map[string]any
	_ = json.Unmarshal(raw, &created)
	// Find the new client by id when wg-easy says it, else as the one
	// client with this name that wasn't there before.
	after, err := c.clients(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	want := ""
	for _, k := range []string{"clientId", "id"} {
		switch v := created[k].(type) {
		case float64:
			want = strconv.FormatInt(int64(v), 10)
		case string:
			want = v
		}
		if want != "" {
			break
		}
	}
	var hit *client
	for i, k := range after {
		if (want != "" && k.id() == want) || (want == "" && !seen[k.id()] && k.Name == name) {
			hit = &after[i]
			break
		}
	}
	if hit == nil || !idRe.MatchString(hit.id()) {
		return sdk.JSON(map[string]any{"created": name, "note": "wg-easy created the client but it couldn't be found afterwards, so there's no undo"})
	}
	res, err := sdk.JSON(map[string]any{"created": c.clientOut(*hit)})
	res.Undo = sdk.UndoWith("delete_client", map[string]string{"client": hit.id()}, "Delete client "+name)
	return res, err
}

// configText reads the client's configuration file.
func (c *conn) configText(ctx context.Context, id string) (string, error) {
	get := func() (int, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.api.Base+c.base()+"/"+id+"/configuration", nil)
		if err != nil {
			return 0, "", err
		}
		req.Header.Set("User-Agent", "Conduit")
		if c.api.Auth != nil {
			if err := c.api.Auth(ctx, req); err != nil {
				return 0, "", err
			}
		}
		res, err := c.api.HTTP.Do(req)
		if err != nil {
			return 0, "", rest.TransportError(err)
		}
		defer res.Body.Close()
		b, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		return res.StatusCode, string(b), err
	}
	if c.legacy {
		c.mu.Lock()
		in := c.loggedIn
		c.mu.Unlock()
		if !in {
			if err := c.login(ctx); err != nil {
				return "", err
			}
		}
	}
	st, text, err := get()
	if err == nil && st == http.StatusUnauthorized && c.legacy {
		if err := c.login(ctx); err != nil {
			return "", err
		}
		st, text, err = get()
	}
	switch {
	case err != nil:
		return "", err
	case st == http.StatusUnauthorized:
		return "", errRefused
	case st >= 300:
		return "", fmt.Errorf("wg-easy answered %d", st)
	case !strings.Contains(text, "[Interface]"):
		return "", errors.New("unexpected configuration from wg-easy")
	}
	return text, nil
}
