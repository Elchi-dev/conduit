// Package npm works with Nginx Proxy Manager through its API: proxy hosts
// (list, enable and disable, create, delete) and SSL certificates with their
// expiry. NPM has no API keys, so the module signs in with an account's
// email and password and keeps the token it hands out.
package npm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
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

// Config is one Nginx Proxy Manager.
type Config struct {
	URL                string `json:"url"`      // admin UI, e.g. http://nas.lan:81
	Email              string `json:"email"`    // account email
	Password           string `json:"password"` // secret:// account password
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api, login *rest.Client
	origin     string
	email      string
	pass       string // secret:// reference
	h          sdk.Host

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	now  func() time.Time
}

// New returns the Nginx Proxy Manager module.
func New() *Module { return &Module{now: time.Now} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	hostRe   = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	id := `{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1,"description":"Proxy host id (from proxy_hosts)"}}}`
	return sdk.Manifest{
		ID: "npm", Name: "Nginx Proxy Manager", Version: "0.1.0", Category: "Network", Icon: "globe",
		Description: "Nginx Proxy Manager: proxy hosts (list, enable, disable, create, delete) and SSL certificates with their expiry.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","email","password"],"properties":{
			"url":{"type":"string","description":"The admin UI's address, e.g. http://nas.lan:81"},
			"email":{"type":"string","description":"Email of the NPM account to act as (best a separate user with only the permissions it needs)"},
			"password":{"type":"string","x-secret":true,"description":"That account's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the admin UI's certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "proxy_hosts", Title: "Proxy hosts", Description: "Every proxy host: domains, where it forwards, SSL certificate and whether it's forced, access list, enabled, and nginx errors.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string","description":"Part of a domain or forward host"}}}`)},
			{Name: "enable", Title: "Enable a proxy host", Description: "Turns a proxy host on. Undo disables it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(id)},
			{Name: "disable", Title: "Disable a proxy host", Description: "Turns a proxy host off, so its domains stop being served. Undo enables it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(id)},
			{Name: "certificates", Title: "Certificates", Description: "SSL certificates with domains, provider and days until they expire, soonest first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"withinDays":{"type":"integer","minimum":1,"maximum":3650,"description":"Only those expiring within this many days (expired included)"}}}`)},
			{Name: "create_proxy_host", Title: "Create a proxy host", Description: "Publishes domains by forwarding them to a service. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["domains","forwardHost","forwardPort"],"properties":{
					"domains":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"string"},"description":"Domain names, e.g. app.example.com or *.example.com"},
					"forwardScheme":{"type":"string","enum":["http","https"],"default":"http"},
					"forwardHost":{"type":"string","description":"Host name or IP of the service"},
					"forwardPort":{"type":"integer","minimum":1,"maximum":65535},
					"certificateId":{"type":"integer","minimum":0,"default":0,"description":"An existing certificate's id (from certificates); 0 for none"},
					"sslForced":{"type":"boolean","default":false,"description":"Redirect HTTP to HTTPS (needs a certificate)"},
					"http2":{"type":"boolean","default":false},
					"hstsEnabled":{"type":"boolean","default":false},
					"hstsSubdomains":{"type":"boolean","default":false},
					"blockExploits":{"type":"boolean","default":true},
					"websockets":{"type":"boolean","default":false,"description":"Allow WebSocket upgrades"},
					"cachingEnabled":{"type":"boolean","default":false},
					"accessListId":{"type":"integer","minimum":0,"default":0},
					"advancedConfig":{"type":"string","description":"Custom nginx configuration (shown in full in the preview)"},
					"locations":{"type":"array","maxItems":50,"items":{"type":"object"},"description":"Custom locations, as NPM stores them"},
					"enabled":{"type":"boolean","default":true}}}`)},
			{Name: "delete_proxy_host", Title: "Delete a proxy host", Description: "Deletes a proxy host; its domains stop being served. Undo creates it again with the same settings (under a new id).", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(id)},
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
		return errors.New("the address is like http://nas.lan:81")
	}
	if !strings.Contains(c.Email, "@") {
		return errors.New("enter the account's email")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second) // through the instance's network, if any
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
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	cn := &conn{origin: origin, email: strings.TrimSpace(c.Email), pass: c.Password, h: h}
	cn.login = rest.New(origin+"/api", nil)
	cn.login.HTTP = client
	cn.api = rest.New(origin+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := cn.bearer(ctx, m.now)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errLogin = errors.New("Nginx Proxy Manager refused the email or password")

// bearer returns a token, signing in when there's none or it's about to expire.
func (c *conn) bearer(ctx context.Context, now func() time.Time) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && now().Before(c.expires.Add(-time.Minute)) {
		return c.token, nil
	}
	pw, err := c.h.Secret(ctx, c.pass)
	if err != nil {
		return "", err
	}
	var out struct {
		Token     string `json:"token"`
		Expires   string `json:"expires"`
		Requires2 string `json:"requires_2fa"`
	}
	if _, err := c.login.Do(ctx, http.MethodPost, "/tokens", nil, map[string]string{"identity": c.email, "secret": pw}, &out); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusForbidden) {
			return "", errLogin
		}
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("Nginx Proxy Manager gave no token (is two-factor sign-in on for this account? Use one without it)")
	}
	c.token = out.Token
	c.expires = now().Add(time.Hour)
	if t, err := time.Parse(time.RFC3339, out.Expires); err == nil {
		c.expires = t
	}
	return c.token, nil
}

// do calls the API, signing in again once if the token was revoked.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		_, err = c.api.Do(ctx, method, path, q, body, out)
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s struct {
		Status  string `json:"status"`
		Version struct {
			Major, Minor, Revision int
		} `json:"version"`
	}
	if _, err := c.login.Do(ctx, http.MethodGet, "/", nil, nil, &s); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var me struct {
		Email string `json:"email"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/me", nil, nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("Nginx Proxy Manager %d.%d.%d", s.Version.Major, s.Version.Minor, s.Version.Revision)
	if s.Status != "" && s.Status != "OK" {
		return sdk.Health{Status: "degraded", Message: msg + " · status " + s.Status}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// flag reads NPM's booleans, which older versions send as 0 and 1.
type flag bool

func (f *flag) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	*f = flag(s == "true" || s == "1")
	return nil
}

type proxyHost struct {
	ID             int               `json:"id"`
	Domains        []string          `json:"domain_names"`
	ForwardScheme  string            `json:"forward_scheme"`
	ForwardHost    string            `json:"forward_host"`
	ForwardPort    int               `json:"forward_port"`
	CertificateID  json.RawMessage   `json:"certificate_id"` // a number, or "new" while one is requested
	SSLForced      flag              `json:"ssl_forced"`
	HTTP2          flag              `json:"http2_support"`
	HSTS           flag              `json:"hsts_enabled"`
	HSTSSubdomains flag              `json:"hsts_subdomains"`
	BlockExploits  flag              `json:"block_exploits"`
	Websockets     flag              `json:"allow_websocket_upgrade"`
	Caching        flag              `json:"caching_enabled"`
	AccessListID   int               `json:"access_list_id"`
	AdvancedConfig string            `json:"advanced_config"`
	Locations      []json.RawMessage `json:"locations"`
	Enabled        flag              `json:"enabled"`
	Meta           struct {
		NginxOnline *bool  `json:"nginx_online"`
		NginxErr    string `json:"nginx_err"`
	} `json:"meta"`
	Certificate *struct {
		NiceName string `json:"nice_name"`
	} `json:"certificate"`
	AccessList *struct {
		Name string `json:"name"`
	} `json:"access_list"`
}

func (p proxyHost) certID() int {
	n, _ := strconv.Atoi(strings.Trim(string(p.CertificateID), `"`))
	return n
}

func (p proxyHost) name() string { return strings.Join(p.Domains, ", ") }

func (p proxyHost) summary() map[string]any {
	e := map[string]any{"id": p.ID, "domains": p.Domains, "forward": fmt.Sprintf("%s://%s:%d", p.ForwardScheme, p.ForwardHost, p.ForwardPort),
		"enabled": bool(p.Enabled), "sslForced": bool(p.SSLForced), "http2": bool(p.HTTP2), "hsts": bool(p.HSTS), "websockets": bool(p.Websockets),
		"blockExploits": bool(p.BlockExploits), "customLocations": len(p.Locations), "advancedConfig": strings.TrimSpace(p.AdvancedConfig) != ""}
	if id := p.certID(); id > 0 {
		e["certificateId"] = id
		if p.Certificate != nil {
			e["certificate"] = p.Certificate.NiceName
		}
	}
	if p.AccessListID > 0 {
		e["accessListId"] = p.AccessListID
		if p.AccessList != nil {
			e["accessList"] = p.AccessList.Name
		}
	}
	if p.Meta.NginxOnline != nil && !*p.Meta.NginxOnline {
		e["nginxError"] = p.Meta.NginxErr
	}
	return e
}

// createInput mirrors create_proxy_host's input; delete's undo fills it
// from the deleted host.
type createInput struct {
	Domains        []string          `json:"domains"`
	ForwardScheme  string            `json:"forwardScheme,omitempty"`
	ForwardHost    string            `json:"forwardHost"`
	ForwardPort    int               `json:"forwardPort"`
	CertificateID  int               `json:"certificateId,omitempty"`
	SSLForced      bool              `json:"sslForced,omitempty"`
	HTTP2          bool              `json:"http2,omitempty"`
	HSTSEnabled    bool              `json:"hstsEnabled,omitempty"`
	HSTSSubdomains bool              `json:"hstsSubdomains,omitempty"`
	BlockExploits  *bool             `json:"blockExploits,omitempty"`
	Websockets     bool              `json:"websockets,omitempty"`
	CachingEnabled bool              `json:"cachingEnabled,omitempty"`
	AccessListID   int               `json:"accessListId,omitempty"`
	AdvancedConfig string            `json:"advancedConfig,omitempty"`
	Locations      []json.RawMessage `json:"locations,omitempty"`
	Enabled        *bool             `json:"enabled,omitempty"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "proxy_hosts":
		var p struct {
			Query string `json:"query"`
		}
		if err := sdk.Decode(call, &p); err != nil {
			return sdk.Result{}, err
		}
		hosts, err := c.hosts(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		needle := strings.ToLower(strings.TrimSpace(p.Query))
		out := []map[string]any{}
		for _, h := range hosts {
			if needle != "" && !strings.Contains(strings.ToLower(h.name()+" "+h.ForwardHost), needle) {
				continue
			}
			out = append(out, h.summary())
		}
		return sdk.JSON(out)

	case "enable", "disable", "delete_proxy_host":
		var p struct {
			ID any `json:"id"`
		}
		if err := sdk.Decode(call, &p); err != nil {
			return sdk.Result{}, err
		}
		f, ok := p.ID.(float64)
		if !ok || f < 1 || f != float64(int(f)) || f > 1e9 {
			return sdk.Result{}, errors.New("enter the proxy host id (a positive number, from proxy_hosts)")
		}
		id := int(f)
		h, err := c.host(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.Action == "delete_proxy_host" {
			return c.deleteHost(ctx, call.DryRun, h)
		}
		enabling := call.Action == "enable"
		if bool(h.Enabled) == enabling {
			return sdk.JSON(map[string]any{"id": id, "enabled": enabling, "note": "nothing to change"})
		}
		back := "disable"
		if !enabling {
			back = "enable"
		}
		if call.DryRun {
			b, _ := json.Marshal(map[string]bool{"enabled": !enabling})
			a, _ := json.Marshal(map[string]bool{"enabled": enabling})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s the proxy host for %s", strings.ToUpper(call.Action[:1])+call.Action[1:], h.name()),
				Changes: []sdk.Change{{Target: "proxy host " + h.name(), Op: call.Action, Before: b, After: a}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/nginx/proxy-hosts/"+strconv.Itoa(id)+"/"+call.Action, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"id": id, "domains": h.Domains, "enabled": enabling})
		res.Undo = sdk.UndoWith(back, map[string]any{"id": id}, fmt.Sprintf("%s the proxy host for %s again", strings.ToUpper(back[:1])+back[1:], h.name()))
		return res, err

	case "certificates":
		var p struct {
			WithinDays int `json:"withinDays"`
		}
		if err := sdk.Decode(call, &p); err != nil {
			return sdk.Result{}, err
		}
		return c.certificates(ctx, m.now(), p.WithinDays)

	case "create_proxy_host":
		var p createInput
		if err := sdk.Decode(call, &p); err != nil {
			return sdk.Result{}, err
		}
		return c.create(ctx, call.DryRun, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) hosts(ctx context.Context) ([]proxyHost, error) {
	var hosts []proxyHost
	if err := c.do(ctx, http.MethodGet, "/nginx/proxy-hosts", url.Values{"expand": {"certificate,access_list"}}, nil, &hosts); err != nil {
		return nil, err
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].name() < hosts[j].name() })
	return hosts, nil
}

func (c *conn) host(ctx context.Context, id int) (proxyHost, error) {
	var h proxyHost
	if err := c.do(ctx, http.MethodGet, "/nginx/proxy-hosts/"+strconv.Itoa(id), url.Values{"expand": {"certificate,access_list"}}, nil, &h); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return h, fmt.Errorf("there's no proxy host %d", id)
		}
		return h, err
	}
	return h, nil
}

func (c *conn) deleteHost(ctx context.Context, dry bool, h proxyHost) (sdk.Result, error) {
	before, _ := json.Marshal(h.summary())
	if dry {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Delete the proxy host for " + h.name(),
			Changes: []sdk.Change{{Target: "proxy host " + h.name(), Op: "delete", Before: before}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, "/nginx/proxy-hosts/"+strconv.Itoa(h.ID), nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	be, en := bool(h.BlockExploits), bool(h.Enabled)
	scheme := h.ForwardScheme
	if scheme != "https" {
		scheme = "http"
	}
	again := createInput{Domains: h.Domains, ForwardScheme: scheme, ForwardHost: h.ForwardHost, ForwardPort: h.ForwardPort,
		CertificateID: h.certID(), SSLForced: bool(h.SSLForced), HTTP2: bool(h.HTTP2), HSTSEnabled: bool(h.HSTS), HSTSSubdomains: bool(h.HSTSSubdomains),
		BlockExploits: &be, Websockets: bool(h.Websockets), CachingEnabled: bool(h.Caching), AccessListID: h.AccessListID,
		AdvancedConfig: h.AdvancedConfig, Locations: h.Locations, Enabled: &en}
	res, err := sdk.JSON(map[string]any{"deleted": h.ID, "domains": h.Domains})
	res.Undo = sdk.UndoWith("create_proxy_host", again, "Recreate the proxy host for "+h.name())
	return res, err
}

func (c *conn) create(ctx context.Context, dry bool, p createInput) (sdk.Result, error) {
	if len(p.Domains) == 0 || len(p.Domains) > 20 {
		return sdk.Result{}, errors.New("give 1 to 20 domain names")
	}
	var domains []string
	seen := map[string]bool{}
	for _, d := range p.Domains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if len(d) > 253 || !domainRe.MatchString(d) {
			return sdk.Result{}, fmt.Errorf("%q isn't a domain name", d)
		}
		if !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	scheme := p.ForwardScheme
	if scheme == "" {
		scheme = "http"
	}
	if scheme != "http" && scheme != "https" {
		return sdk.Result{}, errors.New("forwardScheme is http or https")
	}
	// The forward host lands in nginx's configuration, so it's a plain host
	// name or IP address and nothing else.
	fh := strings.TrimSpace(p.ForwardHost)
	if fh == "" || len(fh) > 253 || (net.ParseIP(fh) == nil && !hostRe.MatchString(fh)) {
		return sdk.Result{}, errors.New("forwardHost is a host name or an IP address")
	}
	if p.ForwardPort < 1 || p.ForwardPort > 65535 {
		return sdk.Result{}, errors.New("forwardPort is 1 to 65535")
	}
	if p.CertificateID < 0 || p.AccessListID < 0 {
		return sdk.Result{}, errors.New("certificateId and accessListId are 0 or an existing id")
	}
	if p.SSLForced && p.CertificateID == 0 {
		return sdk.Result{}, errors.New("sslForced needs a certificate (certificateId)")
	}
	if len(p.Locations) > 50 || len(p.AdvancedConfig) > 64<<10 {
		return sdk.Result{}, errors.New("at most 50 locations and 64 KB of advanced configuration")
	}
	for _, l := range p.Locations {
		var o map[string]any
		if json.Unmarshal(l, &o) != nil {
			return sdk.Result{}, errors.New("each location is an object")
		}
	}
	hosts, err := c.hosts(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	for _, h := range hosts {
		for _, d := range h.Domains {
			if seen[strings.ToLower(d)] {
				return sdk.Result{}, fmt.Errorf("%s is already served by proxy host %d", d, h.ID)
			}
		}
	}
	block := p.BlockExploits == nil || *p.BlockExploits
	enabled := p.Enabled == nil || *p.Enabled
	locations := p.Locations
	if locations == nil {
		locations = []json.RawMessage{}
	}
	body := map[string]any{"domain_names": domains, "forward_scheme": scheme, "forward_host": fh, "forward_port": p.ForwardPort,
		"certificate_id": p.CertificateID, "ssl_forced": p.SSLForced, "http2_support": p.HTTP2, "hsts_enabled": p.HSTSEnabled,
		"hsts_subdomains": p.HSTSSubdomains, "block_exploits": block, "allow_websocket_upgrade": p.Websockets,
		"caching_enabled": p.CachingEnabled, "access_list_id": p.AccessListID, "advanced_config": p.AdvancedConfig,
		"locations": locations, "meta": map[string]any{"letsencrypt_agree": false, "dns_challenge": false}}
	name := strings.Join(domains, ", ")
	if dry {
		after := map[string]any{"forward": fmt.Sprintf("%s://%s:%d", scheme, fh, p.ForwardPort), "certificateId": p.CertificateID,
			"sslForced": p.SSLForced, "blockExploits": block, "websockets": p.Websockets, "enabled": enabled, "customLocations": len(locations)}
		if p.AccessListID > 0 {
			after["accessListId"] = p.AccessListID
		}
		if strings.TrimSpace(p.AdvancedConfig) != "" {
			after["advancedConfig"] = p.AdvancedConfig
		}
		a, _ := json.Marshal(after)
		return sdk.Result{Plan: &sdk.Plan{Summary: "Create a proxy host for " + name, Changes: []sdk.Change{{Target: "proxy host " + name, Op: "create", After: a}}}}, nil
	}
	var created proxyHost
	if err := c.do(ctx, http.MethodPost, "/nginx/proxy-hosts", nil, body, &created); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"id": created.ID, "domains": domains}
	if !enabled && created.ID > 0 {
		if err := c.do(ctx, http.MethodPost, "/nginx/proxy-hosts/"+strconv.Itoa(created.ID)+"/disable", nil, nil, nil); err != nil {
			out["note"] = "created, but disabling it failed: " + err.Error()
		}
	}
	out["enabled"] = enabled
	res, err := sdk.JSON(out)
	if created.ID > 0 {
		res.Undo = sdk.UndoWith("delete_proxy_host", map[string]any{"id": created.ID}, "Delete the proxy host for "+name)
	}
	return res, err
}

// expiry reads NPM's "2026-01-15 12:00:00" (UTC) or an RFC 3339 time.
func expiry(s string) (time.Time, bool) {
	for _, l := range []string{"2006-01-02 15:04:05", time.RFC3339, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func (c *conn) certificates(ctx context.Context, now time.Time, within int) (sdk.Result, error) {
	// meta is left out of the output: for DNS challenges it holds the DNS
	// provider's credentials.
	var certs []struct {
		ID        int      `json:"id"`
		Provider  string   `json:"provider"`
		NiceName  string   `json:"nice_name"`
		Domains   []string `json:"domain_names"`
		ExpiresOn string   `json:"expires_on"`
	}
	if err := c.do(ctx, http.MethodGet, "/nginx/certificates", nil, nil, &certs); err != nil {
		return sdk.Result{}, err
	}
	hosts, err := c.hosts(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	used := map[int]int{}
	for _, h := range hosts {
		used[h.certID()]++
	}
	out := []map[string]any{}
	for _, ct := range certs {
		e := map[string]any{"id": ct.ID, "name": ct.NiceName, "provider": ct.Provider, "domains": ct.Domains, "expiresOn": ct.ExpiresOn, "proxyHosts": used[ct.ID]}
		days := 1 << 30
		if t, ok := expiry(ct.ExpiresOn); ok {
			days = int(t.Sub(now).Hours() / 24)
			if t.Before(now) {
				days = int(t.Sub(now).Hours()/24) - 1
			}
			e["daysLeft"] = days
			e["expired"] = t.Before(now)
		}
		if within > 0 && days > within {
			continue
		}
		e["sort"] = days
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i]["sort"].(int) < out[j]["sort"].(int) })
	for _, e := range out {
		delete(e, "sort")
	}
	return sdk.JSON(out)
}
