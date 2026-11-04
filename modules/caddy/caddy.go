// Package caddy reads a Caddy server's admin API (usually
// http://127.0.0.1:2019): which sites and routes it serves and where they
// proxy to, the state of the reverse proxy's upstreams, TLS automation
// policies and the local CA. It never changes anything: loading a config
// replaces the whole running server, which is better done from the
// Caddyfile or JSON under version control. It never returns the raw config
// either, since that can hold DNS provider tokens, basic auth hashes,
// private keys and EAB credentials; only names, hosts, paths, handler types
// and upstream addresses are read out of it.
package caddy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

// DefaultURL is where Caddy's admin API listens unless configured otherwise.
const DefaultURL = "http://127.0.0.1:2019"

// Config is one Caddy.
type Config struct {
	URL                string `json:"url"`      // admin API, default http://127.0.0.1:2019
	Username           string `json:"username"` // optional basic auth, when a proxy guards a remote admin API
	Password           string `json:"password"` // secret://, with username
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Caddy module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	serverRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	caRe     = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "caddy", Name: "Caddy", Version: "0.1.0", Category: "Network", Icon: "globe",
		Description: "Caddy's sites, routes and upstreams, upstream health, TLS automation and the local CA, from its admin API. Read-only.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"url":{"type":"string","default":"` + DefaultURL + `","description":"The admin API's address; Caddy listens on http://127.0.0.1:2019 (localhost only) unless its admin option says otherwise"},
			"username":{"type":"string","description":"Basic auth username, if a reverse proxy guards a remote admin API"},
			"password":{"type":"string","x-secret":true,"description":"Basic auth password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the certificate, for an admin API behind a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "summary", Title: "Summary", Description: "Apps, servers with what they listen on, every host served, and counts of routes and upstreams.", Risk: sdk.RiskRead},
			{Name: "routes", Title: "Routes", Description: "Each server's routes: hosts and paths matched, handler types, upstreams and file roots (never handler settings such as auth hashes or headers).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"server":{"type":"string","description":"Only this server, e.g. srv0"},"host":{"type":"string","description":"Only routes matching this host"}}}`)},
			{Name: "upstreams", Title: "Upstreams", Description: "The reverse proxy's upstreams with active requests and recent failures.", Risk: sdk.RiskRead},
			{Name: "tls", Title: "TLS", Description: "Automation policies (subjects, issuers, challenge type), names with managed certificates, and how many certificates are loaded by hand.", Risk: sdk.RiskRead},
			{Name: "pki_ca", Title: "Local CA", Description: "The internal CA's root and intermediate names and expiry dates.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"id":{"type":"string","default":"local"}}}`)},
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
		c.URL = DefaultURL
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is the admin API's, like " + DefaultURL)
	}
	user := strings.TrimSpace(c.Username)
	if user != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the basic auth password in the vault and enter its secret:// reference")
	}
	if user == "" && c.Password != "" {
		return errors.New("enter the basic auth username too")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 15*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 15 * time.Second, Transport: tr}
		}
	}
	var auth func(context.Context, *http.Request) error
	if user != "" {
		ref := c.Password
		auth = func(ctx context.Context, r *http.Request) error {
			pw, err := h.Secret(ctx, ref)
			if err != nil {
				return err
			}
			r.SetBasicAuth(user, pw)
			return nil
		}
	}
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), auth)
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) get(ctx context.Context, path string, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		return errors.New("the admin API refused the basic auth username and password")
	}
	if rest.IsStatus(err, http.StatusForbidden) {
		return errors.New("Caddy refused the request (its admin origins don't include this address)")
	}
	return err
}

// The parts of Caddy's JSON config that are read. Everything else, handler
// settings in particular, is never decoded.
type cfg struct {
	Admin *struct {
		Listen   string `json:"listen"`
		Disabled bool   `json:"disabled"`
	} `json:"admin"`
	Apps map[string]json.RawMessage `json:"apps"`
}

type httpApp struct {
	Servers map[string]struct {
		Listen []string `json:"listen"`
		Routes []route  `json:"routes"`
		Auto   *struct {
			Disable bool `json:"disable"`
		} `json:"automatic_https"`
		TLSPolicies []json.RawMessage `json:"tls_connection_policies"`
	} `json:"servers"`
}

type route struct {
	Group    string `json:"group"`
	Terminal bool   `json:"terminal"`
	Match    []struct {
		Host []string `json:"host"`
		Path []string `json:"path"`
	} `json:"match"`
	Handle []handler `json:"handle"`
}

type handler struct {
	Handler   string  `json:"handler"`
	Routes    []route `json:"routes"` // subroute
	Upstreams []struct {
		Dial string `json:"dial"`
	} `json:"upstreams"`
	Dynamic *struct {
		Source string `json:"source"`
	} `json:"dynamic_upstreams"`
	Root       string `json:"root"`        // file_server
	StatusCode any    `json:"status_code"` // static_response
}

// Route is a flattened route.
type Route struct {
	Server    string   `json:"server"`
	Hosts     []string `json:"hosts,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	Handlers  []string `json:"handlers"`
	Upstreams []string `json:"upstreams,omitempty"`
	Dynamic   string   `json:"dynamicUpstreams,omitempty"`
	Roots     []string `json:"fileRoots,omitempty"`
	Status    string   `json:"staticStatus,omitempty"`
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// flatten walks routes and their subroutes; a subroute's hosts and paths
// add to its parent's.
func flatten(server string, rs []route, hosts, paths []string, out *[]Route) {
	for _, r := range rs {
		h, p := append([]string{}, hosts...), append([]string{}, paths...)
		for _, m := range r.Match {
			h = append(h, m.Host...)
			p = append(p, m.Path...)
		}
		fr := Route{Server: server, Hosts: uniq(h), Paths: uniq(p), Handlers: []string{}}
		for _, hd := range r.Handle {
			if hd.Handler == "subroute" {
				flatten(server, hd.Routes, fr.Hosts, fr.Paths, out)
				continue
			}
			fr.Handlers = append(fr.Handlers, hd.Handler)
			for _, u := range hd.Upstreams {
				fr.Upstreams = append(fr.Upstreams, u.Dial)
			}
			if hd.Dynamic != nil {
				fr.Dynamic = hd.Dynamic.Source
			}
			if hd.Handler == "file_server" {
				root := hd.Root
				if root == "" {
					root = "{http.vars.root}"
				}
				fr.Roots = append(fr.Roots, root)
			}
			if hd.Handler == "static_response" && hd.StatusCode != nil {
				fr.Status = fmt.Sprint(hd.StatusCode)
			}
		}
		if len(fr.Handlers) > 0 {
			fr.Upstreams, fr.Roots = uniq(fr.Upstreams), uniq(fr.Roots)
			*out = append(*out, fr)
		}
	}
}

type state struct {
	cfg     cfg
	http    httpApp
	routes  []Route
	servers []string
}

func (c *conn) state(ctx context.Context) (*state, error) {
	s := &state{}
	if err := c.get(ctx, "/config/", &s.cfg); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return nil, errors.New("no Caddy admin API at this address")
		}
		return nil, err
	}
	if raw, ok := s.cfg.Apps["http"]; ok {
		if err := json.Unmarshal(raw, &s.http); err != nil {
			return nil, fmt.Errorf("unexpected http app config: %w", err)
		}
	}
	for name := range s.http.Servers {
		s.servers = append(s.servers, name)
	}
	sort.Strings(s.servers)
	for _, name := range s.servers {
		flatten(name, s.http.Servers[name].Routes, nil, nil, &s.routes)
	}
	return s, nil
}

func (s *state) hosts() []string {
	var hs []string
	for _, r := range s.routes {
		hs = append(hs, r.Hosts...)
	}
	hs = uniq(hs)
	sort.Strings(hs)
	return hs
}

// Upstream is one reverse proxy upstream.
type Upstream struct {
	Address  string `json:"address"`
	Requests int    `json:"numRequests"`
	Fails    int    `json:"fails"`
}

func (c *conn) upstreams(ctx context.Context) ([]Upstream, error) {
	var us []struct {
		Address  string `json:"address"`
		Requests int    `json:"num_requests"`
		Fails    int    `json:"fails"`
	}
	if err := c.get(ctx, "/reverse_proxy/upstreams", &us); err != nil {
		return nil, err
	}
	out := []Upstream{}
	for _, u := range us {
		out = append(out, Upstream{Address: u.Address, Requests: u.Requests, Fails: u.Fails})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.state(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%d servers · %d hosts", len(s.servers), len(s.hosts()))
	if len(s.servers) == 0 {
		return sdk.Health{Status: "degraded", Message: "Caddy is running with no HTTP servers configured"}
	}
	if us, err := c.upstreams(ctx); err == nil {
		var failing []string
		for _, u := range us {
			if u.Fails > 0 {
				failing = append(failing, u.Address)
			}
		}
		if len(failing) > 0 {
			return sdk.Health{Status: "degraded", Message: "upstreams failing: " + strings.Join(failing, ", ") + " · " + msg}
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type certInfo struct {
	CommonName string `json:"commonName"`
	NotAfter   string `json:"notAfter"`
	DaysLeft   int    `json:"daysLeft"`
}

func parseCert(p string) *certInfo {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil
	}
	x, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil
	}
	return &certInfo{CommonName: x.Subject.CommonName, NotAfter: x.NotAfter.UTC().Format(time.RFC3339), DaysLeft: int(time.Until(x.NotAfter).Hours() / 24)}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Server string `json:"server"`
		Host   string `json:"host"`
		ID     string `json:"id"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "summary":
		s, err := c.state(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		apps := []string{}
		for a := range s.cfg.Apps {
			apps = append(apps, a)
		}
		sort.Strings(apps)
		servers := []map[string]any{}
		ups := 0
		for _, name := range s.servers {
			sv := s.http.Servers[name]
			n := 0
			for _, r := range s.routes {
				if r.Server == name {
					n++
					ups += len(r.Upstreams)
				}
			}
			servers = append(servers, map[string]any{"name": name, "listen": sv.Listen, "routes": n, "automaticHTTPS": sv.Auto == nil || !sv.Auto.Disable})
		}
		out := map[string]any{"apps": apps, "servers": servers, "hosts": s.hosts(), "routes": len(s.routes), "upstreams": ups}
		if s.cfg.Admin != nil && s.cfg.Admin.Listen != "" {
			out["adminListen"] = s.cfg.Admin.Listen
		}
		return sdk.JSON(out)

	case "routes":
		if p.Server != "" && !serverRe.MatchString(p.Server) {
			return sdk.Result{}, errors.New("the server is its name in the config, e.g. srv0")
		}
		host := strings.ToLower(strings.TrimSpace(p.Host))
		if len(host) > 253 || strings.ContainsAny(host, " \t\r\n/") {
			return sdk.Result{}, errors.New("the host is a name like example.com")
		}
		s, err := c.state(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if _, ok := s.http.Servers[p.Server]; p.Server != "" && !ok {
			return sdk.Result{}, fmt.Errorf("no server %s (servers: %s)", p.Server, strings.Join(s.servers, ", "))
		}
		out := []Route{}
		for _, r := range s.routes {
			if p.Server != "" && r.Server != p.Server {
				continue
			}
			if host != "" && !matchHost(r.Hosts, host) {
				continue
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "upstreams":
		us, err := c.upstreams(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(us)

	case "tls":
		s, err := c.state(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var app struct {
			Automation *struct {
				Policies []struct {
					Subjects []string `json:"subjects"`
					Issuers  []struct {
						Module     string `json:"module"`
						CA         string `json:"ca"`
						Challenges *struct {
							DNS *struct {
								Provider *struct {
									Name string `json:"name"`
								} `json:"provider"`
							} `json:"dns"`
						} `json:"challenges"`
					} `json:"issuers"`
					OnDemand bool `json:"on_demand"`
				} `json:"policies"`
			} `json:"automation"`
			Certificates map[string]json.RawMessage `json:"certificates"`
		}
		if raw, ok := s.cfg.Apps["tls"]; ok {
			_ = json.Unmarshal(raw, &app)
		}
		policies := []map[string]any{}
		if app.Automation != nil {
			for _, pl := range app.Automation.Policies {
				issuers := []string{}
				challenge := ""
				for _, is := range pl.Issuers {
					name := is.Module
					if is.CA != "" {
						if u, err := url.Parse(is.CA); err == nil && u.Host != "" {
							name += " (" + u.Host + ")"
						}
					}
					issuers = append(issuers, name)
					if is.Challenges != nil && is.Challenges.DNS != nil {
						challenge = "dns"
						if is.Challenges.DNS.Provider != nil && is.Challenges.DNS.Provider.Name != "" {
							challenge += " (" + is.Challenges.DNS.Provider.Name + ")"
						}
					}
				}
				pol := map[string]any{"subjects": pl.Subjects, "issuers": issuers, "onDemand": pl.OnDemand}
				if challenge != "" {
					pol["challenge"] = challenge
				}
				policies = append(policies, pol)
			}
		}
		// Hosts Caddy automates: the explicit "automate" list plus every
		// host of a server with automatic HTTPS on.
		managed := []string{}
		var automate []string
		if raw, ok := app.Certificates["automate"]; ok {
			_ = json.Unmarshal(raw, &automate)
		}
		managed = append(managed, automate...)
		for _, r := range s.routes {
			if sv := s.http.Servers[r.Server]; sv.Auto == nil || !sv.Auto.Disable {
				managed = append(managed, r.Hosts...)
			}
		}
		managed = uniq(managed)
		sort.Strings(managed)
		loaded := 0
		for k, raw := range app.Certificates {
			if k == "automate" {
				continue
			}
			var xs []json.RawMessage
			if json.Unmarshal(raw, &xs) == nil {
				loaded += len(xs)
			} else {
				loaded++
			}
		}
		return sdk.JSON(map[string]any{"policies": policies, "managedNames": managed, "loadedCertificates": loaded})

	case "pki_ca":
		id := p.ID
		if id == "" {
			id = "local"
		}
		if !caRe.MatchString(id) {
			return sdk.Result{}, errors.New("the CA id is like local")
		}
		var ca struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			Root         string `json:"root_certificate"`
			Intermediate string `json:"intermediate_certificate"`
		}
		if err := c.get(ctx, "/pki/ca/"+id, &ca); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
				return sdk.Result{}, fmt.Errorf("Caddy has no CA %s (the local CA exists once something uses the internal issuer)", id)
			}
			return sdk.Result{}, err
		}
		out := map[string]any{"id": ca.ID, "name": ca.Name}
		if r := parseCert(ca.Root); r != nil {
			out["root"] = r
		}
		if i := parseCert(ca.Intermediate); i != nil {
			out["intermediate"] = i
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// matchHost reports whether a route's host matchers cover host, wildcards
// included. A route with no host matcher matches every host.
func matchHost(hosts []string, host string) bool {
	if len(hosts) == 0 {
		return true
	}
	for _, h := range hosts {
		h = strings.ToLower(h)
		if h == host {
			return true
		}
		if strings.HasPrefix(h, "*.") {
			if i := strings.IndexByte(host, '.'); i > 0 && host[i:] == h[1:] {
				return true
			}
		}
	}
	return false
}
