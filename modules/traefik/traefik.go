// Package traefik reads a Traefik proxy's API: the overview, routers,
// services, middlewares and entry points of the HTTP, TCP and UDP
// providers, and which of them have errors. It never changes anything:
// Traefik's API is read-only.
package traefik

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Traefik instance.
type Config struct {
	URL                string `json:"url"`      // where /api is served, e.g. https://traefik.example.com
	Username           string `json:"username"` // optional basic auth (a basicAuth middleware on the dashboard)
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

// New returns the Traefik module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// Traefik names are like web-router@docker or api@internal.
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]{0,254}$`)
	protocols = map[string]bool{"http": true, "tcp": true, "udp": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	proto := `"protocol":{"type":"string","enum":["http","tcp","udp"],"default":"http"}`
	filter := `"search":{"type":"string","description":"Part of a name or rule"},"status":{"type":"string","enum":["enabled","disabled","warning"]},"provider":{"type":"string","description":"e.g. docker, file, kubernetes"}`
	return sdk.Manifest{
		ID: "traefik", Name: "Traefik", Version: "0.1.0", Category: "Network", Icon: "network",
		Description: "Traefik's overview, routers, services, middlewares and entry points, and which routers have errors. Read-only.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Where Traefik serves /api, e.g. https://traefik.example.com or http://server:8080 (api.insecure)"},
			"username":{"type":"string","description":"Basic auth username, if the dashboard is behind a basicAuth middleware"},
			"password":{"type":"string","x-secret":true,"description":"Basic auth password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the certificate, to trust Traefik's default self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "overview", Title: "Overview", Description: "Version, counts of routers, services and middlewares per protocol with warnings and errors, enabled features and providers.", Risk: sdk.RiskRead},
			{Name: "routers", Title: "Routers", Description: "Routers with their rule, entry points, service, middlewares, TLS and status.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + proto + `,` + filter + `}}`)},
			{Name: "router", Title: "Router details", Description: "One router in full, with its errors.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["name"],"properties":{` + proto + `,"name":{"type":"string","description":"Router name with its provider, e.g. web@docker"}}}`)},
			{Name: "services", Title: "Services", Description: "Services with their type, servers and each server's status (UP or DOWN), and the routers using them.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + proto + `,` + filter + `}}`)},
			{Name: "middlewares", Title: "Middlewares", Description: "Middlewares with their type, status and the routers using them (without their settings, which can hold password hashes).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + proto + `,` + filter + `}}`)},
			{Name: "entrypoints", Title: "Entry points", Description: "The addresses Traefik listens on.", Risk: sdk.RiskRead},
			{Name: "errors", Title: "Errors", Description: "Every router, service and middleware (HTTP, TCP and UDP) that is disabled or has warnings, with its error messages.", Risk: sdk.RiskRead},
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
		return errors.New("the address is like https://traefik.example.com")
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
		client = sdk.HTTPClient(h, 20*time.Second) // through the instance's network, if any
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 20 * time.Second, Transport: tr}
		}
	}
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(strings.TrimSuffix(p, "/dashboard"), "/api")
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
	api := rest.New(u.Scheme+"://"+u.Host+p+"/api", auth)
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
		return errors.New("Traefik refused the request (check the basic auth username and password)")
	}
	return err
}

// list reads every page (Traefik pages at 100 by default, next page in
// X-Next-Page) up to 2000 entries.
func (c *conn) list(ctx context.Context, path string, q url.Values) ([]map[string]any, error) {
	var all []map[string]any
	if q == nil {
		q = url.Values{}
	}
	q.Set("per_page", "100")
	for page := 1; page <= 20; {
		q.Set("page", strconv.Itoa(page))
		var batch []map[string]any
		hdr, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &batch)
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return nil, errors.New("Traefik refused the request (check the basic auth username and password)")
		}
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		next, _ := strconv.Atoi(hdr.Get("X-Next-Page"))
		if next <= page || len(batch) == 0 {
			break
		}
		page = next
	}
	return all, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Version string `json:"Version"`
	}
	if err := c.get(ctx, "/version", nil, &v); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Traefik API at this address (is api enabled, and the URL where /api is served?)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "Traefik " + v.Version
	var o overview
	if err := c.get(ctx, "/overview", nil, &o); err == nil {
		if n := o.errors(); n > 0 {
			return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s · %d routers, services or middlewares with errors", msg, n)}
		}
		if n := o.warnings(); n > 0 {
			msg += fmt.Sprintf(" · %d warnings", n)
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type counts struct {
	Total    int `json:"total"`
	Warnings int `json:"warnings"`
	Errors   int `json:"errors"`
}

type overview struct {
	HTTP struct {
		Routers, Services, Middlewares counts
	} `json:"http"`
	TCP struct {
		Routers, Services, Middlewares counts
	} `json:"tcp"`
	UDP struct {
		Routers, Services counts
	} `json:"udp"`
	Features  map[string]any `json:"features"`
	Providers []string       `json:"providers"`
}

func (o overview) all() []counts {
	return []counts{o.HTTP.Routers, o.HTTP.Services, o.HTTP.Middlewares, o.TCP.Routers, o.TCP.Services, o.TCP.Middlewares, o.UDP.Routers, o.UDP.Services}
}

func (o overview) errors() (n int) {
	for _, c := range o.all() {
		n += c.Errors
	}
	return n
}

func (o overview) warnings() (n int) {
	for _, c := range o.all() {
		n += c.Warnings
	}
	return n
}

type input struct {
	Protocol string `json:"protocol"`
	Search   string `json:"search"`
	Status   string `json:"status"`
	Provider string `json:"provider"`
	Name     string `json:"name"`
}

func (p input) query() (string, url.Values, error) {
	proto := p.Protocol
	if proto == "" {
		proto = "http"
	}
	if !protocols[proto] {
		return "", nil, errors.New("protocol is http, tcp or udp")
	}
	q := url.Values{}
	if s := strings.TrimSpace(p.Search); s != "" {
		if len(s) > 200 {
			return "", nil, errors.New("the search is too long")
		}
		q.Set("search", s)
	}
	switch p.Status {
	case "":
	case "enabled", "disabled", "warning":
		q.Set("status", p.Status)
	default:
		return "", nil, errors.New("status is enabled, disabled or warning")
	}
	return proto, q, nil
}

func strs(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func router(r map[string]any) map[string]any {
	e := map[string]any{"name": str(r, "name"), "status": str(r, "status"), "provider": str(r, "provider"), "service": str(r, "service")}
	if s := str(r, "rule"); s != "" {
		e["rule"] = s
	}
	if l := strs(r["entryPoints"]); l != nil {
		e["entryPoints"] = l
	}
	if l := strs(r["middlewares"]); l != nil {
		e["middlewares"] = l
	}
	if l := strs(r["error"]); l != nil {
		e["errors"] = l
	}
	if tls, ok := r["tls"].(map[string]any); ok {
		t := map[string]any{}
		if s := str(tls, "certResolver"); s != "" {
			t["certResolver"] = s
		}
		if s := str(tls, "options"); s != "" {
			t["options"] = s
		}
		if tls["passthrough"] == true {
			t["passthrough"] = true
		}
		e["tls"] = t
	}
	if p, ok := r["priority"].(float64); ok {
		e["priority"] = int64(p)
	}
	return e
}

func service(s map[string]any) map[string]any {
	e := map[string]any{"name": str(s, "name"), "status": str(s, "status"), "provider": str(s, "provider"), "type": str(s, "type")}
	if l := strs(s["usedBy"]); l != nil {
		e["usedBy"] = l
	}
	if l := strs(s["error"]); l != nil {
		e["errors"] = l
	}
	var servers []map[string]any
	status, _ := s["serverStatus"].(map[string]any)
	if lb, ok := s["loadBalancer"].(map[string]any); ok {
		if l, ok := lb["servers"].([]any); ok {
			for _, x := range l {
				if sv, ok := x.(map[string]any); ok {
					addr := str(sv, "url")
					if addr == "" {
						addr = str(sv, "address")
					}
					one := map[string]any{"address": addr}
					if st, ok := status[addr].(string); ok {
						one["status"] = st
					}
					servers = append(servers, one)
				}
			}
		}
	}
	if servers != nil {
		e["servers"] = servers
	}
	return e
}

func middleware(mw map[string]any) map[string]any {
	e := map[string]any{"name": str(mw, "name"), "status": str(mw, "status"), "provider": str(mw, "provider"), "type": str(mw, "type")}
	if l := strs(mw["usedBy"]); l != nil {
		e["usedBy"] = l
	}
	if l := strs(mw["error"]); l != nil {
		e["errors"] = l
	}
	return e
}

func filterProvider(list []map[string]any, provider string) []map[string]any {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return list
	}
	var out []map[string]any
	for _, x := range list {
		if strings.EqualFold(str(x, "provider"), provider) {
			out = append(out, x)
		}
	}
	return out
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
	case "overview":
		var o overview
		if err := c.get(ctx, "/overview", nil, &o); err != nil {
			return sdk.Result{}, err
		}
		var v struct {
			Version   string `json:"Version"`
			Codename  string `json:"Codename"`
			StartDate string `json:"startDate"`
		}
		_ = c.get(ctx, "/version", nil, &v)
		return sdk.JSON(map[string]any{"version": v.Version, "codename": v.Codename, "started": v.StartDate,
			"http":     map[string]any{"routers": o.HTTP.Routers, "services": o.HTTP.Services, "middlewares": o.HTTP.Middlewares},
			"tcp":      map[string]any{"routers": o.TCP.Routers, "services": o.TCP.Services, "middlewares": o.TCP.Middlewares},
			"udp":      map[string]any{"routers": o.UDP.Routers, "services": o.UDP.Services},
			"features": o.Features, "providers": o.Providers, "errors": o.errors(), "warnings": o.warnings()})

	case "routers", "services", "middlewares":
		proto, q, err := p.query()
		if err != nil {
			return sdk.Result{}, err
		}
		if call.Action == "middlewares" && proto == "udp" {
			return sdk.Result{}, errors.New("UDP has no middlewares")
		}
		list, err := c.list(ctx, "/"+proto+"/"+call.Action, q)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range filterProvider(list, p.Provider) {
			switch call.Action {
			case "routers":
				out = append(out, router(x))
			case "services":
				out = append(out, service(x))
			default:
				out = append(out, middleware(x))
			}
		}
		return sdk.JSON(out)

	case "router":
		proto, _, err := p.query()
		if err != nil {
			return sdk.Result{}, err
		}
		name := strings.TrimSpace(p.Name)
		if !nameRe.MatchString(name) {
			return sdk.Result{}, errors.New("enter the router's name, like web@docker")
		}
		var r map[string]any
		if err := c.get(ctx, "/"+proto+"/routers/"+url.PathEscape(name), nil, &r); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no %s router %s (names include the provider, like %s@docker)", proto, name, strings.Split(name, "@")[0])
			}
			return sdk.Result{}, err
		}
		e := router(r)
		if l := strs(r["using"]); l != nil {
			e["using"] = l
		}
		return sdk.JSON(e)

	case "entrypoints":
		list, err := c.list(ctx, "/entrypoints", nil)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, ep := range list {
			e := map[string]any{"name": str(ep, "name"), "address": str(ep, "address")}
			if h, ok := ep["http"].(map[string]any); ok {
				if rd, ok := h["redirections"].(map[string]any); ok {
					if to, ok := rd["entryPoint"].(map[string]any); ok {
						e["redirectsTo"] = str(to, "to")
					}
				}
				if tls, ok := h["tls"].(map[string]any); ok {
					e["tls"] = str(tls, "certResolver")
				}
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "errors":
		return c.allErrors(ctx)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) allErrors(ctx context.Context) (sdk.Result, error) {
	type item struct {
		Kind     string   `json:"kind"`
		Name     string   `json:"name"`
		Status   string   `json:"status"`
		Provider string   `json:"provider"`
		Rule     string   `json:"rule,omitempty"`
		Errors   []string `json:"errors"`
	}
	out := []item{}
	for _, k := range []string{"http/routers", "http/services", "http/middlewares", "tcp/routers", "tcp/services", "tcp/middlewares", "udp/routers", "udp/services"} {
		list, err := c.list(ctx, "/"+k, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		for _, x := range list {
			st := str(x, "status")
			if (st == "" || st == "enabled") && len(strs(x["error"])) == 0 {
				continue
			}
			out = append(out, item{Kind: strings.TrimSuffix(strings.Replace(k, "/", " ", 1), "s"), Name: str(x, "name"), Status: st,
				Provider: str(x, "provider"), Rule: str(x, "rule"), Errors: strs(x["error"])})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Status == "disabled") != (out[j].Status == "disabled") {
			return out[i].Status == "disabled"
		}
		return out[i].Kind+out[i].Name < out[j].Kind+out[j].Name
	})
	return sdk.JSON(map[string]any{"count": len(out), "items": out})
}
