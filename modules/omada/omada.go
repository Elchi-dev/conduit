// Package omada works with a TP-Link Omada controller (software, hardware
// OC200/OC300, or Omada Cloud) through its OpenAPI with client credentials:
// sites, devices (gateways, switches, access points), connected clients,
// restarting a device, and blocking or unblocking a client.
package omada

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one controller.
type Config struct {
	URL                string `json:"url"`          // e.g. https://omada.example.com:8043
	ControllerID       string `json:"controllerId"` // omadacId, from the OpenAPI settings page
	ClientID           string `json:"clientId"`
	ClientSecret       string `json:"clientSecret"` // secret://
	Site               string `json:"site"`         // default site (id or name); optional
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	host sdk.Host
	cfg  Config
	api  *rest.Client
	addr string // the controller's host, without port

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Omada module.
func New() *Module { return &Module{} }

var (
	ctrlRe   = regexp.MustCompile(`^[A-Za-z0-9]{8,64}$`)
	clientRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	siteRe   = regexp.MustCompile(`^[A-Za-z0-9 _.-]{1,64}$`)
	macRe    = regexp.MustCompile(`^(?i)[0-9a-f]{2}([:-][0-9a-f]{2}){5}$`)
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	site := `"site":{"type":"string","description":"Site id or name (default: the instance's site, or the only one)"}`
	mac := func(what string) string {
		return `{"type":"object","required":["mac"],"properties":{"mac":{"type":"string","description":"The ` + what + `'s MAC address, AA-BB-CC-DD-EE-FF or aa:bb:cc:dd:ee:ff"},` + site + `}}`
	}
	return sdk.Manifest{
		ID: "omada", Name: "TP-Link Omada", Version: "0.1.0", Category: "Network", Icon: "wifi",
		Description: "A TP-Link Omada controller: sites, gateways, switches and access points, connected clients; restart a device, block a client.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","controllerId","clientId","clientSecret"],"properties":{
			"url":{"type":"string","description":"The controller's address, e.g. https://192.168.0.2:8043 (or the Omada Cloud API address shown on the OpenAPI page)"},
			"controllerId":{"type":"string","description":"The Omada ID (omadacId) on Settings, Platform Integration, Open API"},
			"clientId":{"type":"string","description":"Client ID of an application in Client mode on that page"},
			"clientSecret":{"type":"string","x-secret":true,"description":"That application's client secret"},
			"site":{"type":"string","description":"The site to use when an action names none (id or name)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the controller's certificate, to trust its own self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "sites", Title: "Sites", Description: "Each site's id, name, region, time zone and scenario.", Risk: sdk.RiskRead},
			{Name: "devices", Title: "Devices", Description: "Gateways, switches and access points of a site: name, model, MAC, address, status, firmware, uptime, CPU and memory, clients.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + site + `}}`)},
			{Name: "clients", Title: "Clients", Description: "Who's connected to a site: name, host name, MAC, address, wired or wireless, SSID, access point or switch, traffic, and whether it's blocked. It lists people's devices, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + site + `,"limit":{"type":"integer","default":100,"maximum":1000}}}`)},
			{Name: "reboot_device", Title: "Restart a device", Description: "Restarts a gateway, switch or access point; what's behind it loses the connection for a few minutes.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(mac("device"))},
			{Name: "block_client", Title: "Block a client", Description: "Cuts a client off the site's network until it's unblocked. Refused for the controller's own address (as set, or its name resolved here); not for the machine Conduit runs on. Undo unblocks it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(mac("client"))},
			{Name: "unblock_client", Title: "Unblock a client", Description: "Lets a blocked client connect again. Undo blocks it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(mac("client"))},
		},
		Resources: []sdk.ResourceSpec{
			{Kind: "device", Title: "Devices", ListAction: "devices", ViewHint: "table"},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.URL), "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is the controller's, like https://192.168.0.2:8043")
	}
	c.ControllerID = strings.TrimSpace(c.ControllerID)
	if !ctrlRe.MatchString(c.ControllerID) {
		return errors.New("the controller id is the Omada ID on the Open API settings page")
	}
	c.ClientID = strings.TrimSpace(c.ClientID)
	if !clientRe.MatchString(c.ClientID) {
		return errors.New("enter the application's client id")
	}
	if !strings.HasPrefix(c.ClientSecret, "secret://") {
		return errors.New("store the client secret in the vault and enter its secret:// reference")
	}
	c.Site = strings.TrimSpace(c.Site)
	if c.Site != "" && !siteRe.MatchString(c.Site) {
		return errors.New("the site is its id or name")
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
	cc := &conn{host: h, cfg: c, addr: u.Hostname()}
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/")+"/openapi", func(ctx context.Context, r *http.Request) error {
		if strings.Contains(r.URL.Path, "/openapi/authorize/") {
			return nil
		}
		t, err := cc.login(ctx, false)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "AccessToken="+t)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	cc.api = api
	m.set.Put(id, cc)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// envelope is every OpenAPI answer.
type envelope struct {
	ErrorCode int             `json:"errorCode"`
	Msg       string          `json:"msg"`
	Result    json.RawMessage `json:"result"`
}

// Token errors: expired, invalid, missing.
var tokenErrors = map[int]bool{-44112: true, -44113: true, -44111: true, -44116: true}

type omadaError struct {
	Code int
	Msg  string
}

func (e *omadaError) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("Omada error %d", e.Code)
	}
	return fmt.Sprintf("Omada: %s (%d)", rest.Redact(e.Msg), e.Code)
}

func (c *conn) login(ctx context.Context, fresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !fresh && c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	sec, err := c.host.Secret(ctx, c.cfg.ClientSecret)
	if err != nil {
		return "", err
	}
	var e envelope
	q := url.Values{"grant_type": {"client_credentials"}}
	body := map[string]string{"omadacId": c.cfg.ControllerID, "client_id": c.cfg.ClientID, "client_secret": strings.TrimSpace(sec)}
	if _, err := c.api.Do(ctx, http.MethodPost, "/authorize/token", q, body, &e); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return "", errors.New("no Omada OpenAPI at this address (controller 5.9 or later)")
		}
		return "", err
	}
	var t struct {
		AccessToken string `json:"accessToken"`
		ExpiresIn   int    `json:"expiresIn"`
	}
	if e.ErrorCode != 0 || json.Unmarshal(e.Result, &t) != nil || t.AccessToken == "" {
		return "", errors.New("Omada refused the client id and secret (or the controller id)")
	}
	ttl := time.Duration(t.ExpiresIn) * time.Second
	if ttl <= time.Minute {
		ttl = 2 * time.Minute
	}
	c.token, c.expires = t.AccessToken, time.Now().Add(ttl-time.Minute)
	return c.token, nil
}

// do calls the API for the controller and decodes result into out, signing
// in again once when the token was refused.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	path = "/v1/" + url.PathEscape(c.cfg.ControllerID) + path
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			if _, err := c.login(ctx, true); err != nil {
				return err
			}
		}
		var e envelope
		_, err := c.api.Do(ctx, method, path, q, body, &e)
		if rest.IsStatus(err, http.StatusUnauthorized) && attempt == 0 {
			continue
		}
		if err != nil {
			if rest.IsStatus(err, http.StatusForbidden) {
				return errors.New("the application isn't allowed to do this (give it the site's privileges on the Open API page)")
			}
			return err
		}
		if tokenErrors[e.ErrorCode] && attempt == 0 {
			continue
		}
		if e.ErrorCode != 0 {
			return &omadaError{Code: e.ErrorCode, Msg: e.Msg}
		}
		if out != nil && len(e.Result) > 0 && string(e.Result) != "null" {
			if err := json.Unmarshal(e.Result, out); err != nil {
				return fmt.Errorf("unexpected answer from Omada: %w", err)
			}
		}
		return nil
	}
	return errors.New("Omada kept refusing the access token")
}

type page[T any] struct {
	TotalRows int `json:"totalRows"`
	Data      []T `json:"data"`
}

// list reads every page of a listing, up to max rows.
func list[T any](ctx context.Context, c *conn, path string, max int) ([]T, error) {
	var out []T
	for pg := 1; pg <= 50; pg++ {
		var p page[T]
		q := url.Values{"page": {fmt.Sprint(pg)}, "pageSize": {"100"}}
		if err := c.do(ctx, http.MethodGet, path, q, nil, &p); err != nil {
			return nil, err
		}
		out = append(out, p.Data...)
		if len(p.Data) < 100 || len(out) >= p.TotalRows || len(out) >= max {
			break
		}
	}
	if len(out) > max {
		out = out[:max]
	}
	return out, nil
}

type site struct {
	ID       string `json:"siteId"`
	Name     string `json:"name"`
	Region   string `json:"region"`
	TimeZone string `json:"timeZone"`
	Scenario string `json:"scenario"`
}

// site finds the site by id or name, or the default one.
func (c *conn) site(ctx context.Context, want string) (site, error) {
	want = strings.TrimSpace(want)
	if want == "" {
		want = c.cfg.Site
	}
	if want != "" && !siteRe.MatchString(want) {
		return site{}, errors.New("the site is its id or name")
	}
	ss, err := list[site](ctx, c, "/sites", 1000)
	if err != nil {
		return site{}, err
	}
	if want == "" {
		if len(ss) == 1 {
			return ss[0], nil
		}
		return site{}, fmt.Errorf("the controller has %d sites: name one (see sites), or set the instance's site", len(ss))
	}
	for _, s := range ss {
		if s.ID == want || strings.EqualFold(s.Name, want) {
			if !clientRe.MatchString(s.ID) {
				return site{}, errors.New("unexpected site id from Omada")
			}
			return s, nil
		}
	}
	return site{}, fmt.Errorf("there's no site %s", want)
}

type device struct {
	MAC       string  `json:"mac"`
	Name      string  `json:"name"`
	Type      string  `json:"type"`
	Model     string  `json:"model"`
	IP        string  `json:"ip"`
	Status    int     `json:"status"`
	Category  int     `json:"statusCategory"`
	Uptime    any     `json:"uptime"`
	Firmware  string  `json:"firmwareVersion"`
	CPU       float64 `json:"cpuUtil"`
	Memory    float64 `json:"memUtil"`
	ClientNum int     `json:"clientNum"`
}

// Status categories: 0 disconnected, 1 connected, 2 pending, 3 heartbeat
// missed, 4 isolated.
var category = map[int]string{0: "disconnected", 1: "connected", 2: "pending", 3: "heartbeat missed", 4: "isolated"}

type client struct {
	MAC        string `json:"mac"`
	Name       string `json:"name"`
	HostName   string `json:"hostName"`
	IP         string `json:"ip"`
	Wireless   bool   `json:"wireless"`
	SSID       string `json:"ssid"`
	APName     string `json:"apName"`
	SwitchName string `json:"switchName"`
	Port       int    `json:"port"`
	Uptime     int64  `json:"uptime"`
	Down       int64  `json:"trafficDown"`
	Up         int64  `json:"trafficUp"`
	Signal     int    `json:"signalLevel"`
	Block      bool   `json:"block"`
	Guest      bool   `json:"guest"`
}

// normMAC writes a MAC address the way Omada does: AA-BB-CC-DD-EE-FF.
func normMAC(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !macRe.MatchString(s) {
		return "", errors.New("the MAC address is like AA-BB-CC-DD-EE-FF")
	}
	return strings.ToUpper(strings.ReplaceAll(s, ":", "-")), nil
}

func sameMAC(a, b string) bool {
	x, err1 := normMAC(a)
	y, err2 := normMAC(b)
	return err1 == nil && err2 == nil && x == y
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ss, err := list[site](ctx, c, "/sites", 1000)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%d sites", len(ss))
	if len(ss) == 1 {
		msg = "1 site"
	}
	if s, err := c.site(ctx, ""); err == nil {
		ds, err := list[device](ctx, c, "/sites/"+url.PathEscape(s.ID)+"/devices", 1000)
		if err == nil {
			off := 0
			for _, d := range ds {
				if d.Category != 1 {
					off++
				}
			}
			msg = fmt.Sprintf("%s: %d devices", s.Name, len(ds))
			if off > 0 {
				return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s, %d not connected", msg, off)}
			}
		}
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
		Site  string `json:"site"`
		MAC   string `json:"mac"`
		Limit int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if p.Site != "" && !siteRe.MatchString(strings.TrimSpace(p.Site)) {
		return sdk.Result{}, errors.New("the site is its id or name")
	}
	switch call.Action {
	case "sites":
		ss, err := list[site](ctx, c, "/sites", 1000)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range ss {
			out = append(out, map[string]any{"id": s.ID, "name": s.Name, "region": s.Region, "timeZone": s.TimeZone, "scenario": s.Scenario})
		}
		return sdk.JSON(out)

	case "devices":
		s, err := c.site(ctx, p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		ds, err := list[device](ctx, c, "/sites/"+url.PathEscape(s.ID)+"/devices", 1000)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range ds {
			out = append(out, map[string]any{"name": d.Name, "type": d.Type, "model": d.Model, "mac": d.MAC, "ip": d.IP,
				"status": category[d.Category], "firmware": d.Firmware, "uptime": d.Uptime, "cpuPercent": d.CPU, "memoryPercent": d.Memory, "clients": d.ClientNum})
		}
		return sdk.JSON(map[string]any{"site": s.Name, "devices": out})

	case "clients":
		if p.Limit <= 0 || p.Limit > 1000 {
			p.Limit = 100
		}
		s, err := c.site(ctx, p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		cs, err := list[client](ctx, c, "/sites/"+url.PathEscape(s.ID)+"/clients", p.Limit)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range cs {
			row := map[string]any{"name": x.Name, "hostname": x.HostName, "mac": x.MAC, "ip": x.IP, "wireless": x.Wireless, "uptimeSeconds": x.Uptime,
				"downBytes": x.Down, "upBytes": x.Up, "blocked": x.Block, "guest": x.Guest}
			if x.Wireless {
				row["ssid"], row["accessPoint"] = x.SSID, x.APName
				if x.Signal != 0 {
					row["signalPercent"] = x.Signal
				}
			} else if x.SwitchName != "" {
				row["switch"], row["port"] = x.SwitchName, x.Port
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"site": s.Name, "clients": out})

	case "reboot_device":
		mac, err := normMAC(p.MAC)
		if err != nil {
			return sdk.Result{}, err
		}
		s, err := c.site(ctx, p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		ds, err := list[device](ctx, c, "/sites/"+url.PathEscape(s.ID)+"/devices", 1000)
		if err != nil {
			return sdk.Result{}, err
		}
		var d *device
		for i := range ds {
			if sameMAC(ds[i].MAC, mac) {
				d = &ds[i]
			}
		}
		if d == nil {
			return sdk.Result{}, fmt.Errorf("there's no device %s in %s", mac, s.Name)
		}
		target := fmt.Sprintf("%s %s (%s, %s) in %s", d.Type, firstOf(d.Name, mac), d.Model, mac, s.Name)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Restart " + target + fmt.Sprintf(", %d clients connected", d.ClientNum), Changes: []sdk.Change{{Target: target, Op: "restart"}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/sites/"+url.PathEscape(s.ID)+"/devices/"+url.PathEscape(mac)+"/reboot", nil, map[string]any{}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"rebooting": target})

	case "block_client", "unblock_client":
		mac, err := normMAC(p.MAC)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.block(ctx, call, p.Site, mac)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func firstOf(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// addrIPs is the controller's address from the settings, or what its name
// resolves to here (nothing when it doesn't resolve).
func (c *conn) addrIPs(ctx context.Context) []net.IP {
	if ip := net.ParseIP(c.addr); ip != nil {
		return []net.IP{ip}
	}
	lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	as, err := net.DefaultResolver.LookupIPAddr(lctx, c.addr)
	if err != nil {
		return nil
	}
	out := make([]net.IP, 0, len(as))
	for _, a := range as {
		out = append(out, a.IP)
	}
	return out
}

func (c *conn) block(ctx context.Context, call sdk.Call, siteName, mac string) (sdk.Result, error) {
	block := call.Action == "block_client"
	s, err := c.site(ctx, siteName)
	if err != nil {
		return sdk.Result{}, err
	}
	cs, err := list[client](ctx, c, "/sites/"+url.PathEscape(s.ID)+"/clients", 1000)
	if err != nil {
		return sdk.Result{}, err
	}
	var found *client
	for i := range cs {
		if sameMAC(cs[i].MAC, mac) {
			found = &cs[i]
		}
	}
	label := mac
	if found != nil {
		label = firstOf(found.Name, found.HostName, mac)
		if found.Block == block {
			return sdk.JSON(map[string]any{"client": mac, "name": label, "blocked": block, "note": "nothing to change"})
		}
		if block && found.IP != "" {
			if ip := net.ParseIP(found.IP); ip != nil {
				for _, own := range c.addrIPs(ctx) {
					if ip.Equal(own) {
						return sdk.Result{}, fmt.Errorf("refusing: %s is the controller's own address (%s), so blocking it would cut Conduit off", label, found.IP)
					}
				}
			}
		}
	}
	verb, back, op := "Block", "unblock_client", "block"
	if !block {
		verb, back, op = "Unblock", "block_client", "unblock"
	}
	target := fmt.Sprintf("client %s (%s) in %s", label, mac, s.Name)
	if call.DryRun {
		var b json.RawMessage
		if found != nil {
			b, _ = json.Marshal(map[string]bool{"blocked": found.Block})
		}
		a, _ := json.Marshal(map[string]bool{"blocked": block})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + target, Changes: []sdk.Change{{Target: target, Op: op, Before: b, After: a}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, "/sites/"+url.PathEscape(s.ID)+"/clients/"+url.PathEscape(mac)+"/"+op, nil, map[string]any{}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"client": mac, "name": label, "blocked": block})
	undo := "Unblock " + label
	if !block {
		undo = "Block " + label + " again"
	}
	in := map[string]string{"mac": mac, "site": s.ID}
	res.Undo = sdk.UndoWith(back, in, undo)
	return res, err
}
