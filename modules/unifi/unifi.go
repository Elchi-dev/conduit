// Package unifi reads and controls a UniFi Network application on a UniFi OS
// console (Dream Machine, Cloud Gateway, Cloud Key, UniFi OS Server):
// devices, clients, restarting a device, and blocking a client.
package unifi

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one UniFi OS console.
type Config struct {
	URL string `json:"url"` // https://192.168.1.1
	// APIKey (secret://), from Settings, Control Plane, Integrations. Reads
	// devices and clients and restarts devices.
	APIKey string `json:"apiKey"`
	// Username and Password (secret://) of a local account; needed to block
	// and unblock clients (the API key can't).
	Username string `json:"username"`
	Password string `json:"password"`
	Site     string `json:"site"` // default "default"
	// Fingerprint pins the console's self-signed certificate (SHA-256).
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	cfg  Config
	host sdk.Host
	base string
	http *http.Client

	mu   sync.Mutex
	csrf string
	auth time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client (tests).
	HTTP *http.Client
}

// New returns the UniFi module.
func New() *Module { return &Module{} }

var (
	macRe  = regexp.MustCompile(`^(?i)[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	siteRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

const macIn = `{"type":"object","required":["mac"],"properties":{"mac":{"type":"string","description":"The client's MAC address, aa:bb:cc:dd:ee:ff"}}}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "unifi", Name: "UniFi Network", Version: "0.1.0", Category: "Network", Icon: "wifi",
		Description: "Access points, switches and gateways, who's connected, restart a device, block a client.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The console's address, e.g. https://192.168.1.1"},
			"apiKey":{"type":"string","x-secret":true,"description":"An API key (UniFi Network, Settings, Control Plane, Integrations)"},
			"username":{"type":"string","description":"A local account, needed to block clients"},
			"password":{"type":"string","x-secret":true},
			"site":{"type":"string","default":"default"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the console's certificate, to trust its own self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "devices", Title: "Devices", Description: "Gateways, switches and access points: state, model, uptime.", Risk: sdk.RiskRead},
			{Name: "clients", Title: "Clients", Description: "Who's connected, busiest first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":50,"maximum":500}}}`)},
			{Name: "restart_device", Title: "Restart a device", Description: "Its clients lose the connection for a minute or two.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["device"],"properties":{"device":{"type":"string","description":"Device id (API key) or MAC address"}}}`)},
			{Name: "block_client", Title: "Block a client", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(macIn)},
			{Name: "unblock_client", Title: "Unblock a client", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(macIn)},
		},
	}
}

func normFingerprint(s string) (string, error) {
	h := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	if b, err := hex.DecodeString(h); err != nil || len(b) != sha256.Size {
		return "", errors.New("the fingerprint is a SHA-256 fingerprint: 32 bytes in hex, like AB:CD:…")
	}
	return h, nil
}

func pinned(fp string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // replaced by the pin check below
		VerifyPeerCertificate: func(certs [][]byte, _ [][]*x509.Certificate) error {
			if len(certs) == 0 {
				return errors.New("unifi: no certificate")
			}
			sum := sha256.Sum256(certs[0])
			if hex.EncodeToString(sum[:]) != fp {
				return errors.New("unifi: the console's certificate doesn't match the pinned fingerprint")
			}
			return nil
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
		return errors.New("the address is the console's https:// address, like https://192.168.1.1")
	}
	if c.Site == "" {
		c.Site = "default"
	}
	if !siteRe.MatchString(c.Site) {
		return errors.New("the site is a short name, like default")
	}
	if c.APIKey == "" && c.Username == "" {
		return errors.New("add an API key, or a local username and password")
	}
	for _, s := range []string{c.APIKey, c.Password} {
		if s != "" && !strings.HasPrefix(s, "secret://") {
			return errors.New("store the API key and password in the vault and enter their secret:// references")
		}
	}
	if (c.Username == "") != (c.Password == "") {
		return errors.New("a username needs a password and the other way round")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	switch {
	case c.Fingerprint != "":
		fp, err := normFingerprint(c.Fingerprint)
		if err != nil {
			return err
		}
		tr.TLSClientConfig = pinned(fp)
	case c.InsecureSkipVerify:
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // the person chose it
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 20 * time.Second, Transport: tr, Jar: jar}
	if m.HTTP != nil {
		client = &http.Client{Timeout: 20 * time.Second, Transport: m.HTTP.Transport, Jar: jar}
	}
	m.set.Put(id, &conn{cfg: c, host: h, base: u.Scheme + "://" + u.Host, http: client})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// integration calls the official Network API with the API key.
func (c *conn) integration(ctx context.Context, method, path string, body, out any) error {
	r := rest.New(c.base+"/proxy/network/integration/v1", func(ctx context.Context, req *http.Request) error {
		k, err := c.host.Secret(ctx, c.cfg.APIKey)
		if err != nil {
			return err
		}
		req.Header.Set("X-API-KEY", k)
		return nil
	})
	r.HTTP = c.http
	_, err := r.Do(ctx, method, path, nil, body, out)
	return err
}

// login signs in with the local account (cookie and CSRF token).
func (c *conn) login(ctx context.Context, fresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !fresh && c.csrf != "" && time.Since(c.auth) < 30*time.Minute {
		return c.csrf, nil
	}
	pw, err := c.host.Secret(ctx, c.cfg.Password)
	if err != nil {
		return "", err
	}
	r := rest.New(c.base, nil)
	r.HTTP = c.http
	hd, err := r.Do(ctx, "POST", "/api/auth/login", nil, map[string]any{"username": c.cfg.Username, "password": pw, "remember": false}, nil)
	if err != nil {
		return "", fmt.Errorf("UniFi sign-in: %w", err)
	}
	c.csrf, c.auth = hd.Get("X-CSRF-Token"), time.Now()
	return c.csrf, nil
}

// classic calls the Network application's own API with the session.
func (c *conn) classic(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	if c.cfg.Username == "" {
		return nil, errors.New("this needs a local username and password in the settings (the API key can't do it)")
	}
	for attempt := 0; attempt < 2; attempt++ {
		csrf, err := c.login(ctx, attempt > 0)
		if err != nil {
			return nil, err
		}
		r := rest.New(c.base+"/proxy/network/api/s/"+c.cfg.Site, func(_ context.Context, req *http.Request) error {
			if csrf != "" {
				req.Header.Set("X-CSRF-Token", csrf)
			}
			return nil
		})
		r.HTTP = c.http
		var out struct {
			Meta struct {
				RC  string `json:"rc"`
				Msg string `json:"msg"`
			} `json:"meta"`
			Data json.RawMessage `json:"data"`
		}
		_, err = r.Do(ctx, method, path, nil, body, &out)
		if rest.IsStatus(err, http.StatusUnauthorized) && attempt == 0 {
			continue
		}
		if err != nil {
			return nil, err
		}
		if out.Meta.RC != "" && out.Meta.RC != "ok" {
			return nil, fmt.Errorf("UniFi: %s", out.Meta.Msg)
		}
		return out.Data, nil
	}
	return nil, errors.New("UniFi kept refusing the session")
}

func (c *conn) siteID(ctx context.Context) (string, error) {
	var out struct {
		Data []struct {
			ID                string `json:"id"`
			InternalReference string `json:"internalReference"`
			Name              string `json:"name"`
		} `json:"data"`
	}
	if err := c.integration(ctx, "GET", "/sites?limit=200", nil, &out); err != nil {
		return "", err
	}
	for _, s := range out.Data {
		if s.InternalReference == c.cfg.Site || strings.EqualFold(s.Name, c.cfg.Site) || (c.cfg.Site == "default" && len(out.Data) == 1) {
			return s.ID, nil
		}
	}
	return "", fmt.Errorf("no site %q on this console", c.cfg.Site)
}

// Device is a gateway, switch or access point.
type Device struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Model         string `json:"model"`
	MAC           string `json:"mac"`
	IP            string `json:"ip"`
	State         string `json:"state"` // online, offline, updating, adopting…
	UptimeSeconds int64  `json:"uptimeSeconds,omitempty"`
	Version       string `json:"version,omitempty"`
}

// Client is a connected device.
type Client struct {
	Name    string `json:"name"`
	MAC     string `json:"mac"`
	IP      string `json:"ip"`
	Wired   bool   `json:"wired"`
	TxBytes int64  `json:"txBytes,omitempty"`
	RxBytes int64  `json:"rxBytes,omitempty"`
}

func (c *conn) devices(ctx context.Context) ([]Device, error) {
	out := []Device{}
	if c.cfg.APIKey != "" {
		site, err := c.siteID(ctx)
		if err != nil {
			return nil, err
		}
		var res struct {
			Data []struct {
				ID, Name, Model, MacAddress, IPAddress, State, FirmwareVersion string
			} `json:"data"`
		}
		if err := c.integration(ctx, "GET", "/sites/"+site+"/devices?limit=200", nil, &res); err != nil {
			return nil, err
		}
		for _, d := range res.Data {
			out = append(out, Device{ID: d.ID, Name: d.Name, Model: d.Model, MAC: strings.ToLower(d.MacAddress), IP: d.IPAddress, State: strings.ToLower(d.State), Version: d.FirmwareVersion})
		}
		return out, nil
	}
	raw, err := c.classic(ctx, "GET", "/stat/device", nil)
	if err != nil {
		return nil, err
	}
	var ds []struct {
		ID      string `json:"_id"`
		Name    string `json:"name"`
		Model   string `json:"model"`
		MAC     string `json:"mac"`
		IP      string `json:"ip"`
		State   int    `json:"state"`
		Uptime  int64  `json:"uptime"`
		Version string `json:"version"`
	}
	_ = json.Unmarshal(raw, &ds)
	states := map[int]string{0: "offline", 1: "online", 2: "pending adoption", 4: "updating", 5: "provisioning", 6: "unreachable", 7: "adopting"}
	for _, d := range ds {
		st := states[d.State]
		if st == "" {
			st = fmt.Sprintf("state %d", d.State)
		}
		out = append(out, Device{ID: d.ID, Name: d.Name, Model: d.Model, MAC: d.MAC, IP: d.IP, State: st, UptimeSeconds: d.Uptime, Version: d.Version})
	}
	return out, nil
}

func (c *conn) clients(ctx context.Context) ([]Client, error) {
	out := []Client{}
	if c.cfg.Username != "" {
		raw, err := c.classic(ctx, "GET", "/stat/sta", nil)
		if err != nil {
			return nil, err
		}
		var cs []struct {
			Name, Hostname, MAC, IP string
			IsWired                 bool  `json:"is_wired"`
			Tx                      int64 `json:"tx_bytes"`
			Rx                      int64 `json:"rx_bytes"`
		}
		_ = json.Unmarshal(raw, &cs)
		for _, x := range cs {
			n := x.Name
			if n == "" {
				n = x.Hostname
			}
			out = append(out, Client{Name: n, MAC: x.MAC, IP: x.IP, Wired: x.IsWired, TxBytes: x.Tx, RxBytes: x.Rx})
		}
		return out, nil
	}
	site, err := c.siteID(ctx)
	if err != nil {
		return nil, err
	}
	var res struct {
		Data []struct {
			Name, Type, IPAddress, MacAddress string
		} `json:"data"`
	}
	if err := c.integration(ctx, "GET", "/sites/"+site+"/clients?limit=500", nil, &res); err != nil {
		return nil, err
	}
	for _, x := range res.Data {
		out = append(out, Client{Name: x.Name, MAC: strings.ToLower(x.MacAddress), IP: x.IPAddress, Wired: x.Type == "WIRED"})
	}
	return out, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ds, err := c.devices(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var off []string
	for _, d := range ds {
		if d.State == "offline" || d.State == "unreachable" {
			off = append(off, d.Name)
		}
	}
	if len(off) > 0 {
		return sdk.Health{Status: "degraded", Message: "offline: " + strings.Join(off, ", ")}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d devices online", len(ds))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Limit  int    `json:"limit"`
		Device string `json:"device"`
		MAC    string `json:"mac"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "devices":
		ds, err := c.devices(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(ds)
	case "clients":
		cs, err := c.clients(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.SliceStable(cs, func(i, j int) bool { return cs[i].TxBytes+cs[i].RxBytes > cs[j].TxBytes+cs[j].RxBytes })
		total := len(cs)
		if p.Limit <= 0 || p.Limit > 500 {
			p.Limit = 50
		}
		if len(cs) > p.Limit {
			cs = cs[:p.Limit]
		}
		return sdk.JSON(map[string]any{"count": total, "clients": cs})
	case "restart_device":
		ds, err := c.devices(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var dev *Device
		for i := range ds {
			if strings.EqualFold(ds[i].ID, p.Device) || strings.EqualFold(ds[i].MAC, p.Device) {
				dev = &ds[i]
			}
		}
		if dev == nil {
			return sdk.Result{}, errors.New("no such device; use an id or MAC address from Devices")
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Restart " + dev.Name + " (" + dev.Model + ")", Changes: []sdk.Change{{Target: dev.Name, Op: "restart"}}}}, nil
		}
		if c.cfg.APIKey != "" && idRe.MatchString(dev.ID) {
			site, err := c.siteID(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := c.integration(ctx, "POST", "/sites/"+site+"/devices/"+dev.ID+"/actions", map[string]string{"action": "RESTART"}, nil); err != nil {
				return sdk.Result{}, err
			}
		} else if _, err := c.classic(ctx, "POST", "/cmd/devmgr", map[string]string{"cmd": "restart", "mac": dev.MAC}); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"restarting": dev.Name})
	case "block_client", "unblock_client":
		if !macRe.MatchString(p.MAC) {
			return sdk.Result{}, errors.New("the MAC address looks like aa:bb:cc:dd:ee:ff")
		}
		mac := strings.ToLower(p.MAC)
		cmd, undo, desc := "block-sta", "unblock_client", "Unblock "+mac
		if call.Action == "unblock_client" {
			cmd, undo, desc = "unblock-sta", "block_client", "Block "+mac+" again"
		}
		if _, err := c.classic(ctx, "POST", "/cmd/stamgr", map[string]string{"cmd": cmd, "mac": mac}); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"mac": mac, "done": cmd})
		r.Undo = sdk.UndoWith(undo, map[string]string{"mac": mac}, desc)
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
