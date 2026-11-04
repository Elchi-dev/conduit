// Package openwrt works with an OpenWrt router through ubus over HTTP
// (uhttpd-mod-ubus, JSON-RPC) with an rpcd session: board and system
// information, network interfaces, wireless radios and their networks
// (never their keys), DHCP leases, bringing a radio up or down, and
// restarting the router.
package openwrt

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
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one router.
type Config struct {
	URL                string `json:"url"`      // e.g. https://192.168.1.1
	Username           string `json:"username"` // an rpcd login (root, or a dedicated one)
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	host  sdk.Host
	cfg   Config
	api   *rest.Client
	where string // https://192.168.1.1
	addr  string // the router's host name or address, without port

	mu      sync.Mutex
	session string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the OpenWrt module.
func New() *Module { return &Module{} }

var (
	userRe    = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
	radioRe   = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)
	sessionRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// noSession is the session id ubus takes for the login call itself.
const noSession = "00000000000000000000000000000000"

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	radio := `{"type":"object","required":["radio"],"properties":{"radio":{"type":"string","description":"The radio's name, e.g. radio0 (from wireless)"}}}`
	return sdk.Manifest{
		ID: "openwrt", Name: "OpenWrt", Version: "0.1.0", Category: "Network", Icon: "router",
		Description: "An OpenWrt router: system, interfaces, wireless radios, DHCP leases; bring a radio up or down, restart it.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"The router's web address, e.g. https://192.168.1.1 (ubus is served at /ubus)"},
			"username":{"type":"string","description":"An rpcd login: root, or a dedicated user with an ACL in /usr/share/rpcd/acl.d"},
			"password":{"type":"string","x-secret":true,"description":"That login's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the router's certificate, to trust its own self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "system", Title: "System", Description: "Host name, model, OpenWrt release, kernel, uptime, load and memory.", Risk: sdk.RiskRead},
			{Name: "interfaces", Title: "Interfaces", Description: "Each network interface: up or down, protocol, device, uptime, addresses and DNS servers.", Risk: sdk.RiskRead},
			{Name: "wireless", Title: "Wireless", Description: "Each radio (up, disabled, band, channel) and its networks: SSID, mode, encryption type and network. Never the key.", Risk: sdk.RiskRead},
			{Name: "leases", Title: "DHCP leases", Description: "Address, MAC address, host name and expiry of each IPv4 and IPv6 lease. It lists the people's devices on the network, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "wifi_up", Title: "Bring a radio up", Description: "Brings a radio and its configured networks up again (until the next restart; the configuration isn't changed). The preview warns when one of them has no key. Undo brings it down.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(radio)},
			{Name: "wifi_down", Title: "Bring a radio down", Description: "Disconnects every client on the radio's networks (until it's brought up or the router restarts). Refused when the router's address sits on a network carried only by that radio (a wireless uplink); it can't tell when Conduit is a wireless client of a bridged network such as the LAN. Undo brings it up.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(radio)},
			{Name: "reboot", Title: "Restart the router", Description: "The network behind it is cut off for a minute or two.", Risk: sdk.RiskDestructive, DryRun: true},
		},
		Resources: []sdk.ResourceSpec{
			{Kind: "interface", Title: "Interfaces", ListAction: "interfaces", ViewHint: "table"},
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
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/ubus") {
		return errors.New("the address is the router's web address, like https://192.168.1.1")
	}
	c.Username = strings.TrimSpace(c.Username)
	if !userRe.MatchString(c.Username) {
		return errors.New("enter the rpcd login name, e.g. root")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
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
	where := u.Scheme + "://" + u.Host
	api := rest.New(where, nil)
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{host: h, cfg: c, api: api, where: where, addr: u.Hostname()})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// ubus status codes (libubus ubus_msg_status).
var ubusStatus = map[int]string{
	1: "invalid command", 2: "invalid argument", 3: "method not found", 4: "not found",
	5: "no data", 6: "permission denied", 7: "timeout", 8: "not supported", 9: "unknown error", 10: "connection failed",
}

// errDenied is a session ubus no longer accepts (expired), or an ACL that
// doesn't allow the call.
var errDenied = errors.New("access denied")

type ubusError struct {
	Code   int
	Object string
	Method string
}

func (e *ubusError) Error() string {
	if e.Code == 6 {
		return fmt.Sprintf("the login's rpcd ACL doesn't allow %s %s", e.Object, e.Method)
	}
	s := ubusStatus[e.Code]
	if s == "" {
		s = fmt.Sprintf("status %d", e.Code)
	}
	return fmt.Sprintf("ubus %s %s: %s", e.Object, e.Method, s)
}

func isUbus(err error, codes ...int) bool {
	var e *ubusError
	if !errors.As(err, &e) {
		return false
	}
	for _, c := range codes {
		if e.Code == c {
			return true
		}
	}
	return false
}

// rpc makes one JSON-RPC call to ubus.
func (c *conn) rpc(ctx context.Context, session, object, method string, args, out any) error {
	if args == nil {
		args = map[string]any{}
	}
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "call", "params": []any{session, object, method, args}}
	var r struct {
		Result []json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/ubus", nil, body, &r); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return errors.New("no ubus endpoint at this address (install uhttpd-mod-ubus)")
		}
		return err
	}
	if r.Error != nil {
		if r.Error.Code == -32002 {
			return errDenied
		}
		return fmt.Errorf("ubus: %s", rest.Redact(r.Error.Message))
	}
	if len(r.Result) == 0 {
		return errors.New("unexpected answer from ubus")
	}
	var code int
	if err := json.Unmarshal(r.Result[0], &code); err != nil {
		return errors.New("unexpected answer from ubus")
	}
	if code != 0 {
		return &ubusError{Code: code, Object: object, Method: method}
	}
	if out != nil && len(r.Result) > 1 {
		if err := json.Unmarshal(r.Result[1], out); err != nil {
			return fmt.Errorf("unexpected answer from ubus %s %s: %w", object, method, err)
		}
	}
	return nil
}

// login returns an rpcd session, signing in when there's none or it's
// about to expire.
func (c *conn) login(ctx context.Context, fresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !fresh && c.session != "" && time.Now().Before(c.expires) {
		return c.session, nil
	}
	pw, err := c.host.Secret(ctx, c.cfg.Password)
	if err != nil {
		return "", err
	}
	var s struct {
		Session string `json:"ubus_rpc_session"`
		Timeout int    `json:"timeout"`
	}
	err = c.rpc(ctx, noSession, "session", "login", map[string]any{"username": c.cfg.Username, "password": pw, "timeout": 600}, &s)
	if isUbus(err, 6) || errors.Is(err, errDenied) {
		return "", errors.New("OpenWrt refused the user name and password")
	}
	if err != nil {
		return "", err
	}
	if !sessionRe.MatchString(s.Session) {
		return "", errors.New("unexpected session from rpcd")
	}
	ttl := time.Duration(s.Timeout) * time.Second
	if ttl <= 0 || ttl > 10*time.Minute {
		ttl = 5 * time.Minute
	}
	c.session, c.expires = s.Session, time.Now().Add(ttl-30*time.Second)
	return c.session, nil
}

// call runs a ubus method with the session, signing in again once when the
// session was refused (it expired, or rpcd restarted).
func (c *conn) call(ctx context.Context, object, method string, args, out any) error {
	for attempt := 0; attempt < 2; attempt++ {
		s, err := c.login(ctx, attempt > 0)
		if err != nil {
			return err
		}
		err = c.rpc(ctx, s, object, method, args, out)
		if errors.Is(err, errDenied) {
			if attempt == 0 {
				continue
			}
			return fmt.Errorf("the login's rpcd ACL doesn't allow %s %s", object, method)
		}
		return err
	}
	return errors.New("unreachable")
}

// System is the board and system information.
type System struct {
	Hostname     string   `json:"hostname"`
	Model        string   `json:"model,omitempty"`
	Board        string   `json:"board,omitempty"`
	Release      string   `json:"release,omitempty"`
	Target       string   `json:"target,omitempty"`
	Kernel       string   `json:"kernel,omitempty"`
	Uptime       int64    `json:"uptimeSeconds"`
	Load         []string `json:"load,omitempty"`
	MemoryTotal  int64    `json:"memoryTotalBytes"`
	MemoryFree   int64    `json:"memoryAvailableBytes"`
	LocalTimeUTC string   `json:"localTime,omitempty"`
}

func (c *conn) system(ctx context.Context) (System, error) {
	var b struct {
		Hostname  string `json:"hostname"`
		Model     string `json:"model"`
		BoardName string `json:"board_name"`
		Kernel    string `json:"kernel"`
		Release   struct {
			Description string `json:"description"`
			Version     string `json:"version"`
			Revision    string `json:"revision"`
			Target      string `json:"target"`
		} `json:"release"`
	}
	if err := c.call(ctx, "system", "board", nil, &b); err != nil {
		return System{}, err
	}
	s := System{Hostname: b.Hostname, Model: b.Model, Board: b.BoardName, Kernel: b.Kernel, Target: b.Release.Target, Release: b.Release.Description}
	if s.Release == "" {
		s.Release = strings.TrimSpace("OpenWrt " + b.Release.Version + " " + b.Release.Revision)
	}
	var i struct {
		Uptime    int64   `json:"uptime"`
		LocalTime int64   `json:"localtime"`
		Load      []int64 `json:"load"`
		Memory    struct {
			Total     int64 `json:"total"`
			Free      int64 `json:"free"`
			Buffered  int64 `json:"buffered"`
			Available int64 `json:"available"`
		} `json:"memory"`
	}
	if c.call(ctx, "system", "info", nil, &i) == nil {
		s.Uptime, s.MemoryTotal = i.Uptime, i.Memory.Total
		s.MemoryFree = i.Memory.Available
		if s.MemoryFree == 0 {
			s.MemoryFree = i.Memory.Free + i.Memory.Buffered
		}
		for _, l := range i.Load {
			// The load averages are fixed point, times 65536.
			s.Load = append(s.Load, fmt.Sprintf("%.2f", float64(l)/65536))
		}
		if i.LocalTime > 0 {
			s.LocalTimeUTC = time.Unix(i.LocalTime, 0).UTC().Format(time.RFC3339)
		}
	}
	return s, nil
}

type address struct {
	Address string `json:"address"`
	Mask    int    `json:"mask"`
}

type iface struct {
	Interface string    `json:"interface"`
	Up        bool      `json:"up"`
	Pending   bool      `json:"pending"`
	Available bool      `json:"available"`
	Proto     string    `json:"proto"`
	Device    string    `json:"device"`
	L3Device  string    `json:"l3_device"`
	Uptime    int64     `json:"uptime"`
	IPv4      []address `json:"ipv4-address"`
	IPv6      []address `json:"ipv6-address"`
	DNS       []string  `json:"dns-server"`
}

func (c *conn) interfaces(ctx context.Context) ([]iface, error) {
	var d struct {
		Interface []iface `json:"interface"`
	}
	if err := c.call(ctx, "network.interface", "dump", nil, &d); err != nil {
		return nil, err
	}
	return d.Interface, nil
}

func cidrs(as []address) []string {
	out := []string{}
	for _, a := range as {
		out = append(out, fmt.Sprintf("%s/%d", a.Address, a.Mask))
	}
	return out
}

// radio is one wireless device from network.wireless status. The networks'
// configuration is decoded field by field: it also holds the key.
type radio struct {
	Up        bool `json:"up"`
	Pending   bool `json:"pending"`
	Autostart bool `json:"autostart"`
	Disabled  bool `json:"disabled"`
	Config    struct {
		Band     string `json:"band"`
		HWMode   string `json:"hwmode"`
		Channel  any    `json:"channel"`
		HTMode   string `json:"htmode"`
		Country  string `json:"country"`
		Disabled bool   `json:"disabled"`
	} `json:"config"`
	Interfaces []struct {
		Section string `json:"section"`
		Ifname  string `json:"ifname"`
		Config  struct {
			Mode       string   `json:"mode"`
			SSID       string   `json:"ssid"`
			Encryption string   `json:"encryption"`
			Network    []string `json:"network"`
			Hidden     bool     `json:"hidden"`
			Disabled   bool     `json:"disabled"`
		} `json:"config"`
	} `json:"interfaces"`
}

func (c *conn) wireless(ctx context.Context) (map[string]radio, error) {
	rs := map[string]radio{}
	if err := c.call(ctx, "network.wireless", "status", nil, &rs); err != nil {
		return nil, err
	}
	return rs, nil
}

func (r radio) out(name string) map[string]any {
	nets := []map[string]any{}
	for _, i := range r.Interfaces {
		row := map[string]any{"section": i.Section, "ifname": i.Ifname, "mode": i.Config.Mode, "ssid": i.Config.SSID,
			"encryption": i.Config.Encryption, "networks": i.Config.Network, "hidden": i.Config.Hidden, "disabled": i.Config.Disabled}
		if row["networks"] == nil {
			row["networks"] = []string{}
		}
		nets = append(nets, row)
	}
	o := map[string]any{"radio": name, "up": r.Up, "pending": r.Pending, "disabled": r.Disabled || r.Config.Disabled, "networks": nets}
	for k, v := range map[string]string{"band": r.Config.Band, "hwmode": r.Config.HWMode, "htmode": r.Config.HTMode, "country": r.Config.Country} {
		if v != "" {
			o[k] = v
		}
	}
	if r.Config.Channel != nil {
		o["channel"] = r.Config.Channel
	}
	return o
}

func (r radio) ssids() []string {
	out := []string{}
	for _, i := range r.Interfaces {
		if i.Config.SSID != "" {
			out = append(out, i.Config.SSID)
		}
	}
	return out
}

// throughRadio reports whether the address Conduit uses for the router sits
// on an interface carried directly by one of the radio's wireless networks
// (a router reached over its wireless uplink, or a wireless-only network).
// Bridges with wired ports don't count: Conduit may be wired. A host name is
// looked up; one that doesn't resolve here can't be checked. When the
// interfaces can't be read, the check fails closed.
func (c *conn) throughRadio(ctx context.Context, r radio) (string, bool, error) {
	ips := c.addrIPs(ctx)
	if len(ips) == 0 {
		return "", false, nil
	}
	ifs, err := c.interfaces(ctx)
	if err != nil {
		return "", false, fmt.Errorf("can't check whether Conduit reaches the router through this radio: %w", err)
	}
	wifi := map[string]bool{}
	for _, i := range r.Interfaces {
		if i.Ifname != "" {
			wifi[i.Ifname] = true
		}
	}
	for _, i := range ifs {
		if !wifi[i.L3Device] && !wifi[i.Device] {
			continue
		}
		for _, a := range append(append([]address{}, i.IPv4...), i.IPv6...) {
			x := net.ParseIP(a.Address)
			for _, ip := range ips {
				if x != nil && x.Equal(ip) {
					return i.Interface, true, nil
				}
			}
		}
	}
	return "", false, nil
}

// addrIPs is the router's address from the settings, or what its name
// resolves to here.
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

// open lists the radio's access-point networks that need no key: bringing
// the radio up lets anyone nearby join them.
func (r radio) open() []string {
	out := []string{}
	for _, i := range r.Interfaces {
		if e := strings.ToLower(strings.TrimSpace(i.Config.Encryption)); (e == "none" || e == "") && i.Config.Mode != "sta" && !i.Config.Disabled {
			out = append(out, firstOf(i.Config.SSID, i.Section))
		}
	}
	return out
}

type lease struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ipaddr"`
	IP6      string `json:"ip6addr"`
	MAC      string `json:"macaddr"`
	DUID     string `json:"duid"`
	Expires  int64  `json:"expires"`
}

func (c *conn) leases(ctx context.Context) ([]map[string]any, error) {
	var l struct {
		V4 []lease `json:"dhcp_leases"`
		V6 []lease `json:"dhcp6_leases"`
	}
	err := c.call(ctx, "luci-rpc", "getDHCPLeases", nil, &l)
	if err != nil && !isUbus(err, 3, 4) {
		return nil, err
	}
	out := []map[string]any{}
	if err != nil {
		// No LuCI: read dnsmasq's lease file (expiry mac ip host clientid).
		var f struct {
			Data string `json:"data"`
		}
		if err := c.call(ctx, "file", "read", map[string]string{"path": "/tmp/dhcp.leases"}, &f); err != nil {
			return nil, fmt.Errorf("can't read the leases (install luci-mod-rpc, or allow file read of /tmp/dhcp.leases): %w", err)
		}
		for _, line := range strings.Split(f.Data, "\n") {
			p := strings.Fields(line)
			if len(p) < 4 {
				continue
			}
			row := map[string]any{"family": "ipv4", "address": p[2], "mac": strings.ToLower(p[1])}
			if p[3] != "*" {
				row["hostname"] = p[3]
			}
			var exp int64
			if _, err := fmt.Sscan(p[0], &exp); err == nil && exp > 0 {
				row["expires"] = time.Unix(exp, 0).UTC().Format(time.RFC3339)
			}
			out = append(out, row)
		}
		return out, nil
	}
	add := func(family string, ls []lease) {
		for _, x := range ls {
			row := map[string]any{"family": family, "address": x.IP, "mac": strings.ToLower(x.MAC)}
			if family == "ipv6" {
				row["address"] = x.IP6
				if x.DUID != "" {
					row["duid"] = x.DUID
				}
			}
			if x.Hostname != "" {
				row["hostname"] = x.Hostname
			}
			if x.Expires > 0 {
				row["expiresInSeconds"] = x.Expires
			}
			out = append(out, row)
		}
	}
	add("ipv4", l.V4)
	add("ipv6", l.V6)
	return out, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.system(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := strings.TrimSpace(s.Hostname + " · " + s.Release)
	if s.Uptime > 0 {
		msg += " · up " + (time.Duration(s.Uptime) * time.Second).String()
	}
	if s.MemoryTotal > 0 && s.MemoryFree*20 < s.MemoryTotal {
		return sdk.Health{Status: "degraded", Message: "memory almost full · " + msg}
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
		Radio string `json:"radio"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "system":
		s, err := c.system(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(s)

	case "interfaces":
		ifs, err := c.interfaces(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, i := range ifs {
			dns := i.DNS
			if dns == nil {
				dns = []string{}
			}
			out = append(out, map[string]any{"name": i.Interface, "up": i.Up, "pending": i.Pending, "available": i.Available, "proto": i.Proto,
				"device": firstOf(i.L3Device, i.Device), "uptimeSeconds": i.Uptime, "ipv4": cidrs(i.IPv4), "ipv6": cidrs(i.IPv6), "dns": dns})
		}
		return sdk.JSON(out)

	case "wireless":
		rs, err := c.wireless(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		names := make([]string, 0, len(rs))
		for n := range rs {
			names = append(names, n)
		}
		sort.Strings(names)
		out := []map[string]any{}
		for _, n := range names {
			out = append(out, rs[n].out(n))
		}
		return sdk.JSON(out)

	case "leases":
		ls, err := c.leases(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(ls)

	case "wifi_up", "wifi_down":
		p.Radio = strings.TrimSpace(p.Radio)
		if !radioRe.MatchString(p.Radio) {
			return sdk.Result{}, errors.New("the radio is its name from wireless, e.g. radio0")
		}
		return c.setRadio(ctx, call, p.Radio)

	case "reboot":
		s, err := c.system(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		target := strings.TrimSpace(s.Hostname+" ("+s.Release+")") + " at " + c.where
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Restart " + target, Changes: []sdk.Change{{Target: target, Op: "restart"}}}}, nil
		}
		if err := c.call(ctx, "system", "reboot", nil, nil); err != nil && !strings.Contains(err.Error(), "EOF") {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"rebooting": target})
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

func (c *conn) setRadio(ctx context.Context, call sdk.Call, name string) (sdk.Result, error) {
	up := call.Action == "wifi_up"
	rs, err := c.wireless(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	r, ok := rs[name]
	if !ok {
		known := make([]string, 0, len(rs))
		for n := range rs {
			known = append(known, n)
		}
		sort.Strings(known)
		return sdk.Result{}, fmt.Errorf("there's no radio %s (the router has %s)", name, strings.Join(known, ", "))
	}
	ssids := strings.Join(r.ssids(), ", ")
	if r.Up == up {
		return sdk.JSON(map[string]any{"radio": name, "up": up, "ssids": r.ssids(), "note": "nothing to change"})
	}
	if up && (r.Disabled || r.Config.Disabled) {
		return sdk.Result{}, fmt.Errorf("%s is disabled in the router's configuration; enable it there first", name)
	}
	if !up {
		via, yes, err := c.throughRadio(ctx, r)
		if err != nil {
			return sdk.Result{}, err
		}
		if yes {
			return sdk.Result{}, fmt.Errorf("refusing: Conduit reaches the router through %s (interface %s), so bringing it down would cut off this connection", name, via)
		}
	}
	verb, back, op := "Bring down", "wifi_up", "down"
	if up {
		verb, back, op = "Bring up", "wifi_down", "up"
	}
	target := "radio " + name
	if ssids != "" {
		target += " (" + ssids + ")"
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]bool{"up": r.Up})
		a, _ := json.Marshal(map[string]bool{"up": up})
		sum := verb + " " + target
		if open := r.open(); up && len(open) > 0 {
			sum += "; " + strings.Join(open, ", ") + " has no key, anyone nearby can join it"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: op, Before: b, After: a}}}}, nil
	}
	if err := c.call(ctx, "network.wireless", op, map[string]string{"device": name}, nil); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"radio": name, "up": up, "ssids": r.ssids()}
	if open := r.open(); up && len(open) > 0 {
		out["openNetworks"] = open
	}
	res, err := sdk.JSON(out)
	undo := "Bring " + name + " up again"
	if up {
		undo = "Bring " + name + " down again"
	}
	res.Undo = sdk.UndoWith(back, map[string]string{"radio": name}, undo)
	return res, err
}
