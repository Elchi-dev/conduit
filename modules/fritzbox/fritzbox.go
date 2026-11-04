// Package fritzbox works with an AVM FRITZ!Box through TR-064 (SOAP over
// HTTP with digest authentication): device information, the internet
// connection, the hosts on the network, the wireless networks (never their
// keys), turning the guest network on or off, and reconnecting to the
// internet. It never calls the actions that return passwords: wireless
// security keys, PPPoE credentials, VPN or user settings.
package fritzbox

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // HTTP digest authentication is defined over MD5
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
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

// Config is one FRITZ!Box.
type Config struct {
	URL                string `json:"url"`      // default http://fritz.box:49000
	Username           string `json:"username"` // a FRITZ!Box user
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	host sdk.Host
	cfg  Config
	http *http.Client
	base string // http://fritz.box:49000
	addr string // fritz.box

	mu       sync.Mutex
	services map[string]string // service type → control URL
	ch       *challenge
	nc       int
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the FRITZ!Box module.
func New() *Module { return &Module{} }

var (
	userRe    = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
	controlRe = regexp.MustCompile(`^/[A-Za-z0-9/_.-]{1,128}$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
	sidRe     = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)
)

const (
	svcDeviceInfo = "urn:dslforum-org:service:DeviceInfo:1"
	svcHosts      = "urn:dslforum-org:service:Hosts:1"
	svcCommon     = "urn:dslforum-org:service:WANCommonInterfaceConfig:1"
	svcPPP        = "urn:dslforum-org:service:WANPPPConnection:1"
	svcIP         = "urn:dslforum-org:service:WANIPConnection:1"
	svcWLAN       = "urn:dslforum-org:service:WLANConfiguration:"
	soapNS        = "http://schemas.xmlsoap.org/soap/envelope/"
	soapEnc       = "http://schemas.xmlsoap.org/soap/encoding/"
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "fritzbox", Name: "FRITZ!Box", Version: "0.1.0", Category: "Network", Icon: "router",
		Description: "An AVM FRITZ!Box: device, internet connection, hosts on the network, wireless networks; guest network on or off, reconnect.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["username","password"],"properties":{
			"url":{"type":"string","default":"http://fritz.box:49000","description":"The TR-064 address: http://fritz.box:49000, or https://fritz.box:49443 with the fingerprint"},
			"username":{"type":"string","description":"A FRITZ!Box user (System, FRITZ!Box Users) with the FRITZ!Box Settings right"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the FRITZ!Box certificate, for https on port 49443"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "device_info", Title: "Device", Description: "Model, FRITZ!OS version, hardware version and uptime.", Risk: sdk.RiskRead},
			{Name: "wan_status", Title: "Internet connection", Description: "Access type (DSL, cable, fibre), link, connection status, uptime, last error, line speeds and the public IPv4 address. Never the PPPoE login.", Risk: sdk.RiskRead},
			{Name: "hosts", Title: "Hosts", Description: "Devices on the network: name, IP and MAC address, interface, speed, guest. Only active ones unless all is set. It lists people's devices, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"all":{"type":"boolean","default":false,"description":"Also the hosts that aren't connected now"}}}`)},
			{Name: "wifi", Title: "Wireless networks", Description: "Each wireless network: SSID, on or off, status, channel, standard, security type and whether it's the guest network. Never the key.", Risk: sdk.RiskRead},
			{Name: "guest_wifi_on", Title: "Turn the guest network on", Description: "Turns on the guest network as it's configured (isolated from the home network). The preview shows its SSID and security. Undo turns it off.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true},
			{Name: "guest_wifi_off", Title: "Turn the guest network off", Description: "Disconnects everyone on the guest network. Undo turns it on.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true},
			{Name: "reconnect", Title: "Reconnect to the internet", Description: "Drops the internet connection and dials again: everything online is cut off for a few seconds and the public address usually changes. Refused when Conduit reaches the FRITZ!Box over the internet (a MyFRITZ! or dynamic DNS name, or a public address); a VPN into the box can't be told apart and is cut off too.", Risk: sdk.RiskDestructive, DryRun: true},
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
		c.URL = "http://fritz.box:49000"
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.URL), "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return errors.New("the address is the TR-064 address, like http://fritz.box:49000")
	}
	c.Username = strings.TrimSpace(c.Username)
	if !userRe.MatchString(c.Username) {
		return errors.New("enter the FRITZ!Box user name")
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
	m.set.Put(id, &conn{host: h, cfg: c, http: rest.SameHostOnly(client), base: u.Scheme + "://" + u.Host, addr: u.Hostname()})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// --- service description ---

type xdevice struct {
	Services []struct {
		Type    string `xml:"serviceType"`
		Control string `xml:"controlURL"`
	} `xml:"serviceList>service"`
	Devices []xdevice `xml:"deviceList>device"`
}

func (d xdevice) walk(out map[string]string) {
	for _, s := range d.Services {
		if controlRe.MatchString(s.Control) && !strings.Contains(s.Control, "..") && !strings.HasPrefix(s.Control, "//") {
			out[strings.TrimSpace(s.Type)] = s.Control
		}
	}
	for _, x := range d.Devices {
		x.walk(out)
	}
}

// discover reads the services the FRITZ!Box offers (tr64desc.xml, no
// sign-in needed).
func (c *conn) discover(ctx context.Context) (map[string]string, error) {
	c.mu.Lock()
	if c.services != nil {
		s := c.services
		c.mu.Unlock()
		return s, nil
	}
	c.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/tr64desc.xml", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Conduit")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't reach the FRITZ!Box at %s: %w", c.base, rest.TransportError(err))
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("no TR-064 at this address (%s); turn on Home Network, Network, Network Settings, Allow access for applications", res.Status)
	}
	var root struct {
		Device xdevice `xml:"device"`
	}
	if err := xml.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&root); err != nil {
		return nil, errors.New("unexpected service description from the FRITZ!Box")
	}
	s := map[string]string{}
	root.Device.walk(s)
	if s[svcDeviceInfo] == "" {
		return nil, errors.New("this doesn't look like a FRITZ!Box (no DeviceInfo service)")
	}
	c.mu.Lock()
	c.services = s
	c.mu.Unlock()
	return s, nil
}

// --- digest authentication ---

type challenge struct {
	realm, nonce, opaque, algorithm string
	qop                             bool
}

// safeValue is a challenge or credential value that can be put between
// quotes as is.
func safeValue(s string) bool {
	if len(s) > 512 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

// parseChallenge reads a WWW-Authenticate: Digest header.
func parseChallenge(h string) (*challenge, error) {
	bad := errors.New("the FRITZ!Box sent an authentication challenge this module can't use")
	scheme, tail, ok := strings.Cut(strings.TrimSpace(h), " ")
	if !ok || !strings.EqualFold(scheme, "Digest") {
		return nil, bad
	}
	params := map[string]string{}
	for s := strings.TrimSpace(tail); s != ""; {
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return nil, bad
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimLeft(v, " ")
		var val string
		if strings.HasPrefix(v, `"`) {
			var b strings.Builder
			i := 1
			for ; i < len(v) && v[i] != '"'; i++ {
				if v[i] == '\\' && i+1 < len(v) {
					i++
				}
				b.WriteByte(v[i])
			}
			if i >= len(v) {
				return nil, bad
			}
			val, s = b.String(), v[i+1:]
		} else {
			end := strings.IndexByte(v, ',')
			if end < 0 {
				end = len(v)
			}
			val, s = strings.TrimSpace(v[:end]), v[end:]
		}
		params[k] = val
		s = strings.TrimLeft(strings.TrimSpace(s), ",")
		s = strings.TrimSpace(s)
	}
	ch := &challenge{realm: params["realm"], nonce: params["nonce"], opaque: params["opaque"], algorithm: params["algorithm"]}
	for _, q := range strings.Split(params["qop"], ",") {
		if strings.TrimSpace(q) == "auth" {
			ch.qop = true
		}
	}
	if params["qop"] != "" && !ch.qop {
		return nil, bad
	}
	if ch.algorithm == "" {
		ch.algorithm = "MD5"
	}
	if ch.nonce == "" || !strings.EqualFold(ch.algorithm, "MD5") && !strings.EqualFold(ch.algorithm, "SHA-256") {
		return nil, bad
	}
	for _, v := range []string{ch.realm, ch.nonce, ch.opaque, ch.algorithm} {
		if !safeValue(v) {
			return nil, bad
		}
	}
	return ch, nil
}

// authorization builds the Authorization header for one request. Every
// value is checked to be safe between quotes; none is escaped by hand.
func (ch *challenge) authorization(user, pw, method, uri string, nc int) (string, error) {
	if !safeValue(user) || !safeValue(uri) {
		return "", errors.New("the user name can't be used for digest authentication")
	}
	var nh func() hash.Hash = md5.New
	if strings.EqualFold(ch.algorithm, "SHA-256") {
		nh = sha256.New
	}
	sum := func(parts ...string) string {
		h := nh()
		io.WriteString(h, strings.Join(parts, ":"))
		return hex.EncodeToString(h.Sum(nil))
	}
	ha1 := sum(user, ch.realm, pw)
	ha2 := sum(method, uri)
	type field struct {
		k, v   string
		quoted bool
	}
	fs := []field{{"username", user, true}, {"realm", ch.realm, true}, {"nonce", ch.nonce, true}, {"uri", uri, true}, {"algorithm", ch.algorithm, false}}
	if ch.qop {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		cnonce, ncs := hex.EncodeToString(b), fmt.Sprintf("%08x", nc)
		fs = append(fs, field{"response", sum(ha1, ch.nonce, ncs, cnonce, "auth", ha2), true}, field{"qop", "auth", false}, field{"nc", ncs, false}, field{"cnonce", cnonce, true})
	} else {
		fs = append(fs, field{"response", sum(ha1, ch.nonce, ha2), true})
	}
	if ch.opaque != "" {
		fs = append(fs, field{"opaque", ch.opaque, true})
	}
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		if f.quoted {
			parts = append(parts, f.k+`="`+f.v+`"`)
		} else {
			parts = append(parts, f.k+"="+f.v)
		}
	}
	return "Digest " + strings.Join(parts, ", "), nil
}

var errRefused = errors.New("the FRITZ!Box refused the user name and password")

// send makes one request with digest authentication, answering a fresh
// challenge once.
func (c *conn) send(ctx context.Context, method, path string, body []byte, hdr http.Header) (int, []byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		for k, v := range hdr {
			req.Header[k] = v
		}
		req.Header.Set("User-Agent", "Conduit")
		c.mu.Lock()
		ch := c.ch
		if ch != nil {
			c.nc++
		}
		nc := c.nc
		c.mu.Unlock()
		if ch != nil {
			pw, err := c.host.Secret(ctx, c.cfg.Password)
			if err != nil {
				return 0, nil, err
			}
			a, err := ch.authorization(c.cfg.Username, pw, method, path, nc)
			if err != nil {
				return 0, nil, err
			}
			req.Header.Set("Authorization", a)
		}
		res, err := c.http.Do(req)
		if err != nil {
			return 0, nil, fmt.Errorf("can't reach the FRITZ!Box at %s: %w", c.base, rest.TransportError(err))
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
		res.Body.Close()
		if err != nil {
			return 0, nil, err
		}
		if res.StatusCode == http.StatusUnauthorized {
			next, err := parseChallenge(res.Header.Get("WWW-Authenticate"))
			if err != nil {
				return 0, nil, err
			}
			c.mu.Lock()
			c.ch, c.nc = next, 0
			c.mu.Unlock()
			if attempt == 0 {
				continue
			}
			return 0, nil, errRefused
		}
		return res.StatusCode, raw, nil
	}
	return 0, nil, errRefused
}

// --- SOAP ---

type arg struct{ name, value string }

// envelope builds a SOAP request with encoding/xml, which escapes every
// value.
func envelope(service, action string, args []arg) ([]byte, error) {
	if !nameRe.MatchString(action) {
		return nil, fmt.Errorf("invalid action %q", action)
	}
	var b bytes.Buffer
	b.WriteString(xml.Header)
	e := xml.NewEncoder(&b)
	env := xml.StartElement{Name: xml.Name{Local: "s:Envelope"}, Attr: []xml.Attr{
		{Name: xml.Name{Local: "xmlns:s"}, Value: soapNS}, {Name: xml.Name{Local: "s:encodingStyle"}, Value: soapEnc}}}
	bodyEl := xml.StartElement{Name: xml.Name{Local: "s:Body"}}
	act := xml.StartElement{Name: xml.Name{Local: "u:" + action}, Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns:u"}, Value: service}}}
	for _, t := range []xml.Token{env, bodyEl, act} {
		if err := e.EncodeToken(t); err != nil {
			return nil, err
		}
	}
	for _, a := range args {
		if !nameRe.MatchString(a.name) {
			return nil, fmt.Errorf("invalid argument %q", a.name)
		}
		if err := e.EncodeElement(a.value, xml.StartElement{Name: xml.Name{Local: a.name}}); err != nil {
			return nil, err
		}
	}
	for _, t := range []xml.Token{act.End(), bodyEl.End(), env.End()} {
		if err := e.EncodeToken(t); err != nil {
			return nil, err
		}
	}
	if err := e.Flush(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// leaves reads every leaf element under the SOAP body into a map by its
// local name.
func leaves(raw []byte) (map[string]string, bool, error) {
	d := xml.NewDecoder(bytes.NewReader(raw))
	out := map[string]string{}
	fault := false
	var stack []string
	var text strings.Builder
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, errors.New("unexpected answer from the FRITZ!Box")
		}
		switch x := t.(type) {
		case xml.StartElement:
			stack = append(stack, x.Name.Local)
			text.Reset()
			if x.Name.Local == "Fault" {
				fault = true
			}
		case xml.CharData:
			text.Write(x)
		case xml.EndElement:
			if len(stack) > 0 {
				out[stack[len(stack)-1]] = strings.TrimSpace(text.String())
				stack = stack[:len(stack)-1]
			}
			text.Reset()
		}
	}
	return out, fault, nil
}

type upnpError struct {
	Code int
	Desc string
}

func (e *upnpError) Error() string {
	switch e.Code {
	case 606:
		return "the FRITZ!Box user isn't allowed to do this (give it the FRITZ!Box Settings right)"
	case 401:
		return "this FRITZ!Box doesn't offer that action"
	}
	if e.Desc != "" {
		return fmt.Sprintf("FRITZ!Box: %s (%d)", rest.Redact(e.Desc), e.Code)
	}
	return fmt.Sprintf("FRITZ!Box error %d", e.Code)
}

var errNoService = errors.New("this FRITZ!Box doesn't offer that service")

// soap calls one TR-064 action and returns its output arguments.
func (c *conn) soap(ctx context.Context, service, action string, args ...arg) (map[string]string, error) {
	svcs, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	control := svcs[service]
	if control == "" {
		return nil, errNoService
	}
	body, err := envelope(service, action, args)
	if err != nil {
		return nil, err
	}
	hdr := http.Header{"Content-Type": {`text/xml; charset="utf-8"`}, "Soapaction": {service + "#" + action}}
	status, raw, err := c.send(ctx, http.MethodPost, control, body, hdr)
	if err != nil {
		return nil, err
	}
	out, fault, err := leaves(raw)
	if err != nil {
		return nil, err
	}
	if fault || status >= 300 {
		code, _ := strconv.Atoi(out["errorCode"])
		if code == 0 && status >= 300 {
			return nil, &rest.Error{Status: status, Message: fmt.Sprintf("FRITZ!Box: HTTP %d", status)}
		}
		return nil, &upnpError{Code: code, Desc: out["errorDescription"]}
	}
	return out, nil
}

// --- actions ---

func (c *conn) deviceInfo(ctx context.Context) (map[string]any, error) {
	r, err := c.soap(ctx, svcDeviceInfo, "GetInfo")
	if err != nil {
		return nil, err
	}
	up, _ := strconv.ParseInt(r["NewUpTime"], 10, 64)
	// The serial number, provisioning code and device log aren't passed on.
	return map[string]any{"manufacturer": r["NewManufacturerName"], "model": r["NewModelName"], "description": r["NewDescription"],
		"productClass": r["NewProductClass"], "softwareVersion": r["NewSoftwareVersion"], "hardwareVersion": r["NewHardwareVersion"], "uptimeSeconds": up}, nil
}

// wan returns the internet connection's state and which connection
// service carries it.
func (c *conn) wan(ctx context.Context) (map[string]any, string, error) {
	out := map[string]any{}
	if l, err := c.soap(ctx, svcCommon, "GetCommonLinkProperties"); err == nil {
		up, _ := strconv.ParseInt(l["NewLayer1UpstreamMaxBitRate"], 10, 64)
		down, _ := strconv.ParseInt(l["NewLayer1DownstreamMaxBitRate"], 10, 64)
		out["accessType"], out["link"], out["upstreamMaxBitsPerSecond"], out["downstreamMaxBitsPerSecond"] = l["NewWANAccessType"], l["NewPhysicalLinkStatus"], up, down
	} else if !errors.Is(err, errNoService) {
		return nil, "", err
	}
	used := ""
	var status map[string]string
	for _, svc := range []string{svcPPP, svcIP} {
		// GetStatusInfo, not GetInfo: GetInfo of the PPP connection holds
		// the PPPoE user name.
		s, err := c.soap(ctx, svc, "GetStatusInfo")
		if errors.Is(err, errNoService) {
			continue
		}
		var ue *upnpError
		if errors.As(err, &ue) && ue.Code != 606 {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		if used == "" || s["NewConnectionStatus"] == "Connected" {
			used, status = svc, s
		}
		if s["NewConnectionStatus"] == "Connected" {
			break
		}
	}
	if used == "" {
		return nil, "", errors.New("this FRITZ!Box has no internet connection service")
	}
	up, _ := strconv.ParseInt(status["NewUptime"], 10, 64)
	out["connection"] = map[string]string{svcPPP: "ppp", svcIP: "ip"}[used]
	out["status"], out["uptimeSeconds"], out["lastError"] = status["NewConnectionStatus"], up, status["NewLastConnectionError"]
	if ip, err := c.soap(ctx, used, "GetExternalIPAddress"); err == nil {
		out["externalIPv4"] = ip["NewExternalIPAddress"]
	}
	return out, used, nil
}

type host struct {
	IP        string `xml:"IPAddress"`
	MAC       string `xml:"MACAddress"`
	Active    string `xml:"Active"`
	Name      string `xml:"HostName"`
	Interface string `xml:"InterfaceType"`
	Speed     string `xml:"X_AVM-DE_Speed"`
	Guest     string `xml:"X_AVM-DE_Guest"`
}

func (h host) out() map[string]any {
	o := map[string]any{"name": h.Name, "ip": h.IP, "mac": strings.ToLower(h.MAC), "active": h.Active == "1", "interface": h.Interface}
	if h.Guest == "1" {
		o["guest"] = true
	}
	if n, err := strconv.Atoi(h.Speed); err == nil && n > 0 {
		o["speedMbps"] = n
	}
	return o
}

func (c *conn) hosts(ctx context.Context) ([]host, error) {
	if r, err := c.soap(ctx, svcHosts, "X_AVM-DE_GetHostListPath"); err == nil {
		if hs, err := c.hostList(ctx, r["NewX_AVM-DE_HostListPath"]); err == nil {
			return hs, nil
		}
	}
	// Older FRITZ!OS: one entry at a time.
	n, err := c.soap(ctx, svcHosts, "GetHostNumberOfEntries")
	if err != nil {
		return nil, err
	}
	count, _ := strconv.Atoi(n["NewHostNumberOfEntries"])
	if count > 256 {
		count = 256
	}
	out := []host{}
	for i := 0; i < count; i++ {
		e, err := c.soap(ctx, svcHosts, "GetGenericHostEntry", arg{"NewIndex", strconv.Itoa(i)})
		if err != nil {
			return nil, err
		}
		out = append(out, host{IP: e["NewIPAddress"], MAC: e["NewMACAddress"], Active: e["NewActive"], Name: e["NewHostName"], Interface: e["NewInterfaceType"]})
	}
	return out, nil
}

// hostList reads the host list file the FRITZ!Box names (on the same
// address, authorised by the session id in its query).
func (c *conn) hostList(ctx context.Context, p string) ([]host, error) {
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || !controlRe.MatchString(u.Path) || strings.Contains(u.Path, "..") {
		return nil, errors.New("unexpected host list path")
	}
	q := u.Query()
	if len(q) != 1 || !sidRe.MatchString(q.Get("sid")) {
		return nil, errors.New("unexpected host list path")
	}
	status, raw, err := c.send(ctx, http.MethodGet, u.Path+"?"+url.Values{"sid": {q.Get("sid")}}.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("host list: HTTP %d", status)
	}
	var l struct {
		Items []host `xml:"Item"`
	}
	if err := xml.Unmarshal(raw, &l); err != nil {
		return nil, errors.New("unexpected host list from the FRITZ!Box")
	}
	return l.Items, nil
}

type wlan struct {
	Index    int
	Service  string
	Enabled  bool
	Status   string
	SSID     string
	Channel  string
	Standard string
	Beacon   string
	Guest    bool
}

func (w wlan) out() map[string]any {
	return map[string]any{"index": w.Index, "ssid": w.SSID, "enabled": w.Enabled, "status": w.Status, "channel": w.Channel,
		"standard": w.Standard, "security": security(w.Beacon), "guest": w.Guest}
}

// security names a beacon type; "None" is an open network.
func security(b string) string {
	switch b {
	case "None":
		return "open"
	case "Basic":
		return "WEP"
	case "WPA":
		return "WPA"
	case "11i":
		return "WPA2"
	case "WPAand11i":
		return "WPA/WPA2"
	case "11iandWPA3":
		return "WPA2/WPA3"
	case "WPA3":
		return "WPA3"
	}
	return b
}

// wlans reads every wireless network with GetInfo, which holds no key
// (GetSecurityKeys is never called), and marks the guest network.
func (c *conn) wlans(ctx context.Context) ([]wlan, error) {
	svcs, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	var idx []int
	for s := range svcs {
		if n, err := strconv.Atoi(strings.TrimPrefix(s, svcWLAN)); strings.HasPrefix(s, svcWLAN) && err == nil {
			idx = append(idx, n)
		}
	}
	sort.Ints(idx)
	out := []wlan{}
	typed := false
	for _, n := range idx {
		svc := svcWLAN + strconv.Itoa(n)
		r, err := c.soap(ctx, svc, "GetInfo")
		if err != nil {
			return nil, err
		}
		w := wlan{Index: n, Service: svc, Enabled: r["NewEnable"] == "1", Status: r["NewStatus"], SSID: r["NewSSID"], Channel: r["NewChannel"], Standard: r["NewStandard"], Beacon: r["NewBeaconType"]}
		if x, err := c.soap(ctx, svc, "X_AVM-DE_GetWLANExtInfo"); err == nil && x["NewX_AVM-DE_APType"] != "" {
			typed = true
			w.Guest = x["NewX_AVM-DE_APType"] == "guest"
		}
		out = append(out, w)
	}
	if !typed && len(out) > 1 {
		// FRITZ!OS numbers the guest network last.
		out[len(out)-1].Guest = true
	}
	return out, nil
}

// remote reports whether Conduit reaches the FRITZ!Box over the internet:
// through a MyFRITZ! name, the box's public address, any other public
// address (a reconnect usually changes the IPv6 prefix too), or a name that
// resolves to one (a dynamic DNS name). A name that doesn't resolve here
// doesn't count; neither does a VPN into the box, which uses its local
// address.
func (c *conn) remote(ctx context.Context, external string) bool {
	a := strings.ToLower(strings.TrimSuffix(c.addr, "."))
	if strings.HasSuffix(a, ".myfritz.net") {
		return true
	}
	var ips []net.IP
	if ip := net.ParseIP(a); ip != nil {
		ips = append(ips, ip)
	} else {
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if as, err := net.DefaultResolver.LookupIPAddr(lctx, a); err == nil {
			for _, x := range as {
				ips = append(ips, x.IP)
			}
		}
	}
	y := net.ParseIP(external)
	for _, ip := range ips {
		if (y != nil && ip.Equal(y)) || public(ip) {
			return true
		}
	}
	return false
}

// public reports whether an address is reached over the internet: not
// loopback, private, link-local or shared (100.64.0.0/10, carrier-grade
// NAT and overlay networks).
func public(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return false
	}
	return ip.IsGlobalUnicast()
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	d, err := c.deviceInfo(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%v · FRITZ!OS %v · up %s", d["model"], d["softwareVersion"], time.Duration(d["uptimeSeconds"].(int64))*time.Second)
	if w, _, err := c.wan(ctx); err == nil && w["status"] != "Connected" {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("internet %v · %s", w["status"], msg)}
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
		All bool `json:"all"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "device_info":
		d, err := c.deviceInfo(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(d)

	case "wan_status":
		w, _, err := c.wan(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(w)

	case "hosts":
		hs, err := c.hosts(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, h := range hs {
			if p.All || h.Active == "1" {
				out = append(out, h.out())
			}
		}
		return sdk.JSON(out)

	case "wifi":
		ws, err := c.wlans(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, w := range ws {
			out = append(out, w.out())
		}
		return sdk.JSON(out)

	case "guest_wifi_on", "guest_wifi_off":
		return c.guest(ctx, call)

	case "reconnect":
		w, svc, err := c.wan(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		ext, _ := w["externalIPv4"].(string)
		if c.remote(ctx, ext) {
			return sdk.Result{}, errors.New("refusing: Conduit reaches the FRITZ!Box over the internet, so reconnecting would cut off this connection (and the address usually changes)")
		}
		target := fmt.Sprintf("internet connection (%v, %v, up %s)", w["connection"], w["status"], time.Duration(w["uptimeSeconds"].(int64))*time.Second)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Reconnect the " + target + "; the public address usually changes", Changes: []sdk.Change{{Target: target, Op: "reconnect"}}}}, nil
		}
		if _, err := c.soap(ctx, svc, "ForceTermination"); err != nil {
			var ue *upnpError
			// 707: a disconnect is already in progress.
			if !errors.As(err, &ue) || ue.Code != 707 {
				return sdk.Result{}, err
			}
		}
		return sdk.JSON(map[string]string{"reconnecting": target})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) guest(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	on := call.Action == "guest_wifi_on"
	ws, err := c.wlans(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	var g *wlan
	for i := range ws {
		if ws[i].Guest {
			g = &ws[i]
		}
	}
	if g == nil {
		return sdk.Result{}, errors.New("this FRITZ!Box has no guest network")
	}
	if g.Enabled == on {
		return sdk.JSON(map[string]any{"ssid": g.SSID, "enabled": on, "note": "nothing to change"})
	}
	verb, back, op := "Turn off", "guest_wifi_on", "off"
	if on {
		verb, back, op = "Turn on", "guest_wifi_off", "on"
	}
	target := fmt.Sprintf("guest network %s (%s)", g.SSID, security(g.Beacon))
	if call.DryRun {
		sum := verb + " the " + target
		if on && g.Beacon == "None" {
			sum += ": it's open, anyone nearby can use the internet connection through it"
		}
		b, _ := json.Marshal(map[string]bool{"enabled": g.Enabled})
		a, _ := json.Marshal(map[string]bool{"enabled": on})
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: op, Before: b, After: a}}}}, nil
	}
	v := "0"
	if on {
		v = "1"
	}
	if _, err := c.soap(ctx, g.Service, "SetEnable", arg{"NewEnable", v}); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"ssid": g.SSID, "enabled": on, "security": security(g.Beacon)})
	undo := "Turn the guest network on again"
	if on {
		undo = "Turn the guest network off again"
	}
	res.Undo = sdk.UndoWith(back, map[string]any{}, undo)
	return res, err
}
