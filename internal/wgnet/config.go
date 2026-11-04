// Package wgnet runs the daemon's networks: userspace WireGuard tunnels
// (wireguard-go on a gVisor netstack, pure Go) that module instances can be
// attached to, so they reach hosts inside a WireGuard network without root,
// without a kernel interface and without touching the host's routes or DNS.
//
// A tunnel never becomes a route on the machine. Only connections that a
// module makes through its host (sdk.DialContext, sdk.Transport) and whose
// destination falls inside a peer's AllowedIPs are carried through it;
// everything else is dialled directly, as without a network (split tunnel).
//
// See docs/architecture/networks.md.
package wgnet

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Peer is one WireGuard peer.
type Peer struct {
	Name      string `json:"name,omitempty"`
	PublicKey string `json:"publicKey"`
	// PresharedKey is a secret:// reference (optional).
	PresharedKey string `json:"presharedKey,omitempty"`
	// Endpoint is host:port; a name is resolved when the tunnel starts.
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
}

// Config is one network.
type Config struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// PrivateKey is a secret:// reference to the interface's private key.
	PrivateKey string `json:"privateKey"`
	// PublicKey is derived from the private key (shown so it can be added
	// on the other side).
	PublicKey  string    `json:"publicKey,omitempty"`
	Addresses  []string  `json:"addresses"`
	DNS        []string  `json:"dns,omitempty"`
	MTU        int       `json:"mtu,omitempty"`
	ListenPort int       `json:"listenPort,omitempty"`
	Peers      []Peer    `json:"peers"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// DefaultMTU is wg-quick's default.
const DefaultMTU = 1420

// ParseKey decodes a base64 WireGuard key (32 bytes).
func ParseKey(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return nil, errors.New("not a WireGuard key (44 characters of base64)")
	}
	return b, nil
}

// PublicKey derives the base64 public key of a base64 private key.
func PublicKey(private string) (string, error) {
	k, err := ParseKey(private)
	if err != nil {
		return "", err
	}
	pub, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// GenerateKey returns a new base64 private key.
func GenerateKey() (string, error) {
	var k [32]byte
	if _, err := randRead(k[:]); err != nil {
		return "", err
	}
	// Clamp as wg genkey does.
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

// addrs returns the interface addresses (each may be written with or
// without a mask).
func (c Config) addrs() ([]netip.Addr, error) {
	var out []netip.Addr
	for _, a := range c.Addresses {
		a = strings.TrimSpace(a)
		if p, err := netip.ParsePrefix(a); err == nil {
			out = append(out, p.Addr())
			continue
		}
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("address %q isn't an IP address", a)
		}
		out = append(out, ip)
	}
	return out, nil
}

func (c Config) dnsAddrs() []netip.Addr {
	var out []netip.Addr
	for _, d := range c.DNS {
		if ip, err := netip.ParseAddr(strings.TrimSpace(d)); err == nil {
			out = append(out, ip)
		}
	}
	return out
}

// Routes returns every peer's AllowedIPs, masked.
func (c Config) Routes() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range c.Peers {
		for _, a := range p.AllowedIPs {
			if pr, err := netip.ParsePrefix(strings.TrimSpace(a)); err == nil {
				out = append(out, pr.Masked())
			}
		}
	}
	return out
}

// Normalize trims values and fills defaults.
func (c *Config) Normalize() {
	c.Name = strings.TrimSpace(c.Name)
	c.PrivateKey = strings.TrimSpace(c.PrivateKey)
	c.Addresses = trimAll(c.Addresses)
	c.DNS = trimAll(c.DNS)
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.Peers == nil {
		c.Peers = []Peer{}
	}
	for i := range c.Peers {
		p := &c.Peers[i]
		p.Name = strings.TrimSpace(p.Name)
		p.PublicKey = strings.TrimSpace(p.PublicKey)
		p.PresharedKey = strings.TrimSpace(p.PresharedKey)
		p.Endpoint = strings.TrimSpace(p.Endpoint)
		p.AllowedIPs = trimAll(p.AllowedIPs)
	}
}

func trimAll(in []string) []string {
	out := []string{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Validate checks a normalized config.
func (c Config) Validate() error {
	if c.Name == "" {
		return errors.New("give the network a name")
	}
	if !strings.HasPrefix(c.PrivateKey, "secret://") {
		return errors.New("the private key must be a secret:// reference to the vault")
	}
	if len(c.Addresses) == 0 {
		return errors.New("add the interface address inside the network, e.g. 10.8.0.2/32")
	}
	if _, err := c.addrs(); err != nil {
		return err
	}
	for _, d := range c.DNS {
		if _, err := netip.ParseAddr(d); err != nil {
			return fmt.Errorf("DNS server %q isn't an IP address", d)
		}
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return errors.New("MTU must be between 576 and 9000")
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return errors.New("listen port must be between 0 and 65535")
	}
	if len(c.Peers) == 0 {
		return errors.New("add at least one peer")
	}
	seen := map[string]bool{}
	for i, p := range c.Peers {
		n := fmt.Sprintf("peer %d", i+1)
		if _, err := ParseKey(p.PublicKey); err != nil {
			return fmt.Errorf("%s: public key: %v", n, err)
		}
		if seen[p.PublicKey] {
			return fmt.Errorf("%s: the same public key is listed twice", n)
		}
		seen[p.PublicKey] = true
		if p.PresharedKey != "" && !strings.HasPrefix(p.PresharedKey, "secret://") {
			return fmt.Errorf("%s: the preshared key must be a secret:// reference", n)
		}
		if p.Endpoint != "" {
			host, port, err := net.SplitHostPort(p.Endpoint)
			if err != nil || host == "" {
				return fmt.Errorf("%s: endpoint %q is not host:port", n, p.Endpoint)
			}
			if pn, err := strconv.Atoi(port); err != nil || pn < 1 || pn > 65535 {
				return fmt.Errorf("%s: endpoint port %q is invalid", n, port)
			}
		}
		if len(p.AllowedIPs) == 0 {
			return fmt.Errorf("%s: add the addresses it routes (AllowedIPs), e.g. 10.8.0.0/24", n)
		}
		for _, a := range p.AllowedIPs {
			if _, err := netip.ParsePrefix(a); err != nil {
				return fmt.Errorf("%s: allowed IP %q isn't a CIDR range", n, a)
			}
		}
		if p.PersistentKeepalive < 0 || p.PersistentKeepalive > 65535 {
			return fmt.Errorf("%s: keepalive must be between 0 and 65535 seconds", n)
		}
	}
	return nil
}

// Parsed is a wg-quick file split into the config (with no key material)
// and the keys it contained, which the caller moves into the vault.
type Parsed struct {
	Config     Config
	PrivateKey string
	// PresharedKeys holds each peer's preshared key ("" for none), by index.
	PresharedKeys []string
	// Ignored lists settings that only wg-quick itself acts on (PostUp,
	// Table, …), which a userspace tunnel doesn't need.
	Ignored []string
}

// ParseWGQuick reads a standard wg-quick .conf file.
func ParseWGQuick(text string) (Parsed, error) {
	var p Parsed
	section := ""
	var peer *Peer
	psk := ""
	flush := func() {
		if peer != nil {
			p.Config.Peers = append(p.Config.Peers, *peer)
			p.PresharedKeys = append(p.PresharedKeys, psk)
			peer, psk = nil, ""
		}
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		s := sc.Text()
		if i := strings.IndexAny(s, "#;"); i >= 0 {
			s = s[:i]
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			flush()
			section = strings.ToLower(strings.TrimSpace(s[1 : len(s)-1]))
			switch section {
			case "interface":
			case "peer":
				peer = &Peer{}
			default:
				return p, fmt.Errorf("line %d: unknown section [%s]", line, s[1:len(s)-1])
			}
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return p, fmt.Errorf("line %d: expected Key = Value", line)
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch section {
		case "interface":
			switch k {
			case "privatekey":
				p.PrivateKey = v
			case "address":
				p.Config.Addresses = append(p.Config.Addresses, splitList(v)...)
			case "dns":
				for _, d := range splitList(v) {
					if _, err := netip.ParseAddr(d); err == nil {
						p.Config.DNS = append(p.Config.DNS, d)
					} else {
						p.Ignored = append(p.Ignored, "DNS search domain "+d)
					}
				}
			case "mtu":
				n, err := strconv.Atoi(v)
				if err != nil {
					return p, fmt.Errorf("line %d: MTU %q isn't a number", line, v)
				}
				p.Config.MTU = n
			case "listenport":
				n, err := strconv.Atoi(v)
				if err != nil {
					return p, fmt.Errorf("line %d: ListenPort %q isn't a number", line, v)
				}
				p.Config.ListenPort = n
			case "table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark":
				p.Ignored = append(p.Ignored, strings.TrimSpace(s[:strings.Index(s, "=")]))
			default:
				return p, fmt.Errorf("line %d: unknown interface setting %q", line, k)
			}
		case "peer":
			switch k {
			case "publickey":
				peer.PublicKey = v
			case "presharedkey":
				psk = v
			case "endpoint":
				peer.Endpoint = v
			case "allowedips":
				peer.AllowedIPs = append(peer.AllowedIPs, splitList(v)...)
			case "persistentkeepalive":
				if strings.EqualFold(v, "off") {
					continue
				}
				n, err := strconv.Atoi(v)
				if err != nil {
					return p, fmt.Errorf("line %d: PersistentKeepalive %q isn't a number", line, v)
				}
				peer.PersistentKeepalive = n
			default:
				return p, fmt.Errorf("line %d: unknown peer setting %q", line, k)
			}
		default:
			return p, fmt.Errorf("line %d: setting outside [Interface] or [Peer]", line)
		}
	}
	if err := sc.Err(); err != nil {
		return p, err
	}
	flush()
	if p.PrivateKey == "" {
		return p, errors.New("the file has no [Interface] PrivateKey")
	}
	pub, err := PublicKey(p.PrivateKey)
	if err != nil {
		return p, fmt.Errorf("PrivateKey: %v", err)
	}
	p.Config.PublicKey = pub
	for i, k := range p.PresharedKeys {
		if k != "" {
			if _, err := ParseKey(k); err != nil {
				return p, fmt.Errorf("peer %d: PresharedKey: %v", i+1, err)
			}
		}
	}
	return p, nil
}

func splitList(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
