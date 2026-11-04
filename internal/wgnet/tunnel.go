package wgnet

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func randRead(b []byte) (int, error) { return rand.Read(b) }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Keys is the key material a tunnel needs, resolved from the vault.
type Keys struct {
	Private string
	// Preshared holds each peer's preshared key ("" for none), by index.
	Preshared []string
}

// Tunnel is one running userspace WireGuard interface.
type Tunnel struct {
	cfg    Config
	dev    *device.Device
	tnet   *netstack.Net
	routes []netip.Prefix
	dns    bool
	start  time.Time
}

// Start brings a tunnel up. Endpoints given as names are resolved now.
func Start(ctx context.Context, cfg Config, keys Keys, log *slog.Logger) (*Tunnel, error) {
	cfg.Normalize()
	addrs, err := cfg.addrs()
	if err != nil {
		return nil, err
	}
	priv, err := ParseKey(keys.Private)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", hex.EncodeToString(priv))
	if cfg.ListenPort > 0 {
		fmt.Fprintf(&uapi, "listen_port=%d\n", cfg.ListenPort)
	}
	for i, p := range cfg.Peers {
		pub, err := ParseKey(p.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %d: %w", i+1, err)
		}
		fmt.Fprintf(&uapi, "public_key=%s\n", hex.EncodeToString(pub))
		if i < len(keys.Preshared) && keys.Preshared[i] != "" {
			psk, err := ParseKey(keys.Preshared[i])
			if err != nil {
				return nil, fmt.Errorf("peer %d: preshared key: %w", i+1, err)
			}
			fmt.Fprintf(&uapi, "preshared_key=%s\n", hex.EncodeToString(psk))
		}
		if p.Endpoint != "" {
			ep, err := resolveEndpoint(ctx, p.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("peer %d: endpoint: %w", i+1, err)
			}
			fmt.Fprintf(&uapi, "endpoint=%s\n", ep)
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&uapi, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}
		uapi.WriteString("replace_allowed_ips=true\n")
		for _, a := range p.AllowedIPs {
			pr, err := netip.ParsePrefix(a)
			if err != nil {
				return nil, fmt.Errorf("peer %d: allowed IP %q: %w", i+1, a, err)
			}
			fmt.Fprintf(&uapi, "allowed_ip=%s\n", pr.Masked())
		}
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	dns := cfg.dnsAddrs()
	tdev, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		return nil, err
	}
	logger := device.NewLogger(device.LogLevelSilent, "")
	if log != nil {
		l := log.With("network", cfg.ID)
		logger = &device.Logger{
			Verbosef: func(string, ...any) {},
			Errorf:   func(f string, a ...any) { l.Debug("wireguard: " + fmt.Sprintf(f, a...)) },
		}
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapi.String()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure WireGuard: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &Tunnel{cfg: cfg, dev: dev, tnet: tnet, routes: cfg.Routes(), dns: len(dns) > 0, start: time.Now()}, nil
}

func resolveEndpoint(ctx context.Context, ep string) (string, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return "", err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), mustPort(port)).String(), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("%s has no address", host)
	}
	// Prefer IPv4: it works on more networks.
	best := ips[0]
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			best = ip
			break
		}
	}
	return netip.AddrPortFrom(best.Unmap(), mustPort(port)).String(), nil
}

func mustPort(s string) uint16 {
	n, _ := strconv.Atoi(s)
	return uint16(n)
}

// Close takes the tunnel down.
func (t *Tunnel) Close() { t.dev.Close() }

// Net is the tunnel's network stack (tests listen on it).
func (t *Tunnel) Net() *netstack.Net { return t.tnet }

// Routes reports whether ip is carried by the tunnel (inside a peer's
// AllowedIPs).
func (t *Tunnel) Routes(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range t.routes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// DirectFunc decides whether a destination outside the tunnel may be dialled
// directly. nil allows every destination.
type DirectFunc func(netip.Addr) bool

// ErrNotRouted is returned when a destination is outside the tunnel and the
// caller doesn't allow it directly.
var ErrNotRouted = errors.New("destination is outside the network and not allowed directly")

// Dial connects to addr: through the tunnel when its address is inside the
// network, directly otherwise (if direct allows it). Names are resolved by
// the network's DNS servers first, then by the system resolver.
func (t *Tunnel) Dial(ctx context.Context, network, addr string, direct DirectFunc) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := t.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		target := net.JoinHostPort(ip.String(), port)
		var c net.Conn
		if t.Routes(ip) {
			c, err = t.tnet.DialContext(ctx, network, target)
		} else {
			if direct != nil && !direct(ip) {
				lastErr = fmt.Errorf("%s (%s): %w", host, ip, ErrNotRouted)
				continue
			}
			d := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
			c, err = d.DialContext(ctx, network, target)
		}
		if err == nil {
			return c, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%s has no usable address", host)
	}
	return nil, lastErr
}

func (t *Tunnel) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if ip, err := netip.ParseAddr(h); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if t.dns {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		names, err := t.tnet.LookupContextHost(lctx, h)
		cancel()
		if err == nil && len(names) > 0 {
			var out []netip.Addr
			for _, n := range names {
				if ip, err := netip.ParseAddr(n); err == nil {
					out = append(out, ip.Unmap())
				}
			}
			if len(out) > 0 {
				return out, nil
			}
		}
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", h)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.Unmap())
	}
	return out, nil
}

// PeerStatus is what WireGuard reports about one peer.
type PeerStatus struct {
	PublicKey string `json:"publicKey"`
	Name      string `json:"name,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	// LastHandshake is zero before the first handshake.
	LastHandshake *time.Time `json:"lastHandshake,omitempty"`
	// HandshakeAgeSeconds is how long ago the last handshake was (-1: never).
	HandshakeAgeSeconds int64 `json:"handshakeAgeSeconds"`
	RxBytes             int64 `json:"rxBytes"`
	TxBytes             int64 `json:"txBytes"`
}

// Status reads every peer's handshake and traffic counters.
func (t *Tunnel) Status() ([]PeerStatus, error) {
	s, err := t.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, p := range t.cfg.Peers {
		if k, err := ParseKey(p.PublicKey); err == nil {
			names[hex.EncodeToString(k)] = p.Name
		}
	}
	var out []PeerStatus
	var cur *PeerStatus
	var sec, nsec int64
	finish := func() {
		if cur == nil {
			return
		}
		cur.HandshakeAgeSeconds = -1
		if sec > 0 {
			ts := time.Unix(sec, nsec).UTC()
			cur.LastHandshake = &ts
			cur.HandshakeAgeSeconds = int64(time.Since(ts).Seconds())
		}
		out = append(out, *cur)
		cur, sec, nsec = nil, 0, 0
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			finish()
			b, _ := hex.DecodeString(v)
			cur = &PeerStatus{PublicKey: b64(b), Name: names[v]}
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	finish()
	return out, nil
}
