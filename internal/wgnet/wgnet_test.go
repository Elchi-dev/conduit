package wgnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
)

const sampleConf = `
# Exported from a Forgejo box's WireGuard server
[Interface]
PrivateKey = %s
Address = 10.66.0.2/32, fd00:66::2/128
DNS = 10.66.0.1, internal.example
MTU = 1380
PostUp = iptables -A FORWARD -i %%i -j ACCEPT

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = vpn.example.com:51820
AllowedIPs = 10.66.0.0/24, fd00:66::/64
PersistentKeepalive = 25
`

func TestParseWGQuick(t *testing.T) {
	priv, _ := GenerateKey()
	peerPriv, _ := GenerateKey()
	peerPub, _ := PublicKey(peerPriv)
	psk, _ := GenerateKey()
	p, err := ParseWGQuick(fmt.Sprintf(sampleConf, priv, peerPub, psk))
	if err != nil {
		t.Fatal(err)
	}
	c := p.Config
	wantPub, _ := PublicKey(priv)
	if p.PrivateKey != priv || c.PublicKey != wantPub {
		t.Fatalf("keys: %+v", p)
	}
	if strings.Join(c.Addresses, ",") != "10.66.0.2/32,fd00:66::2/128" || strings.Join(c.DNS, ",") != "10.66.0.1" || c.MTU != 1380 {
		t.Fatalf("interface: %+v", c)
	}
	if len(c.Peers) != 1 || len(p.PresharedKeys) != 1 || p.PresharedKeys[0] != psk {
		t.Fatalf("peers: %+v %v", c.Peers, p.PresharedKeys)
	}
	pr := c.Peers[0]
	if pr.PublicKey != peerPub || pr.Endpoint != "vpn.example.com:51820" || pr.PersistentKeepalive != 25 || len(pr.AllowedIPs) != 2 {
		t.Fatalf("peer: %+v", pr)
	}
	if pr.PresharedKey != "" {
		t.Fatal("key material must not stay in the config")
	}
	if len(p.Ignored) != 2 {
		t.Fatalf("ignored: %v", p.Ignored)
	}
	// The parsed config validates once the keys are vault references.
	c.ID, c.Name, c.PrivateKey = "net_x", "Forgejo", "secret://networks/net_x/private-key"
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseWGQuickErrors(t *testing.T) {
	for _, tc := range []struct{ conf, want string }{
		{"[Peer]\nPublicKey = x\n", "no [Interface] PrivateKey"},
		{"[Interface]\nPrivateKey = nope\n", "PrivateKey"},
		{"[Interface]\nBogus = 1\n", "unknown interface setting"},
		{"[Wat]\n", "unknown section"},
		{"Address = 10.0.0.1\n", "outside [Interface]"},
		{"[Interface]\nMTU = big\n", "MTU"},
	} {
		if _, err := ParseWGQuick(tc.conf); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: got %v, want %q", tc.conf, err, tc.want)
		}
	}
}

func TestValidate(t *testing.T) {
	pub, _ := GenerateKey()
	good := Config{ID: "n", Name: "x", PrivateKey: "secret://k", Addresses: []string{"10.0.0.2/32"}, Peers: []Peer{{PublicKey: pub, AllowedIPs: []string{"10.0.0.0/24"}}}}
	good.Normalize()
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.PrivateKey = "raw-key"
	if err := bad.Validate(); err == nil {
		t.Fatal("a raw private key must be refused")
	}
	bad = good
	bad.Peers = []Peer{{PublicKey: pub, AllowedIPs: []string{"10.0.0.0/24"}, Endpoint: "nope"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("a bad endpoint must be refused")
	}
	bad = good
	bad.Peers = []Peer{{PublicKey: pub}}
	if err := bad.Validate(); err == nil {
		t.Fatal("a peer without allowed IPs must be refused")
	}
}

// pair brings up two tunnels on loopback that are each other's peer: A
// (10.77.0.1, listening) and B (10.77.0.2, dialling A's UDP port).
func pair(t *testing.T) (a, b *Tunnel, ca, cb Config) {
	t.Helper()
	ka, _ := GenerateKey()
	kb, _ := GenerateKey()
	pa, _ := PublicKey(ka)
	pb, _ := PublicKey(kb)
	ca = Config{ID: "net_a", Name: "A", PrivateKey: "secret://a", Addresses: []string{"10.77.0.1/24"}, ListenPort: freeUDP(t),
		Peers: []Peer{{Name: "b", PublicKey: pb, AllowedIPs: []string{"10.77.0.2/32"}}}}
	ctx := context.Background()
	a, err := Start(ctx, ca, Keys{Private: ka}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	port := ca.ListenPort
	cb = Config{ID: "net_b", Name: "B", PrivateKey: "secret://b", Addresses: []string{"10.77.0.2/32"},
		Peers: []Peer{{Name: "a", PublicKey: pa, Endpoint: fmt.Sprintf("127.0.0.1:%d", port), AllowedIPs: []string{"10.77.0.0/24"}, PersistentKeepalive: 1}}}
	b, err = Start(ctx, cb, Keys{Private: kb}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return a, b, ca, cb
}

// freeUDP finds a free UDP port on loopback. (wireguard-go reports port 0
// for a random port when the machine has no IPv6, so tests pick one.)
func freeUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func serveOn(t *testing.T, tn *Tunnel, addr string) {
	t.Helper()
	ln, err := tn.Net().ListenTCPAddrPort(netip.MustParseAddrPort(addr))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from inside the tunnel, you are "+r.RemoteAddr)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func TestTwoTunnelsHTTP(t *testing.T) {
	a, b, _, _ := pair(t)
	serveOn(t, a, "10.77.0.1:80")

	cl := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return b.Dial(ctx, network, addr, nil)
		},
	}}
	res, err := cl.Get("http://10.77.0.1/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(body), "hello from inside the tunnel, you are 10.77.0.2:") {
		t.Fatalf("body %q", body)
	}
	st, err := b.Status()
	if err != nil || len(st) != 1 {
		t.Fatalf("status %v %+v", err, st)
	}
	if st[0].Name != "a" || st[0].LastHandshake == nil || st[0].HandshakeAgeSeconds < 0 || st[0].RxBytes == 0 || st[0].TxBytes == 0 {
		t.Fatalf("peer status %+v", st[0])
	}
}

func TestDialOutsideTunnel(t *testing.T) {
	_, b, _, _ := pair(t)
	if b.Routes(netip.MustParseAddr("127.0.0.1")) || !b.Routes(netip.MustParseAddr("10.77.0.9")) {
		t.Fatal("routes")
	}
	// A plain local server outside the network is reached directly ...
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	c, err := b.Dial(context.Background(), "tcp", ln.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// ... unless the caller refuses direct destinations of that kind.
	noLoopback := func(ip netip.Addr) bool { return !ip.IsLoopback() }
	if _, err := b.Dial(context.Background(), "tcp", ln.Addr().String(), noLoopback); !errors.Is(err, ErrNotRouted) {
		t.Fatalf("got %v", err)
	}
}

func TestManager(t *testing.T) {
	ctx := context.Background()
	store, err := core.OpenStore(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ka, _ := GenerateKey()
	kb, _ := GenerateKey()
	pa, _ := PublicKey(ka)
	pb, _ := PublicKey(kb)
	secrets := map[string]string{"secret://a": ka, "secret://b": kb}
	m := NewManager(store.DB, func(_ context.Context, ref string) (string, error) {
		if v, ok := secrets[ref]; ok {
			return v, nil
		}
		return "", errors.New("no such secret")
	}, nil)
	defer m.Close()

	// A is started by hand, so its UDP port is known.
	ca := Config{ID: "net_a", Name: "A", PrivateKey: "secret://a", Addresses: []string{"10.78.0.1/24"}, ListenPort: freeUDP(t),
		Peers: []Peer{{PublicKey: pb, AllowedIPs: []string{"10.78.0.2/32"}}}}
	a, err := Start(ctx, ca, Keys{Private: ka}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	serveOn(t, a, "10.78.0.1:8080")

	cb := Config{ID: "net_b", Name: "Office", PrivateKey: "secret://b", Addresses: []string{"10.78.0.2"},
		Peers: []Peer{{PublicKey: pa, Endpoint: fmt.Sprintf("127.0.0.1:%d", ca.ListenPort), AllowedIPs: []string{"10.78.0.0/24"}}}}
	saved, err := m.Save(ctx, cb)
	if err != nil {
		t.Fatal(err)
	}
	if saved.MTU != DefaultMTU || saved.CreatedAt.IsZero() {
		t.Fatalf("saved %+v", saved)
	}
	if list, _ := m.List(ctx); len(list) != 1 || list[0].Name != "Office" {
		t.Fatalf("list %+v", list)
	}
	st, err := m.Status(ctx, "net_b", false)
	if err != nil || st.Running {
		t.Fatalf("a network starts on first use: %+v %v", st, err)
	}
	cl := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return m.Dial(ctx, "net_b", network, addr, nil)
		},
	}}
	res, err := cl.Get("http://10.78.0.1:8080/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if st, _ = m.Status(ctx, "net_b", false); !st.Running || len(st.Peers) != 1 || st.Peers[0].RxBytes == 0 {
		t.Fatalf("status %+v", st)
	}

	// A missing key is reported, not fatal.
	cb.PrivateKey = "secret://missing"
	if _, err := m.Save(ctx, cb); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Dial(ctx, "net_b", "tcp", "10.78.0.1:8080", nil); err == nil {
		t.Fatal("expected an error")
	}
	if st, _ = m.Status(ctx, "net_b", false); st.Running || !strings.Contains(st.Error, "private key") {
		t.Fatalf("status %+v", st)
	}
	if err := m.Delete(ctx, "net_b"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, "net_b"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
