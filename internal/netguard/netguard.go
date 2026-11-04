// Package netguard keeps outgoing requests that a module or a person points
// at a URL off the local network. Reserved says whether an address is one a
// fetched URL must never reach; Control does that check when a connection is
// made, on the address actually dialled, so DNS rebinding, a second DNS
// answer or a redirect can't get around it.
package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// Ranges refused besides the stdlib's loopback, private, link-local,
// multicast and unspecified checks: "this network", carrier-grade NAT (also
// Tailscale), IETF protocol assignments, benchmarking, the old class E block (and
// broadcast), NAT64 (which can embed
// any IPv4 address, private ones included), 6to4, Teredo and unique local.
var reservedNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, c := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4",
		"64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32", "fc00::/7"} {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}()

// Reserved reports whether ip is an address a fetched URL must not reach:
// loopback, private, link-local, carrier-grade NAT, unique local, multicast,
// unspecified, NAT64 and the other special ranges above, in IPv4, IPv6 and
// IPv4-mapped IPv6 form. An address that doesn't parse counts as reserved.
func Reserved(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	return ReservedAddr(a)
}

// ReservedAddr is Reserved for a netip.Addr.
func ReservedAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return true
	}
	a = a.Unmap().WithZone("")
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range reservedNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ErrReserved is returned when a connection to a reserved address is refused.
var ErrReserved = errors.New("refused to connect to a local or reserved address")

// Control is a net.Dialer Control function that refuses connections to
// reserved addresses. It runs after DNS resolution, for every address the
// dialer tries.
func Control(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrReserved, address)
	}
	a, err := netip.ParseAddr(host)
	if err != nil || ReservedAddr(a) {
		return fmt.Errorf("%w: %s", ErrReserved, host)
	}
	return nil
}

// Dialer returns a dialer that only connects to public addresses.
func Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, Control: Control}
}

// PublicHTTPSClient returns a client for fetching URLs that come from
// untrusted places: it uses no proxy (a proxy would make the connection, so
// the address check couldn't apply), connects only to public addresses,
// speaks only https, and follows at most maxRedirects redirects, each to an
// https URL (the dial check covers the address it leads to).
func PublicHTTPSClient(timeout time.Duration, maxRedirects int) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           Dialer(10 * time.Second).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirect to a non-https URL refused")
			}
			return nil
		},
	}
}
