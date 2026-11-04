// Package urlguard checks links that a module hands to a server which then
// fetches them itself (a read-it-later service, a bookmark crawler), so an
// agent can't use that server to reach services on its local network.
//
// Conduit can only check the name it is given: it normalises it (IDNA, so
// full-width digits and other look-alikes become the ASCII the server would
// use), refuses local and reserved addresses and names, and resolves the
// name itself, refusing it if any address is reserved. What the server does
// next, following redirects or resolving the name again to a different
// address (DNS rebinding), is for the server's own outbound rules: configure
// it to refuse private addresses as well.
package urlguard

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/elchi-dev/conduit/internal/netguard"
)

// Lookup resolves a name. Tests replace it.
var Lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// localSuffixes are names that only resolve inside a network: mDNS,
// Kubernetes services, the special-use and commonly squatted internal TLDs.
var localSuffixes = []string{
	".localhost", ".local", ".internal", ".home.arpa", ".lan", ".localdomain",
	".svc", ".cluster.local", ".home", ".corp", ".intranet",
}

// wildcardDNS are public services whose names resolve to an IP address
// written into the name (127.0.0.1.nip.io, app-10-0-0-1.sslip.io,
// 7f000001.nip.io), and ones whose every name is loopback.
var (
	wildcardDNS = []string{"nip.io", "sslip.io", "xip.io", "nip.direct", "traefik.me", "ip.addr.tools"}
	loopbackDNS = []string{"localtest.me", "lvh.me", "vcap.me", "lacolhost.com", "localhost.direct", "fuf.me"}
)

func errLocal(host string) error {
	return fmt.Errorf("%s is a local or private address; only links to public sites can be saved", host)
}

// Host checks a host name or IP address without resolving it and returns
// its ASCII form.
func Host(host string) (string, error) {
	h := strings.TrimSuffix(strings.TrimSpace(host), ".")
	if h == "" {
		return "", errLocal(host)
	}
	if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		if netguard.ReservedAddr(a) || deprecated(a) {
			return "", errLocal(host)
		}
		return a.String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(h)
	if err != nil {
		return "", fmt.Errorf("%s isn't a valid host name", host)
	}
	h = strings.ToLower(strings.TrimSuffix(ascii, "."))
	for i := 0; i < len(h); i++ {
		if h[i] >= 0x80 {
			return "", fmt.Errorf("%s isn't a valid host name", host)
		}
	}
	// IDNA can turn look-alikes (full-width digits) into an IP literal.
	if a, err := netip.ParseAddr(h); err == nil {
		if netguard.ReservedAddr(a) || deprecated(a) {
			return "", errLocal(host)
		}
		return a.String(), nil
	}
	if !strings.Contains(h, ".") || h == "localhost" {
		return "", errLocal(host)
	}
	for _, s := range localSuffixes {
		if strings.HasSuffix(h, s) {
			return "", errLocal(host)
		}
	}
	// No top-level domain is numeric: such a host is an IP address in a
	// form some resolvers accept (octal, hex, fewer than four parts).
	labels := strings.Split(h, ".")
	last := labels[len(labels)-1]
	if strings.HasPrefix(last, "0x") || strings.Trim(last, "0123456789") == "" {
		return "", errLocal(host)
	}
	for _, d := range loopbackDNS {
		if h == d || strings.HasSuffix(h, "."+d) {
			return "", errLocal(host)
		}
	}
	for _, d := range wildcardDNS {
		if strings.HasSuffix(h, "."+d) {
			for _, a := range embedded(strings.TrimSuffix(h, "."+d)) {
				if netguard.ReservedAddr(a) || deprecated(a) {
					return "", errLocal(host)
				}
			}
		}
	}
	return h, nil
}

// deprecated are IPv6 ranges netguard doesn't list but no public site uses:
// IPv4-compatible addresses (::/96, ::7f00:1 is 127.0.0.1) and the old
// site-local block (fec0::/10).
func deprecated(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if !a.Is6() {
		return false
	}
	b := a.As16()
	if b[0] == 0xfe && b[1]&0xc0 == 0xc0 {
		return true
	}
	for _, x := range b[:12] {
		if x != 0 {
			return false
		}
	}
	return true
}

// embedded finds the addresses a wildcard DNS name encodes in its labels:
// dotted (10.0.0.1.nip.io), dashed (app-10-0-0-1.nip.io), hex
// (0a000001.nip.io) and dashed IPv6 (fd00--1.sslip.io).
func embedded(sub string) []netip.Addr {
	var out []netip.Addr
	add := func(s string) {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	labels := strings.Split(sub, ".")
	for i := 0; i+4 <= len(labels); i++ {
		add(strings.Join(labels[i:i+4], "."))
	}
	for _, l := range labels {
		parts := strings.Split(l, "-")
		for i := 0; i+4 <= len(parts); i++ {
			add(strings.Join(parts[i:i+4], "."))
		}
		for _, p := range parts {
			if len(p) == 8 {
				if b, err := hex.DecodeString(p); err == nil {
					out = append(out, netip.AddrFrom4([4]byte(b)))
				}
			}
		}
		if strings.Contains(l, "--") || strings.Count(l, "-") >= 2 {
			// sslip.io writes IPv6 with dashes for colons, possibly after a
			// prefix ("www-2001-db8--1"); try every suffix.
			for i := 0; i < len(parts); i++ {
				add(strings.Join(parts[i:], ":"))
			}
		}
	}
	return out
}

// Check checks host as Host does, then resolves it and refuses it if any
// address it resolves to is reserved, or if it doesn't resolve.
func Check(ctx context.Context, host string) (string, error) {
	h, err := Host(host)
	if err != nil {
		return "", err
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return h, nil
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := Lookup(lctx, h)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("couldn't look up %s; only links to public sites that resolve can be saved", host)
	}
	for _, a := range addrs {
		if netguard.ReservedAddr(a) || deprecated(a) {
			return "", errLocal(host)
		}
	}
	return h, nil
}

// URL checks a link a server will fetch: http or https, no user name or
// password, and a public host (Check). It returns the link with its host in
// ASCII form, so the server is given exactly the name that was checked.
func URL(ctx context.Context, raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(raw) > 4096 {
		return nil, errors.New("the link is an http(s) address")
	}
	if u.User != nil {
		return nil, errors.New("the link has a user name or password in it; leave those out")
	}
	h, err := Check(ctx, u.Hostname())
	if err != nil {
		return nil, err
	}
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	if p := u.Port(); p != "" {
		h += ":" + p
	}
	u.Host = h
	return u, nil
}
