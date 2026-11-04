package urlguard

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func fakeDNS(t *testing.T) {
	t.Helper()
	old := Lookup
	Lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "rebind.example.com":
			return []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("10.0.0.1")}, nil
		case "gone.example.com":
			return nil, errors.New("no such host")
		case "v6.example.com":
			return []netip.Addr{netip.MustParseAddr("::7f00:1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
	t.Cleanup(func() { Lookup = old })
}

func TestHostRefusesLocalForms(t *testing.T) {
	for _, h := range []string{
		"１２７.０.０.１", "127.0.0.1.nip.io", "169.254.169.254.nip.io", "app-10-0-0-1.sslip.io", "7f000001.nip.io",
		"fd00--1.sslip.io", "www.127.0.0.1.xip.io", "anything.localtest.me", "lvh.me",
		"kubernetes.default.svc", "api.default.svc.cluster.local", "router.home", "nas.corp", "wiki.intranet",
		"printer.local", "grafana.corp.internal", "router.lan", "box.home.arpa", "host.localdomain",
		"::7f00:1", "::a00:1", "fec0::1", "[::ffff:127.0.0.1]", "127.0.0.1", "0x7f.0.0.1", "2130706433", "127.1",
		"localhost", "LOCALHOST.", "app.localhost", "nas", "",
	} {
		if _, err := Host(h); err == nil {
			t.Errorf("%q accepted", h)
		}
	}
	for h, want := range map[string]string{
		"example.com": "example.com", "Example.COM.": "example.com", "münchen.de": "xn--mnchen-3ya.de",
		"1.1.1.1": "1.1.1.1", "2606:4700::1111": "2606:4700::1111", "8.8.8.8.nip.io": "8.8.8.8.nip.io",
		"sub.example.co.uk": "sub.example.co.uk",
	} {
		if got, err := Host(h); err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", h, got, err, want)
		}
	}
}

func TestCheckResolves(t *testing.T) {
	fakeDNS(t)
	for _, h := range []string{"rebind.example.com", "gone.example.com", "v6.example.com"} {
		if _, err := Check(context.Background(), h); err == nil {
			t.Errorf("%s accepted", h)
		}
	}
	if _, err := Check(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestURLNormalisesHost(t *testing.T) {
	fakeDNS(t)
	u, err := URL(context.Background(), "https://München.de:8443/a?b=c")
	if err != nil || u.String() != "https://xn--mnchen-3ya.de:8443/a?b=c" {
		t.Fatalf("%v %v", u, err)
	}
	for _, raw := range []string{"javascript:alert(1)", "example.com", "https://u:p@example.com/", "http://１２７.０.０.１/", "http://[::7f00:1]/"} {
		if _, err := URL(context.Background(), raw); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
}
