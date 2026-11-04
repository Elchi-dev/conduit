package karakeep

import (
	"context"
	"net/netip"
	"testing"

	"github.com/elchi-dev/conduit/modules/internal/urlguard"
)

// Tests never use the network: names resolve to a public test address,
// except one that also resolves to a private one.
func init() {
	urlguard.Lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "rebind.example.com" {
			return []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("10.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
}

// Look-alike, wildcard-DNS, cluster and internal names are refused before
// anything reaches the server, and so is a name that resolves to a private
// address.
func TestLocalHostForms(t *testing.T) {
	m, f := setup(t, "secret://k")
	for _, u := range []string{
		"http://１２７.０.０.１/", "http://127.0.0.1.nip.io/", "http://169.254.169.254.nip.io/latest/meta-data/",
		"http://app-10-0-0-1.sslip.io/", "http://kubernetes.default.svc/", "http://api.svc.cluster.local/",
		"http://[::7f00:1]/", "http://[fec0::1]/", "http://router.home/", "http://nas.corp/", "http://wiki.intranet/",
		"http://rebind.example.com/",
	} {
		if _, err := invoke(m, "add_bookmark", `{"url":"`+u+`"}`, false); err == nil {
			t.Errorf("add_bookmark accepted %s", u)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("reached the server: %v", f.seen)
	}
}
