package dnsctl

import "testing"

func TestReasons(t *testing.T) {
	for _, n := range []string{"_dmarc", "_mta-sts", "_smtp._tls", "_atproto", "_github-challenge-evilorg", "_autodiscover._tcp",
		"_acme-challenge.www", "sel._domainkey", "mta-sts", "autodiscover", "autoconfig", "wpad", "wpad.office", "MTA-STS.", "autodiscover.shop", "x._dmarc.sub"} {
		if len(Reasons(n)) == 0 {
			t.Errorf("%s: no reason", n)
		}
	}
	for _, n := range []string{"", "www", "shop.www", "api", "office.wpad", "mta-sts-x", "my_host"} {
		if r := Reasons(n); len(r) != 0 {
			t.Errorf("%s: %v", n, r)
		}
	}
}
