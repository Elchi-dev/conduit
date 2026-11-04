// Package dnsctl names the DNS records that carry control over a domain
// beyond answering for a host: ownership and certificate proofs, mail
// policy and keys, service discovery and client auto-configuration. DNS
// modules treat a record at such a name as an override (destructive), not
// as a fresh name an agent approved for writes may add.
package dnsctl

import "strings"

// autoconfHosts are first labels clients look up by convention to fetch
// policy or settings from (MTA-STS policy, mail client set-up, proxy
// auto-discovery), wherever in the zone they sit.
var autoconfHosts = map[string]string{
	"mta-sts":      "it is an mta-sts host (it serves the domain's mail transport policy)",
	"autodiscover": "it is an autodiscover host (mail clients fetch their settings, and send passwords, there)",
	"autoconfig":   "it is an autoconfig host (mail clients fetch their settings there)",
	"wpad":         "it is a wpad host (browsers fetch their proxy settings there)",
}

// Reasons says why a record at rel, a name relative to the zone ("" for the
// apex, labels separated by dots, lower case), controls more than a host.
// Any label starting with "_" counts (ACME, DKIM, DMARC, MTA-STS, TLS-RPT,
// SRV services, ownership proofs such as _atproto or _github-challenge-*),
// as do the hosts above as the first label at any depth.
func Reasons(rel string) []string {
	rel = strings.ToLower(strings.TrimSuffix(rel, "."))
	if rel == "" {
		return nil
	}
	labels := strings.Split(rel, ".")
	var out []string
	under := false
	for _, l := range labels {
		switch {
		case strings.HasPrefix(l, "_acme-challenge"):
			out = append(out, "it is an _acme-challenge name (it proves control for certificates)")
		case l == "_domainkey":
			out = append(out, "it is a DKIM key name (it lets mail be signed for the domain)")
		case strings.HasPrefix(l, "_") && !under:
			under = true
			out = append(out, "it is a service, policy or verification name ("+l+": mail policy, service discovery or proof of ownership)")
		}
	}
	first := labels[0]
	if first == "*" && len(labels) > 1 {
		first = labels[1]
	}
	if r, ok := autoconfHosts[first]; ok {
		out = append(out, r)
	}
	return out
}
