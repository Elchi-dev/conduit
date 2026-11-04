package rest

import (
	"net/url"
	"regexp"
	"strings"
)

// tokenish matches a path segment that may be a credential: a long run
// with digits in it (an API key, a webhook or heartbeat token, a UUID),
// rather than a word like api or healthz.
var tokenish = regexp.MustCompile(`^[A-Za-z0-9_.~%=+-]{16,}$`)

// ShortURL shows an address as scheme://host plus its first path segment
// (masked when it looks like a token), and "/…" for anything after it. The
// user, password, query and fragment are dropped: monitoring tools keep
// tokens in all of those (https://hc-ping.com/<uuid>, ?key=…), and what
// modules output ends up in the audit log.
func ShortURL(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme == "" || u.Host == "" {
		// Not an absolute URL (a host name, an IP, a heartbeat id): keep
		// what comes before any path, query or user part.
		s = StripUserinfo(strings.TrimSpace(s))
		if i := strings.IndexAny(s, "/?#"); i >= 0 {
			if strings.HasPrefix(s, "//") || i == 0 {
				return "…"
			}
			return s[:i] + "/…"
		}
		if tokenish.MatchString(s) && mixed(s) {
			return "…"
		}
		return s
	}
	out := u.Scheme + "://" + u.Host
	segs := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(segs) == 1 && segs[0] == "" {
		segs = nil
	}
	if len(segs) > 0 {
		first := segs[0]
		if len(first) > 40 || (tokenish.MatchString(first) && mixed(first)) {
			first = "…"
		}
		out += "/" + first
		if len(segs) > 1 {
			out += "/…"
		}
	}
	if u.RawQuery != "" || u.Fragment != "" {
		out += "?…"
	}
	return out
}

// mixed says whether s has a digit.
func mixed(s string) bool { return strings.ContainsAny(s, "0123456789") }
