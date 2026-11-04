package rest

import (
	"net/url"
	"strings"
)

// StripUserinfo removes credentials from a repository or other URL before it
// is shown: https://user:token@host/x becomes https://host/x. An address
// that doesn't parse but has an "@" before its host part (scp-like Git
// addresses, or a URL with a malformed password) keeps only what follows the
// last "@" there.
func StripUserinfo(s string) string {
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
		if u.User == nil {
			return s
		}
		u.User = nil
		return u.String()
	}
	rest := s
	scheme := ""
	if i := strings.Index(s, "://"); i >= 0 {
		scheme, rest = s[:i+3], s[i+3:]
	}
	end := len(rest)
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		end = i
	}
	if i := strings.LastIndex(rest[:end], "@"); i >= 0 {
		return scheme + rest[i+1:]
	}
	return s
}
