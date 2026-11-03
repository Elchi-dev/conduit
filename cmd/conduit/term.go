package main

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"unicode/utf8"
)

// termWriter makes text safe to show on a terminal. Module output (game
// server MOTDs, media titles, commit messages…) reaches the CLI from servers
// nobody here controls, and printed raw an escape sequence in it could move
// the cursor, rewrite what is on screen, set the window title, write to the
// clipboard (OSC 52) or worse. C0 control characters other than newline and
// tab, DEL, C1 control characters, stray bytes that aren't UTF-8 and the
// Unicode bidirectional overrides are shown escaped (\x1b, \u009b) instead.
//
// The only escape sequences let through are the handful of colour codes the
// CLI itself uses (see paint), so the worst an injected one can do is change
// a colour.
type termWriter struct{ w io.Writer }

var allowedSGR = []string{"\x1b[0m", "\x1b[1m", "\x1b[2m", "\x1b[31m", "\x1b[33m"}

func (t termWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(t.w, sanitize(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// sanitize escapes what a terminal would act on rather than show.
func sanitize(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\n' && c != '\t') || c >= 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
next:
	for i := 0; i < len(s); {
		c := s[i]
		if c == 0x1b {
			for _, a := range allowedSGR {
				if strings.HasPrefix(s[i:], a) {
					b.WriteString(a)
					i += len(a)
					continue next
				}
			}
		}
		if c < 0x80 {
			if (c < 0x20 && c != '\n' && c != '\t') || c == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
			i++
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n <= 1:
			fmt.Fprintf(&b, `\x%02x`, c)
		case (r >= 0x80 && r <= 0x9f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// plainHTTPWarning returns a warning when an API key would travel in clear
// text: over http:// to a host that isn't this machine.
func plainHTTPWarning(base string) string {
	u, err := url.Parse(base)
	if err != nil || !strings.EqualFold(u.Scheme, "http") {
		return ""
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return ""
	}
	return fmt.Sprintf("conduit: warning: sending the API key to %s over plain http; anyone on the network path can read it. Use https:// for a daemon on another machine.", sanitize(u.Host))
}
