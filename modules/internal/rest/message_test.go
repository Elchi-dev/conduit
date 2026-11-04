package rest

import (
	"strings"
	"testing"
)

// Error text reaches agents and the audit log: JSON messages are still read
// out, raw bodies only when they're one short line, and anything that looks
// like a credential is redacted.
func TestMessage(t *testing.T) {
	const st = "401 Unauthorized"
	for _, c := range []struct{ raw, want string }{
		{`{"message":"Bad credentials"}`, "Bad credentials"},
		{`{"errors":[{"detail":"Not found"}]}`, "Not found"},
		{`{"error":{"message":"No access"}}`, "No access"},
		{`{"detail":"Token invalid/expired"}`, "Token invalid/expired"},
		{`Permission denied`, st + ": Permission denied"},
		{`<html><body>oops</body></html>`, st},
		{"line one\nline two", st},
		{strings.Repeat("a ", 50), st}, // longer than a status phrase
		{`invalid key sk_fake_51HxQyZ2eZvKYlo2C0123456789`, st + ": invalid key [redacted]"},
		{`{"message":"Authorization: Bearer abc.def-ghi_jkl rejected"}`, "Authorization: [redacted] rejected"},
		{`{"message":"bad token=ghp_shortish1 for user"}`, "bad [redacted] for user"},
		{`{"message":"key 0123456789abcdefABCDEF0123 is revoked"}`, "key [redacted] is revoked"},
		{``, st},
	} {
		if got := message(st, []byte(c.raw)); got != c.want {
			t.Errorf("%q: got %q, want %q", c.raw, got, c.want)
		}
	}
}
