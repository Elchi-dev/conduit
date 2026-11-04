package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"syscall"
)

// StatusError is implemented by errors that carry an HTTP status (the
// modules' REST client's *rest.Error). A sensitive action's failure is
// recorded as that status alone.
type StatusError interface {
	error
	HTTPStatus() int
}

// ErrorText is what the audit log, events, approvals and automation runs
// keep of a failed call's error. A sensitive action's error text may quote
// what it carries (an address in a request URL, a server echoing a
// filter), so only its class is kept: "failed (HTTP 404)", "failed
// (timeout)", "failed (connection error)" or "failed". Any other error is
// kept with SanitizeErrorText applied. The caller still gets the full error.
func ErrorText(sensitive bool, err error) string {
	if err == nil {
		return ""
	}
	if sensitive {
		return ErrorClass(err)
	}
	return SanitizeErrorText(err.Error())
}

// ErrorClass names the kind of failure without any of its text.
func ErrorClass(err error) string {
	var se StatusError
	if errors.As(err, &se) && se.HTTPStatus() > 0 {
		return fmt.Sprintf("failed (HTTP %d)", se.HTTPStatus())
	}
	var te interface{ Timeout() bool }
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &te) && te.Timeout()) {
		return "failed (timeout)"
	}
	if errors.Is(err, context.Canceled) {
		return "failed (canceled)"
	}
	var ue *url.Error
	var oe *net.OpError
	var de *net.DNSError
	if errors.As(err, &ue) || errors.As(err, &oe) || errors.As(err, &de) || errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return "failed (connection error)"
	}
	return "failed"
}

// urlInText matches a URL in free text, up to a space, a quote, a parenthesis or a brace.
var urlInText = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>(){}]+`)

// SanitizeErrorText strips the userinfo, query and fragment of every URL in
// an error message: Go's HTTP client quotes the full request URL, whose
// query or userinfo may hold a credential or personal data.
func SanitizeErrorText(s string) string {
	return urlInText.ReplaceAllStringFunc(s, cleanURL)
}

func cleanURL(s string) string {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		u.User = nil
		u.RawQuery, u.ForceQuery = "", false
		u.Fragment, u.RawFragment = "", ""
		return u.String()
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		end := len(rest)
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			end = j
		}
		if j := strings.LastIndex(rest[:end], "@"); j >= 0 {
			s = s[:i+3] + rest[j+1:]
		}
	}
	return s
}
