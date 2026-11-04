package rest

import (
	"errors"
	"net/url"
	"strings"
)

// TransportError makes an error from http.Client.Do safe to show: Go's
// *url.Error quotes the request's full URL ("Get \"https://host/x?email=…\":
// EOF"), and a query often holds personal data (a filter on an email
// address) or a credential (an API key, a signed URL). The URL is cut down
// to scheme://host/path, a refused redirect becomes the fixed
// *RedirectError naming only the target host, and the message is passed
// through Redact. errors.As still finds the *url.Error (with the cleaned
// URL) and Timeout() still answers. Do and Send apply it; modules calling
// an http.Client themselves should too.
func TransportError(err error) error {
	if err == nil {
		return nil
	}
	var re *RedirectError
	if errors.As(err, &re) {
		return &RedirectError{Host: re.Host}
	}
	if errors.Is(err, ErrInsecureRedirect) {
		return ErrInsecureRedirect
	}
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	return &transportError{e: &url.Error{Op: ue.Op, URL: CleanURL(ue.URL), Err: ue.Err}}
}

type transportError struct{ e *url.Error }

func (t *transportError) Error() string { return redact(t.e.Error()) }
func (t *transportError) Unwrap() error { return t.e }
func (t *transportError) Timeout() bool { return t.e.Timeout() }

// CleanURL returns scheme://host/path for a URL: no userinfo, query or
// fragment. Text that doesn't parse as a URL is cut at its first "?" or "#"
// and loses anything up to an "@" before the path.
func CleanURL(s string) string {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		u.User = nil
		u.RawQuery, u.ForceQuery = "", false
		u.Fragment, u.RawFragment = "", ""
		return u.String()
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	return StripUserinfo(s)
}
