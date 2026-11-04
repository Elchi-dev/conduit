package rest

import (
	"errors"
	"net/http"
	"strings"
)

// ErrCrossHostRedirect is returned when a server redirects a request that
// carries credentials to a different host.
// The error SameHostRedirects returns is a *RedirectError naming only the
// target host, which matches it with errors.Is.
var ErrCrossHostRedirect = errors.New("refusing redirect to another host")

// ErrInsecureRedirect is returned when an https request is redirected to
// http on the same host.
var ErrInsecureRedirect = errors.New("refusing redirect from https to http")

// RedirectError is a refused cross-host redirect. It names only the host it
// pointed to: the Location may be a signed URL (a log in object storage)
// whose query is a credential.
type RedirectError struct{ Host string }

func (e *RedirectError) Error() string {
	return ErrCrossHostRedirect.Error() + " (" + e.Host + ")"
}

// Is matches ErrCrossHostRedirect.
func (e *RedirectError) Is(target error) bool { return target == ErrCrossHostRedirect }

// SameHostRedirects is an http.Client CheckRedirect that follows redirects
// only to the same scheme and host (port included) as the original request.
//
// Go drops Authorization and Cookie when a redirect leaves the host, but it
// forwards every other header, so an API key sent as X-API-KEY, X-Emby-Token,
// PRIVATE-TOKEN and the like would reach whichever host the server (or
// anyone who can answer for it) redirects to. A switch from https to http on
// the same host is refused too, since it would send the key in clear text.
func SameHostRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if len(via) == 0 {
		return nil
	}
	first := via[0].URL
	if !strings.EqualFold(req.URL.Host, first.Host) {
		return &RedirectError{Host: req.URL.Host}
	}
	if first.Scheme == "https" && req.URL.Scheme != "https" {
		return ErrInsecureRedirect
	}
	return nil
}

// SameHostOnly returns a copy of c (or of a default client when c is nil)
// that follows redirects only within the same host; see SameHostRedirects.
func SameHostOnly(c *http.Client) *http.Client {
	var cp http.Client
	if c != nil {
		cp = *c
	}
	cp.CheckRedirect = SameHostRedirects
	return &cp
}
