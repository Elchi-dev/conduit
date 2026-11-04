// Package oauth gets OAuth 2.0 access tokens for the modules that call
// hosted APIs: a form post to a token endpoint (refresh token, client
// credentials or a signed JWT assertion) and an in-memory cache that keeps
// the token until shortly before it expires. Errors never quote the token
// endpoint's answer beyond its OAuth error code.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/rest"
)

// Grant is a token endpoint's answer.
type Grant struct {
	Access    string
	ExpiresIn int    // seconds
	Refresh   string // a rotated refresh token, if the endpoint sent one
}

// Error is a token request the endpoint refused. Code is the OAuth error
// code (invalid_grant, invalid_client, …), or "" when there was none.
type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("token request refused (%s)", e.Code)
	}
	return fmt.Sprintf("token request refused (HTTP %d)", e.Status)
}

// HTTPStatus is the response's status code.
func (e *Error) HTTPStatus() int { return e.Status }

var codeRe = regexp.MustCompile(`^[a-z_]{1,64}$`)

// Exchange posts form to tokenURL and reads the access token. When user is
// set, the client authenticates with HTTP Basic (user, pass) instead of
// form fields. A redirect to another host (or from https to http) isn't
// followed, whatever client is passed: a 307 would repost the form, with
// its secret, there.
func Exchange(ctx context.Context, client *http.Client, tokenURL string, form url.Values, user, pass string) (Grant, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Grant{}, errors.New("invalid token endpoint")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	res, err := rest.SameHostOnly(client).Do(req)
	if err != nil {
		return Grant{}, rest.TransportError(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var t struct {
		Access    string          `json:"access_token"`
		ExpiresIn json.Number     `json:"expires_in"`
		Refresh   string          `json:"refresh_token"`
		Error     json.RawMessage `json:"error"`
	}
	_ = json.Unmarshal(body, &t)
	if res.StatusCode != http.StatusOK || t.Access == "" {
		var code string
		_ = json.Unmarshal(t.Error, &code)
		if !codeRe.MatchString(code) {
			code = ""
		}
		status := res.StatusCode
		if status == http.StatusOK {
			status = http.StatusBadGateway
		}
		return Grant{}, &Error{Status: status, Code: code}
	}
	n, _ := t.ExpiresIn.Int64()
	return Grant{Access: t.Access, ExpiresIn: int(n), Refresh: t.Refresh}, nil
}

// maxLife is the longest an access token is kept, in seconds, whatever
// lifetime the endpoint names.
const maxLife = 24 * 3600

// Cache holds one access token in memory.
type Cache struct {
	// Now replaces time.Now (tests).
	Now func() time.Time

	mu      sync.Mutex
	access  string
	expires time.Time
}

func (c *Cache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Get returns the cached token, or calls fetch for a new one when there's
// none or it expires within a minute. Calls are serialized, so concurrent
// callers share one refresh.
func (c *Cache) Get(ctx context.Context, fetch func(context.Context) (Grant, error)) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.access != "" && c.now().Before(c.expires.Add(-time.Minute)) {
		return c.access, nil
	}
	g, err := fetch(ctx)
	if err != nil {
		return "", err
	}
	if g.Access == "" {
		return "", errors.New("the token endpoint answered without a token")
	}
	if g.ExpiresIn <= 0 {
		g.ExpiresIn = 3600
	}
	if g.ExpiresIn > maxLife {
		g.ExpiresIn = maxLife
	}
	c.access, c.expires = g.Access, c.now().Add(time.Duration(g.ExpiresIn)*time.Second)
	return c.access, nil
}

// Drop forgets the cached token (after the API refused it).
func (c *Cache) Drop() {
	c.mu.Lock()
	c.access = ""
	c.mu.Unlock()
}
