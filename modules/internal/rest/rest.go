// Package rest is a small JSON-over-HTTP client shared by the modules that
// wrap web APIs (GitHub, GitLab, Cloudflare, Home Assistant, Discord).
package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Client calls one API.
type Client struct {
	Base string // e.g. https://api.github.com, no trailing slash
	HTTP *http.Client
	// Auth sets credentials on each request.
	Auth func(ctx context.Context, r *http.Request) error
	// Header is added to every request.
	Header http.Header
}

// New returns a client with a 30-second timeout.
func New(base string, auth func(context.Context, *http.Request) error) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 30 * time.Second}, Auth: auth, Header: http.Header{}}
}

// Error is an API error with its HTTP status.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

// HTTPStatus is the response's status code. Conduit's engine uses it to
// record only "failed (HTTP <status>)" for a sensitive action's error.
func (e *Error) HTTPStatus() int { return e.Status }

// IsStatus reports whether err is an API error with this status.
func IsStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

// Do sends a request with an optional JSON body and decodes a JSON answer
// into out (if non-nil). It returns the response headers.
func (c *Client) Do(ctx context.Context, method, path string, q url.Values, body, out any) (http.Header, error) {
	u := c.Base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	for k, v := range c.Header {
		req.Header[k] = v
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Conduit")
	}
	if c.Auth != nil {
		if err := c.Auth(ctx, req); err != nil {
			return nil, err
		}
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, TransportError(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return res.Header, err
	}
	if res.StatusCode >= 300 {
		return res.Header, &Error{Status: res.StatusCode, Message: message(res.Status, raw)}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return res.Header, fmt.Errorf("unexpected answer from %s: %w", c.Base, err)
		}
	}
	return res.Header, nil
}

// maxRawMessage is the longest non-JSON error body passed on, after the
// status: enough for "Permission denied" or "Invalid token", not for an
// HTML page, a stack trace or an echoed request.
const maxRawMessage = 80

// secretRun matches what looks like a credential: a Bearer or Basic scheme
// with its value, a URL's user:password@, token=/key:/secret=/password= with a value, or any long run of token characters (API keys,
// session ids, JWT segments). Error text is shown to agents and kept in
// the audit log, and some servers echo the request's credentials in it.
var secretRun = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}|://[^\s/:@]+:[^\s/@]+@|(token|key|secret|password)["']?\s*[:=]\s*["']?[^\s"',;&]{6,}|[A-Za-z0-9_-]{20,}`)

// Redact replaces anything that looks like a credential with [redacted], for
// modules passing on free text a server produced (check output, logs).
func Redact(s string) string { return redact(s) }

// redact replaces anything that looks like a credential with [redacted].
func redact(s string) string {
	return secretRun.ReplaceAllString(s, "[redacted]")
}

// message pulls a human error out of the common API error shapes. Messages
// are redacted; a body that isn't JSON is only passed on when it's one short
// line.
func message(status string, raw []byte) string {
	if m := jsonMessage(raw); m != "" {
		return redact(m)
	}
	if t := strings.TrimSpace(string(raw)); t != "" && len(t) <= maxRawMessage && !strings.HasPrefix(t, "<") && !strings.ContainsAny(t, "\r\n") {
		return status + ": " + redact(t)
	}
	return status
}

// jsonMessage reads the message out of a JSON error body, or "".
func jsonMessage(raw []byte) string {
	var e struct {
		Message string `json:"message"`
		Detail  string `json:"detail"` // Django REST framework
		Error   any    `json:"error"`
		Errors  []struct {
			Message string `json:"message"`
			Detail  string `json:"detail"` // JSON:API
			Title   string `json:"title"`
		} `json:"errors"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return ""
	}
	if len(e.Errors) > 0 {
		for _, s := range []string{e.Errors[0].Message, e.Errors[0].Detail, e.Errors[0].Title} {
			if s != "" {
				return s
			}
		}
	}
	if e.Message != "" {
		return e.Message
	}
	if s, ok := e.Error.(string); ok && s != "" {
		return s
	}
	if e.Detail != "" {
		return e.Detail
	}
	// {"error":{"message":"..."}} (Bitbucket and others).
	if m, ok := e.Error.(map[string]any); ok {
		if s, ok := m["message"].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// ValidBase checks an http(s) base URL.
func ValidBase(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid URL %q", s)
	}
	return nil
}
