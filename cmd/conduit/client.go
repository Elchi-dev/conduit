package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// client calls one daemon's REST API with an API key.
type client struct {
	base string // e.g. http://127.0.0.1:7600
	key  string
	http *http.Client
}

// apiError is an answer outside 2xx, carrying the daemon's own message.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("the daemon answered %d", e.Status)
	}
	return e.Message
}

func newClient(base, key string) *client {
	return &client{base: strings.TrimRight(base, "/"), key: key, http: &http.Client{Timeout: 2 * time.Minute}}
}

func (c *client) request(ctx context.Context, method, path string, q url.Values, body any) (*http.Request, error) {
	u := c.base + "/api/v1" + path
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
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "conduit-cli/"+cliVersion())
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	return req, nil
}

// do sends a request and decodes a JSON answer into out. It returns the
// HTTP status so callers can tell 200 from 202.
func (c *client) do(ctx context.Context, method, path string, q url.Values, body, out any) (int, error) {
	req, err := c.request(ctx, method, path, q, body)
	if err != nil {
		return 0, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("couldn't reach Conduit at %s: %w", c.base, stripURL(err))
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return res.StatusCode, err
	}
	if res.StatusCode >= 300 && res.StatusCode != http.StatusAccepted {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		return res.StatusCode, &apiError{Status: res.StatusCode, Message: e.Error}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return res.StatusCode, fmt.Errorf("unexpected answer: %w", err)
		}
	}
	return res.StatusCode, nil
}

// stripURL keeps errors short (the URL is already in the message).
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// sseEvent is one server-sent event.
type sseEvent struct {
	Type string
	Data string
}

// readSSE parses a text/event-stream until it ends, calling fn per event.
func readSSE(r io.Reader, fn func(sseEvent)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	var ev sseEvent
	var data []string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if len(data) > 0 || ev.Type != "" {
				ev.Data = strings.Join(data, "\n")
				fn(ev)
			}
			ev, data = sseEvent{}, nil
		case strings.HasPrefix(line, ":"):
			// comment / keep-alive
		case strings.HasPrefix(line, "event:"):
			ev.Type = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	return sc.Err()
}

// stream follows GET /events, reconnecting with a growing pause until ctx
// ends. Authentication errors stop it.
func (c *client) stream(ctx context.Context, prefix string, fn func(sseEvent), onRetry func(error, time.Duration)) error {
	q := url.Values{}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	wait := time.Second
	h := &http.Client{} // no timeout: the stream stays open
	for {
		req, err := c.request(ctx, http.MethodGet, "/events", q, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "text/event-stream")
		res, err := h.Do(req)
		if err == nil {
			if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
				raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
				res.Body.Close()
				var e struct {
					Error string `json:"error"`
				}
				_ = json.Unmarshal(raw, &e)
				return &apiError{Status: res.StatusCode, Message: e.Error}
			}
			if res.StatusCode == http.StatusOK {
				wait = time.Second
				err = readSSE(res.Body, fn)
				if err == nil {
					err = errors.New("the stream ended")
				}
			} else {
				err = fmt.Errorf("the daemon answered %d", res.StatusCode)
			}
			res.Body.Close()
		}
		if ctx.Err() != nil {
			return nil
		}
		if onRetry != nil {
			onRetry(stripURL(err), wait)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		if wait < 30*time.Second {
			wait *= 2
		}
	}
}
