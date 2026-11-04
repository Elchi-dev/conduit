package rest

import (
	"context"
	"io"
	"net/http"
	"net/url"
)

// Send makes a request with any body and headers (a JSON Patch, a Range
// request for a log) and returns the response for the caller to read and
// close. Credentials, User-Agent and the client's headers are set as in Do;
// hdr is applied last. A status of 400 or more is returned as an *Error with
// the body closed; a redirect the client didn't follow is returned as is.
func (c *Client) Send(ctx context.Context, method, path string, q url.Values, body io.Reader, hdr http.Header) (*http.Response, error) {
	u := c.Base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	for k, v := range c.Header {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", "Conduit")
	for k, v := range hdr {
		req.Header[k] = v
	}
	if c.Auth != nil {
		if err := c.Auth(ctx, req); err != nil {
			return nil, err
		}
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		res.Body.Close()
		return nil, &Error{Status: res.StatusCode, Message: message(res.Status, raw)}
	}
	return res, nil
}
