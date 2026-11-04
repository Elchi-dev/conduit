// Package wasm lets a module written in Go run in Conduit's WebAssembly
// sandbox (signature feature 12). Build with GOOS=wasip1 GOARCH=wasm.
//
// A sandboxed module speaks the same JSON-RPC protocol as any external
// module, over its stdin and stdout, but it has no file system, no
// environment and no sockets. The only way out is HTTP through the host,
// which allows only the hosts listed in the module's permissions.
package wasm

import (
	"encoding/json"
	"errors"
)

// Request is an HTTP request made through the host.
type Request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
	// Instance is the instance the request is made for (Call.Instance), so
	// the host sends it through that instance's network. It may be left
	// out when the module has a single instance.
	Instance string `json:"instance,omitempty"`
}

// Response is the host's answer.
type Response struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// HTTP sends a request through the host. The host refuses hosts the module
// wasn't granted.
func HTTP(req Request) (Response, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	raw, err := hostHTTP(b)
	if err != nil {
		return Response{}, err
	}
	var res Response
	if err := json.Unmarshal(raw, &res); err != nil {
		return Response{}, err
	}
	if res.Error != "" {
		return res, errors.New(res.Error)
	}
	return res, nil
}
