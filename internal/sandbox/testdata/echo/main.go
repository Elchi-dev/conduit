//go:build wasip1

// A sandboxed test module: echoes input, resolves a secret through the host,
// and fetches a URL through the host's permission-checked HTTP function.
package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/elchi-dev/conduit/pkg/sdk"
	"github.com/elchi-dev/conduit/pkg/sdk/wasm"
)

type echo struct{ h sdk.Host }

// moduleID can be set at build time (-ldflags "-X main.moduleID=…"), for
// tests that install it under an author's name.
var moduleID = "echo"

func (e *echo) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: moduleID, Name: "Echo", Version: "1.0.0", Actions: []sdk.ActionSpec{
		{Name: "echo", Risk: sdk.RiskRead}, {Name: "secret", Risk: sdk.RiskRead}, {Name: "fetch", Risk: sdk.RiskRead}, {Name: "file", Risk: sdk.RiskRead},
	}}
}
func (e *echo) Configure(_ context.Context, h sdk.Host, _ string, _ json.RawMessage) error {
	e.h = h
	return nil
}
func (e *echo) Health(context.Context, string) sdk.Health {
	return sdk.Health{Status: "ok", Message: "sandboxed"}
}
func (e *echo) Close(string) error { return nil }
func (e *echo) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	var in struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(c.Input, &in)
	switch c.Action {
	case "echo":
		return sdk.Result{Output: c.Input}, nil
	case "secret":
		s, err := e.h.Secret(ctx, "secret://token")
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(len(s))
	case "fetch":
		res, err := wasm.HTTP(wasm.Request{Method: "GET", URL: in.URL})
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"status": res.Status, "body": string(res.Body)})
	case "file":
		_, err := os.ReadFile("/etc/passwd")
		return sdk.JSON(map[string]any{"error": err != nil})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

func main() { _ = wasm.Serve(&echo{}) }
