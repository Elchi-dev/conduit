//go:build !wasip1

package wasm

import (
	"errors"
	"os"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Serve runs m over stdio. Outside the sandbox (for tests, or as a normal
// external module) HTTP isn't available through the host.
func Serve(m sdk.Module) error { return sdk.Serve(m, os.Stdin, os.Stdout) }

func hostHTTP([]byte) ([]byte, error) {
	return nil, errors.New("host HTTP is only available inside the WebAssembly sandbox")
}
