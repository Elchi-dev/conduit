//go:build wasip1

package wasm

import (
	"errors"
	"os"
	"syscall"
	"unsafe"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

//go:wasmimport conduit http_request
func httpRequest(ptr, size uint32) uint32

//go:wasmimport conduit http_response
func httpResponse(ptr uint32)

// Serve runs m in the sandbox until the host closes stdin.
func Serve(m sdk.Module) error {
	// Non-blocking stdin lets the Go scheduler keep running handlers (and
	// host callbacks) while it waits for the next message.
	_ = syscall.SetNonblock(0, true)
	return sdk.Serve(m, os.Stdin, os.Stdout)
}

func hostHTTP(req []byte) ([]byte, error) {
	if len(req) == 0 {
		return nil, errors.New("empty request")
	}
	n := httpRequest(uint32(uintptr(unsafe.Pointer(&req[0]))), uint32(len(req)))
	if n == 0 {
		return nil, errors.New("the host returned nothing")
	}
	buf := make([]byte, n)
	httpResponse(uint32(uintptr(unsafe.Pointer(&buf[0]))))
	return buf, nil
}
