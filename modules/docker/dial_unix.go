//go:build !windows

package docker

import (
	"context"
	"net"
)

func dialLocal(ctx context.Context, sock string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", sock)
}
