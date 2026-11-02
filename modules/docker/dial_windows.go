//go:build windows

package docker

import (
	"context"
	"errors"
	"net"
	"os"
	"time"
)

// dialLocal opens Docker Desktop's named pipe.
func dialLocal(ctx context.Context, pipe string) (net.Conn, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		f, err := os.OpenFile(pipe, os.O_RDWR, 0)
		if err == nil {
			return &pipeConn{f}, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, errors.New("Docker Desktop is not running (" + err.Error() + ")")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type pipeConn struct{ *os.File }

func (pipeConn) LocalAddr() net.Addr                { return pipeAddr{} }
func (pipeConn) RemoteAddr() net.Addr               { return pipeAddr{} }
func (p pipeConn) SetDeadline(t time.Time) error    { return nil }
func (p pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (p pipeConn) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "docker_engine" }
