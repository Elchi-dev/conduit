package sdk

import (
	"context"
	"net"
	"net/http"
	"time"
)

// NetHost is implemented by hosts that decide how an instance reaches the
// network. Conduit's host implements it: an instance attached to one of the
// daemon's networks (a userspace WireGuard tunnel, see
// docs/architecture/networks.md) has its connections to that network's
// addresses carried through the tunnel, and everything else dialled
// directly.
//
// It is a separate interface so that hosts written before it (tests, other
// embedders) keep working; modules use the helpers below, which fall back
// to a plain dialer.
type NetHost interface {
	// Network names the network the instance is attached to ("" for none).
	Network() string
	// DialContext opens a connection the way this instance must reach addr.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// DialContext returns the dial function a module should use for raw
// connections (SSH, database and TCP sockets) of the instance h belongs to.
func DialContext(h Host) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if nh, ok := h.(NetHost); ok {
		return nh.DialContext
	}
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return d.DialContext
}

// Transport returns a new HTTP transport whose connections go the way the
// instance h belongs to must reach the network. It starts from Go's default
// transport (proxy settings from the environment, HTTP/2, timeouts); on a
// network the environment proxy is not used, since a proxy outside the
// tunnel can't reach the hosts inside it.
func Transport(h Host) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if nh, ok := h.(NetHost); ok {
		tr.DialContext = nh.DialContext
		if nh.Network() != "" {
			tr.Proxy = nil
		}
	}
	return tr
}

// HTTPClient returns a client using Transport(h), with the given timeout
// (30 seconds when zero).
func HTTPClient(h Host, timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{Timeout: timeout, Transport: Transport(h)}
}
