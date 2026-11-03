package remote

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"

	"github.com/elchi-dev/conduit/pkg/relay"
)

// Hub-free pairing (signature feature 11). When the daemon listens on the
// local network, phones on the same network connect straight to its /relay
// endpoint with the same end-to-end protocol they use through a hub: one
// WebSocket is one stream, the first frame is the hello, every later frame
// is encrypted. No hub sees anything, and the daemon key is still pinned
// from the QR code.

const maxLANStreams = 16

var _, cgnat, _ = net.ParseCIDR("100.64.0.0/10")

var lanStreams atomic.Int32

// ServeLAN handles one direct client connection.
func (s *Service) ServeLAN(w http.ResponseWriter, r *http.Request) {
	if lanStreams.Load() >= maxLANStreams {
		http.Error(w, "too many direct connections", http.StatusServiceUnavailable)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	lanStreams.Add(1)
	defer lanStreams.Add(-1)
	defer ws.CloseNow()
	ws.SetReadLimit(8 << 20)
	ctx := r.Context()

	_, frame, err := ws.Read(ctx)
	if err != nil {
		return
	}
	var h relay.Hello
	if json.Unmarshal(frame, &h) != nil {
		return
	}
	sess, intro, err := relay.DaemonHandshake(s.key, h)
	if err != nil {
		return // wrong pinned key or forged static key: nothing to say
	}
	client, err := s.admit(ctx, h, intro)
	welcome := relay.Welcome{OK: err == nil, Client: client, Daemon: s.Name}
	if err != nil {
		welcome.Error = err.Error()
	}
	out, _ := sess.SealJSON(welcome)
	var wmu sync.Mutex
	write := func(b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return ws.Write(ctx, websocket.MessageBinary, b)
	}
	if write(out) != nil || err != nil {
		return
	}
	s.mu.Lock()
	s.streams++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.streams--
		s.mu.Unlock()
	}()
	var smu sync.Mutex // orders seal+write
	for {
		_, frame, err := ws.Read(ctx)
		if err != nil {
			return
		}
		var req relay.Request
		if err := sess.OpenJSON(frame, &req); err != nil {
			s.Log.Warn("relay (LAN): dropping a connection after a bad frame", "client", client)
			return
		}
		go func() {
			res := s.execute(ctx, client, req)
			smu.Lock()
			defer smu.Unlock()
			if b, err := sess.SealJSON(res); err == nil {
				_ = write(b)
			}
		}()
	}
}

// LANURLs lists ws:// addresses for a listen address that reaches the local
// network, or nothing for loopback-only daemons.
func LANURLs(listen string) []string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	var ips []string
	if host == "" || (ip != nil && ip.IsUnspecified()) {
		ifaces, _ := net.Interfaces()
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || strings.HasPrefix(ifc.Name, "docker") || strings.HasPrefix(ifc.Name, "veth") || strings.HasPrefix(ifc.Name, "br-") {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				// Private ranges, plus 100.64.0.0/10 (Tailscale and other overlays).
				if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && (n.IP.IsPrivate() || cgnat.Contains(n.IP)) {
					ips = append(ips, n.IP.String())
				}
			}
		}
	} else if ip != nil {
		ips = []string{ip.String()}
	} else {
		ips = []string{host}
	}
	var out []string
	for _, i := range ips {
		out = append(out, fmt.Sprintf("ws://%s/relay", net.JoinHostPort(i, port)))
	}
	return out
}

