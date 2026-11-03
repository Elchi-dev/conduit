package daemon

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/internal/mdns"
	"github.com/elchi-dev/conduit/internal/version"
	"github.com/elchi-dev/conduit/pkg/relay"
)

// LAN discovery (signature feature 11): a daemon that listens beyond
// loopback announces itself as _conduit._tcp on the local network with
// mDNS, and GET /api/v1/remote/discover lists the others, for sync peers and
// pairing without typing addresses. The TXT record carries only public
// facts: a short id, the name, the relay key fingerprint (compare it with
// the one the other daemon shows), the version and the relay path.

// lanAnnouncement is the service this daemon announces, or ok=false when it
// only listens on loopback.
func lanAnnouncement(app *App, listen string) (mdns.Service, bool) {
	if app.Remote == nil || len(app.Remote.LANAddrs) == 0 {
		return mdns.Service{}, false
	}
	var ips []net.IP
	port := mdns.Port(listen)
	for _, a := range app.Remote.LANAddrs {
		u, err := url.Parse(a)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			ips = append(ips, ip)
		}
		if p, err := strconv.Atoi(u.Port()); err == nil && port == 0 {
			port = p
		}
	}
	if len(ips) == 0 || port == 0 {
		return mdns.Service{}, false
	}
	fp := relay.Fingerprint(app.Remote.PublicKey())
	id := strings.ToLower(fp)
	if len(id) > 10 {
		id = id[:10]
	}
	name := app.Remote.Name
	if name == "" {
		name, _ = os.Hostname()
	}
	clean := strings.Map(func(r rune) rune {
		if r == '.' || r < 32 {
			return '-'
		}
		return r
	}, name)
	host := "conduit-" + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, id) + ".local."
	return mdns.Service{
		Instance: clean + " (" + id[:min(6, len(id))] + ")",
		Host:     host,
		Port:     port,
		IPs:      ips,
		TXT:      map[string]string{"id": id, "name": name, "fp": fp, "v": version.Get().Version, "path": "/relay"},
	}, true
}

func announceOnLAN(ctx context.Context, app *App, listen string) {
	svc, ok := lanAnnouncement(app, listen)
	if !ok {
		return
	}
	if err := mdns.Announce(ctx, svc, app.Server.Log); err != nil {
		app.Server.Log.Info("not announcing on the local network (no multicast)", "err", err)
	}
}

func (s *Server) discoverRoutes() []route {
	return []route{
		{"GET /api/v1/remote/discover", s.need("admin:*:*", s.discover)},
	}
}

// Discovered is another Conduit daemon on the local network.
type Discovered struct {
	Name        string   `json:"name"`
	ID          string   `json:"id"`
	Fingerprint string   `json:"fingerprint"`
	Version     string   `json:"version"`
	Addresses   []string `json:"addresses"`
	Port        int      `json:"port"`
	URL         string   `json:"url"`   // http://<address>:<port>, for sync peers
	Relay       string   `json:"relay"` // ws://<address>:<port>/relay
}

func (s *Server) discover(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	found, err := mdns.Browse(ctx, 1500*time.Millisecond)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "couldn't search the local network: "+err.Error())
		return
	}
	self := ""
	if s.Remote != nil {
		self = relay.Fingerprint(s.Remote.PublicKey())
	}
	out := []Discovered{}
	for _, f := range found {
		if f.TXT["fp"] != "" && f.TXT["fp"] == self {
			continue
		}
		d := Discovered{Name: f.TXT["name"], ID: f.TXT["id"], Fingerprint: f.TXT["fp"], Version: f.TXT["v"], Addresses: f.IPs, Port: f.Port}
		if d.Name == "" {
			d.Name = f.Instance
		}
		if len(f.IPs) > 0 && f.Port > 0 {
			host := net.JoinHostPort(f.IPs[0], strconv.Itoa(f.Port))
			path := f.TXT["path"]
			if !strings.HasPrefix(path, "/") {
				path = "/relay"
			}
			d.URL = "http://" + host
			d.Relay = "ws://" + host + path
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, out)
}
