package hub

import (
	"net"
	"net/http"
	"sync"
)

// Install pings are anonymous, so anyone can send them with made-up daemon
// ids. Two limits keep one source from inflating a package's counts (and
// with them its place in search):
//
//   - the per-address rate limit counts an IPv6 client by its /64, the
//     block one holder usually has;
//   - each source (address, or IPv6 /64) can add at most
//     newDaemonsPerSource daemon ids a package hasn't seen before per UTC
//     day. Pings from daemons the package already counts (heartbeats,
//     updates, uninstalls) aren't limited by it.

// newDaemonsPerSource is how many daemon ids new to a package one source
// may add per day.
const newDaemonsPerSource = 3

// maxSourceEntries bounds the memory the per-source counts take; when it's
// full, pings that would add a new daemon aren't counted until the next day.
const maxSourceEntries = 200000

// sourceKey names where a request came from, for rate limits: the address,
// with IPv6 addresses cut to their /64.
func (s *Server) sourceKey(r *http.Request) string {
	return ipBucket(s.clientIP(r))
}

func ipBucket(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return host
}

// newDaemons counts, for the current day, the daemon ids each source added
// to each package. It lives in memory: a restart only forgets one day's
// counts.
type newDaemons struct {
	mu   sync.Mutex
	day  string
	seen map[string]map[string]bool // hash(source, package) -> daemon hashes
	n    int
}

var installSources sync.Map // *Server -> *newDaemons

func (s *Server) newDaemons() *newDaemons {
	v, _ := installSources.LoadOrStore(s, &newDaemons{})
	return v.(*newDaemons)
}

// allow reports whether source may add daemon to pkg today. A daemon it
// already added today is allowed again (the same install pinged twice).
func (d *newDaemons) allow(day, source, pkg, daemon string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.day != day {
		d.day, d.seen, d.n = day, map[string]map[string]bool{}, 0
	}
	k := hash(source + "\x00" + pkg)
	set := d.seen[k]
	if set[daemon] {
		return true
	}
	if len(set) >= newDaemonsPerSource || d.n >= maxSourceEntries {
		return false
	}
	if set == nil {
		set = map[string]bool{}
		d.seen[k] = set
	}
	set[daemon] = true
	d.n++
	return true
}
