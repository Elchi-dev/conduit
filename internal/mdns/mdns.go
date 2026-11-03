package mdns

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServiceType is what Conduit daemons announce.
const ServiceType = "_conduit._tcp.local."

var (
	group4 = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	group6 = &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: 5353}
)

const ttl = 120

// Service is one announced daemon.
type Service struct {
	Instance string // human name, e.g. "Desk"; becomes "<Instance>._conduit._tcp.local."
	Host     string // e.g. "conduit-3f2a9c.local."
	Port     int
	IPs      []net.IP
	TXT      map[string]string
}

func (s Service) fullName() string {
	inst := strings.NewReplacer(".", "-").Replace(s.Instance)
	return canonical(inst + "." + ServiceType)
}

func (s Service) records() []RR {
	keys := make([]string, 0, len(s.TXT))
	for k := range s.TXT {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	txt := make([]string, 0, len(keys))
	for _, k := range keys {
		txt = append(txt, k+"="+s.TXT[k])
	}
	host := canonical(s.Host)
	rr := []RR{
		{Name: ServiceType, Type: TypePTR, TTL: ttl, Target: s.fullName()},
		{Name: s.fullName(), Type: TypeSRV, TTL: ttl, Flush: true, Port: uint16(s.Port), Target: host},
		{Name: s.fullName(), Type: TypeTXT, TTL: ttl, Flush: true, TXT: txt},
	}
	for _, ip := range s.IPs {
		if ip.To4() != nil {
			rr = append(rr, RR{Name: host, Type: TypeA, TTL: ttl, Flush: true, IP: ip.To4()})
		} else {
			rr = append(rr, RR{Name: host, Type: TypeAAAA, TTL: ttl, Flush: true, IP: ip})
		}
	}
	return rr
}

// answers returns the records that answer q, or nil.
func (s Service) answers(q Question) []RR {
	all := s.records()
	match := func(t uint16) bool { return q.Type == t || q.Type == TypeANY }
	switch q.Name {
	case ServiceType, "_services._dns-sd._udp.local.":
		if q.Name == ServiceType && match(TypePTR) {
			return all // PTR plus SRV, TXT and addresses as additional records
		}
		if q.Name != ServiceType && match(TypePTR) {
			return []RR{{Name: q.Name, Type: TypePTR, TTL: ttl, Target: ServiceType}}
		}
	case s.fullName():
		if match(TypeSRV) || match(TypeTXT) {
			return all[1:]
		}
	case canonical(s.Host):
		var out []RR
		for _, r := range all[3:] {
			if match(r.Type) {
				out = append(out, r)
			}
		}
		return out
	}
	return nil
}

// Announce answers queries for svc until ctx ends, and announces it twice at
// the start. It returns an error only when no socket could be opened.
func Announce(ctx context.Context, svc Service, log *slog.Logger) error {
	var conns []*net.UDPConn
	if c, err := net.ListenMulticastUDP("udp4", nil, group4); err == nil {
		conns = append(conns, c)
	} else if log != nil {
		log.Debug("mdns: no IPv4 multicast", "err", err)
	}
	if c, err := net.ListenMulticastUDP("udp6", nil, group6); err == nil {
		conns = append(conns, c)
	}
	if len(conns) == 0 {
		return net.ErrClosed
	}
	announce := Message{Response: true, Answers: svc.records()}
	for _, c := range conns {
		c := c
		go serve(c, svc)
		dst := group4
		if c.LocalAddr().(*net.UDPAddr).IP.To4() == nil {
			dst = group6
		}
		go func() {
			for i := 0; i < 2; i++ {
				_, _ = c.WriteToUDP(announce.Pack(), dst)
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
		}()
	}
	<-ctx.Done()
	// Goodbye: TTL 0 tells caches to forget us (RFC 6762 §10.1).
	bye := svc.records()
	for i := range bye {
		bye[i].TTL = 0
	}
	for _, c := range conns {
		dst := group4
		if c.LocalAddr().(*net.UDPAddr).IP.To4() == nil {
			dst = group6
		}
		_, _ = c.WriteToUDP(Message{Response: true, Answers: bye}.Pack(), dst)
		c.Close()
	}
	return nil
}

// Limits that keep the responder from being used as an amplifier and the
// browser from collecting without bound.
const (
	maxQuestions = 16  // a query with more questions is dropped whole
	maxRecords   = 256 // Browse keeps at most this many records
)

func serve(c *net.UDPConn, svc Service) {
	serveWith(c, svc, newLocalNets().contains)
}

// serveWith answers queries on c. onLink reports whether a source address is
// on one of this machine's networks; queries from anywhere else are ignored
// (RFC 6762 §11), so a spoofed source off the link can't aim replies at a
// victim.
func serveWith(c *net.UDPConn, svc Service, onLink func(net.IP) bool) {
	buf := make([]byte, 9000)
	for {
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		m, err := Unpack(buf[:n])
		if err != nil || m.Response {
			continue
		}
		reply, unicast, ok := respond(m, src, svc)
		if !ok || !onLink(src.IP) {
			continue
		}
		dst := group4
		if src.IP.To4() == nil {
			dst = group6
		}
		if unicast {
			dst = src
		}
		_, _ = c.WriteToUDP(reply.Pack(), dst)
	}
}

// respond builds the reply to query m from src, and whether to send it
// straight back to src. ok is false when there is nothing to send.
//
// Each distinct question is answered once and each record appears once,
// however the query repeats itself, and queries with more than maxQuestions
// questions are dropped, so a reply is never much bigger than the service's
// own records.
func respond(m Message, src *net.UDPAddr, svc Service) (reply Message, unicast, ok bool) {
	if len(m.Questions) == 0 || len(m.Questions) > maxQuestions {
		return Message{}, false, false
	}
	legacy := src.Port != 5353 // a one-shot query from an ordinary socket (RFC 6762 §6.7)
	unicast = legacy
	var out []RR
	seenQ := map[Question]bool{}
	seenRR := map[string]bool{}
	var asked []Question
	for _, q := range m.Questions {
		unicast = unicast || q.Unicast
		q.Unicast = false
		if seenQ[q] {
			continue
		}
		seenQ[q] = true
		var answered bool
		for _, r := range svc.answers(q) {
			k := rrKey(r)
			if seenRR[k] {
				continue
			}
			seenRR[k] = true
			out = append(out, r)
			answered = true
		}
		if answered {
			asked = append(asked, q)
		}
	}
	if len(out) == 0 {
		return Message{}, false, false
	}
	reply = Message{Response: true, Answers: out}
	if unicast {
		reply.ID = m.ID
	}
	// Responses carry no questions (RFC 6762 §6), with one exception: a legacy
	// resolver asking a single question expects it repeated (§6.7). Echoing at
	// most one question keeps the reply bounded.
	if legacy && len(m.Questions) == 1 && len(asked) == 1 {
		reply.Questions = asked
	}
	return reply, unicast, true
}

func rrKey(r RR) string {
	return r.Name + "\x00" + strconv.Itoa(int(r.Type)) + "\x00" + r.Target + "\x00" + strconv.Itoa(int(r.Port)) + "\x00" + r.IP.String() + "\x00" + strings.Join(r.TXT, "\x00")
}

// localNets answers whether an address is on one of this machine's networks.
// The interface list is cached briefly so a flood of queries doesn't turn
// into a flood of system calls.
type localNets struct {
	mu      sync.Mutex
	nets    []*net.IPNet
	fetched time.Time
}

func newLocalNets() *localNets { return &localNets{} }

func (l *localNets) contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.fetched) > 30*time.Second {
		l.nets = l.nets[:0]
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok {
					l.nets = append(l.nets, n)
				}
			}
		}
		l.fetched = time.Now()
	}
	for _, n := range l.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Found is a daemon seen on the network.
type Found struct {
	Instance string            `json:"instance"` // lowercased; the display name is TXT["name"]
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	IPs      []string          `json:"addresses"`
	TXT      map[string]string `json:"txt"`
}

// Browse asks the network for Conduit daemons and collects answers for wait.
func Browse(ctx context.Context, wait time.Duration) ([]Found, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	q := Message{Questions: []Question{{Name: ServiceType, Type: TypePTR}}}
	if _, err := c.WriteToUDP(q.Pack(), group4); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetReadDeadline(deadline)
	return collect(gather(c)), nil
}

// gather reads responses from c until its read deadline, keeping at most
// maxRecords records, and notes which address each instance answered from.
// A busy or hostile network can't make Browse collect without bound.
func gather(c *net.UDPConn) ([]RR, map[string]net.IP) {
	var all []RR
	srcs := map[string]net.IP{} // instance -> address the answer came from
	buf := make([]byte, 9000)
	for len(all) < maxRecords {
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			break
		}
		m, err := Unpack(buf[:n])
		if err != nil || !m.Response {
			continue
		}
		for _, r := range m.Answers {
			if len(all) >= maxRecords {
				break
			}
			if r.Type == TypeSRV {
				srcs[r.Name] = src.IP
			}
			all = append(all, r)
		}
	}
	return all, srcs
}

// collect turns records into services.
func collect(rrs []RR, srcs map[string]net.IP) []Found {
	instances := map[string]bool{}
	srv := map[string]RR{}
	txt := map[string][]string{}
	addrs := map[string][]net.IP{}
	for _, r := range rrs {
		switch r.Type {
		case TypePTR:
			if r.Name == ServiceType && r.TTL > 0 {
				instances[r.Target] = true
			}
		case TypeSRV:
			srv[r.Name] = r
		case TypeTXT:
			txt[r.Name] = r.TXT
		case TypeA, TypeAAAA:
			if r.IP != nil {
				addrs[r.Name] = append(addrs[r.Name], r.IP)
			}
		}
	}
	var out []Found
	for inst := range instances {
		s, ok := srv[inst]
		if !ok || !strings.HasSuffix(inst, "."+ServiceType) {
			continue
		}
		f := Found{Instance: strings.TrimSuffix(inst, "."+ServiceType), Host: s.Target, Port: int(s.Port), TXT: map[string]string{}}
		for _, kv := range txt[inst] {
			k, v, _ := strings.Cut(kv, "=")
			f.TXT[strings.ToLower(k)] = v
		}
		seen := map[string]bool{}
		for _, ip := range addrs[s.Target] {
			if !seen[ip.String()] {
				seen[ip.String()] = true
				f.IPs = append(f.IPs, ip.String())
			}
		}
		if len(f.IPs) == 0 && srcs[inst] != nil {
			f.IPs = []string{srcs[inst].String()}
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out
}

// Port parses the port of a host:port listen address.
func Port(listen string) int {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}
