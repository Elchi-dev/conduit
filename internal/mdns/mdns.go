package mdns

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
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

func serve(c *net.UDPConn, svc Service) {
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
		var out []RR
		unicast := src.Port != 5353 // a one-shot query from an ordinary socket (RFC 6762 §6.7)
		for _, q := range m.Questions {
			out = append(out, svc.answers(q)...)
			unicast = unicast || q.Unicast
		}
		if len(out) == 0 {
			continue
		}
		reply := Message{Response: true, Answers: out}
		dst := group4
		if src.IP.To4() == nil {
			dst = group6
		}
		if unicast {
			reply.ID = m.ID
			reply.Questions = m.Questions
			dst = src
		}
		_, _ = c.WriteToUDP(reply.Pack(), dst)
	}
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
	var all []RR
	srcs := map[string]net.IP{} // instance -> address the answer came from
	buf := make([]byte, 9000)
	for {
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			break
		}
		m, err := Unpack(buf[:n])
		if err != nil || !m.Response {
			continue
		}
		for _, r := range m.Answers {
			if r.Type == TypeSRV {
				srcs[r.Name] = src.IP
			}
		}
		all = append(all, m.Answers...)
	}
	return collect(all, srcs), nil
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
