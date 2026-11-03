package mdns

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func testService() Service {
	return Service{Instance: "Desk", Host: "conduit-3f2a9c.local", Port: 7600, IPs: []net.IP{net.ParseIP("192.168.1.20")},
		TXT: map[string]string{"id": "3f2a9c", "fp": "abc", "v": "0.2.0", "path": "/relay", "name": "Desk"}}
}

func TestPackUnpack(t *testing.T) {
	svc := testService()
	m := Message{Response: true, Answers: svc.records()}
	got, err := Unpack(m.Pack())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Response || len(got.Answers) != 4 {
		t.Fatalf("%+v", got)
	}
	f := collect(got.Answers, nil)
	if len(f) != 1 || f[0].Instance != "desk" || f[0].TXT["name"] != "Desk" || f[0].Port != 7600 || f[0].IPs[0] != "192.168.1.20" || f[0].TXT["fp"] != "abc" || f[0].TXT["path"] != "/relay" {
		t.Fatalf("%+v", f)
	}
}

func TestCompressedNames(t *testing.T) {
	// A PTR answer whose target points back into the question name.
	q := Message{Questions: []Question{{Name: ServiceType, Type: TypePTR, Unicast: true}}}.Pack()
	q[2] = 0x84 // make it a response
	q[7] = 1    // one answer
	// answer: name = pointer to offset 12, type PTR, class IN, ttl, rdata = "x" + pointer to 12
	ans := []byte{0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 120, 0, 4, 1, 'x', 0xC0, 12}
	m, err := Unpack(append(q, ans...))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Questions[0].Unicast || m.Answers[0].Name != ServiceType || m.Answers[0].Target != "x."+ServiceType {
		t.Fatalf("%+v", m)
	}
	// A pointer loop is refused, not followed forever.
	loop := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1}
	if _, err := Unpack(loop); err == nil {
		t.Fatal("compression loop accepted")
	}
	if _, err := Unpack([]byte{1, 2, 3}); err == nil {
		t.Fatal("short message accepted")
	}
}

// The responder answers a one-shot query from an ordinary socket directly.
func TestResponderUnicast(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip("no UDP:", err)
	}
	defer srv.Close()
	go serve(srv, testService())
	cl, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer cl.Close()
	q := Message{ID: 7, Questions: []Question{{Name: ServiceType, Type: TypePTR}}}
	_, _ = cl.WriteToUDP(q.Pack(), srv.LocalAddr().(*net.UDPAddr))
	_ = cl.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 9000)
	n, _, err := cl.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Unpack(buf[:n])
	if err != nil || m.ID != 7 || len(collect(m.Answers, nil)) != 1 {
		t.Fatalf("%+v %v", m, err)
	}
	// Other names get no answer.
	q = Message{Questions: []Question{{Name: "_http._tcp.local.", Type: TypePTR}}}
	_, _ = cl.WriteToUDP(q.Pack(), srv.LocalAddr().(*net.UDPAddr))
	_ = cl.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := cl.ReadFromUDP(buf); err == nil {
		t.Fatal("answered a query for another service")
	}
}

// End to end over real multicast, when the machine allows it.
func TestAnnounceBrowse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- Announce(ctx, testService(), nil) }()
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-errc:
		t.Skip("multicast isn't available here:", err)
	default:
	}
	found, err := Browse(ctx, 1500*time.Millisecond)
	if err != nil || len(found) == 0 {
		t.Skip("no multicast answers here (", err, ")")
	}
	if found[0].TXT["id"] != "3f2a9c" {
		t.Fatalf("%+v", found)
	}
}

// A query stuffed with questions must not turn into a large reply.
func TestResponderAmplification(t *testing.T) {
	svc := testService()
	src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 30), Port: 40000}
	var qs []Question
	for i := 0; i < 180; i++ {
		qs = append(qs, Question{Name: ServiceType, Type: TypePTR})
	}
	q := Message{ID: 1, Questions: qs}
	if _, _, ok := respond(q, src, svc); ok {
		t.Fatal("answered a query with 180 questions")
	}

	// Repeated questions within the cap are answered once, with each record
	// once and no questions echoed.
	q = Message{ID: 2, Questions: []Question{
		{Name: ServiceType, Type: TypePTR}, {Name: ServiceType, Type: TypePTR, Unicast: true},
		{Name: svc.fullName(), Type: TypeSRV}, {Name: svc.fullName(), Type: TypeANY},
		{Name: canonical(svc.Host), Type: TypeA},
	}}
	reply, unicast, ok := respond(q, src, svc)
	if !ok || !unicast || reply.ID != 2 {
		t.Fatalf("reply %+v unicast %v ok %v", reply, unicast, ok)
	}
	if len(reply.Questions) != 0 {
		t.Fatalf("questions echoed: %+v", reply.Questions)
	}
	if len(reply.Answers) != len(svc.records()) {
		t.Fatalf("%d answers, want %d", len(reply.Answers), len(svc.records()))
	}
	in := len(q.Pack())
	if out := len(reply.Pack()); out > 4*in {
		t.Fatalf("reply %d bytes for a %d-byte query", out, in)
	}

	// The same query over the wire: the 180-question packet gets nothing back.
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip("no UDP:", err)
	}
	defer srv.Close()
	go serveWith(srv, svc, func(net.IP) bool { return true })
	cl, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer cl.Close()
	_, _ = cl.WriteToUDP(Message{Questions: qs}.Pack(), srv.LocalAddr().(*net.UDPAddr))
	_ = cl.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := cl.ReadFromUDP(make([]byte, 9000)); err == nil {
		t.Fatal("answered a query with 180 questions")
	}
}

// Queries from addresses that aren't on a local network are ignored.
func TestResponderOffLink(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip("no UDP:", err)
	}
	defer srv.Close()
	go serveWith(srv, testService(), func(net.IP) bool { return false })
	cl, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer cl.Close()
	q := Message{ID: 7, Questions: []Question{{Name: ServiceType, Type: TypePTR}}}
	_, _ = cl.WriteToUDP(q.Pack(), srv.LocalAddr().(*net.UDPAddr))
	_ = cl.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := cl.ReadFromUDP(make([]byte, 9000)); err == nil {
		t.Fatal("answered an off-link source")
	}

	l := newLocalNets()
	if l.contains(net.IPv4(203, 0, 113, 9)) || l.contains(net.IPv4(198, 51, 100, 9)) {
		t.Fatal("documentation addresses counted as on-link")
	}
	if !l.contains(net.IPv4(127, 0, 0, 1)) || !l.contains(net.ParseIP("fe80::1")) {
		t.Fatal("loopback or link-local counted as off-link")
	}
}

// Browse stops collecting after maxRecords records.
func TestGatherCap(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip("no UDP:", err)
	}
	defer c.Close()
	sender, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer sender.Close()
	var rrs []RR
	for i := 0; i < 100; i++ {
		rrs = append(rrs, RR{Name: ServiceType, Type: TypePTR, TTL: ttl, Target: "x" + strconv.Itoa(i) + "." + ServiceType})
	}
	pkt := Message{Response: true, Answers: rrs}.Pack()
	for i := 0; i < 10; i++ {
		_, _ = sender.WriteToUDP(pkt, c.LocalAddr().(*net.UDPAddr))
	}
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	all, _ := gather(c)
	if len(all) != maxRecords {
		t.Fatalf("gathered %d records, want %d", len(all), maxRecords)
	}
}
