package mdns

import (
	"context"
	"net"
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
