package netguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReserved(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "127.8.9.10", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "100.100.100.100", "100.127.255.254", "198.18.0.1", "0.0.0.0", "0.1.2.3", "255.255.255.255", "224.0.0.1", "239.1.1.1",
		"::1", "::", "fe80::1", "fd00::1", "fc00::1", "ff02::1", "64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b::808:808",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:100.64.0.1", "2002:7f00:1::", "2001::1"} {
		if !Reserved(net.ParseIP(s)) {
			t.Errorf("%s should be refused", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "100.63.255.255", "100.128.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if Reserved(net.ParseIP(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
	if !Reserved(nil) {
		t.Error("nil should be refused")
	}
}

func TestControlRefusesAtConnect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secret") }))
	defer srv.Close()
	_, err := Dialer(time.Second).DialContext(context.Background(), "tcp", srv.Listener.Addr().String())
	if !errors.Is(err, ErrReserved) {
		t.Fatalf("dialled loopback: %v", err)
	}
	// "localhost" resolves to loopback; the check runs on the resolved address.
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	if _, err := Dialer(time.Second).DialContext(context.Background(), "tcp", "localhost:"+port); err == nil {
		t.Fatal("dialled localhost")
	}
}

func TestPublicHTTPSClient(t *testing.T) {
	c := PublicHTTPSClient(5*time.Second, 3)
	if c.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("must not use a proxy")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secret") }))
	defer srv.Close()
	if _, err := c.Get(srv.URL); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reached a local server: %v", err)
	}
	// Redirect rules, checked directly.
	mk := func(u string) *http.Request { r, _ := http.NewRequest("GET", u, nil); return r }
	if err := c.CheckRedirect(mk("http://example.com/"), []*http.Request{mk("https://a/")}); err == nil {
		t.Error("followed a redirect to http")
	}
	if err := c.CheckRedirect(mk("https://example.com/"), make([]*http.Request, 4)); err == nil {
		t.Error("followed a fourth redirect")
	}
	if err := c.CheckRedirect(mk("https://example.com/"), make([]*http.Request, 3)); err != nil {
		t.Errorf("third redirect refused: %v", err)
	}
}
