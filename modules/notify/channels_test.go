package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestMatrixAndGotify(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "PUT" && strings.HasPrefix(r.URL.EscapedPath(), "/_matrix/client/v3/rooms/%21room:example.org/send/m.room.message/"):
			if r.Header.Get("Authorization") != "Bearer mtok" {
				w.WriteHeader(401)
				return
			}
			got["matrix"] = string(b)
			io.WriteString(w, `{"event_id":"$1"}`)
		case r.Method == "POST" && r.URL.Path == "/message":
			if r.Header.Get("X-Gotify-Key") != "gtok" {
				w.WriteHeader(401)
				return
			}
			got["gotify"] = string(b)
			io.WriteString(w, `{"id":1}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	host := fakehost.New(map[string]string{"secret://m": "mtok", "secret://g": "gtok"})
	if err := m.Configure(ctx, host, "x", mustJSON(Config{Channel: "matrix", Server: srv.URL, Room: "../../admin", Token: "secret://m"})); err == nil {
		t.Fatal("bad room accepted")
	}
	if err := m.Configure(ctx, host, "x", mustJSON(Config{Channel: "matrix", Server: srv.URL, Room: "!room:example.org", Token: "plain"})); err == nil {
		t.Fatal("plaintext token accepted")
	}
	_ = m.Configure(ctx, host, "mx", mustJSON(Config{Channel: "matrix", Server: srv.URL, Room: "!room:example.org", Token: "secret://m"}))
	_ = m.Configure(ctx, host, "gf", mustJSON(Config{Channel: "gotify", Server: srv.URL, Token: "secret://g"}))
	note := json.RawMessage(`{"title":"Disk","message":"98% full","priority":"high","link":"conduit://open/approvals"}`)
	for _, id := range []string{"mx", "gf"} {
		if _, err := m.Invoke(ctx, sdk.Call{Instance: id, Action: "send", Input: note}); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if !strings.Contains(got["matrix"], `98% full`) || !strings.Contains(got["matrix"], "conduit://open/approvals") {
		t.Fatalf("matrix body %s", got["matrix"])
	}
	var g map[string]any
	_ = json.Unmarshal([]byte(got["gotify"]), &g)
	if g["priority"] != 8.0 || g["title"] != "Disk" {
		t.Fatalf("gotify body %s", got["gotify"])
	}
}

// fakeSMTP is a minimal SMTP server with STARTTLS and AUTH PLAIN.
type fakeSMTP struct {
	ln       net.Listener
	tls      *tls.Config
	starttls bool
	mu       sync.Mutex
	authed   string
	tlsUsed  bool
	data     string
	rcpts    []string
}

func (f *fakeSMTP) serve(t *testing.T) {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeSMTP) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := func(s string) { io.WriteString(c, s+"\r\n") }
	w("220 fake ESMTP")
	secure := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		up := strings.ToUpper(cmd)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			w("250-fake")
			if f.starttls && !secure {
				w("250-STARTTLS")
			}
			w("250 AUTH PLAIN")
		case up == "STARTTLS":
			w("220 go ahead")
			tc := tls.Server(c, f.tls)
			if tc.Handshake() != nil {
				return
			}
			c, r, secure = tc, bufio.NewReader(tc), true
			f.mu.Lock()
			f.tlsUsed = true
			f.mu.Unlock()
		case strings.HasPrefix(up, "AUTH PLAIN"):
			parts := strings.Fields(cmd)
			raw, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			f.mu.Lock()
			f.authed = string(raw)
			f.mu.Unlock()
			w("235 ok")
		case strings.HasPrefix(up, "MAIL FROM"):
			w("250 ok")
		case strings.HasPrefix(up, "RCPT TO"):
			f.mu.Lock()
			f.rcpts = append(f.rcpts, cmd)
			f.mu.Unlock()
			w("250 ok")
		case up == "DATA":
			w("354 send")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			w("250 queued")
		case up == "QUIT":
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func TestEmail(t *testing.T) {
	cert, pool := selfSigned(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	f := &fakeSMTP{ln: ln, tls: &tls.Config{Certificates: []tls.Certificate{cert}}, starttls: true}
	go f.serve(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx := context.Background()
	m := New()
	m.roots = pool
	host := fakehost.New(map[string]string{"secret://smtp": "hunter2"})
	base := Config{Channel: "email", SMTPHost: "127.0.0.1", SMTPPort: port, SMTPUser: "conduit", SMTPPass: "secret://smtp",
		From: "Conduit <conduit@example.com>", To: "ops@example.com, me@example.com"}
	bad := base
	bad.SMTPPass = "hunter2"
	if err := m.Configure(ctx, host, "e", mustJSON(bad)); err == nil {
		t.Fatal("plaintext password accepted")
	}
	bad = base
	bad.To = "not an address"
	if err := m.Configure(ctx, host, "e", mustJSON(bad)); err == nil {
		t.Fatal("bad To accepted")
	}
	if err := m.Configure(ctx, host, "e", mustJSON(base)); err != nil {
		t.Fatal(err)
	}
	in := json.RawMessage(`{"title":"Backup failed\r\nBcc: evil@example.com","message":"restic exited 1","priority":"urgent","link":"conduit://open/timeline"}`)
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "e", Action: "send", Input: in}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if !f.tlsUsed || f.authed != "\x00conduit\x00hunter2" || len(f.rcpts) != 2 {
		t.Fatalf("tls %v auth %q rcpts %v", f.tlsUsed, f.authed, f.rcpts)
	}
	if !strings.Contains(f.data, "restic exited 1") || !strings.Contains(f.data, "Subject: ") || strings.Contains(f.data, "\r\nBcc:") {
		t.Fatalf("message:\n%s", f.data)
	}
	f.mu.Unlock()

	// A server without STARTTLS never gets the password.
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	f2 := &fakeSMTP{ln: ln2, tls: f.tls}
	go f2.serve(t)
	defer ln2.Close()
	plain := base
	plain.SMTPPort = ln2.Addr().(*net.TCPAddr).Port
	_ = m.Configure(ctx, host, "p", mustJSON(plain))
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "p", Action: "test"}); err == nil {
		t.Fatal("password sent without TLS")
	}
	f2.mu.Lock()
	if f2.authed != "" {
		t.Fatal("credentials reached a server without TLS")
	}
	f2.mu.Unlock()
}
