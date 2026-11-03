package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/internal/hub"
	"github.com/elchi-dev/conduit/pkg/relay"
)

type mailbox struct {
	mu   sync.Mutex
	last string
}

func (m *mailbox) Name() string { return "test" }
func (m *mailbox) Send(_ context.Context, _, _, text string) error {
	m.mu.Lock()
	m.last = text
	m.mu.Unlock()
	return nil
}

func post(t *testing.T, url, tok string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode >= 300 {
		t.Fatalf("POST %s: %d %v", url, res.StatusCode, out)
	}
	return out
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestTunnelEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A hub with one account and a pairing code.
	h, err := hub.New(ctx, hub.Config{DatabaseURL: filepath.Join(t.TempDir(), "hub.db"), PublicURL: "http://hub", OpenRegistration: true}, quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	mb := &mailbox{}
	h.SetMailer(mb)
	hs := httptest.NewServer(h.Handler())
	defer hs.Close()
	post(t, hs.URL+"/v1/accounts", "", map[string]string{"email": "a@example.com", "password": "correct horse battery"})
	tok := regexp.MustCompile(`token=([0-9a-z]+)`).FindStringSubmatch(mb.last)[1]
	post(t, hs.URL+"/v1/accounts/verify", "", map[string]string{"token": tok})
	session := post(t, hs.URL+"/v1/sessions", "", map[string]string{"email": "a@example.com", "password": "correct horse battery"})["token"].(string)
	code := post(t, hs.URL+"/v1/pairing-codes", session, nil)["code"].(string)

	// A daemon whose API echoes what it received.
	store, err := core.OpenStore(ctx, filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	svc, err := New(ctx, store.DB, quiet(), "desk")
	if err != nil {
		t.Fatal(err)
	}
	svc.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"method": r.Method, "path": r.URL.Path, "auth": r.Header.Get("Authorization"), "body": string(b), "client": r.Header.Get("X-Conduit-Relay-Client"), "cookie": r.Header.Get("Cookie")})
	})
	svc.Start(ctx)
	if _, err := svc.NewPairing(); err == nil {
		t.Fatal("pairing before linking should fail")
	}
	link, err := svc.LinkHub(ctx, hs.URL, code)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return svc.Status(ctx).Connected })

	// The key survives a restart.
	again, _ := New(ctx, store.DB, quiet(), "desk")
	if again.PublicKey() != svc.PublicKey() || again.Status(ctx).Link.DeviceID != link.DeviceID {
		t.Fatal("relay key and link must persist")
	}

	p, err := svc.NewPairing()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.URI, "conduit://pair?d=") {
		t.Fatalf("uri %q", p.URI)
	}
	phone, _ := relay.NewKeyPair()

	// Without the secret, an unknown key is refused.
	if _, err := relay.Dial(ctx, hs.URL, p.Daemon, p.Key, phone, "", "phone"); err == nil || !strings.Contains(err.Error(), "unknown device") {
		t.Fatalf("want refusal, got %v", err)
	}
	// A client that pinned the wrong daemon key notices.
	other, _ := relay.NewKeyPair()
	if _, err := relay.Dial(ctx, hs.URL, p.Daemon, other.Public(), phone, p.Secret, "phone"); err == nil {
		t.Fatal("a wrong pinned key must fail")
	}
	// That attempt didn't burn the secret: the proof never opened.
	c, err := relay.Dial(ctx, hs.URL, p.Daemon, p.Key, phone, p.Secret, "Pixel")
	if err != nil {
		t.Fatal(err)
	}
	if c.Welcome.Daemon != "desk" || c.Welcome.Client == "" {
		t.Fatalf("welcome %+v", c.Welcome)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := c.Do(ctx, relay.Request{Method: "POST", Path: "/api/v1/x", Headers: map[string]string{"Authorization": "Bearer cds_abc", "Cookie": "smuggled=1"}, Body: []byte{byte('a' + i)}})
			if err != nil {
				t.Error(err)
				return
			}
			var got map[string]string
			_ = json.Unmarshal(res.Body, &got)
			if res.Status != 200 || got["auth"] != "Bearer cds_abc" || got["body"] != string(rune('a'+i)) || got["client"] != c.Welcome.Client || got["cookie"] != "" {
				t.Errorf("response %d %v", res.Status, got)
			}
		}(i)
	}
	wg.Wait()
	res, _ := c.Do(ctx, relay.Request{Method: "GET", Path: "/index.html"})
	if res.Status != 404 {
		t.Fatalf("non-API paths must not be reachable: %d", res.Status)
	}
	c.Close()

	// Known clients reconnect without a secret; the secret is single use.
	c2, err := relay.Dial(ctx, hs.URL, p.Daemon, p.Key, phone, "", "Pixel")
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
	intruder, _ := relay.NewKeyPair()
	if _, err := relay.Dial(ctx, hs.URL, p.Daemon, p.Key, intruder, p.Secret, "x"); err == nil {
		t.Fatal("a used pairing secret must not enroll another device")
	}

	clients, _ := svc.Clients(ctx)
	if len(clients) != 1 || clients[0].Name != "Pixel" {
		t.Fatalf("clients %v", clients)
	}
	if err := svc.RevokeClient(ctx, clients[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.Dial(ctx, hs.URL, p.Daemon, p.Key, phone, "", "Pixel"); err == nil {
		t.Fatal("a revoked client must be refused")
	}

	if err := svc.Unlink(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !svc.Status(ctx).Connected })
	var n int
	_ = store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM remote_link`).Scan(&n)
	if n != 0 {
		t.Fatal("unlink must forget the link")
	}
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestLANWithoutHub(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := core.OpenStore(ctx, filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	svc, _ := New(ctx, store.DB, quiet(), "laptop")
	svc.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"path":"` + r.URL.Path + `"}`))
	})
	if _, err := svc.NewPairing(); err == nil {
		t.Fatal("no hub and no LAN: pairing must fail")
	}
	srv := httptest.NewServer(http.HandlerFunc(svc.ServeLAN))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	svc.LANAddrs = []string{wsURL}
	p, err := svc.NewPairing()
	if err != nil || p.LAN != wsURL || p.Hub != "" {
		t.Fatalf("pairing %+v %v", p, err)
	}
	phone, _ := relay.NewKeyPair()
	c, err := relay.DialURL(ctx, p.LAN, p.Key, phone, p.Secret, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Do(ctx, relay.Request{Method: "GET", Path: "/api/v1/me"})
	if err != nil || res.Status != 200 || !strings.Contains(string(res.Body), "/api/v1/me") {
		t.Fatalf("request %v %+v", err, res)
	}
	c.Close()
	c, err = relay.DialURL(ctx, p.LAN, p.Key, phone, "", "Phone")
	if err != nil {
		t.Fatal("known device must reconnect without a secret:", err)
	}
	c.Close()
	stranger, _ := relay.NewKeyPair()
	if _, err := relay.DialURL(ctx, p.LAN, p.Key, stranger, "", "x"); err == nil {
		t.Fatal("unknown device admitted")
	}
}

func TestLANURLs(t *testing.T) {
	if LANURLs("127.0.0.1:7600") != nil || LANURLs("localhost:7600") != nil {
		t.Fatal("loopback must not advertise")
	}
	if got := LANURLs("192.168.1.20:7600"); len(got) != 1 || got[0] != "ws://192.168.1.20:7600/relay" {
		t.Fatalf("%v", got)
	}
}

func TestEventStreamOverRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, _ := core.OpenStore(ctx, filepath.Join(t.TempDir(), "d.db"))
	defer store.Close()
	svc, _ := New(ctx, store.DB, quiet(), "laptop")
	stopped := make(chan struct{})
	svc.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/events" {
			w.Write([]byte(`{}`))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; ; i++ {
			fmt.Fprintf(w, "event: tick\ndata: %d\n\n", i)
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				close(stopped)
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	})
	srv := httptest.NewServer(http.HandlerFunc(svc.ServeLAN))
	defer srv.Close()
	svc.LANAddrs = []string{"ws" + strings.TrimPrefix(srv.URL, "http")}
	p, _ := svc.NewPairing()
	phone, _ := relay.NewKeyPair()
	c, err := relay.DialURL(ctx, p.LAN, p.Key, phone, p.Secret, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	frames, stop, err := c.Stream(ctx, relay.Request{Method: "GET", Path: "/api/v1/events"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for f := range frames {
		got = append(got, string(f.Body))
		if len(got) == 3 {
			break
		}
	}
	if !strings.Contains(got[0], "data: 0") || !strings.Contains(got[2], "data: 2") {
		t.Fatalf("frames %q", got)
	}
	stop()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelling must stop the handler")
	}
	// Normal requests still work on the same connection.
	if res, err := c.Do(ctx, relay.Request{Method: "GET", Path: "/api/v1/x"}); err != nil || res.Status != 200 {
		t.Fatalf("request after stream: %v %+v", err, res)
	}
}
