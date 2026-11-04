package games

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Covers are fetched with a client of their own: the module's HTTP client
// (whatever transport or proxy it has) isn't used, so a redirect or a name
// that resolves locally can't reach the local network.
func TestCoverDownloadStaysOffLocalNetwork(t *testing.T) {
	internalHit := false
	internal := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		internalHit = true
		io.WriteString(w, "\x89PNG\r\n\x1a\nINTERNAL-SECRET")
	}))
	defer internal.Close()
	m, _, _ := newTestModule(t, emptyEnv(t, "linux"), nil)
	// The review's setup: a module client that would happily reach it.
	m.HTTP = &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, internal.Listener.Addr().String())
		}}}
	_, port, _ := net.SplitHostPort(internal.Listener.Addr().String())
	st, _ := m.store()
	for i, u := range []string{
		"https://localhost:" + port + "/c.png", // resolves to loopback: refused when dialled
		"https://127.0.0.1:" + port + "/c.png",
		"https://[::ffff:127.0.0.1]:" + port + "/c.png",
		"https://100.64.0.1/c.png",
		"https://[64:ff9b::7f00:1]/c.png",
		"https://169.254.169.254/latest/meta-data",
		"http://93.184.216.34/c.png",
	} {
		st.d.Custom = []CustomGame{{ID: "custom:x", Title: "X", URI: "steam://x", CoverURL: u}}
		m.invalidate()
		if _, _, err := m.Cover(context.Background(), "custom:x"); err == nil {
			t.Errorf("%d %s: fetched", i, u)
		} else if i < 6 && !strings.Contains(err.Error(), "local network") {
			t.Errorf("%d %s: %v", i, u, err)
		}
	}
	if internalHit {
		t.Fatal("the local server was reached")
	}
	tr := coverClient.Transport.(*http.Transport)
	if tr.Proxy != nil || coverClient.CheckRedirect == nil {
		t.Fatal("cover client must not use a proxy and must check redirects")
	}
}
