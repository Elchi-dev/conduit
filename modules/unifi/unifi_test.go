package unifi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeConsole struct {
	mu       sync.Mutex
	restarts []string
	blocked  map[string]bool
	logins   int
}

func (f *fakeConsole) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/proxy/network/integration/v1/"):
			if r.Header.Get("X-API-KEY") != "key123" {
				w.WriteHeader(401)
				return
			}
			switch {
			case p == "/proxy/network/integration/v1/sites":
				io.WriteString(w, `{"data":[{"id":"site-uuid","internalReference":"default","name":"Default"}]}`)
			case p == "/proxy/network/integration/v1/sites/site-uuid/devices":
				io.WriteString(w, `{"data":[{"id":"dev-1","name":"Gateway","model":"UDM Pro","macAddress":"AA:BB:CC:00:00:01","ipAddress":"192.168.1.1","state":"ONLINE"},{"id":"dev-2","name":"Garage AP","model":"U6 Lite","macAddress":"aa:bb:cc:00:00:02","ipAddress":"192.168.1.5","state":"OFFLINE"}]}`)
			case p == "/proxy/network/integration/v1/sites/site-uuid/clients":
				io.WriteString(w, `{"data":[{"name":"Laptop","type":"WIRELESS","ipAddress":"192.168.1.50","macAddress":"11:22:33:44:55:66"}]}`)
			case p == "/proxy/network/integration/v1/sites/site-uuid/devices/dev-2/actions" && r.Method == "POST":
				f.restarts = append(f.restarts, "dev-2")
				io.WriteString(w, `{}`)
			default:
				w.WriteHeader(404)
			}
		case p == "/api/auth/login":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["username"] != "admin" || b["password"] != "pw" {
				w.WriteHeader(401)
				return
			}
			f.logins++
			http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "tok", Path: "/"})
			w.Header().Set("X-CSRF-Token", "csrf-1")
			io.WriteString(w, `{}`)
		case strings.HasPrefix(p, "/proxy/network/api/s/default/"):
			if ck, err := r.Cookie("TOKEN"); err != nil || ck.Value != "tok" || (r.Method == "POST" && r.Header.Get("X-CSRF-Token") != "csrf-1") {
				w.WriteHeader(401)
				return
			}
			switch p {
			case "/proxy/network/api/s/default/stat/sta":
				io.WriteString(w, `{"meta":{"rc":"ok"},"data":[{"hostname":"tv","mac":"11:22:33:44:55:77","ip":"192.168.1.60","tx_bytes":10,"rx_bytes":5000},{"name":"Laptop","mac":"11:22:33:44:55:66","ip":"192.168.1.50","tx_bytes":100,"rx_bytes":100}]}`)
			case "/proxy/network/api/s/default/cmd/stamgr":
				var b map[string]string
				_ = json.NewDecoder(r.Body).Decode(&b)
				f.blocked[b["mac"]] = b["cmd"] == "block-sta"
				io.WriteString(w, `{"meta":{"rc":"ok"},"data":[]}`)
			default:
				io.WriteString(w, `{"meta":{"rc":"error","msg":"api.err.NotFound"}}`)
			}
		default:
			w.WriteHeader(404)
		}
	})
}

func TestUniFi(t *testing.T) {
	f := &fakeConsole{blocked: map[string]bool{}}
	srv := httptest.NewTLSServer(f.handler(t))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	fp := hex.EncodeToString(sum[:])
	ctx := context.Background()
	h := fakehost.New(map[string]string{"secret://key": "key123", "secret://pw": "pw"})
	m := New()

	// The pin: the right fingerprint connects, a wrong one doesn't, and
	// without either the self-signed certificate is refused.
	wrong := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		fp   string
		want string
	}{{fp, "degraded"}, {wrong, "down"}, {"", "down"}} {
		cfg, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://key", Fingerprint: tc.fp})
		if err := m.Configure(ctx, h, "u", cfg); err != nil {
			t.Fatal(err)
		}
		if hl := m.Health(ctx, "u"); hl.Status != tc.want {
			t.Fatalf("fingerprint %q: health %+v", tc.fp, hl)
		}
	}
	cfg, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://key", Username: "admin", Password: "secret://pw", Fingerprint: fp})
	if err := m.Configure(ctx, h, "u", cfg); err != nil {
		t.Fatal(err)
	}
	run := func(action, in string, dry bool) (sdk.Result, error) {
		return m.Invoke(ctx, sdk.Call{Instance: "u", Action: action, Input: json.RawMessage(in), DryRun: dry})
	}
	r, err := run("devices", "", false)
	var ds []Device
	_ = json.Unmarshal(r.Output, &ds)
	if err != nil || len(ds) != 2 || ds[1].State != "offline" || ds[0].MAC != "aa:bb:cc:00:00:01" {
		t.Fatalf("devices %+v %v", ds, err)
	}
	// Clients come from the session (traffic numbers), busiest first.
	r, err = run("clients", "", false)
	var cs struct {
		Count   int
		Clients []Client
	}
	_ = json.Unmarshal(r.Output, &cs)
	if err != nil || cs.Count != 2 || cs.Clients[0].Name != "tv" {
		t.Fatalf("clients %+v %v", cs, err)
	}
	r, err = run("restart_device", `{"device":"AA:BB:CC:00:00:02"}`, true)
	if err != nil || r.Plan == nil || len(f.restarts) != 0 {
		t.Fatalf("dry run %v", err)
	}
	if _, err := run("restart_device", `{"device":"dev-2"}`, false); err != nil || len(f.restarts) != 1 {
		t.Fatalf("restart %v", err)
	}
	if _, err := run("restart_device", `{"device":"nope"}`, false); err == nil {
		t.Fatal("unknown device restarted")
	}
	r, err = run("block_client", `{"mac":"11:22:33:44:55:66"}`, false)
	if err != nil || !f.blocked["11:22:33:44:55:66"] || r.Undo == nil {
		t.Fatalf("block %v", err)
	}
	if _, err := run(r.Undo.Action, string(r.Undo.Input), false); err != nil || f.blocked["11:22:33:44:55:66"] {
		t.Fatalf("unblock %v", err)
	}
	if _, err := run("block_client", `{"mac":"../../x"}`, false); err == nil {
		t.Fatal("bad MAC accepted")
	}

	// API key only: blocking explains what's missing.
	cfg, _ = json.Marshal(Config{URL: srv.URL, APIKey: "secret://key", Fingerprint: fp})
	_ = m.Configure(ctx, h, "k", cfg)
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "k", Action: "block_client", Input: json.RawMessage(`{"mac":"11:22:33:44:55:66"}`)}); err == nil || !strings.Contains(err.Error(), "username") {
		t.Fatalf("block with key only: %v", err)
	}
	if err := m.Configure(ctx, h, "x", json.RawMessage(`{"url":"http://192.168.1.1","apiKey":"secret://key"}`)); err == nil {
		t.Fatal("plain http accepted")
	}
}
