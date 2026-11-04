package romm

import (
	"context"
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

type fakeRomM struct {
	mu      sync.Mutex
	seen    []string
	events  []string
	refuse  bool // the namespace connect is refused
	pending string
	closed  bool
	list    bool // answer roms as a plain list (older RomM)
}

func (f *fakeRomM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if !ok || u != "admin" || p != "pw_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":"Incorrect username or password"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /api/heartbeat":
		io.WriteString(w, `{"SYSTEM":{"VERSION":"4.1.0","SHOW_SETUP_WIZARD":false}}`)
	case "GET /api/users/me":
		io.WriteString(w, `{"id":1,"username":"admin","email":"LEAKME@example.com","role":"admin"}`)
	case "GET /api/platforms":
		io.WriteString(w, `[{"id":2,"slug":"snes","name":"Super Nintendo","rom_count":40},{"id":1,"slug":"n64","name":"Nintendo 64","display_name":"Nintendo 64","rom_count":12}]`)
	case "GET /api/roms":
		items := `[{"id":7,"name":"Super Metroid","fs_name":"Super Metroid (USA).sfc","platform_id":2,"fs_size_bytes":3145728,"regions":["USA"],"languages":["En"],"created_at":"2026-10-01T00:00:00"}]`
		if f.list {
			io.WriteString(w, items)
		} else {
			io.WriteString(w, `{"items":`+items+`,"total":40,"limit":25,"offset":0}`)
		}
	case "GET /ws/socket.io/":
		if r.URL.Query().Get("EIO") != "4" || r.URL.Query().Get("transport") != "polling" {
			w.WriteHeader(400)
			return
		}
		if r.URL.Query().Get("sid") == "" {
			io.WriteString(w, `0{"sid":"abc123","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000}`)
			return
		}
		io.WriteString(w, f.pending)
		f.pending = ""
	case "POST /ws/socket.io/":
		if r.URL.Query().Get("sid") != "abc123" {
			w.WriteHeader(400)
			return
		}
		s := string(body)
		switch {
		case s == "40":
			if f.refuse {
				f.pending = `44{"message":"Not authorized"}`
			} else {
				f.pending = "40{\"sid\":\"x\"}\x1e2"
			}
		case strings.HasPrefix(s, "42"):
			f.events = append(f.events, s[2:])
		case s == "1":
			f.closed = true
		}
		io.WriteString(w, "ok")
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeRomM) {
	f := &fakeRomM{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://rm": "pw_good", "secret://bad": "pw_bad"}), "r", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "r", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestRomM(t *testing.T) {
	m, f := setup(t, "secret://rm")
	if h := m.Health(context.Background(), "r"); h.Status != "ok" || h.Message != "RomM 4.1.0 · 2 platforms, 52 games" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"platforms", `{}`, `[{"games":12,"id":1,"name":"Nintendo 64"`},
		{"roms", `{"platform":2,"search":"metroid"}`, `"sizeMB":3`},
		{"roms", `{}`, `"total":40`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if all := strings.Join(f.seen, "\n"); !strings.Contains(all, "platform_id=2&platform_ids=2&search_term=metroid") {
		t.Fatal(all)
	}
	f.list = true
	if r, err := invoke(m, "roms", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"total":1`) {
		t.Fatal(string(r.Output), err)
	}

	f.seen = nil
	r, err := invoke(m, "scan_library", `{"platforms":[2]}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Scan Super Nintendo (quick)" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	for _, s := range f.seen {
		if strings.Contains(s, "socket.io") {
			t.Fatal("the preview scanned")
		}
	}
	r, err = invoke(m, "scan_library", `{"platforms":[2,2]}`, false)
	if err != nil || len(f.events) != 1 || !strings.HasPrefix(f.events[0], `["scan",{"apis":["igdb"`) || !strings.Contains(f.events[0], `"platforms":[2],"type":"quick"`) || !f.closed {
		t.Fatalf("%s %v %v", r.Output, err, f.events)
	}
	if _, err := invoke(m, "scan_library", `{"platforms":[9]}`, false); err == nil || !strings.Contains(err.Error(), "no platform 9") {
		t.Fatal(err)
	}
	f.refuse = true
	if _, err := invoke(m, "scan_library", `{}`, false); err == nil || !strings.Contains(err.Error(), "refused") || len(f.events) != 1 {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "scan_library" && a.Risk != sdk.RiskWrite {
			t.Fatal(a.Risk)
		}
	}
}

func TestRomMValidation(t *testing.T) {
	m, f := setup(t, "secret://rm")
	for _, c := range []struct{ action, in string }{
		{"roms", `{"platform":0}`}, {"roms", `{"platform":"2&x=1"}`}, {"roms", `{"search":"a\nb"}`},
		{"scan_library", `{"mode":"complete"}`}, {"scan_library", `{"platforms":[0]}`}, {"scan_library", `{"platforms":["1"]}`},
		{"scan_library", `{"platforms":[` + strings.Repeat("1,", 50) + `1]}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://r.example.com", Username: "a", Password: "plain"}, {URL: "r.example.com", Username: "a", Password: "secret://rm"},
		{URL: "https://u:p@r.example.com", Username: "a", Password: "secret://rm"}, {URL: "https://r.example.com/#x", Username: "a", Password: "secret://rm"},
		{URL: "https://r.example.com", Password: "secret://rm"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "r"); h.Status != "down" || h.Message != "RomM refused the user name or password" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "scan_library", `{}`, false); err == nil || strings.Contains(err.Error(), "pw_bad") {
		t.Fatal(err)
	}
}

func TestRomMRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://rm"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://rm": "pw_good"}), "r", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "r"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
