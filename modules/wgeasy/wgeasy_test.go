package wgeasy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type fakeWG struct {
	mu      sync.Mutex
	legacy  bool
	clients []map[string]any
	nextID  int
	writes  []string
	logins  int
	session string
}

func (f *fakeWG) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	base := "/api/client"
	if f.legacy {
		base = "/api/wireguard/client"
		if r.URL.Path == "/api/session" && r.Method == "POST" {
			var b struct{ Password string }
			json.Unmarshal(body, &b)
			if b.Password != "pw" {
				w.WriteHeader(401)
				io.WriteString(w, `{"error":"Incorrect Password"}`)
				return
			}
			f.logins++
			f.session = "sess" + strconv.Itoa(f.logins)
			http.SetCookie(w, &http.Cookie{Name: "connect.sid", Value: f.session, Path: "/"})
			io.WriteString(w, `{"success":true}`)
			return
		}
		if ck, _ := r.Cookie("connect.sid"); ck == nil || ck.Value != f.session {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"Not Logged In"}`)
			return
		}
	} else if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "pw" {
		w.WriteHeader(401)
		return
	}
	if r.Method != "GET" {
		f.writes = append(f.writes, r.Method+" "+r.URL.Path+" "+string(body))
	}
	find := func(id string) int {
		for i, c := range f.clients {
			if c["_id"] == id {
				return i
			}
		}
		return -1
	}
	rest := strings.TrimPrefix(r.URL.Path, base)
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	switch {
	case !strings.HasPrefix(r.URL.Path, base):
		w.WriteHeader(404)
	case rest == "" && r.Method == "GET":
		out := []map[string]any{}
		for _, c := range f.clients {
			cp := map[string]any{}
			for k, v := range c {
				if k != "_id" {
					cp[k] = v
				}
			}
			out = append(out, cp)
		}
		json.NewEncoder(w).Encode(out)
	case rest == "" && r.Method == "POST":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.nextID++
		id := strconv.Itoa(f.nextID)
		c := map[string]any{"_id": id, "name": b["name"], "enabled": true, "publicKey": "pub" + id, "privateKey": "LEAKME", "preSharedKey": "LEAKME", "createdAt": "2026-11-04T12:00:00Z", "transferRx": 0, "transferTx": 0}
		if f.legacy {
			c["id"], c["address"] = "aaaaaaaa-0000-0000-0000-00000000000"+id, "10.8.0."+id
			c["_id"] = c["id"]
			io.WriteString(w, `{"success":true}`)
		} else {
			c["id"], c["ipv4Address"] = f.nextID, "10.8.0."+id
			io.WriteString(w, `{"success":true,"clientId":`+id+`}`)
		}
		f.clients = append(f.clients, c)
	case len(parts) == 1 && r.Method == "DELETE":
		i := find(parts[0])
		if i < 0 {
			w.WriteHeader(404)
			return
		}
		f.clients = append(f.clients[:i], f.clients[i+1:]...)
		io.WriteString(w, `{"success":true}`)
	case len(parts) == 2 && r.Method == "POST" && (parts[1] == "enable" || parts[1] == "disable"):
		i := find(parts[0])
		if i < 0 {
			w.WriteHeader(404)
			return
		}
		f.clients[i]["enabled"] = parts[1] == "enable"
		io.WriteString(w, `{"success":true}`)
	case len(parts) == 2 && r.Method == "GET" && parts[1] == "configuration":
		w.Header().Set("Content-Disposition", `attachment; filename="phone.conf"`)
		io.WriteString(w, "[Interface]\nPrivateKey = PRIVATEKEY\nAddress = 10.8.0.2/24\n\n[Peer]\nPublicKey = serverpub\n")
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, legacy bool, pass string) (*Module, *fakeWG) {
	f := &fakeWG{legacy: legacy, nextID: 2}
	if legacy {
		f.clients = []map[string]any{
			{"_id": "11111111-0000-0000-0000-000000000001", "id": "11111111-0000-0000-0000-000000000001", "name": "phone", "enabled": true, "address": "10.8.0.2", "publicKey": "pubA", "privateKey": "LEAKME",
				"latestHandshakeAt": now.Add(-time.Minute).Format(time.RFC3339), "transferRx": 1000, "transferTx": 5000, "downloadableConfig": true},
			{"_id": "11111111-0000-0000-0000-000000000002", "id": "11111111-0000-0000-0000-000000000002", "name": "laptop", "enabled": false, "address": "10.8.0.3", "publicKey": "pubB", "latestHandshakeAt": nil, "transferRx": 70000, "transferTx": 100},
		}
	} else {
		f.clients = []map[string]any{
			{"_id": "1", "id": 1, "name": "phone", "enabled": true, "ipv4Address": "10.8.0.2", "ipv6Address": "fdcc::2", "publicKey": "pubA", "privateKey": "LEAKME", "preSharedKey": "LEAKME",
				"latestHandshakeAt": now.Add(-time.Minute).Format(time.RFC3339), "endpoint": "203.0.113.5:4500", "transferRx": 1000, "transferTx": 5000, "expiresAt": nil},
			{"_id": "2", "id": 2, "name": "laptop", "enabled": false, "ipv4Address": "10.8.0.3", "publicKey": "pubB", "privateKey": "LEAKME", "latestHandshakeAt": now.Add(-time.Hour).Format(time.RFC3339), "transferRx": 70000, "transferTx": 100},
		}
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	cfg := Config{URL: srv.URL + "/", Password: pass, Username: "admin", Version: "15"}
	if legacy {
		cfg.Version, cfg.Username = "14", ""
	}
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "x"}), "w", raw); err != nil {
		t.Fatal(err)
	}
	c, _ := m.set.Get("w")
	c.now = func() time.Time { return now }
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "w", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestWGEasy(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		m, f := setup(t, legacy, "secret://pw")
		if h := m.Health(context.Background(), "w"); h.Status != "ok" || h.Message != "2 clients · 1 connected" {
			t.Fatalf("%v %+v", legacy, h)
		}
		for _, c := range []struct{ action, in, want string }{
			{"clients", `{}`, `"address":"10.8.0.2","enabled":true`},
			{"clients", `{"online":true}`, `"online":true,"publicKey":"pubA","receivedBytes":1000,"sentBytes":5000`},
			{"traffic", `{}`, `"connected":1,"receivedBytes":71000`},
		} {
			r, err := invoke(m, c.action, c.in, false)
			if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "LEAKME") {
				t.Fatalf("%v %s: %s %v", legacy, c.action, r.Output, err)
			}
		}
		r, _ := invoke(m, "clients", `{"online":true}`, false)
		if strings.Contains(string(r.Output), "laptop") {
			t.Fatal(string(r.Output))
		}
		r, _ = invoke(m, "traffic", `{}`, false)
		if i, j := strings.Index(string(r.Output), "laptop"), strings.Index(string(r.Output), "phone"); !legacy && i > j {
			t.Fatalf("not largest first: %s", r.Output)
		}

		p, err := invoke(m, "disable_client", `{"client":"phone"}`, true)
		if err != nil || p.Plan == nil || p.Plan.Summary != "Turn client phone (10.8.0.2) off; it's connected now and will be cut off" || len(f.writes) != 0 {
			t.Fatalf("%+v %v", p, err)
		}
		r, err = invoke(m, "disable_client", `{"client":"phone"}`, false)
		if err != nil || f.clients[0]["enabled"] != false || r.Undo == nil || r.Undo.Action != "enable_client" {
			t.Fatalf("%+v %v", r, err)
		}
		if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.clients[0]["enabled"] != true || r.Undo.Action != "disable_client" {
			t.Fatalf("%+v %v", r, err)
		}

		p, err = invoke(m, "create_client", `{"name":"tablet","expiresAt":"2027-01-31"}`, true)
		if err != nil || p.Plan == nil || len(f.clients) != 2 {
			t.Fatalf("%+v %v", p, err)
		}
		r, err = invoke(m, "create_client", `{"name":"tablet","expiresAt":"2027-01-31"}`, false)
		if err != nil || len(f.clients) != 3 || r.Undo == nil || r.Undo.Action != "delete_client" || strings.Contains(string(r.Output), "LEAKME") || !strings.Contains(string(r.Output), `"name":"tablet"`) {
			t.Fatalf("%v %s %+v %v", legacy, r.Output, r.Undo, err)
		}
		if w := f.writes[len(f.writes)-1]; (legacy && !strings.Contains(w, `"expiredDate":"2027-01-31"`)) || (!legacy && !strings.Contains(w, `"expiresAt":"2027-01-31"`)) {
			t.Fatal(w)
		}
		if _, err := invoke(m, "create_client", `{"name":"Tablet"}`, false); err == nil || !strings.Contains(err.Error(), "already a client") {
			t.Fatal(err)
		}
		p, err = invoke(m, r.Undo.Action, string(r.Undo.Input), true)
		if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, "can't be undone") || strings.Contains(string(p.Plan.Changes[0].Before), "LEAKME") {
			t.Fatalf("%+v %v", p, err)
		}
		if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.clients) != 2 || r.Undo != nil {
			t.Fatalf("%+v %v", r, err)
		}

		r, err = invoke(m, "config", `{"client":"phone"}`, false)
		if err != nil || !strings.Contains(string(r.Output), "PrivateKey = PRIVATEKEY") || !strings.Contains(string(r.Output), `"filename":"phone.conf"`) {
			t.Fatalf("%s %v", r.Output, err)
		}
	}
	for _, a := range New().Manifest().Actions {
		switch a.Name {
		case "config":
			if !a.Sensitive || a.Risk != sdk.RiskDestructive {
				t.Fatal("config reveals a private key")
			}
		case "delete_client":
			if a.Risk != sdk.RiskDestructive {
				t.Fatal(a)
			}
		default:
			if a.Sensitive {
				t.Fatal(a.Name)
			}
		}
	}
}

func TestWGEasySessionExpiry(t *testing.T) {
	m, f := setup(t, true, "secret://pw")
	if _, err := invoke(m, "clients", `{}`, false); err != nil || f.logins != 1 {
		t.Fatal(err, f.logins)
	}
	f.session = "gone"
	if _, err := invoke(m, "clients", `{}`, false); err != nil || f.logins != 2 {
		t.Fatal(err, f.logins)
	}
}

func TestWGEasyRefusals(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		bad, _ := setup(t, legacy, "secret://bad")
		if h := bad.Health(context.Background(), "w"); h.Status != "down" || h.Message != "wg-easy refused the username or password" {
			t.Fatalf("%v %+v", legacy, h)
		}
	}
	m, f := setup(t, false, "secret://pw")
	for _, c := range []struct{ action, in string }{
		{"enable_client", `{"client":""}`},
		{"delete_client", `{"client":"../session"}`},
		{"delete_client", `{"client":"a\nb"}`},
		{"create_client", `{"name":""}`},
		{"create_client", `{"name":"` + strings.Repeat("x", 65) + `"}`},
		{"create_client", `{"name":"ok","expiresAt":"2020-01-01"}`},
		{"create_client", `{"name":"ok","expiresAt":"soon"}`},
		{"enable_client", `{"client":"phone"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.writes) != 0 {
		t.Fatal(f.writes)
	}
	for _, c := range []Config{{URL: "http://w", Username: "admin", Password: "plain"}, {URL: "http://w", Password: "secret://pw"}, {URL: "http://w", Version: "13", Password: "secret://pw"},
		{URL: "vpn:51821", Username: "a", Password: "secret://pw"}, {URL: "http://u:p@w", Username: "a", Password: "secret://pw"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked += r.Header.Get("Authorization") + string(b)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	for _, v := range []string{"15", "14"} {
		rm := New()
		raw, _ := json.Marshal(Config{URL: srv.URL, Version: v, Username: "admin", Password: "secret://pw"})
		if err := rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "w", raw); err != nil {
			t.Fatal(err)
		}
		if h := rm.Health(context.Background(), "w"); h.Status != "down" || leaked != "" {
			t.Fatalf("followed the redirect: %+v %q", h, leaked)
		}
	}
}
