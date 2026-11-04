package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	acct     = "0123456789abcdef0123456789abcdef"
	tunnelID = "c1744f8b-faa1-48a4-9e5c-02ac921467fa"
)

type fakeTunnels struct {
	mu       sync.Mutex
	accounts int
	seen     []string
}

func (f *fakeTunnels) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer cf" {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"success":false,"errors":[{"message":"Invalid access token"}]}`)
		return
	}
	f.seen = append(f.seen, r.URL.Path)
	ok := func(v string) { fmt.Fprintf(w, `{"success":true,"errors":[],"result":%s}`, v) }
	base := "/accounts/" + acct + "/cfd_tunnel"
	switch r.URL.Path {
	case "/accounts":
		list := []string{}
		for i := 0; i < f.accounts; i++ {
			id := acct
			if i > 0 {
				id = strings.Repeat("f", 32)
			}
			list = append(list, fmt.Sprintf(`{"id":%q,"name":"acct %d"}`, id, i))
		}
		ok("[" + strings.Join(list, ",") + "]")
	case base:
		if r.URL.Query().Get("is_deleted") != "false" {
			w.WriteHeader(400)
			return
		}
		all := map[string]string{
			"home": `{"id":"` + tunnelID + `","name":"home","status":"healthy","tun_type":"cfd_tunnel","remote_config":true,"conns_active_at":"2026-11-01T10:00:00Z","connections":[{"colo_name":"ams01","is_pending_reconnect":false},{"colo_name":"fra02","is_pending_reconnect":false}]}`,
			"lab":  `{"id":"b2b2b2b2-0000-4000-8000-000000000000","name":"lab","status":"down","remote_config":false,"connections":[]}`,
		}
		if n := r.URL.Query().Get("name"); n != "" {
			if t, has := all[n]; has {
				ok("[" + t + "]")
			} else {
				ok("[]")
			}
			return
		}
		ok("[" + all["home"] + "," + all["lab"] + "]")
	case base + "/" + tunnelID:
		ok(`{"id":"` + tunnelID + `","name":"home","status":"healthy","remote_config":true,"connections":[{"colo_name":"ams01"}]}`)
	case base + "/" + tunnelID + "/connections":
		ok(`[{"id":"1bedc50d-42b3-473c-b108-ff3d10c0d925","version":"2026.10.0","arch":"linux_arm64","run_at":"2026-11-01T09:59:00Z","conns":[{"colo_name":"ams01","opened_at":"2026-11-01T10:00:00Z","origin_ip":"198.51.100.2","is_pending_reconnect":false}]}]`)
	case base + "/" + tunnelID + "/configurations":
		ok(`{"config":{"ingress":[{"hostname":"ha.example.com","service":"http://192.168.1.10:8123"},{"service":"http_status:404"}]}}`)
	default:
		w.WriteHeader(404)
		fmt.Fprint(w, `{"success":false,"errors":[{"message":"not found"}]}`)
	}
}

func tunnelSetup(t *testing.T, f *fakeTunnels, accountID string) *Module {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	cfg, _ := json.Marshal(Config{Token: "secret://cf", API: srv.URL, AccountID: accountID})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cf": "cf"}), "cf", cfg); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTunnels(t *testing.T) {
	f := &fakeTunnels{accounts: 1}
	m := tunnelSetup(t, f, "")
	r := run(t, m, "tunnels", map[string]any{}, false)
	if !strings.HasPrefix(string(r.Output), `[{"id":"b2b2b2b2`) || !strings.Contains(string(r.Output), `"edge":"ams01, fra02"`) || !strings.Contains(string(r.Output), `"managed":"dashboard"`) {
		t.Fatalf("%s", r.Output)
	}
	for _, name := range []string{"home", tunnelID} {
		r = run(t, m, "tunnel", map[string]any{"tunnel": name}, false)
		if !strings.Contains(string(r.Output), `"version":"2026.10.0"`) || !strings.Contains(string(r.Output), `"hostname":"ha.example.com"`) {
			t.Fatalf("%s: %s", name, r.Output)
		}
	}
	if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "cf", Action: "tunnel", Input: json.RawMessage(`{"tunnel":"nope"}`)}); err == nil || !strings.Contains(err.Error(), "no tunnel") {
		t.Fatal(err)
	}

	// Several accounts need the account ID; with it, /accounts isn't asked.
	f2 := &fakeTunnels{accounts: 2}
	m2 := tunnelSetup(t, f2, "")
	if _, err := m2.Invoke(context.Background(), sdk.Call{Instance: "cf", Action: "tunnels"}); err == nil || !strings.Contains(err.Error(), "several accounts") {
		t.Fatal(err)
	}
	m3 := tunnelSetup(t, f2, acct)
	f2.seen = nil
	run(t, m3, "tunnels", map[string]any{}, false)
	if len(f2.seen) != 1 || f2.seen[0] != "/accounts/"+acct+"/cfd_tunnel" {
		t.Fatal(f2.seen)
	}

	f2.seen = nil
	for _, in := range []string{`{"tunnel":"../../user"}`, `{"tunnel":""}`, `{"tunnel":"a?b"}`} {
		if _, err := m3.Invoke(context.Background(), sdk.Call{Instance: "cf", Action: "tunnel", Input: json.RawMessage(in)}); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f2.seen) != 0 {
		t.Fatal(f2.seen)
	}
	cfg, _ := json.Marshal(Config{Token: "secret://cf", AccountID: "../x"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", cfg); err == nil {
		t.Fatal("accepted a bad account id")
	}
}
