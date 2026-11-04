package tailscale

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fake struct {
	mu        sync.Mutex
	tags      []string
	deleted   bool
	expired   bool
	tokenHits int
	expires   string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/api/v2/oauth/token" {
		r.ParseForm()
		if r.Form.Get("client_id") != "kCLIENT" || r.Form.Get("client_secret") != "tskey-client-s" {
			w.WriteHeader(401)
			return
		}
		f.tokenHits++
		io.WriteString(w, `{"access_token":"oauth-tok","expires_in":3600}`)
		return
	}
	a := r.Header.Get("Authorization")
	if a != "Bearer tskey-api-x" && a != "Bearer oauth-tok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"API token invalid"}`)
		return
	}
	dev := func() map[string]any {
		return map[string]any{"id": "n123", "hostname": "nas", "name": "nas.tail-1.ts.net", "os": "linux", "addresses": []string{"100.64.0.2"},
			"connectedToControl": true, "authorized": true, "expires": f.expires, "tags": f.tags}
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v2/tailnet/-/devices":
		laptop := map[string]any{"id": "n456", "hostname": "laptop", "keyExpiryDisabled": true, "connectedToControl": false}
		json.NewEncoder(w).Encode(map[string]any{"devices": []any{dev(), laptop}})
	case "GET /api/v2/device/n123":
		json.NewEncoder(w).Encode(dev())
	case "POST /api/v2/device/n123/tags":
		var b struct{ Tags []string }
		json.NewDecoder(r.Body).Decode(&b)
		f.tags = b.Tags
		io.WriteString(w, `{}`)
	case "POST /api/v2/device/n123/authorized":
		io.WriteString(w, `{}`)
	case "POST /api/v2/device/n123/expire":
		f.expired = true
	case "DELETE /api/v2/device/n123":
		f.deleted = true
	case "GET /api/v2/tailnet/-/dns/nameservers":
		io.WriteString(w, `{"dns":["1.1.1.1"]}`)
	case "GET /api/v2/tailnet/-/dns/preferences":
		io.WriteString(w, `{"magicDNS":true}`)
	case "GET /api/v2/tailnet/-/dns/searchpaths":
		io.WriteString(w, `{"searchPaths":[]}`)
	case "GET /api/v2/tailnet/-/acl":
		io.WriteString(w, `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`)
	default:
		w.WriteHeader(404)
	}
}

func TestTailscale(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	f := &fake{tags: []string{"tag:server"}, expires: now.Add(90 * 24 * time.Hour).Format(time.RFC3339)}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ctx := context.Background()
	host := fakehost.New(map[string]string{"secret://ts": "tskey-api-x", "secret://oc": "tskey-client-s"})
	m := New()
	m.now = func() time.Time { return now }
	cfg, _ := json.Marshal(Config{APIKey: "secret://ts", API: srv.URL})
	if err := m.Configure(ctx, host, "t", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "t"); h.Status != "ok" || h.Message != "2 devices, 1 online" {
		t.Fatalf("health %+v", h)
	}
	f.expires = now.Add(5 * 24 * time.Hour).Format(time.RFC3339)
	if h := m.Health(ctx, "t"); h.Status != "degraded" || !strings.Contains(h.Message, "nas expires 8 Nov") {
		t.Fatalf("expiry warning %+v", h)
	}
	call := func(action, in string) sdk.Result {
		t.Helper()
		r, err := m.Invoke(ctx, sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in)})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return r
	}
	if out := string(call("devices", "").Output); !strings.Contains(out, `"keyExpiresSoon":true`) || !strings.Contains(out, `"keyExpires":"never"`) {
		t.Fatal(out)
	}
	call("dns", "")
	call("acl", "")
	call("authorize", `{"device":"n123"}`)
	dry, _ := m.Invoke(ctx, sdk.Call{Instance: "t", Action: "set_tags", DryRun: true, Input: json.RawMessage(`{"device":"n123","tags":["tag:media"]}`)})
	if dry.Plan == nil || f.tags[0] != "tag:server" {
		t.Fatal("dry run")
	}
	r := call("set_tags", `{"device":"n123","tags":["tag:media"]}`)
	if f.tags[0] != "tag:media" {
		t.Fatal("tags")
	}
	call(r.Undo.Action, string(r.Undo.Input))
	if f.tags[0] != "tag:server" {
		t.Fatal("undo tags")
	}
	call("expire_key", `{"device":"n123"}`)
	call("delete", `{"device":"n123"}`)
	if !f.expired || !f.deleted {
		t.Fatal("destructive actions")
	}
	for _, bad := range []string{`{"device":"../acl"}`, `{"device":"n123","tags":["server"]}`} {
		if _, err := m.Invoke(ctx, sdk.Call{Instance: "t", Action: "set_tags", Input: json.RawMessage(bad)}); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}

	// OAuth client: one token, reused.
	o := New()
	cfg, _ = json.Marshal(Config{ClientID: "kCLIENT", ClientSecret: "secret://oc", API: srv.URL})
	if err := o.Configure(ctx, host, "o", cfg); err != nil {
		t.Fatal(err)
	}
	o.Health(ctx, "o")
	o.Health(ctx, "o")
	if f.tokenHits != 1 {
		t.Fatalf("token fetched %d times", f.tokenHits)
	}
	for _, c := range []Config{{}, {ClientID: "k"}, {APIKey: "secret://ts", Tailnet: "a/b"}} {
		b, _ := json.Marshal(c)
		if err := New().Configure(ctx, host, "x", b); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

// What these do reaches past what an agent approved for write may do
// (going public, paging or silencing people, filtering every client,
// network access, stopping a service), so they're destructive.
func TestRiskOfReachingActions(t *testing.T) {
	want := map[string]bool{}
	for _, n := range []string{"authorize", "set_tags"} {
		want[n] = true
	}
	for _, a := range New().Manifest().Actions {
		if want[a.Name] {
			delete(want, a.Name)
			if a.Risk != sdk.RiskDestructive {
				t.Errorf("%s must be destructive, is %s", a.Name, a.Risk)
			}
		}
	}
	for n := range want {
		t.Errorf("no action %s", n)
	}
}
