package hetzner

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

func TestHetzner(t *testing.T) {
	var mu sync.Mutex
	state := "running"
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"message":"unauthorized"}}`)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		sv := `{"id":42,"name":"web-1","status":"` + state + `","server_type":{"name":"cx22"},"public_net":{"ipv4":{"ip":"203.0.113.4"}},"datacenter":{"name":"fsn1-dc14"}}`
		switch r.Method + " " + r.URL.Path {
		case "GET /servers":
			io.WriteString(w, `{"servers":[`+sv+`],"meta":{"pagination":{"next_page":null}}}`)
		case "GET /servers/42":
			io.WriteString(w, `{"server":`+sv+`}`)
		case "POST /servers/42/actions/shutdown":
			state = "off"
			io.WriteString(w, `{"action":{"id":1}}`)
		case "POST /servers/42/actions/poweron":
			state = "running"
			io.WriteString(w, `{"action":{"id":2}}`)
		case "POST /servers/42/actions/create_image":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			if b["type"] != "snapshot" {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"image":{"id":7}}`)
		case "GET /images/7":
			io.WriteString(w, `{"image":{"type":"snapshot","description":"x"}}`)
		case "DELETE /images/7":
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"error":{"message":"not found"}}`)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	host := fakehost.New(map[string]string{"secret://hz": "tok"})
	if err := m.Configure(ctx, host, "h", json.RawMessage(`{"token":"plain"}`)); err == nil {
		t.Fatal("plaintext token accepted")
	}
	cfg, _ := json.Marshal(Config{Token: "secret://hz", API: srv.URL})
	if err := m.Configure(ctx, host, "h", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "h"); h.Status != "ok" || !strings.Contains(h.Message, "1 servers") {
		t.Fatalf("health %+v", h)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "h", Action: "servers"})
	if err != nil || !strings.Contains(string(r.Output), "203.0.113.4") {
		t.Fatalf("servers %s %v", r.Output, err)
	}
	// Dry run changes nothing.
	r, _ = m.Invoke(ctx, sdk.Call{Instance: "h", Action: "shutdown", DryRun: true, Input: json.RawMessage(`{"server":42}`)})
	if r.Plan == nil || state != "running" {
		t.Fatal("dry run")
	}
	r, err = m.Invoke(ctx, sdk.Call{Instance: "h", Action: "shutdown", Input: json.RawMessage(`{"server":42}`)})
	if err != nil || state != "off" || r.Undo == nil || r.Undo.Action != "power_on" {
		t.Fatalf("shutdown %v %+v", err, r.Undo)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "h", Action: r.Undo.Action, Input: r.Undo.Input}); err != nil || state != "running" {
		t.Fatalf("undo %v", err)
	}
	r, err = m.Invoke(ctx, sdk.Call{Instance: "h", Action: "snapshot", Input: json.RawMessage(`{"server":42}`)})
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_image" {
		t.Fatalf("snapshot %v", err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "h", Action: r.Undo.Action, Input: r.Undo.Input}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "h", Action: "reboot", Input: json.RawMessage(`{"server":0}`)}); err == nil {
		t.Fatal("no server accepted")
	}
}
