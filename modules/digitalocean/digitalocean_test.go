package digitalocean

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

func TestDigitalOcean(t *testing.T) {
	var mu sync.Mutex
	state := "active"
	deployed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			io.WriteString(w, `{"id":"unauthorized","message":"Unable to authenticate you"}`)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		d := `{"id":9,"name":"db-1","status":"` + state + `","size_slug":"s-1vcpu-1gb","region":{"slug":"fra1"},"networks":{"v4":[{"ip_address":"198.51.100.2","type":"public"}]}}`
		switch r.Method + " " + r.URL.Path {
		case "GET /account":
			io.WriteString(w, `{"account":{"email":"me@example.com","status":"active"}}`)
		case "GET /droplets":
			io.WriteString(w, `{"droplets":[`+d+`]}`)
		case "GET /droplets/9":
			io.WriteString(w, `{"droplet":`+d+`}`)
		case "POST /droplets/9/actions":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			switch b["type"] {
			case "shutdown":
				state = "off"
			case "power_on":
				state = "active"
			}
			w.WriteHeader(201)
			io.WriteString(w, `{"action":{"id":1}}`)
		case "GET /apps":
			io.WriteString(w, `{"apps":[{"id":"0b6f5c5e-1111-2222-3333-444455556666","spec":{"name":"site"},"active_deployment":{"phase":"ACTIVE"}}]}`)
		case "POST /apps/0b6f5c5e-1111-2222-3333-444455556666/deployments":
			deployed = true
			io.WriteString(w, `{"deployment":{"id":"d1","phase":"PENDING_BUILD"}}`)
		case "GET /customers/my/balance":
			io.WriteString(w, `{"month_to_date_usage":"3.20","account_balance":"0.00"}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"id":"not_found","message":"The resource you were accessing could not be found."}`)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	host := fakehost.New(map[string]string{"secret://do": "tok"})
	if err := m.Configure(ctx, host, "d", json.RawMessage(`{"token":"dop_v1_plain"}`)); err == nil {
		t.Fatal("plaintext token accepted")
	}
	cfg, _ := json.Marshal(Config{Token: "secret://do", API: srv.URL})
	if err := m.Configure(ctx, host, "d", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "d"); h.Status != "ok" {
		t.Fatalf("health %+v", h)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: "droplets"})
	if err != nil || !strings.Contains(string(r.Output), "198.51.100.2") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = m.Invoke(ctx, sdk.Call{Instance: "d", Action: "shutdown", Input: json.RawMessage(`{"droplet":9}`)})
	if err != nil || state != "off" || r.Undo == nil {
		t.Fatalf("shutdown %v", err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: r.Undo.Action, Input: r.Undo.Input}); err != nil || state != "active" {
		t.Fatal("undo")
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: "redeploy", Input: json.RawMessage(`{"app":"../../account"}`)}); err == nil {
		t.Fatal("path injection accepted")
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: "redeploy", Input: json.RawMessage(`{"app":"0b6f5c5e-1111-2222-3333-444455556666"}`)}); err != nil || !deployed {
		t.Fatalf("redeploy %v", err)
	}
	if r, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: "balance"}); err != nil || !strings.Contains(string(r.Output), "3.20") {
		t.Fatal("balance")
	}
}
