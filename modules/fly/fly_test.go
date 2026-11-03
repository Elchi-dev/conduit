package fly

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

func TestFly(t *testing.T) {
	var mu sync.Mutex
	st := "started"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "FlyV1 fm2_tok" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"unauthorized"}`)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		mc := `{"id":"3d8d9ab1","name":"web","state":"` + st + `","region":"fra","image_ref":{"repository":"library/app","tag":"v2"}}`
		switch r.Method + " " + r.URL.Path {
		case "GET /apps":
			if r.URL.Query().Get("org_slug") != "personal" {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"apps":[{"name":"shop","machine_count":2}]}`)
		case "GET /apps/shop/machines":
			io.WriteString(w, `[`+mc+`]`)
		case "GET /apps/shop/machines/3d8d9ab1":
			io.WriteString(w, mc)
		case "POST /apps/shop/machines/3d8d9ab1/stop":
			st = "stopped"
			io.WriteString(w, `{"ok":true}`)
		case "POST /apps/shop/machines/3d8d9ab1/start":
			st = "started"
			io.WriteString(w, `{"ok":true}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"not found"}`)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	host := fakehost.New(map[string]string{"secret://fly": "FlyV1 fm2_tok\n"})
	cfg, _ := json.Marshal(Config{Token: "secret://fly", API: srv.URL})
	if err := m.Configure(ctx, host, "f", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "f"); h.Status != "ok" || !strings.Contains(h.Message, "1 apps") {
		t.Fatalf("health %+v", h)
	}
	if r, err := m.Invoke(ctx, sdk.Call{Instance: "f", Action: "machines", Input: json.RawMessage(`{"app":"shop"}`)}); err != nil || !strings.Contains(string(r.Output), "library/app:v2") {
		t.Fatalf("machines %v", err)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "f", Action: "stop", Input: json.RawMessage(`{"app":"shop","machine":"3d8d9ab1"}`)})
	if err != nil || st != "stopped" || r.Undo == nil {
		t.Fatalf("stop %v", err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "f", Action: r.Undo.Action, Input: r.Undo.Input}); err != nil || st != "started" {
		t.Fatal("undo")
	}
	for _, in := range []string{`{"app":"../x","machine":"3d8d9ab1"}`, `{"app":"shop","machine":"../../apps"}`} {
		if _, err := m.Invoke(ctx, sdk.Call{Instance: "f", Action: "restart", Input: json.RawMessage(in)}); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
}
