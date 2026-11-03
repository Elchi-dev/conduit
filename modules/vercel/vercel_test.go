package vercel

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

func TestVercel(t *testing.T) {
	var mu sync.Mutex
	prod := "dpl_old"
	redeployed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Query().Get("teamId") != "team_abc" && r.URL.Path != "/v2/user" {
			w.WriteHeader(403)
			io.WriteString(w, `{"error":{"code":"forbidden","message":"Not authorized"}}`)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method + " " + r.URL.Path {
		case "GET /v2/user":
			io.WriteString(w, `{"user":{"username":"me"}}`)
		case "GET /v9/projects":
			io.WriteString(w, `{"projects":[{"id":"prj_1","name":"site","targets":{"production":{"id":"`+prod+`","url":"site.vercel.app"}}}]}`)
		case "GET /v9/projects/site", "GET /v9/projects/prj_1":
			io.WriteString(w, `{"id":"prj_1","name":"site","targets":{"production":{"id":"`+prod+`"}}}`)
		case "GET /v6/deployments":
			if r.URL.Query().Get("projectId") != "prj_1" {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"deployments":[{"uid":"dpl_new","name":"site","state":"READY","target":null}]}`)
		case "POST /v10/projects/prj_1/promote/dpl_new":
			prod = "dpl_new"
			w.WriteHeader(201)
		case "POST /v10/projects/prj_1/promote/dpl_old":
			prod = "dpl_old"
			w.WriteHeader(201)
		case "GET /v13/deployments/dpl_new":
			io.WriteString(w, `{"id":"dpl_new","name":"site"}`)
		case "POST /v13/deployments":
			var b map[string]any
			json.NewDecoder(r.Body).Decode(&b)
			redeployed = b["deploymentId"] == "dpl_new" && b["target"] == "production"
			io.WriteString(w, `{"id":"dpl_x","readyState":"QUEUED"}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"error":{"message":"not found"}}`)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	host := fakehost.New(map[string]string{"secret://v": "tok"})
	if err := m.Configure(ctx, host, "v", json.RawMessage(`{"token":"secret://v","teamId":"evil/../x"}`)); err == nil {
		t.Fatal("bad team id accepted")
	}
	cfg, _ := json.Marshal(Config{Token: "secret://v", TeamID: "team_abc", API: srv.URL})
	if err := m.Configure(ctx, host, "v", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "v"); h.Status != "ok" {
		t.Fatalf("health %+v", h)
	}
	if r, err := m.Invoke(ctx, sdk.Call{Instance: "v", Action: "deployments", Input: json.RawMessage(`{"project":"site"}`)}); err != nil || !strings.Contains(string(r.Output), "dpl_new") {
		t.Fatalf("deployments %v", err)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "v", Action: "promote", Input: json.RawMessage(`{"project":"site","deployment":"dpl_new"}`)})
	if err != nil || prod != "dpl_new" || r.Undo == nil {
		t.Fatalf("promote %v", err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "v", Action: r.Undo.Action, Input: r.Undo.Input}); err != nil || prod != "dpl_old" {
		t.Fatalf("undo %v %s", err, prod)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "v", Action: "redeploy", Input: json.RawMessage(`{"deployment":"dpl_new","production":true}`)}); err != nil || !redeployed {
		t.Fatalf("redeploy %v", err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "v", Action: "cancel", Input: json.RawMessage(`{"deployment":"../v2/user"}`)}); err == nil {
		t.Fatal("path injection accepted")
	}
}
