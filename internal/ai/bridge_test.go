package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// TestBridgeMountsAnMCPServer mounts one Conduit's MCP endpoint into another
// Conduit and checks tools become actions with the right risk.
func TestBridgeMountsAnMCPServer(t *testing.T) {
	_, remoteTB, _, l := setup(t)
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", 401)
			return
		}
		HandleMCP(w, r, remoteTB)
	}))
	defer remote.Close()

	ctx := context.Background()
	st, _ := core.OpenStore(ctx, t.TempDir()+"/local.db")
	defer st.Close()
	local := core.NewEngine(st, nil)
	b := &Bridge{DB: st.DB, Engine: local, Secrets: secrets{"secret://remote": "Bearer tok"}}

	if _, err := b.Save(ctx, MCPServer{Name: "Remote", Transport: "http", URL: remote.URL, Headers: map[string]string{"Authorization": "Bearer plaintext"}}); err == nil {
		t.Fatal("plaintext credential header accepted")
	}
	srv, err := b.Save(ctx, MCPServer{Name: "Remote", Transport: "http", URL: "http://127.0.0.1" + strings.TrimPrefix(remote.URL, "http://127.0.0.1"), Headers: map[string]string{"Authorization": "secret://remote"}})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := local.Module(srv.ModuleID())
	if !ok {
		t.Fatal("not mounted")
	}
	risks := map[string]sdk.Risk{}
	for _, a := range m.Manifest().Actions {
		risks[a.Name] = a.Risk
	}
	if risks["lamp__status"] != sdk.RiskRead || risks["lamp__toggle"] != sdk.RiskWrite || risks["conduit_emergency_stop"] != "" && risks["conduit_emergency_stop"] != sdk.RiskDestructive {
		t.Fatalf("risks = %v", risks)
	}
	if h := local.Health(ctx, srv.ModuleID()); h.Status != "ok" {
		t.Fatalf("health = %+v", h)
	}
	// A person calling through the local Conduit reaches the remote one, whose
	// own agent rules then ask for approval.
	out, err := local.Invoke(ctx, core.Actor{ID: "u", Kind: core.ActorUser}, sdk.Call{Instance: srv.ModuleID(), Action: "lamp__status"}, core.InvokeOptions{})
	if err != nil || !strings.Contains(string(out.Result.Output), "on") {
		t.Fatalf("call: %s %v", out.Result.Output, err)
	}
	out, _ = local.Invoke(ctx, core.Actor{ID: "u", Kind: core.ActorUser}, sdk.Call{Instance: srv.ModuleID(), Action: "lamp__toggle", Input: json.RawMessage(`{}`)}, core.InvokeOptions{})
	if l.on {
		t.Fatal("remote rules bypassed")
	}
	if err := b.Delete(ctx, srv.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := local.Module(srv.ModuleID()); ok {
		t.Fatal("still mounted after delete")
	}
}
