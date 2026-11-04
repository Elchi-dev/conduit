package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type flaky struct {
	mu     sync.Mutex
	status string
}

func (f *flaky) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "flaky", Name: "Flaky", Version: "1.0.0", Actions: []sdk.ActionSpec{{Name: "x", Risk: sdk.RiskRead}}}
}
func (f *flaky) Configure(context.Context, sdk.Host, string, json.RawMessage) error { return nil }
func (f *flaky) Invoke(context.Context, sdk.Call) (sdk.Result, error)               { return sdk.Result{}, nil }
func (f *flaky) Close(string) error                                                 { return nil }
func (f *flaky) Health(context.Context, string) sdk.Health {
	f.mu.Lock()
	defer f.mu.Unlock()
	return sdk.Health{Status: f.status}
}

func TestAmbientStates(t *testing.T) {
	app, c, _, _ := setup(t)
	ctx := context.Background()
	f := &flaky{status: "ok"}
	if err := app.Engine.Register(f); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Engine.SaveInstance(ctx, core.Instance{ID: "web1", Module: "flaky", Name: "Web 1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	a := app.ambient()
	if st := a.compute(ctx); st.State != "ok" || st.Summary != "All good" {
		t.Fatalf("ok: %+v", st)
	}
	f.mu.Lock()
	f.status = "degraded"
	f.mu.Unlock()
	if st := a.compute(ctx); st.State != "attention" || st.Summary != "1 connection needs a look" {
		t.Fatalf("attention: %+v", st)
	}
	f.mu.Lock()
	f.status = "down"
	f.mu.Unlock()
	if st := a.compute(ctx); st.State != "down" || st.Summary != "Down: Web 1" {
		t.Fatalf("down: %+v", st)
	}
	if err := app.Engine.Policy.SetFrozen(ctx, true); err != nil {
		t.Fatal(err)
	}
	if st := a.compute(ctx); st.State != "stopped" {
		t.Fatalf("stopped: %+v", st)
	}

	var got Ambient
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
	}))
	defer hook.Close()
	cfg, _ := json.Marshal(map[string]string{"webhook": hook.URL})
	if err := a.Configure(ctx, nil, ambientID, cfg); err != nil {
		t.Fatal(err)
	}
	st := a.compute(ctx)
	st.Color = ambientColors[st.State]
	if p := a.push(ctx, st, systemActor); len(p) != 0 || got.State != "stopped" || got.Color != "purple" {
		t.Fatalf("push %v %+v", p, got)
	}

	var api Ambient
	if code := c.do("GET", "/api/v1/ambient", nil, &api); code != 200 || api.State == "" {
		t.Fatalf("api %d %+v", code, api)
	}
	if err := a.Configure(ctx, nil, ambientID, json.RawMessage(`{"light":{"instance":"ha"}}`)); err == nil {
		t.Fatal("half a light config accepted")
	}
}
