package core

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

type secretUser struct{ host sdk.Host }

func (s *secretUser) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "remote", Name: "Remote", Version: "0.1.0", Actions: []sdk.ActionSpec{{Name: "whoami", Risk: sdk.RiskRead}}}
}
func (s *secretUser) Configure(_ context.Context, h sdk.Host, _ string, _ json.RawMessage) error {
	s.host = h
	return nil
}
func (s *secretUser) Invoke(ctx context.Context, _ sdk.Call) (sdk.Result, error) {
	v, err := s.host.Secret(ctx, "secret://token")
	if err != nil {
		return sdk.Result{}, err
	}
	s.host.Publish(ctx, sdk.Event{Type: "remote.used"})
	b, _ := json.Marshal(len(v))
	return sdk.Result{Output: b}, nil
}
func (s *secretUser) Health(context.Context, string) sdk.Health { return sdk.Health{Status: "ok"} }
func (s *secretUser) Close(string) error                        { return nil }

type staticSecrets map[string]string

func (s staticSecrets) Resolve(_ context.Context, ref string) (string, error) { return s[ref], nil }

func TestExternalModuleRoundTrip(t *testing.T) {
	ctx := context.Background()
	// daemon <-> module over two pipes
	dr, mw := io.Pipe()
	mr, dw := io.Pipe()
	go sdk.Serve(&secretUser{}, mr, mw)

	x, err := ConnectExternal(ctx, dr, dw)
	if err != nil {
		t.Fatal(err)
	}
	if x.Manifest().ID != "remote" {
		t.Fatalf("manifest id = %q", x.Manifest().ID)
	}

	st, _ := OpenStore(ctx, t.TempDir()+"/x.db")
	defer st.Close()
	e := NewEngine(st, nil)
	e.SetSecrets(staticSecrets{"secret://token": "hunter2"})
	if err := e.Register(x); err != nil {
		t.Fatal(err)
	}
	events, stop := e.Bus.Subscribe("remote.", 4)
	defer stop()
	in, err := e.SaveInstance(ctx, Instance{Module: "remote", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.Invoke(ctx, user, sdk.Call{Instance: in.ID, Action: "whoami"}, InvokeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Result.Output) != "7" {
		t.Fatalf("output = %s, want 7 (len of secret)", out.Result.Output)
	}
	select {
	case ev := <-events:
		if ev.Module != "remote" || ev.Instance != in.ID {
			t.Fatalf("event not attributed: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event not delivered")
	}
	if h := e.Health(ctx, in.ID); h.Status != "ok" {
		t.Fatalf("health = %+v", h)
	}
}
