package system

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestOverviewAndProcesses(t *testing.T) {
	m := &Module{}
	ctx := context.Background()
	if err := m.Configure(ctx, nil, InstanceID, json.RawMessage(`{"profiles":[{"name":"sleeper","command":"sleep","args":["30"]}]}`)); err != nil {
		t.Fatal(err)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "overview"})
	if err != nil || !strings.Contains(string(r.Output), `"cpus"`) {
		t.Fatalf("overview: %s %v", r.Output, err)
	}
	r, err = m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "processes", Input: json.RawMessage(`{"limit":5}`)})
	if err != nil {
		t.Fatal(err)
	}
	var ps []procInfo
	_ = json.Unmarshal(r.Output, &ps)
	if len(ps) == 0 || len(ps) > 5 {
		t.Fatalf("processes: %d", len(ps))
	}
	// Launch a profile, then undo it by killing the process.
	r, err = m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "launch", Input: json.RawMessage(`{"profile":"sleeper"}`)})
	if err != nil || r.Undo == nil {
		t.Fatalf("launch: %v", err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "kill", Input: r.Undo.Input}); err != nil {
		t.Fatalf("undo launch: %v", err)
	}
	self, _ := json.Marshal(map[string]int{"pid": os.Getpid()})
	if _, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "kill", Input: self}); err == nil {
		t.Fatal("killing the daemon itself must be refused")
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "launch", Input: json.RawMessage(`{"profile":"rm -rf /"}`)}); err == nil {
		t.Fatal("only saved profiles may launch")
	}
}
