package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// keystore is a test module with sensitive writes: create undoes through a
// non-sensitive delete, replace (wrongly) offers an undo that replays the
// old value through itself.
type keystore struct {
	mu sync.Mutex
	kv map[string]string
}

func (k *keystore) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "keystore", Name: "Keys", Version: "1.0.0", Actions: []sdk.ActionSpec{
		{Name: "create", Risk: sdk.RiskWrite, Reversible: true, Sensitive: true},
		{Name: "replace", Risk: sdk.RiskDestructive, Reversible: true, Sensitive: true},
		{Name: "delete", Risk: sdk.RiskDestructive},
	}}
}

func (k *keystore) Configure(context.Context, sdk.Host, string, json.RawMessage) error { return nil }
func (k *keystore) Health(context.Context, string) sdk.Health                          { return sdk.Health{Status: "ok"} }
func (k *keystore) Close(string) error                                                 { return nil }

func (k *keystore) Invoke(_ context.Context, call sdk.Call) (sdk.Result, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var in struct{ Key, Value string }
	_ = json.Unmarshal(call.Input, &in)
	switch call.Action {
	case "create":
		k.kv[in.Key] = in.Value
		return sdk.Result{Output: json.RawMessage(`{"name":"` + in.Key + `"}`), Undo: sdk.UndoWith("delete", map[string]string{"key": in.Key}, "Delete "+in.Key)}, nil
	case "replace":
		old := k.kv[in.Key]
		k.kv[in.Key] = in.Value
		return sdk.Result{Undo: sdk.UndoWith("replace", map[string]string{"key": in.Key, "value": old}, "Put back")}, nil
	case "delete":
		delete(k.kv, in.Key)
		return sdk.Result{}, nil
	}
	return sdk.Result{}, errors.New("unknown action")
}

func TestSensitiveUndoKeptOnlyWithoutSecrets(t *testing.T) {
	e, _, _ := newTestEngine(t)
	ctx := context.Background()
	k := &keystore{kv: map[string]string{}}
	if err := e.Register(k); err != nil {
		t.Fatal(err)
	}
	in, err := e.SaveInstance(ctx, Instance{Module: "keystore", Name: "k", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	call := func(action, input string) Outcome {
		t.Helper()
		out, err := e.Invoke(ctx, user, sdk.Call{Instance: in.ID, Action: action, Input: json.RawMessage(input)}, InvokeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	noSecret := func(seq int64, secrets ...string) {
		t.Helper()
		ent, err := e.Audit.Get(ctx, seq)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(ent)
		for _, s := range secrets {
			if strings.Contains(string(b), s) {
				t.Fatalf("audit entry %d holds %q: %s", seq, s, b)
			}
		}
	}

	// A sensitive create whose undo is a non-sensitive delete keeps it.
	out := call("create", `{"key":"db","value":"hunter2"}`)
	ent, _ := e.Audit.Get(ctx, out.Audit.Seq)
	if ent.Undo == nil || ent.Undo.Action != "delete" {
		t.Fatalf("undo dropped: %+v", ent)
	}
	noSecret(out.Audit.Seq, "hunter2")
	if _, err := e.Undo(ctx, user, out.Audit.Seq, InvokeOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.kv["db"]; ok {
		t.Fatal("undo didn't delete the key")
	}

	// An undo that replays a secret through a sensitive action is dropped.
	call("create", `{"key":"db","value":"first-s3cret"}`)
	out = call("replace", `{"key":"db","value":"second-s3cret"}`)
	if out.Result.Undo == nil {
		t.Fatal("module should have offered an undo")
	}
	ent, _ = e.Audit.Get(ctx, out.Audit.Seq)
	if ent.Undo != nil {
		t.Fatalf("an undo carrying the old value was kept: %+v", ent.Undo)
	}
	noSecret(out.Audit.Seq, "first-s3cret", "second-s3cret")
	if _, err := e.Undo(ctx, user, out.Audit.Seq, InvokeOptions{}); err == nil {
		t.Fatal("undid a sensitive replace")
	}
}
