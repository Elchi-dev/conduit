package notes

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestNotes(t *testing.T) {
	dir := t.TempDir()
	m := New(dir)
	ctx := context.Background()
	if err := m.Configure(ctx, nil, InstanceID, nil); err != nil {
		t.Fatal(err)
	}
	do := func(action string, in any) (sdk.Result, error) {
		b, _ := json.Marshal(in)
		return m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: action, Input: b})
	}
	must := func(action string, in any) sdk.Result {
		r, err := do(action, in)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return r
	}
	undo := func(r sdk.Result) {
		if _, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: r.Undo.Action, Input: r.Undo.Input}); err != nil {
			t.Fatal(err)
		}
	}
	created := must("write", map[string]string{"name": "runbooks/db", "content": "# DB failover\nPromote the replica.\n"})
	appended := must("append", map[string]string{"name": "runbooks/db", "text": "Then update DNS."})
	b, _ := os.ReadFile(filepath.Join(dir, "runbooks", "db.md"))
	if !strings.HasSuffix(string(b), "replica.\nThen update DNS.\n") {
		t.Fatalf("content %q", b)
	}
	undo(appended)
	b, _ = os.ReadFile(filepath.Join(dir, "runbooks", "db.md"))
	if strings.Contains(string(b), "DNS") {
		t.Fatal("undo of append must restore")
	}
	var list []Note
	json.Unmarshal(must("list", nil).Output, &list)
	if len(list) != 1 || list[0].Title != "DB failover" {
		t.Fatalf("list %+v", list)
	}
	if !strings.Contains(string(must("search", map[string]string{"query": "replica"}).Output), "Promote the replica") {
		t.Fatal("search")
	}
	deleted := must("delete", map[string]string{"name": "runbooks/db"})
	undo(deleted)
	if _, err := os.Stat(filepath.Join(dir, "runbooks", "db.md")); err != nil {
		t.Fatal("undo of delete must bring it back")
	}
	undo(created)
	if _, err := os.Stat(filepath.Join(dir, "runbooks", "db.md")); !os.IsNotExist(err) {
		t.Fatal("undo of create must remove it")
	}
	for _, bad := range []string{"../escape", "/etc/passwd", "a/../../b", ".hidden", ""} {
		if _, err := do("write", map[string]string{"name": bad, "content": "x"}); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
}
