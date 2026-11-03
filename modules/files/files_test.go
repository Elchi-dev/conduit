package files

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/modules/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestFoldersAndJobs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), make([]byte, 1000), 0o644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("hi"), 0o644)
	out := filepath.Join(t.TempDir(), "ran")

	host := fakehost.New(map[string]string{"secret://k": "s3cr3t"})
	m := New()
	ctx := context.Background()
	cfg, _ := json.Marshal(Config{
		Folders: []Folder{{Name: "Docs", Path: dir, MinFreeG: 1e9}},
		Jobs: []Job{
			{Name: "ok", Kind: "command", Command: []string{"sh", "-c", `echo "$TOKEN" > ` + out}, Env: map[string]string{"TOKEN": "secret://k"}, MaxAgeHours: 24},
			{Name: "bad", Kind: "command", Command: []string{"sh", "-c", "echo boom >&2; exit 3"}},
		},
	})
	if err := m.Configure(ctx, host, "f", cfg); err != nil {
		t.Fatal(err)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "f", Action: "folders"})
	if err != nil {
		t.Fatal(err)
	}
	var fs []FolderStatus
	json.Unmarshal(r.Output, &fs)
	if fs[0].Files != 2 || !strings.Contains(fs[0].Warning, "free") {
		t.Fatalf("folders %+v", fs)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "f", Action: "run_job", Input: json.RawMessage(`{"name":"ok"}`)}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); strings.TrimSpace(string(b)) != "s3cr3t" {
		t.Fatalf("env secret not passed: %q", b)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "f", Action: "run_job", Input: json.RawMessage(`{"name":"bad"}`)}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("failing job: %v", err)
	}
	if h := m.Health(ctx, "f"); h.Status != "degraded" || !strings.Contains(h.Message, "bad failed") {
		t.Fatalf("health %+v", h)
	}
	evs := host.Events()
	if len(evs) != 2 || evs[0].Type != "files.backup_ok" || evs[1].Type != "files.backup_failed" {
		t.Fatalf("events %+v", evs)
	}
	if err := m.Configure(ctx, host, "x", json.RawMessage(`{"jobs":[{"name":"r","kind":"restic"}]}`)); err == nil {
		t.Fatal("incomplete restic job accepted")
	}
}
