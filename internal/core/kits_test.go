package core

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// The starter kits in sdk/external must speak the protocol the engine
// expects. These tests run them as real external modules.

func kitModule(t *testing.T, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shebang scripts")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func exercise(t *testing.T, path string) {
	t.Helper()
	ctx := context.Background()
	x, err := StartExternal(ctx, path, nil, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Stop()
	if x.Manifest().ID != "echo" {
		t.Fatalf("manifest %+v", x.Manifest())
	}
	if err := x.Configure(ctx, fakehost.New(map[string]string{"secret://k": "abcdef"}), "e", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	r, err := x.Invoke(ctx, sdk.Call{Instance: "e", Action: "echo", Input: json.RawMessage(`{"x":1}`)})
	if err != nil || string(r.Output) != `{"x":1}` {
		t.Fatalf("echo %v %s", err, r.Output)
	}
	r, err = x.Invoke(ctx, sdk.Call{Instance: "e", Action: "secret"})
	if err != nil || string(r.Output) != "6" {
		t.Fatalf("secret %v %s", err, r.Output)
	}
	if _, err := x.Invoke(ctx, sdk.Call{Instance: "e", Action: "fail"}); err == nil {
		t.Fatal("a failing action must fail")
	}
}

func TestPythonKit(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	kit, _ := filepath.Abs("../../sdk/external/python")
	exercise(t, kitModule(t, "echo.py", "#!"+py+`
import sys
sys.path.insert(0, "`+kit+`")
from conduit_module import Module, ActionError, run
class Echo(Module):
    manifest = {"id": "echo", "name": "Echo", "version": "1.0.0", "actions": [{"name": "echo", "risk": "read"}, {"name": "secret", "risk": "read"}, {"name": "fail", "risk": "read"}]}
    def configure(self, host, instance, config):
        self.host = host
    def invoke(self, instance, action, input, dry_run):
        if action == "secret":
            return {"output": len(self.host.secret("secret://k"))}
        if action == "fail":
            raise ActionError("nope")
        return {"output": input}
run(Echo())
`))
}

func TestTypeScriptKit(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node")
	}
	kit, _ := filepath.Abs("../../sdk/external/typescript/conduit-module.ts")
	dir := t.TempDir()
	mod := filepath.Join(dir, "echo.ts")
	os.WriteFile(mod, []byte(`import { serve, ActionError } from "`+kit+`";
let host;
serve({
  manifest: { id: "echo", name: "Echo", version: "1.0.0", actions: [{ name: "echo", risk: "read" }, { name: "secret", risk: "read" }, { name: "fail", risk: "read" }] },
  configure(h) { host = h; },
  async invoke(_i, action, input) {
    if (action === "secret") return { output: (await host.secret("secret://k")).length };
    if (action === "fail") throw new ActionError("nope");
    return { output: input };
  },
});
`), 0o644)
	exercise(t, kitModule(t, "echo", "#!/bin/sh\nexec "+node+" --experimental-strip-types --no-warnings "+mod+"\n"))
}
