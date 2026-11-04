package restic

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const repo = "sftp:backup@nas:/srv/restic"

// setup installs the fake restic from testdata (a shell script) and
// configures an instance with it; $HOME is a fresh directory where the
// script logs its arguments and environment.
func setup(t *testing.T, cfg Config) (*Module, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake restic is a shell script")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CONDUIT_LEAKY", "should-not-reach-restic")
	src, err := os.ReadFile("testdata/restic")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "restic")
	if err := os.WriteFile(bin, src, 0o755); err != nil {
		t.Fatal(err)
	}
	if cfg.Binary == "" {
		cfg.Binary = bin
	}
	if cfg.Repository == "" {
		cfg.Repository = repo
	}
	if cfg.Password == "" {
		cfg.Password = "secret://pw"
	}
	m := New()
	m.now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(cfg)
	h := fakehost.New(map[string]string{"secret://pw": "s3cr3t-pass\n", "secret://bad": "wrong", "secret://aws": "AWS-LEAKME-SECRET"})
	if err := m.Configure(context.Background(), h, "r", raw); err != nil {
		t.Fatal(err)
	}
	return m, home
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "r", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func read(t *testing.T, path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func TestRestic(t *testing.T) {
	m, home := setup(t, Config{Env: map[string]string{"AWS_SECRET_ACCESS_KEY": "secret://aws", "AWS_DEFAULT_REGION": "eu-central-1"}, WarnAfterHours: 48})
	if h := m.Health(context.Background(), "r"); h.Status != "ok" || h.Message != "3 snapshots, newest 2026-11-03 02:00 (nas)" {
		t.Fatalf("%+v", h)
	}
	// The password and repository go through the environment, never the
	// arguments, and nothing else of Conduit's environment does.
	env := read(t, filepath.Join(home, "env.log"))
	if !strings.Contains(env, "RESTIC_PASSWORD=s3cr3t-pass\n") || !strings.Contains(env, "RESTIC_REPOSITORY="+repo) ||
		!strings.Contains(env, "AWS_SECRET_ACCESS_KEY=AWS-LEAKME-SECRET") || !strings.Contains(env, "AWS_DEFAULT_REGION=eu-central-1") || strings.Contains(env, "CONDUIT_LEAKY") {
		t.Fatal(env)
	}

	for _, c := range []struct{ action, in, want string }{
		{"snapshots", `{}`, `"total":3`},
		{"snapshots", `{}`, `"bytesAdded":2048`},
		{"snapshots", `{"limit":1}`, `"id":"11111111"`},
		{"snapshots", `{"host":"web"}`, `"id":"33333333"`},
		{"stats", `{}`, `"bytes":123456`},
		{"stats", `{"mode":"restore-size","snapshot":"latest"}`, `"mode":"restore-size"`},
		{"check", `{}`, `"ok":true`},
		{"check", `{"readData":"2.5%"}`, `"summary":"check all packs; check snapshots, trees and blobs; no errors were found"`},
		{"forget", `{"keepDaily":7}`, `"forgotten":["22222222"]`},
		{"forget", `{"ids":["33333333"]}`, `"forgotten":["33333333"]`},
		{"prune", `{}`, `"to delete":"34 blobs / 12.3 MiB"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "snapshots", `{"limit":1}`, false); strings.Contains(string(r.Output), "22222222") {
		t.Fatal(string(r.Output))
	}
	args := read(t, filepath.Join(home, "args.log"))
	for _, want := range []string{"snapshots --json --no-lock --host=web", "stats --json --no-lock --mode=restore-size latest", "check --read-data-subset=2.5%",
		"forget --json --keep-daily=7", "forget 3333333333cccccccccc3333333333cccccccccc3333333333cccccccccc3333", "prune"} {
		if !strings.Contains(args, want+"\n") {
			t.Fatalf("missing %q in\n%s", want, args)
		}
	}
	if strings.Contains(args, "s3cr3t") || strings.Contains(args, "LEAKME") || strings.Contains(args, "nas:/srv") {
		t.Fatal("a secret or the repository in the arguments:\n" + args)
	}

	// Previews run restic with --dry-run and list what would go.
	before := read(t, filepath.Join(home, "args.log"))
	r, err := invoke(m, "forget", `{"keepDaily":7,"host":"nas"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Forget 1 snapshots, keeping 2" || len(r.Plan.Changes) != 1 || !strings.Contains(r.Plan.Changes[0].Target, "22222222 (nas:/home, 2026-11-02 02:00)") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "forget", `{"ids":["2222222222"]}`, true); err != nil || r.Plan == nil || r.Plan.Summary != "Forget 1 of 3 snapshots" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "prune", `{}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Prune unused data from the repository: delete 34 blobs / 12.3 MiB" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	added := strings.TrimPrefix(read(t, filepath.Join(home, "args.log")), before)
	if added != "forget --json --keep-daily=7 --host=nas --dry-run\nsnapshots --json --no-lock\nprune --dry-run\n" {
		t.Fatalf("previews ran:\n%s", added)
	}

	// A check that finds errors is reported, not failed.
	os.WriteFile(filepath.Join(home, "broken"), nil, 0o600)
	if r, err := invoke(m, "check", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"ok":false`) || !strings.Contains(string(r.Output), "repository contains errors") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "forget", `{"ids":["99999999"]}`, false); err == nil || !strings.Contains(err.Error(), "no snapshot") {
		t.Fatal(err)
	}

	for _, a := range m.Manifest().Actions {
		want := map[string]sdk.Risk{"snapshots": sdk.RiskRead, "stats": sdk.RiskRead, "check": sdk.RiskWrite, "forget": sdk.RiskDestructive, "prune": sdk.RiskDestructive}[a.Name]
		if a.Risk != want || (want == sdk.RiskDestructive) != a.DryRun {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestResticHealth(t *testing.T) {
	m, _ := setup(t, Config{Password: "secret://bad"})
	if h := m.Health(context.Background(), "r"); h.Status != "down" || h.Message != "restic refused the repository password" {
		t.Fatalf("%+v", h)
	}
	m, _ = setup(t, Config{Repository: "/srv/elsewhere"})
	if h := m.Health(context.Background(), "r"); h.Status != "down" || !strings.Contains(h.Message, "no restic repository") {
		t.Fatalf("%+v", h)
	}
	m, _ = setup(t, Config{Binary: "/nonexistent/restic"})
	if h := m.Health(context.Background(), "r"); h.Status != "down" || h.Message != "restic isn't installed at /nonexistent/restic" {
		t.Fatalf("%+v", h)
	}
	m, _ = setup(t, Config{WarnAfterHours: 12})
	if h := m.Health(context.Background(), "r"); h.Status != "degraded" || !strings.HasPrefix(h.Message, "newest snapshot is 34 hours old") {
		t.Fatalf("%+v", h)
	}
}

func TestResticLimits(t *testing.T) {
	m, home := setup(t, Config{})
	defer func(d, w time.Duration, n int) { readTimeout, waitDelay, maxStdout = d, w, n }(readTimeout, waitDelay, maxStdout)
	readTimeout, waitDelay = 300*time.Millisecond, 200*time.Millisecond
	os.WriteFile(filepath.Join(home, "slow"), nil, 0o600)
	start := time.Now()
	if _, err := invoke(m, "snapshots", `{}`, false); err == nil || !strings.Contains(err.Error(), "didn't finish") || time.Since(start) > 4*time.Second {
		t.Fatal(err, time.Since(start))
	}
	os.Remove(filepath.Join(home, "slow"))
	maxStdout = 64 << 10
	os.WriteFile(filepath.Join(home, "big"), nil, 0o600)
	if _, err := invoke(m, "snapshots", `{}`, false); err == nil || !strings.Contains(err.Error(), "printed more than") {
		t.Fatal(err)
	}
}

func TestResticValidation(t *testing.T) {
	m, home := setup(t, Config{})
	for _, c := range []struct{ action, in string }{
		{"snapshots", `{"host":"--password-command=sh"}`},
		{"snapshots", `{"tag":"a,b c"}`},
		{"snapshots", `{"path":"relative/dir"}`},
		{"snapshots", `{"limit":5000}`},
		{"stats", `{"mode":"blobs-per-file"}`},
		{"stats", `{"snapshot":"--help"}`},
		{"check", `{"readData":"50%"}`},
		{"check", `{"readData":"1/2"}`},
		{"check", `{"readData":"--read-data"}`},
		{"forget", `{}`},
		{"forget", `{"keepDaily":-1}`},
		{"forget", `{"keepWithin":"forever"}`},
		{"forget", `{"keepTags":["--prune"]}`},
		{"forget", `{"ids":["--prune"]}`},
		{"forget", `{"ids":["11111111"],"keepLast":1}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "args.log")); err == nil {
		t.Fatalf("invalid input reached restic:\n%s", read(t, filepath.Join(home, "args.log")))
	}
	for _, c := range []Config{
		{Repository: repo, Password: "plain-password"},
		{Repository: "", Password: "secret://pw"},
		{Repository: "rest:https://user:hunter2@host:8000/", Password: "secret://pw"},
		{Repository: repo, Password: "secret://pw", Env: map[string]string{"LD_PRELOAD": "/tmp/x.so"}},
		{Repository: repo, Password: "secret://pw", Env: map[string]string{"RESTIC_PASSWORD_COMMAND": "cat /etc/shadow"}},
		{Repository: repo, Password: "secret://pw", Env: map[string]string{"B2_ACCOUNT_KEY": "plain-key"}},
		{Repository: repo, Password: "secret://pw", Binary: "restic"},
		{Repository: repo, Password: "secret://pw", TimeoutMinutes: 5000},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	// rest: with a user but no password in the address is fine.
	raw, _ := json.Marshal(Config{Repository: "rest:https://user@host:8000/", Password: "secret://pw"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
		t.Fatal(err)
	}
}
