// Package files watches folders and runs backup jobs (restic, rsync or any
// command), and warns when space runs low or a backup is overdue.
package files

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/disk"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Folder is a watched folder.
type Folder struct {
	Name     string  `json:"name"`
	Path     string  `json:"path"`
	MinFreeG float64 `json:"minFreeGB"` // warn below this much free space
}

// Job is a backup job.
type Job struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // restic, rsync, command
	// restic
	Repo     string   `json:"repo"`
	Password string   `json:"password"` // secret://
	Paths    []string `json:"paths"`
	// rsync: Paths are sources, Target the destination
	Target string `json:"target"`
	// command: argv, no shell
	Command []string `json:"command"`
	// Env adds environment variables; values may be secret:// references
	// (cloud storage keys for restic, say).
	Env map[string]string `json:"env"`
	// MaxAgeHours marks the job overdue when its last success is older.
	MaxAgeHours float64 `json:"maxAgeHours"`
}

// Config is one instance's settings.
type Config struct {
	Folders []Folder `json:"folders"`
	Jobs    []Job    `json:"jobs"`
}

type runInfo struct {
	At       time.Time `json:"at"`
	OK       bool      `json:"ok"`
	Duration string    `json:"duration"`
	Output   string    `json:"output"`
}

type instance struct {
	cfg  Config
	host sdk.Host
	mu   sync.Mutex
	runs map[string]runInfo // last run per job
	busy map[string]bool
}

// Module implements sdk.Module.
type Module struct {
	mu   sync.Mutex
	inst map[string]*instance
}

// New returns the files module.
func New() *Module { return &Module{inst: map[string]*instance{}} }

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "files", Name: "Files and backups", Version: "0.1.0", Category: "Storage", Icon: "folder",
		Description: "Watched folders with free space, and backup jobs with restic, rsync or your own command.",
		Presets:     []string{"homelab", "team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"folders":{"type":"array","items":{"type":"object","required":["name","path"],"properties":{
				"name":{"type":"string"},"path":{"type":"string"},"minFreeGB":{"type":"number","description":"Warn when the drive has less free space"}}}},
			"jobs":{"type":"array","items":{"type":"object","required":["name","kind"],"properties":{
				"name":{"type":"string"},
				"kind":{"type":"string","enum":["restic","rsync","command"]},
				"repo":{"type":"string","description":"restic repository, e.g. /mnt/backup or s3:s3.amazonaws.com/bucket"},
				"password":{"type":"string","x-secret":true,"description":"restic repository password"},
				"paths":{"type":"array","items":{"type":"string"},"description":"What to back up"},
				"target":{"type":"string","description":"rsync destination, e.g. nas:/backups/laptop"},
				"command":{"type":"array","items":{"type":"string"},"description":"Program and arguments (no shell)"},
				"env":{"type":"object","additionalProperties":{"type":"string"},"description":"Extra environment; values can be vault references"},
				"maxAgeHours":{"type":"number","description":"Overdue when the last success is older"}}}}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "folders", Title: "Folders", Description: "Size, file count, latest change and free space.", Risk: sdk.RiskRead},
			{Name: "jobs", Title: "Backup jobs", Description: "Last run and whether it's overdue.", Risk: sdk.RiskRead},
			{Name: "run_job", Title: "Run a backup now", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}`)},
			{Name: "snapshots", Title: "Snapshots", Description: "A restic job's snapshots.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}`)},
		},
		Events: []sdk.EventSpec{{Type: "files.backup_ok", Description: "A backup job finished"}, {Type: "files.backup_failed", Description: "A backup job failed"}},
	}
}

var envKey = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if len(c.Folders) == 0 && len(c.Jobs) == 0 {
		return errors.New("add a folder to watch or a backup job")
	}
	names := map[string]bool{}
	for _, f := range c.Folders {
		if f.Name == "" || !filepath.IsAbs(f.Path) {
			return fmt.Errorf("folder %q needs a name and a full path", f.Name)
		}
	}
	for _, j := range c.Jobs {
		if j.Name == "" || names[j.Name] {
			return fmt.Errorf("each job needs a unique name (%q)", j.Name)
		}
		names[j.Name] = true
		switch j.Kind {
		case "restic":
			if j.Repo == "" || len(j.Paths) == 0 || j.Password == "" {
				return fmt.Errorf("restic job %s needs a repository, a password and paths", j.Name)
			}
		case "rsync":
			if j.Target == "" || len(j.Paths) == 0 {
				return fmt.Errorf("rsync job %s needs paths and a target", j.Name)
			}
		case "command":
			if len(j.Command) == 0 {
				return fmt.Errorf("job %s needs a command", j.Name)
			}
		default:
			return fmt.Errorf("job %s: kind must be restic, rsync or command", j.Name)
		}
		for k := range j.Env {
			if !envKey.MatchString(k) {
				return fmt.Errorf("job %s: %q isn't an environment variable name", j.Name, k)
			}
		}
	}
	m.mu.Lock()
	old := m.inst[id]
	in := &instance{cfg: c, host: h, runs: map[string]runInfo{}, busy: map[string]bool{}}
	if old != nil {
		old.mu.Lock()
		for k, v := range old.runs {
			in.runs[k] = v
		}
		old.mu.Unlock()
	}
	m.inst[id] = in
	m.mu.Unlock()
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error {
	m.mu.Lock()
	delete(m.inst, id)
	m.mu.Unlock()
	return nil
}

func (m *Module) get(id string) (*instance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if in := m.inst[id]; in != nil {
		return in, nil
	}
	return nil, errors.New("this instance isn't set up")
}

// FolderStatus is a folders row.
type FolderStatus struct {
	Name     string  `json:"name"`
	Path     string  `json:"path"`
	SizeGB   float64 `json:"sizeGB"`
	Files    int     `json:"files"`
	Changed  string  `json:"changed,omitempty"`
	FreeGB   float64 `json:"freeGB"`
	UsedPct  float64 `json:"usedPercent"`
	Warning  string  `json:"warning,omitempty"`
	Unusable string  `json:"error,omitempty"`
}

func round(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

func folderStatus(ctx context.Context, f Folder) FolderStatus {
	st := FolderStatus{Name: f.Name, Path: f.Path}
	if _, err := os.Stat(f.Path); err != nil {
		st.Unusable = "missing or unreadable"
		return st
	}
	var size int64
	var latest time.Time
	deadline := time.Now().Add(5 * time.Second)
	_ = filepath.WalkDir(f.Path, func(_ string, e fs.DirEntry, err error) error {
		if err != nil || ctx.Err() != nil {
			return nil
		}
		if time.Now().After(deadline) {
			st.Warning = "very large; counts are partial"
			return filepath.SkipAll
		}
		if e.IsDir() {
			return nil
		}
		if info, err := e.Info(); err == nil {
			st.Files++
			size += info.Size()
			if info.ModTime().After(latest) {
				latest = info.ModTime()
			}
		}
		return nil
	})
	st.SizeGB = round(float64(size) / 1e9)
	if !latest.IsZero() {
		st.Changed = latest.UTC().Format(time.RFC3339)
	}
	if u, err := disk.UsageWithContext(ctx, f.Path); err == nil {
		st.FreeGB = round(float64(u.Free) / 1e9)
		st.UsedPct = round(u.UsedPercent)
		if f.MinFreeG > 0 && st.FreeGB < f.MinFreeG {
			st.Warning = fmt.Sprintf("only %.1f GB free", st.FreeGB)
		}
	}
	return st
}

// JobStatus is a jobs row.
type JobStatus struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	LastRun  string `json:"lastRun,omitempty"`
	Result   string `json:"result"`
	Duration string `json:"duration,omitempty"`
	Overdue  bool   `json:"overdue"`
	Running  bool   `json:"running"`
}

func (in *instance) jobStatus(j Job) JobStatus {
	in.mu.Lock()
	r, ran := in.runs[j.Name]
	busy := in.busy[j.Name]
	in.mu.Unlock()
	st := JobStatus{Name: j.Name, Kind: j.Kind, Result: "never run", Running: busy}
	if ran {
		st.LastRun, st.Duration = r.At.UTC().Format(time.RFC3339), r.Duration
		st.Result = "ok"
		if !r.OK {
			st.Result = "failed"
		}
	}
	if j.MaxAgeHours > 0 {
		st.Overdue = !ran || !r.OK || time.Since(r.At) > time.Duration(j.MaxAgeHours*float64(time.Hour))
	}
	return st
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	in, err := m.get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var problems []string
	for _, j := range in.cfg.Jobs {
		if s := in.jobStatus(j); s.Result == "failed" {
			problems = append(problems, j.Name+" failed")
		} else if s.Overdue && s.Result != "never run" {
			problems = append(problems, j.Name+" overdue")
		}
	}
	for _, f := range in.cfg.Folders {
		if f.MinFreeG <= 0 {
			continue
		}
		if u, err := disk.UsageWithContext(ctx, f.Path); err == nil && float64(u.Free)/1e9 < f.MinFreeG {
			problems = append(problems, fmt.Sprintf("%s: %.1f GB free", f.Name, float64(u.Free)/1e9))
		}
	}
	if len(problems) > 0 {
		return sdk.Health{Status: "degraded", Message: strings.Join(problems, "; ")}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d folders, %d backup jobs", len(in.cfg.Folders), len(in.cfg.Jobs))}
}

func (in *instance) job(name string) (Job, error) {
	for _, j := range in.cfg.Jobs {
		if j.Name == name {
			return j, nil
		}
	}
	return Job{}, fmt.Errorf("no job named %q", name)
}

// command builds the job's process.
func (in *instance) command(ctx context.Context, j Job, args ...string) (*exec.Cmd, error) {
	env := os.Environ()
	for k, v := range j.Env {
		if strings.HasPrefix(v, "secret://") {
			s, err := in.host.Secret(ctx, v)
			if err != nil {
				return nil, err
			}
			v = s
		}
		env = append(env, k+"="+v)
	}
	var cmd *exec.Cmd
	switch j.Kind {
	case "restic":
		pw, err := in.host.Secret(ctx, j.Password)
		if err != nil {
			return nil, err
		}
		env = append(env, "RESTIC_PASSWORD="+pw, "RESTIC_REPOSITORY="+j.Repo)
		if len(args) == 0 {
			args = append([]string{"backup", "--json", "--quiet"}, j.Paths...)
		}
		cmd = exec.CommandContext(ctx, "restic", args...)
	case "rsync":
		cmd = exec.CommandContext(ctx, "rsync", append(append([]string{"-a", "--delete-after", "--stats"}, j.Paths...), j.Target)...)
	default:
		cmd = exec.CommandContext(ctx, j.Command[0], j.Command[1:]...)
	}
	cmd.Env = env
	return cmd, nil
}

func tail(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	in, err := m.get(c.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Name string `json:"name"`
	}
	if err := sdk.Decode(c, &p); err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "folders":
		out := []FolderStatus{}
		for _, f := range in.cfg.Folders {
			out = append(out, folderStatus(ctx, f))
		}
		return sdk.JSON(out)
	case "jobs":
		out := []JobStatus{}
		for _, j := range in.cfg.Jobs {
			out = append(out, in.jobStatus(j))
		}
		return sdk.JSON(out)
	case "run_job":
		j, err := in.job(p.Name)
		if err != nil {
			return sdk.Result{}, err
		}
		in.mu.Lock()
		if in.busy[j.Name] {
			in.mu.Unlock()
			return sdk.Result{}, fmt.Errorf("%s is already running", j.Name)
		}
		in.busy[j.Name] = true
		in.mu.Unlock()
		defer func() {
			in.mu.Lock()
			delete(in.busy, j.Name)
			in.mu.Unlock()
		}()
		rctx, cancel := context.WithTimeout(ctx, 6*time.Hour)
		defer cancel()
		cmd, err := in.command(rctx, j)
		if err != nil {
			return sdk.Result{}, err
		}
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		start := time.Now()
		runErr := cmd.Run()
		r := runInfo{At: start, OK: runErr == nil, Duration: time.Since(start).Round(time.Second).String(), Output: tail(out.Bytes(), 2000)}
		in.mu.Lock()
		in.runs[j.Name] = r
		in.mu.Unlock()
		ev := "files.backup_ok"
		if runErr != nil {
			ev = "files.backup_failed"
		}
		data, _ := json.Marshal(map[string]string{"job": j.Name, "duration": r.Duration})
		in.host.Publish(ctx, sdk.Event{Type: ev, Instance: c.Instance, Data: data})
		if runErr != nil {
			return sdk.Result{}, fmt.Errorf("%s failed: %v\n%s", j.Name, runErr, tail(out.Bytes(), 600))
		}
		return sdk.JSON(r)
	case "snapshots":
		j, err := in.job(p.Name)
		if err != nil {
			return sdk.Result{}, err
		}
		if j.Kind != "restic" {
			return sdk.Result{}, errors.New("snapshots are for restic jobs")
		}
		cmd, err := in.command(ctx, j, "snapshots", "--json", "--latest", "20")
		if err != nil {
			return sdk.Result{}, err
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		b, err := cmd.Output()
		if err != nil {
			return sdk.Result{}, fmt.Errorf("restic: %v %s", err, tail(stderr.Bytes(), 400))
		}
		var snaps []struct {
			ID       string   `json:"short_id"`
			Time     string   `json:"time"`
			Hostname string   `json:"hostname"`
			Paths    []string `json:"paths"`
		}
		if err := json.Unmarshal(b, &snaps); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(snaps)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}
