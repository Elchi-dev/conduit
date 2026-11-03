// Package system is the "This computer" module: resources, temperatures,
// processes, saved launch profiles and game mode for the machine running the
// daemon.
package system

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/shirou/gopsutil/v4/sensors"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// InstanceID is the fixed id of this module's single instance.
const InstanceID = "system"

// Profile is a saved command the user can launch with one click.
type Profile struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Dir     string   `json:"dir,omitempty"`
}

// Config is the module's settings.
type Config struct {
	Profiles []Profile `json:"profiles"`
	// Games are executable names that start game mode automatically.
	Games []string `json:"games"`
	// Pause are process names suspended while game mode is on.
	Pause []string `json:"pause"`
	// AutoGameMode turns game mode on when a listed game starts and off when
	// it exits.
	AutoGameMode bool `json:"autoGameMode"`
}

// Module implements sdk.Module.
type Module struct {
	mu       sync.Mutex
	cfg      Config
	host     sdk.Host
	stop     context.CancelFunc
	gameMode bool
	paused   []int32
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "system", Name: "This computer", Version: "0.1.0", Category: "Devices", Icon: "cpu",
		Description: "Resources, temperatures, processes, saved launch profiles and game mode for the machine running Conduit.",
		Presets:     []string{"developer", "gamer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"profiles":{"type":"array","title":"Launch profiles","description":"Commands you start often. JSON list of {name, command, args, dir}.","items":{"type":"object"}},
			"games":{"type":"array","items":{"type":"string"},"description":"Executable names of games, e.g. cs2.exe or eldenring.exe"},
			"pause":{"type":"array","items":{"type":"string"},"description":"Processes to pause while gaming, e.g. backup tools or indexers"},
			"autoGameMode":{"type":"boolean","title":"Turn game mode on automatically","description":"When a listed game starts; off again when it exits"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "overview", Title: "Overview", Description: "CPU, memory, disks, network and uptime.", Risk: sdk.RiskRead},
			{Name: "processes", Title: "Processes", Description: "What's running, busiest first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"sort":{"type":"string","enum":["cpu","memory"],"default":"cpu"},"filter":{"type":"string","description":"Only names containing this"},"limit":{"type":"integer","default":40}}}`)},
			{Name: "temperatures", Title: "Temperatures", Description: "Sensor readings where the system exposes them.", Risk: sdk.RiskRead},
			{Name: "profiles", Title: "Launch profiles", Description: "Saved commands you can start.", Risk: sdk.RiskRead},
			{Name: "launch", Title: "Launch", Description: "Start a saved launch profile.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["profile"],"properties":{"profile":{"type":"string","description":"Profile name"}}}`)},
			{Name: "kill", Title: "End a process", Description: "Stop a process by id or every process with a name.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"pid":{"type":"integer"},"name":{"type":"string","description":"Exact process name"},"force":{"type":"boolean","description":"Kill immediately instead of asking it to quit"}}}`)},
			{Name: "game_mode", Title: "Game mode", Description: "Pause background processes you listed while you play; resume them after.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["on"],"properties":{"on":{"type":"boolean"}}}`)},
		},
		Events: []sdk.EventSpec{
			{Type: "system.game.started", Description: "A listed game started"},
			{Type: "system.game.stopped", Description: "A listed game exited"},
			{Type: "system.game_mode", Description: "Game mode turned on or off; automations can pause containers or mute alerts"},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(ctx context.Context, h sdk.Host, _ string, raw json.RawMessage) error {
	var cfg Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("invalid settings: %w", err)
		}
	}
	for _, p := range cfg.Profiles {
		if p.Name == "" || p.Command == "" {
			return errors.New("every launch profile needs a name and a command")
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stop != nil {
		m.stop()
	}
	m.cfg, m.host = cfg, h
	if len(cfg.Games) > 0 {
		wctx, cancel := context.WithCancel(context.Background())
		m.stop = cancel
		go m.watchGames(wctx)
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(context.Context, string) sdk.Health {
	m.mu.Lock()
	gm := m.gameMode
	m.mu.Unlock()
	if gm {
		return sdk.Health{Status: "ok", Message: "Game mode is on"}
	}
	return sdk.Health{Status: "ok"}
}

// Close implements sdk.Module.
func (m *Module) Close(string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stop != nil {
		m.stop()
		m.stop = nil
	}
	return nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	switch c.Action {
	case "overview":
		return sdk.JSON(overview(ctx))
	case "processes":
		var in struct {
			Sort   string `json:"sort"`
			Filter string `json:"filter"`
			Limit  int    `json:"limit"`
		}
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		list, err := processes(ctx, in.Sort, in.Filter, in.Limit)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(list)
	case "temperatures":
		temps, _ := sensors.TemperaturesWithContext(ctx)
		out := []map[string]any{}
		for _, t := range temps {
			if t.Temperature > 0 {
				out = append(out, map[string]any{"sensor": t.SensorKey, "celsius": round1(t.Temperature), "high": round1(t.High), "critical": round1(t.Critical)})
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["sensor"].(string) < out[j]["sensor"].(string) })
		return sdk.JSON(out)
	case "profiles":
		m.mu.Lock()
		p := append([]Profile{}, m.cfg.Profiles...)
		m.mu.Unlock()
		return sdk.JSON(p)
	case "launch":
		return m.launch(c)
	case "kill":
		return kill(ctx, c)
	case "game_mode":
		var in struct {
			On bool `json:"on"`
		}
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		return m.setGameMode(ctx, in.On, c.DryRun)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

func overview(ctx context.Context) map[string]any {
	out := map[string]any{}
	if h, err := host.InfoWithContext(ctx); err == nil {
		out["hostname"] = h.Hostname
		out["os"] = strings.TrimSpace(h.Platform + " " + h.PlatformVersion)
		out["kernel"] = h.KernelVersion
		out["uptimeHours"] = round1(float64(h.Uptime) / 3600)
	}
	out["cpus"] = runtime.NumCPU()
	if p, err := cpu.PercentWithContext(ctx, 300*time.Millisecond, false); err == nil && len(p) > 0 {
		out["cpuPercent"] = round1(p[0])
	}
	if l, err := load.AvgWithContext(ctx); err == nil {
		out["load"] = []float64{round1(l.Load1), round1(l.Load5), round1(l.Load15)}
	}
	if v, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		out["memory"] = map[string]any{"usedGB": gb(v.Used), "totalGB": gb(v.Total), "percent": round1(v.UsedPercent)}
	}
	if parts, err := disk.PartitionsWithContext(ctx, false); err == nil {
		var disks []map[string]any
		for _, p := range parts {
			// Skip pseudo and network mounts that report no real capacity.
			if u, err := disk.UsageWithContext(ctx, p.Mountpoint); err == nil && u.Total >= 1<<30 {
				disks = append(disks, map[string]any{"mount": p.Mountpoint, "usedGB": gb(u.Used), "totalGB": gb(u.Total), "percent": round1(u.UsedPercent)})
			}
		}
		out["disks"] = disks
	}
	if n, err := net.IOCountersWithContext(ctx, false); err == nil && len(n) > 0 {
		out["network"] = map[string]any{"sentGB": gb(n[0].BytesSent), "receivedGB": gb(n[0].BytesRecv)}
	}
	return out
}

func gb(b uint64) float64 { return round1(float64(b) / (1 << 30)) }

type procInfo struct {
	PID      int32   `json:"pid"`
	Name     string  `json:"name"`
	User     string  `json:"user"`
	CPU      float64 `json:"cpu"`
	MemoryMB float64 `json:"memoryMB"`
	Status   string  `json:"status"`
	Command  string  `json:"command"`
}

func processes(ctx context.Context, by, filter string, limit int) ([]procInfo, error) {
	ps, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 40
	}
	var out []procInfo
	for _, p := range ps {
		name, _ := p.NameWithContext(ctx)
		if filter != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(filter)) {
			continue
		}
		cpuP, _ := p.CPUPercentWithContext(ctx)
		mi, _ := p.MemoryInfoWithContext(ctx)
		user, _ := p.UsernameWithContext(ctx)
		st, _ := p.StatusWithContext(ctx)
		cmd, _ := p.CmdlineWithContext(ctx)
		if len(cmd) > 160 {
			cmd = cmd[:160] + "…"
		}
		info := procInfo{PID: p.Pid, Name: name, User: user, CPU: round1(cpuP), Command: cmd}
		if mi != nil {
			info.MemoryMB = round1(float64(mi.RSS) / (1 << 20))
		}
		if len(st) > 0 {
			info.Status = st[0]
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if by == "memory" {
			return out[i].MemoryMB > out[j].MemoryMB
		}
		return out[i].CPU > out[j].CPU
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Module) launch(c sdk.Call) (sdk.Result, error) {
	var in struct {
		Profile string `json:"profile"`
	}
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	m.mu.Lock()
	var prof *Profile
	for i := range m.cfg.Profiles {
		if m.cfg.Profiles[i].Name == in.Profile {
			p := m.cfg.Profiles[i]
			prof = &p
		}
	}
	m.mu.Unlock()
	if prof == nil {
		return sdk.Result{}, fmt.Errorf("no launch profile named %q", in.Profile)
	}
	// Only commands saved in settings can run: agents choose a profile, never
	// an arbitrary command line.
	cmd := exec.Command(prof.Command, prof.Args...)
	cmd.Dir = prof.Dir
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return sdk.Result{}, err
	}
	pid := cmd.Process.Pid
	go func() { _ = cmd.Wait() }()
	r, err := sdk.JSON(map[string]any{"profile": prof.Name, "pid": pid})
	r.Undo = sdk.UndoWith("kill", map[string]any{"pid": pid}, "Stop "+prof.Name)
	return r, err
}

func kill(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	var in struct {
		PID   int32  `json:"pid"`
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	if in.PID == 0 && in.Name == "" {
		return sdk.Result{}, errors.New("give a process id or a name")
	}
	if in.PID == int32(os.Getpid()) {
		return sdk.Result{}, errors.New("refusing to end Conduit itself")
	}
	var targets []*process.Process
	if in.PID != 0 {
		p, err := process.NewProcessWithContext(ctx, in.PID)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("no process %d", in.PID)
		}
		targets = append(targets, p)
	} else {
		ps, _ := process.ProcessesWithContext(ctx)
		for _, p := range ps {
			if n, _ := p.NameWithContext(ctx); n == in.Name && p.Pid != int32(os.Getpid()) {
				targets = append(targets, p)
			}
		}
		if len(targets) == 0 {
			return sdk.Result{}, fmt.Errorf("no running process named %q", in.Name)
		}
	}
	if c.DryRun {
		plan := &sdk.Plan{Summary: fmt.Sprintf("End %d %s", len(targets), pluralize(len(targets), "process", "processes"))}
		for _, p := range targets {
			n, _ := p.NameWithContext(ctx)
			op := "terminate"
			if in.Force {
				op = "kill"
			}
			plan.Changes = append(plan.Changes, sdk.Change{Target: fmt.Sprintf("%s (pid %d)", n, p.Pid), Op: op})
		}
		return sdk.Result{Plan: plan}, nil
	}
	var ended []int32
	for _, p := range targets {
		var err error
		if in.Force {
			err = p.KillWithContext(ctx)
		} else {
			err = p.TerminateWithContext(ctx)
		}
		if err != nil {
			return sdk.Result{}, fmt.Errorf("pid %d: %w", p.Pid, err)
		}
		ended = append(ended, p.Pid)
	}
	return sdk.JSON(map[string]any{"ended": ended})
}

func (m *Module) setGameMode(ctx context.Context, on, dryRun bool) (sdk.Result, error) {
	m.mu.Lock()
	names := append([]string{}, m.cfg.Pause...)
	paused := append([]int32{}, m.paused...)
	m.mu.Unlock()

	if on {
		ps, _ := process.ProcessesWithContext(ctx)
		var targets []*process.Process
		want := map[string]bool{}
		for _, n := range names {
			want[strings.ToLower(n)] = true
		}
		for _, p := range ps {
			if n, _ := p.NameWithContext(ctx); want[strings.ToLower(n)] {
				targets = append(targets, p)
			}
		}
		if dryRun {
			summary := "Announce game mode. No listed background processes are running, so nothing will be paused."
			if len(names) == 0 {
				summary = "Announce game mode. Add processes to pause in this computer's settings to free up more resources."
			} else if len(targets) > 0 {
				summary = fmt.Sprintf("Pause %d background %s and announce game mode", len(targets), pluralize(len(targets), "process", "processes"))
			}
			plan := &sdk.Plan{Summary: summary}
			for _, p := range targets {
				n, _ := p.NameWithContext(ctx)
				plan.Changes = append(plan.Changes, sdk.Change{Target: fmt.Sprintf("%s (pid %d)", n, p.Pid), Op: "pause"})
			}
			return sdk.Result{Plan: plan}, nil
		}
		var done []int32
		for _, p := range targets {
			if err := p.SuspendWithContext(ctx); err == nil {
				done = append(done, p.Pid)
			}
		}
		m.mu.Lock()
		m.gameMode, m.paused = true, append(m.paused, done...)
		h := m.host
		m.mu.Unlock()
		if h != nil {
			h.Publish(ctx, sdk.Event{Type: "system.game_mode", Data: json.RawMessage(`{"on":true}`)})
		}
		r, err := sdk.JSON(map[string]any{"gameMode": true, "paused": len(done)})
		r.Undo = sdk.UndoWith("game_mode", map[string]bool{"on": false}, "Turn game mode off")
		return r, err
	}

	if dryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Turn game mode off and resume %d paused %s", len(paused), pluralize(len(paused), "process", "processes"))}}, nil
	}
	resumed := 0
	for _, pid := range paused {
		if p, err := process.NewProcessWithContext(ctx, pid); err == nil && p.ResumeWithContext(ctx) == nil {
			resumed++
		}
	}
	m.mu.Lock()
	m.gameMode, m.paused = false, nil
	h := m.host
	m.mu.Unlock()
	if h != nil {
		h.Publish(ctx, sdk.Event{Type: "system.game_mode", Data: json.RawMessage(`{"on":false}`)})
	}
	r, err := sdk.JSON(map[string]any{"gameMode": false, "resumed": resumed})
	r.Undo = sdk.UndoWith("game_mode", map[string]bool{"on": true}, "Turn game mode back on")
	return r, err
}

// watchGames publishes game start/stop events and, if enabled, toggles game
// mode automatically.
func (m *Module) watchGames(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	running := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.mu.Lock()
		games := append([]string{}, m.cfg.Games...)
		auto, h := m.cfg.AutoGameMode, m.host
		m.mu.Unlock()
		now := map[string]bool{}
		ps, _ := process.ProcessesWithContext(ctx)
		names := map[string]bool{}
		for _, p := range ps {
			if n, err := p.NameWithContext(ctx); err == nil {
				names[strings.ToLower(n)] = true
			}
		}
		for _, g := range games {
			if names[strings.ToLower(g)] {
				now[g] = true
			}
		}
		for g := range now {
			if !running[g] && h != nil {
				h.Publish(ctx, sdk.Event{Type: "system.game.started", Data: mustJSON(map[string]string{"game": g})})
				if auto {
					_, _ = m.setGameMode(ctx, true, false)
				}
			}
		}
		for g := range running {
			if !now[g] && h != nil {
				h.Publish(ctx, sdk.Event{Type: "system.game.stopped", Data: mustJSON(map[string]string{"game": g})})
				if auto && len(now) == 0 {
					_, _ = m.setGameMode(ctx, false, false)
				}
			}
		}
		running = now
	}
}

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func pluralize(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
