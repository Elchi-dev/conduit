// Package servers manages Linux servers over SSH: status, systemd services,
// logs, files and commands.
package servers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/elchi-dev/conduit/internal/sshx"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one server's settings.
type Config struct {
	sshx.Config
	// Sudo prefixes service changes with "sudo -n" (needs passwordless sudo
	// for systemctl).
	Sudo bool `json:"sudo"`
}

// Module implements sdk.Module.
type Module struct {
	mu      sync.Mutex
	clients map[string]*sshx.Client
	cfgs    map[string]Config
}

// New returns the servers module.
func New() *Module { return &Module{clients: map[string]*sshx.Client{}, cfgs: map[string]Config{}} }

var unitRe = regexp.MustCompile(`^[A-Za-z0-9@._:-]{1,200}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	unit := `{"type":"object","required":["service"],"properties":{"service":{"type":"string","description":"systemd unit, e.g. nginx or nginx.service"}}}`
	return sdk.Manifest{
		ID: "servers", Name: "Server (SSH)", Version: "0.1.0", Category: "Infrastructure", Icon: "server",
		Description: "A Linux machine over SSH: health, systemd services, logs, files and commands.",
		Presets:     []string{"developer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["host"],"properties":{` + sshx.SchemaProps + `,
			"sudo":{"type":"boolean","title":"Use sudo for services","description":"Needs passwordless sudo for systemctl"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Status", Description: "Uptime, load, memory and disks.", Risk: sdk.RiskRead},
			{Name: "services", Title: "Services", Description: "systemd services and their state.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"failedOnly":{"type":"boolean","title":"Only failed services"}}}`)},
			{Name: "service_status", Title: "Service details", Risk: sdk.RiskRead, Input: sdk.Schema(unit)},
			{Name: "logs", Title: "Logs", Description: "Recent journal lines for a service, or the whole system.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"service":{"type":"string","description":"Leave empty for the whole system"},"lines":{"type":"integer","default":200,"maximum":5000},"since":{"type":"string","description":"e.g. '1 hour ago' or '2026-11-03 01:00'"}}}`)},
			{Name: "files", Title: "Files", Description: "List a directory.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"path":{"type":"string","default":"/"}}}`)},
			{Name: "read_file", Title: "Read a file", Description: "The first 512 KiB of a file.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}`)},
			{Name: "service_restart", Title: "Restart a service", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(unit)},
			{Name: "service_start", Title: "Start a service", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(unit)},
			{Name: "service_stop", Title: "Stop a service", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(unit)},
			{Name: "run", Title: "Run a command", Description: "Run any shell command as the SSH user.", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["command"],"properties":{"command":{"type":"string","x-multiline":true}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c, err := sshx.New(cfg.Config, h)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if old := m.clients[id]; old != nil {
		old.Close()
	}
	m.clients[id], m.cfgs[id] = c, cfg
	m.mu.Unlock()
	return nil
}

func (m *Module) client(id string) (*sshx.Client, Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[id]
	if !ok {
		return nil, Config{}, errors.New("server is not configured")
	}
	return c, m.cfgs[id], nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, _, err := m.client(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	r, err := c.Run(ctx, "systemctl is-system-running 2>/dev/null || true")
	if err != nil {
		var hk *sshx.HostKeyError
		if errors.As(err, &hk) && hk.Expected == "" {
			return sdk.Health{Status: "unconfigured", Message: "Pin the host key in settings: " + hk.Got}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	switch s := strings.TrimSpace(r.Stdout); s {
	case "running", "":
		return sdk.Health{Status: "ok"}
	case "degraded":
		return sdk.Health{Status: "degraded", Message: "Some services failed"}
	default:
		return sdk.Health{Status: "degraded", Message: "System state: " + s}
	}
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.clients[id]; c != nil {
		c.Close()
	}
	delete(m.clients, id)
	delete(m.cfgs, id)
	return nil
}

// statusScript prints key=value lines that parse into the status output.
const statusScript = `echo "hostname=$(hostname)"
echo "os=$( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -s)"
echo "kernel=$(uname -r)"
echo "uptime=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
echo "load=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
echo "cpus=$(nproc 2>/dev/null)"
awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{print "memTotalKB="t; print "memAvailKB="a}' /proc/meminfo 2>/dev/null
df -P -k -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1{print "disk="$6","$2","$3}'`

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	cl, cfg, err := m.client(c.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	sudo := ""
	if cfg.Sudo {
		sudo = "sudo -n "
	}
	unitIn := func() (string, error) {
		var in struct {
			Service string `json:"service"`
		}
		if err := sdk.Decode(c, &in); err != nil {
			return "", err
		}
		if !unitRe.MatchString(in.Service) {
			return "", fmt.Errorf("invalid service name %q", in.Service)
		}
		return in.Service, nil
	}

	switch c.Action {
	case "status":
		r, err := cl.Run(ctx, statusScript)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(parseStatus(r.Stdout))

	case "services":
		var in struct {
			FailedOnly bool `json:"failedOnly"`
		}
		_ = sdk.Decode(c, &in)
		cmd := "systemctl list-units --type=service --all --no-pager --plain --no-legend"
		if in.FailedOnly {
			cmd += " --state=failed"
		}
		r, err := cl.Run(ctx, cmd)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(parseUnits(r.Stdout))

	case "service_status":
		u, err := unitIn()
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := cl.Run(ctx, "systemctl status --no-pager --lines=30 "+sshx.Quote(u))
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r.Stdout + r.Stderr)

	case "logs":
		var in struct {
			Service string `json:"service"`
			Lines   int    `json:"lines"`
			Since   string `json:"since"`
		}
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		if in.Lines <= 0 || in.Lines > 5000 {
			in.Lines = 200
		}
		cmd := "journalctl --no-pager -o short-iso -n " + strconv.Itoa(in.Lines)
		if in.Service != "" {
			if !unitRe.MatchString(in.Service) {
				return sdk.Result{}, fmt.Errorf("invalid service name %q", in.Service)
			}
			cmd += " -u " + sshx.Quote(in.Service)
		}
		if in.Since != "" {
			cmd += " --since " + sshx.Quote(in.Since)
		}
		r, err := cl.Run(ctx, sudo+cmd)
		if err != nil {
			return sdk.Result{}, err
		}
		if r.ExitCode != 0 && r.Stdout == "" {
			return sdk.Result{}, errors.New(strings.TrimSpace(r.Stderr))
		}
		return sdk.JSON(r.Stdout)

	case "files":
		var in struct {
			Path string `json:"path"`
		}
		_ = sdk.Decode(c, &in)
		if in.Path == "" {
			in.Path = "/"
		}
		r, err := cl.Run(ctx, "LC_ALL=C ls -la --time-style=+%Y-%m-%dT%H:%M "+sshx.Quote(in.Path))
		if err != nil {
			return sdk.Result{}, err
		}
		if r.ExitCode != 0 {
			return sdk.Result{}, errors.New(strings.TrimSpace(r.Stderr))
		}
		return sdk.JSON(parseLS(r.Stdout))

	case "read_file":
		var in struct {
			Path string `json:"path"`
		}
		if err := sdk.Decode(c, &in); err != nil || in.Path == "" {
			return sdk.Result{}, errors.New("path is required")
		}
		r, err := cl.Run(ctx, "head -c 524288 -- "+sshx.Quote(in.Path))
		if err != nil {
			return sdk.Result{}, err
		}
		if r.ExitCode != 0 {
			return sdk.Result{}, errors.New(strings.TrimSpace(r.Stderr))
		}
		return sdk.JSON(r.Stdout)

	case "service_restart", "service_start", "service_stop":
		u, err := unitIn()
		if err != nil {
			return sdk.Result{}, err
		}
		verb := strings.TrimPrefix(c.Action, "service_")
		if c.DryRun {
			st, _ := cl.Run(ctx, "systemctl show -p ActiveState,SubState,MainPID --value "+sshx.Quote(u))
			before := strings.Fields(st.Stdout)
			return sdk.Result{Plan: &sdk.Plan{
				Summary: fmt.Sprintf("%s %s on %s", strings.ToUpper(verb[:1])+verb[1:], u, cfg.Host),
				Changes: []sdk.Change{{Target: u + " on " + cfg.Host, Op: verb, Before: mustJSON(map[string]any{"state": before})}},
			}}, nil
		}
		r, err := cl.Run(ctx, sudo+"systemctl "+verb+" "+sshx.Quote(u))
		if err != nil {
			return sdk.Result{}, err
		}
		if r.ExitCode != 0 {
			return sdk.Result{}, fmt.Errorf("systemctl %s failed: %s", verb, strings.TrimSpace(r.Stderr))
		}
		st, _ := cl.Run(ctx, "systemctl is-active "+sshx.Quote(u))
		res, err := sdk.JSON(map[string]string{"service": u, "state": strings.TrimSpace(st.Stdout)})
		switch verb {
		case "start":
			res.Undo = sdk.UndoWith("service_stop", map[string]string{"service": u}, "Stop "+u+" again")
		case "stop":
			res.Undo = sdk.UndoWith("service_start", map[string]string{"service": u}, "Start "+u+" again")
		}
		return res, err

	case "run":
		var in struct {
			Command string `json:"command"`
		}
		if err := sdk.Decode(c, &in); err != nil || strings.TrimSpace(in.Command) == "" {
			return sdk.Result{}, errors.New("command is required")
		}
		r, err := cl.Run(ctx, in.Command)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func parseStatus(out string) map[string]any {
	res := map[string]any{}
	var disks []map[string]any
	var total, avail float64
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "uptime":
			f, _ := strconv.ParseFloat(v, 64)
			res["uptimeHours"] = float64(int(f/360)) / 10
		case "load":
			res["load"] = v
		case "cpus":
			n, _ := strconv.Atoi(v)
			res["cpus"] = n
		case "memTotalKB":
			total, _ = strconv.ParseFloat(v, 64)
		case "memAvailKB":
			avail, _ = strconv.ParseFloat(v, 64)
		case "disk":
			p := strings.Split(v, ",")
			if len(p) == 3 {
				size, _ := strconv.ParseFloat(p[1], 64)
				used, _ := strconv.ParseFloat(p[2], 64)
				if size > 0 {
					disks = append(disks, map[string]any{"mount": p[0], "totalGB": round1(size / (1 << 20)), "usedGB": round1(used / (1 << 20)), "percent": round1(used / size * 100)})
				}
			}
		default:
			res[k] = v
		}
	}
	if total > 0 {
		res["memory"] = map[string]any{"totalGB": round1(total / (1 << 20)), "usedGB": round1((total - avail) / (1 << 20)), "percent": round1((total - avail) / total * 100)}
	}
	res["disks"] = disks
	return res
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

// Unit is one line of systemctl list-units.
type Unit struct {
	Name        string `json:"name"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

func parseUnits(out string) []Unit {
	units := []Unit{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimLeft(line, "● "))
		if len(f) < 4 {
			continue
		}
		units = append(units, Unit{Name: strings.TrimSuffix(f[0], ".service"), Load: f[1], Active: f[2], Sub: f[3], Description: strings.Join(f[4:], " ")})
	}
	return units
}

// Entry is one line of a directory listing.
type Entry struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Mode     string `json:"mode"`
	Owner    string `json:"owner"`
	Modified string `json:"modified"`
}

func parseLS(out string) []Entry {
	entries := []Entry{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || f[0] == "total" {
			continue
		}
		name := strings.Join(f[6:], " ")
		if name == "." || name == ".." {
			continue
		}
		size, _ := strconv.ParseInt(f[4], 10, 64)
		t := "file"
		switch f[0][0] {
		case 'd':
			t = "dir"
		case 'l':
			t = "link"
		}
		entries = append(entries, Entry{Name: name, Type: t, Size: size, Mode: f[0], Owner: f[2], Modified: f[5]})
	}
	return entries
}
