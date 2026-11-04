// Package docker manages containers and Compose stacks through the Docker
// Engine API, on this machine, over TCP, or on a remote host through SSH.
package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/internal/sshx"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Docker endpoint's settings.
type Config struct {
	// Mode is "local" (this machine's socket), "ssh" or "tcp".
	Mode string `json:"mode"`
	// Socket overrides the socket path (local and ssh).
	Socket string `json:"socket"`
	// Address is host:port for tcp mode (use only on trusted networks).
	Address string `json:"address"`
	sshx.Config
}

type endpoint struct {
	http *http.Client
	ssh  *sshx.Client
}

// Module implements sdk.Module.
type Module struct {
	mu  sync.Mutex
	eps map[string]*endpoint
}

// New returns the Docker module.
func New() *Module { return &Module{eps: map[string]*endpoint{}} }

var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	one := `{"type":"object","required":["container"],"properties":{"container":{"type":"string","description":"Name or ID"}}}`
	return sdk.Manifest{
		ID: "docker", Name: "Docker", Version: "0.1.0", Category: "Infrastructure", Icon: "box",
		Description: "Containers and Compose stacks on this machine or a remote host.",
		Presets:     []string{"developer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"mode":{"type":"string","enum":["local","ssh","tcp"],"default":"local","description":"local: this machine. ssh: a server you reach over SSH. tcp: a Docker API port on a trusted network."},
			"socket":{"type":"string","description":"Socket path, if not the default"},
			"address":{"type":"string","description":"host:port, for tcp mode"},` + sshx.SchemaProps + `}}`),
		Actions: []sdk.ActionSpec{
			{Name: "containers", Title: "Containers", Description: "Every container and its state.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"running":{"type":"boolean","title":"Only running"}}}`)},
			{Name: "stacks", Title: "Compose stacks", Description: "Containers grouped by Compose project.", Risk: sdk.RiskRead},
			{Name: "stats", Title: "Usage", Description: "CPU and memory of running containers.", Risk: sdk.RiskRead},
			{Name: "logs", Title: "Logs", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["container"],"properties":{"container":{"type":"string"},"lines":{"type":"integer","default":200,"maximum":5000}}}`)},
			{Name: "images", Title: "Images", Risk: sdk.RiskRead},
			{Name: "start", Title: "Start", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(one)},
			{Name: "unpause", Title: "Resume", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(one)},
			{Name: "pause", Title: "Pause", Description: "Freezes every process in a container: what it serves is unavailable until it's resumed, so it's destructive. Undo resumes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(one)},
			{Name: "stop", Title: "Stop", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(one)},
			{Name: "restart", Title: "Restart", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(one)},
			{Name: "stack_action", Title: "Start, stop or restart a stack", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","action"],"properties":{"project":{"type":"string"},"action":{"type":"string","enum":["start","stop","restart","pause","unpause"]}}}`)},
		},
	}
}

func defaultSocket() string {
	if runtime.GOOS == "windows" {
		return `//./pipe/docker_engine`
	}
	return "/var/run/docker.sock"
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var cfg Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("invalid settings: %w", err)
		}
	}
	if cfg.Mode == "" {
		cfg.Mode = "local"
	}
	ep := &endpoint{}
	var dial func(ctx context.Context) (net.Conn, error)
	switch cfg.Mode {
	case "local":
		sock := cfg.Socket
		if sock == "" {
			sock = defaultSocket()
		}
		dial = func(ctx context.Context) (net.Conn, error) { return dialLocal(ctx, sock) }
	case "ssh":
		c, err := sshx.New(cfg.Config, h)
		if err != nil {
			return err
		}
		ep.ssh = c
		sock := cfg.Socket
		if sock == "" {
			sock = "/var/run/docker.sock"
		}
		dial = func(ctx context.Context) (net.Conn, error) { return c.DialUnix(ctx, sock) }
	case "tcp":
		if cfg.Address == "" {
			return errors.New("address is required for tcp mode")
		}
		// Through the instance's network when it has one.
		netDial := sdk.DialContext(h)
		dial = func(ctx context.Context) (net.Conn, error) { return netDial(ctx, "tcp", cfg.Address) }
	default:
		return fmt.Errorf("unknown mode %q", cfg.Mode)
	}
	ep.http = &http.Client{
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) }, MaxIdleConns: 4, IdleConnTimeout: 60 * time.Second},
		Timeout:   60 * time.Second,
	}
	m.mu.Lock()
	if old := m.eps[id]; old != nil && old.ssh != nil {
		old.ssh.Close()
	}
	m.eps[id] = ep
	m.mu.Unlock()
	return nil
}

func (m *Module) ep(id string) (*endpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.eps[id]; e != nil {
		return e, nil
	}
	return nil, errors.New("Docker endpoint is not configured")
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.eps[id]; e != nil && e.ssh != nil {
		e.ssh.Close()
	}
	delete(m.eps, id)
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	e, err := m.ep(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var info struct {
		Containers        int    `json:"Containers"`
		ContainersRunning int    `json:"ContainersRunning"`
		ServerVersion     string `json:"ServerVersion"`
	}
	if err := e.get(ctx, "/info", &info); err != nil {
		var hk *sshx.HostKeyError
		if errors.As(err, &hk) && hk.Expected == "" {
			return sdk.Health{Status: "unconfigured", Message: "Pin the host key in settings: " + hk.Got}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("Docker %s, %d of %d containers running", info.ServerVersion, info.ContainersRunning, info.Containers)}
}

const apiPrefix = "http://docker/v1.43"

func (e *endpoint) do(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, apiPrefix+path, nil)
	if err != nil {
		return err
	}
	res, err := e.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode != http.StatusNotModified {
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(&msg)
		if msg.Message == "" {
			msg.Message = res.Status
		}
		return errors.New(msg.Message)
	}
	if out != nil {
		return json.NewDecoder(res.Body).Decode(out)
	}
	return nil
}

func (e *endpoint) get(ctx context.Context, path string, out any) error {
	return e.do(ctx, http.MethodGet, path, out)
}

type apiContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
	Labels map[string]string `json:"Labels"`
	Ports  []struct {
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
	Created int64 `json:"Created"`
}

// Container is the module's view of a container.
type Container struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	State   string `json:"state"`
	Status  string `json:"status"`
	Project string `json:"project,omitempty"`
	Ports   string `json:"ports,omitempty"`
	ID      string `json:"id"`
}

func (e *endpoint) containers(ctx context.Context, all bool) ([]Container, error) {
	var raw []apiContainer
	q := "/containers/json"
	if all {
		q += "?all=1"
	}
	if err := e.get(ctx, q, &raw); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(raw))
	for _, c := range raw {
		name := c.ID[:12]
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		var ports []string
		for _, p := range c.Ports {
			if p.PublicPort > 0 {
				ports = append(ports, fmt.Sprintf("%d→%d/%s", p.PublicPort, p.PrivatePort, p.Type))
			}
		}
		out = append(out, Container{Name: name, Image: c.Image, State: c.State, Status: c.Status, Project: c.Labels["com.docker.compose.project"], Ports: strings.Join(ports, " "), ID: c.ID[:12]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Project != out[j].Project {
			return out[i].Project < out[j].Project
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	e, err := m.ep(c.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	target := func() (string, error) {
		var in struct {
			Container string `json:"container"`
		}
		if err := sdk.Decode(c, &in); err != nil {
			return "", err
		}
		if !idRe.MatchString(in.Container) {
			return "", fmt.Errorf("invalid container %q", in.Container)
		}
		return in.Container, nil
	}

	switch c.Action {
	case "containers":
		var in struct {
			Running bool `json:"running"`
		}
		_ = sdk.Decode(c, &in)
		list, err := e.containers(ctx, !in.Running)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(list)

	case "stacks":
		list, err := e.containers(ctx, true)
		if err != nil {
			return sdk.Result{}, err
		}
		type stack struct {
			Project    string   `json:"project"`
			Running    int      `json:"running"`
			Total      int      `json:"total"`
			Containers []string `json:"containers"`
		}
		by := map[string]*stack{}
		for _, ct := range list {
			if ct.Project == "" {
				continue
			}
			s := by[ct.Project]
			if s == nil {
				s = &stack{Project: ct.Project}
				by[ct.Project] = s
			}
			s.Total++
			if ct.State == "running" {
				s.Running++
			}
			s.Containers = append(s.Containers, ct.Name)
		}
		out := []stack{}
		for _, s := range by {
			out = append(out, *s)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Project < out[j].Project })
		return sdk.JSON(out)

	case "stats":
		list, err := e.containers(ctx, false)
		if err != nil {
			return sdk.Result{}, err
		}
		type stat struct {
			Name     string  `json:"name"`
			CPU      float64 `json:"cpu"`
			MemoryMB float64 `json:"memoryMB"`
			LimitMB  float64 `json:"limitMB"`
		}
		out := make([]stat, len(list))
		var wg sync.WaitGroup
		for i, ct := range list {
			wg.Add(1)
			go func(i int, ct Container) {
				defer wg.Done()
				var s struct {
					CPU struct {
						Usage struct {
							Total uint64 `json:"total_usage"`
						} `json:"cpu_usage"`
						System uint64 `json:"system_cpu_usage"`
						Online int    `json:"online_cpus"`
					} `json:"cpu_stats"`
					Pre struct {
						Usage struct {
							Total uint64 `json:"total_usage"`
						} `json:"cpu_usage"`
						System uint64 `json:"system_cpu_usage"`
					} `json:"precpu_stats"`
					Mem struct {
						Usage uint64 `json:"usage"`
						Limit uint64 `json:"limit"`
					} `json:"memory_stats"`
				}
				out[i] = stat{Name: ct.Name}
				if e.get(ctx, "/containers/"+ct.ID+"/stats?stream=false&one-shot=false", &s) != nil {
					return
				}
				cpuDelta := float64(s.CPU.Usage.Total) - float64(s.Pre.Usage.Total)
				sysDelta := float64(s.CPU.System) - float64(s.Pre.System)
				if sysDelta > 0 && cpuDelta > 0 {
					online := s.CPU.Online
					if online == 0 {
						online = 1
					}
					out[i].CPU = round1(cpuDelta / sysDelta * float64(online) * 100)
				}
				out[i].MemoryMB = round1(float64(s.Mem.Usage) / (1 << 20))
				out[i].LimitMB = round1(float64(s.Mem.Limit) / (1 << 20))
			}(i, ct)
		}
		wg.Wait()
		sort.Slice(out, func(i, j int) bool { return out[i].CPU > out[j].CPU })
		return sdk.JSON(out)

	case "logs":
		var in struct {
			Container string `json:"container"`
			Lines     int    `json:"lines"`
		}
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		if !idRe.MatchString(in.Container) {
			return sdk.Result{}, fmt.Errorf("invalid container %q", in.Container)
		}
		if in.Lines <= 0 || in.Lines > 5000 {
			in.Lines = 200
		}
		text, err := e.logs(ctx, in.Container, in.Lines)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(text)

	case "images":
		var raw []struct {
			ID       string   `json:"Id"`
			RepoTags []string `json:"RepoTags"`
			Size     int64    `json:"Size"`
			Created  int64    `json:"Created"`
		}
		if err := e.get(ctx, "/images/json", &raw); err != nil {
			return sdk.Result{}, err
		}
		type img struct {
			Tag     string  `json:"tag"`
			SizeMB  float64 `json:"sizeMB"`
			Created string  `json:"created"`
		}
		out := []img{}
		for _, r := range raw {
			tag := "<none>"
			if len(r.RepoTags) > 0 {
				tag = strings.Join(r.RepoTags, ", ")
			}
			out = append(out, img{Tag: tag, SizeMB: round1(float64(r.Size) / (1 << 20)), Created: time.Unix(r.Created, 0).UTC().Format("2006-01-02")})
		}
		return sdk.JSON(out)

	case "start", "stop", "restart", "pause", "unpause":
		id, err := target()
		if err != nil {
			return sdk.Result{}, err
		}
		if c.DryRun {
			var st struct {
				State struct{ Status string } `json:"State"`
			}
			_ = e.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &st)
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s container %s", strings.ToUpper(c.Action[:1])+c.Action[1:], id),
				Changes: []sdk.Change{{Target: id, Op: c.Action, Before: mustJSON(map[string]string{"state": st.State.Status})}}}}, nil
		}
		if err := e.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/"+c.Action, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]string{"container": id, "done": c.Action})
		switch c.Action {
		case "start":
			res.Undo = sdk.UndoWith("stop", map[string]string{"container": id}, "Stop "+id+" again")
		case "stop":
			res.Undo = sdk.UndoWith("start", map[string]string{"container": id}, "Start "+id+" again")
		case "pause":
			res.Undo = sdk.UndoWith("unpause", map[string]string{"container": id}, "Resume "+id)
		case "unpause":
			res.Undo = sdk.UndoWith("pause", map[string]string{"container": id}, "Pause "+id+" again")
		}
		return res, err

	case "stack_action":
		var in struct {
			Project string `json:"project"`
			Action  string `json:"action"`
		}
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		switch in.Action {
		case "start", "stop", "restart", "pause", "unpause":
		default:
			return sdk.Result{}, fmt.Errorf("invalid stack action %q", in.Action)
		}
		list, err := e.containers(ctx, true)
		if err != nil {
			return sdk.Result{}, err
		}
		var members []Container
		for _, ct := range list {
			if ct.Project == in.Project {
				members = append(members, ct)
			}
		}
		if len(members) == 0 {
			return sdk.Result{}, fmt.Errorf("no containers in project %q", in.Project)
		}
		if c.DryRun {
			plan := &sdk.Plan{Summary: fmt.Sprintf("%s %d containers of %s", in.Action, len(members), in.Project)}
			for _, ct := range members {
				plan.Changes = append(plan.Changes, sdk.Change{Target: ct.Name, Op: in.Action, Before: mustJSON(map[string]string{"state": ct.State})})
			}
			return sdk.Result{Plan: plan}, nil
		}
		var done []string
		var errs []string
		for _, ct := range members {
			if err := e.do(ctx, http.MethodPost, "/containers/"+ct.ID+"/"+in.Action, nil); err != nil {
				errs = append(errs, ct.Name+": "+err.Error())
			} else {
				done = append(done, ct.Name)
			}
		}
		res := map[string]any{"project": in.Project, "done": done}
		if len(errs) > 0 {
			res["errors"] = errs
		}
		r, err := sdk.JSON(res)
		inverse := map[string]string{"start": "stop", "stop": "start", "pause": "unpause", "unpause": "pause"}[in.Action]
		if inverse != "" && len(errs) == 0 {
			r.Undo = sdk.UndoWith("stack_action", map[string]string{"project": in.Project, "action": inverse}, inverse+" "+in.Project)
		}
		return r, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

// logs fetches recent log lines, decoding Docker's multiplexed stream format
// when the container has no TTY.
func (e *endpoint) logs(ctx context.Context, id string, lines int) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiPrefix+"/containers/"+url.PathEscape(id)+"/logs?stdout=1&stderr=1&timestamps=1&tail="+strconv.Itoa(lines), nil)
	res, err := e.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return "", fmt.Errorf("logs: %s %s", res.Status, strings.TrimSpace(string(b)))
	}
	body := bufio.NewReader(io.LimitReader(res.Body, 8<<20))
	head, err := body.Peek(8)
	if err != nil || (head[0] != 1 && head[0] != 2) || head[1] != 0 || head[2] != 0 || head[3] != 0 {
		b, _ := io.ReadAll(body)
		return string(b), nil
	}
	var sb strings.Builder
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(body, hdr); err != nil {
			break
		}
		n := binary.BigEndian.Uint32(hdr[4:])
		if _, err := io.CopyN(&sb, body, int64(n)); err != nil {
			break
		}
	}
	return sb.String(), nil
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
