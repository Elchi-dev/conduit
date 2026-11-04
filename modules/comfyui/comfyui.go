// Package comfyui works with a ComfyUI server: GPU and memory, the queue,
// recent generations with their output files, interrupting the current
// one, clearing what's waiting, and queueing a workflow saved in a folder
// the user chose. Workflows never come from the caller: a workflow can run
// any custom node installed on the server, which is arbitrary code.
package comfyui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one ComfyUI server.
type Config struct {
	URL   string `json:"url"`   // default http://127.0.0.1:8188
	Token string `json:"token"` // secret://, for ComfyUI behind a proxy that wants a bearer token
	// WorkflowsDir is the folder of workflows (saved with Export (API))
	// that queue_workflow may run. Empty: queueing is off.
	WorkflowsDir string `json:"workflowsDir"`
}

type conn struct {
	api  *rest.Client
	host string
	dir  string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the ComfyUI module.
func New() *Module { return &Module{} }

const maxWorkflowBytes = 4 << 20

var (
	fileRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.()-]{0,120}\.json$`)
	promptRe = regexp.MustCompile(`^[0-9a-fA-F-]{8,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "comfyui", Name: "ComfyUI", Version: "0.1.0", Category: "Development", Icon: "workflow",
		Description: "ComfyUI: GPU and memory, the queue, recent generations and their files, interrupt, clear the queue, and queue a workflow from your workflows folder.",
		Presets:     []string{"developer", "gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"url":{"type":"string","default":"http://127.0.0.1:8188"},
			"token":{"type":"string","x-secret":true,"description":"Only if ComfyUI sits behind a proxy that asks for a bearer token"},
			"workflowsDir":{"type":"string","description":"Full path of a folder of workflows saved with Export (API). Only these can be queued; leave empty to turn queueing off"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "system_stats", Title: "System", Description: "ComfyUI and PyTorch versions, memory, and each GPU with its graphics memory total and free.", Risk: sdk.RiskRead},
			{Name: "queue", Title: "Queue", Description: "The generation running now and the ones waiting, by number and id.", Risk: sdk.RiskRead},
			{Name: "history", Title: "Recent generations", Description: "Recent generations, newest first: status, how long they took, the prompt texts and the output file names. Sensitive: prompts can be private.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "workflows", Title: "Saved workflows", Description: "Workflow files in the workflows folder that queue_workflow can run, with whether each is in the API format it needs.", Risk: sdk.RiskRead},
			{Name: "interrupt", Title: "Interrupt", Description: "Stops the generation running now (its partial result is lost); the waiting ones carry on.", Risk: sdk.RiskWrite},
			{Name: "clear_queue", Title: "Clear the queue", Description: "Removes every waiting generation (not the running one). Destructive: they're gone and have to be queued again.", Risk: sdk.RiskDestructive, DryRun: true},
			{Name: "queue_workflow", Title: "Queue a workflow", Description: "Queues a workflow file from the workflows folder, optionally with a new seed. Destructive: a workflow runs every node in it, and custom nodes are code that runs on the server. The preview lists the custom node packs it uses.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["file"],"properties":{"file":{"type":"string","description":"A file name from workflows, e.g. portrait.json"},"seed":{"type":"integer","minimum":0,"maximum":9007199254740991,"description":"Replaces the seed of every sampler in it"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.URL == "" {
		c.URL = "http://127.0.0.1:8188"
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.URL), "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is like http://127.0.0.1:8188")
	}
	if c.Token != "" && !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the token in the vault and enter its secret:// reference")
	}
	if c.WorkflowsDir != "" {
		if !filepath.IsAbs(c.WorkflowsDir) {
			return errors.New("the workflows folder is a full path, like /home/me/comfy-workflows")
		}
		c.WorkflowsDir = filepath.Clean(c.WorkflowsDir)
	}
	ref := c.Token
	auth := func(ctx context.Context, r *http.Request) error {
		if ref == "" {
			return nil
		}
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api := rest.New(u.String(), auth)
	api.HTTP = rest.SameHostOnly(client)
	api.HTTP.Timeout = 30 * time.Second
	m.set.Put(id, &conn{api: api, host: u.Host, dir: c.WorkflowsDir})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("ComfyUI (or the proxy in front of it) refused the token")
	}
	return err
}

type stats struct {
	System struct {
		OS      string `json:"os"`
		RAM     int64  `json:"ram_total"`
		RAMFree int64  `json:"ram_free"`
		Version string `json:"comfyui_version"`
		Python  string `json:"python_version"`
		PyTorch string `json:"pytorch_version"`
	} `json:"system"`
	Devices []struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Index    int    `json:"index"`
		VRAM     int64  `json:"vram_total"`
		VRAMFree int64  `json:"vram_free"`
	} `json:"devices"`
}

// gpuName turns "cuda:0 NVIDIA GeForce RTX 4090 : cudaMallocAsync" into
// "NVIDIA GeForce RTX 4090".
func gpuName(s string) string {
	s, _, _ = strings.Cut(s, " : ")
	if f := strings.Fields(s); len(f) > 1 && strings.Contains(f[0], ":") {
		s = strings.Join(f[1:], " ")
	}
	return strings.TrimSpace(s)
}

func (c *conn) stats(ctx context.Context) (stats, error) {
	var s stats
	_, err := c.api.Do(ctx, http.MethodGet, "/system_stats", nil, nil, &s)
	return s, friendly(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.stats(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "ComfyUI"
	if s.System.Version != "" {
		msg += " " + s.System.Version
	}
	for _, d := range s.Devices {
		if d.Type != "cpu" && d.VRAM > 0 {
			msg += fmt.Sprintf(", %s with %.1f of %.1f GB free", gpuName(d.Name), float64(d.VRAMFree)/1e9, float64(d.VRAM)/1e9)
			break
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type queued struct {
	Number   int64  `json:"number"`
	PromptID string `json:"promptId"`
	Nodes    int    `json:"nodes"`
}

func parseQueue(items [][]json.RawMessage) []queued {
	out := []queued{}
	for _, it := range items {
		var q queued
		if len(it) > 0 {
			_ = json.Unmarshal(it[0], &q.Number)
		}
		if len(it) > 1 {
			_ = json.Unmarshal(it[1], &q.PromptID)
		}
		if len(it) > 2 {
			var g map[string]json.RawMessage
			if json.Unmarshal(it[2], &g) == nil {
				q.Nodes = len(g)
			}
		}
		out = append(out, q)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out
}

func (c *conn) queue(ctx context.Context) (running, pending []queued, err error) {
	var out struct {
		Running [][]json.RawMessage `json:"queue_running"`
		Pending [][]json.RawMessage `json:"queue_pending"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/queue", nil, nil, &out); err != nil {
		return nil, nil, friendly(err)
	}
	return parseQueue(out.Running), parseQueue(out.Pending), nil
}

type node struct {
	ClassType string                     `json:"class_type"`
	Inputs    map[string]json.RawMessage `json:"inputs"`
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// texts collects the prompt texts of a workflow: the string "text" inputs
// of its text-encoding nodes.
func texts(g map[string]node) []string {
	ids := make([]string, 0, len(g))
	for id := range g {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := []string{}
	for _, id := range ids {
		n := g[id]
		if !strings.Contains(strings.ToLower(n.ClassType), "textencode") {
			continue
		}
		for _, k := range []string{"text", "text_g", "text_l", "prompt"} {
			var s string
			if json.Unmarshal(n.Inputs[k], &s) == nil && strings.TrimSpace(s) != "" {
				out = append(out, clip(s, 1000))
			}
		}
	}
	return out
}

// loadWorkflow reads a workflow file from the workflows folder. os.Root
// refuses names that leave the folder, symlinks included.
func (c *conn) loadWorkflow(file string) (map[string]node, error) {
	if c.dir == "" {
		return nil, errors.New("queueing is off: set a workflows folder in this instance's settings")
	}
	if !fileRe.MatchString(file) || strings.Contains(file, "..") {
		return nil, errors.New("give a file name from workflows, like portrait.json")
	}
	root, err := os.OpenRoot(c.dir)
	if err != nil {
		return nil, fmt.Errorf("workflows folder: %w", err)
	}
	defer root.Close()
	f, err := root.Open(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errors.New("there's no such workflow in the workflows folder")
		}
		return nil, errors.New("that workflow can't be read from the workflows folder")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("that isn't a workflow file")
	}
	if st.Size() > maxWorkflowBytes {
		return nil, errors.New("that workflow is over 4 MB")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxWorkflowBytes+1))
	if err != nil {
		return nil, err
	}
	return parseWorkflow(b)
}

func parseWorkflow(b []byte) (map[string]node, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, errors.New("that file isn't a JSON workflow")
	}
	if _, ok := top["nodes"]; ok {
		if _, ok := top["links"]; ok {
			return nil, errors.New("that's a workflow in the editor format; in ComfyUI use Workflow, Export (API) and save that file instead")
		}
	}
	if len(top) == 0 {
		return nil, errors.New("that workflow has no nodes")
	}
	g := map[string]node{}
	for id, raw := range top {
		var n node
		if err := json.Unmarshal(raw, &n); err != nil || n.ClassType == "" {
			return nil, fmt.Errorf("node %s has no class_type: is this an Export (API) file?", clip(id, 20))
		}
		if n.Inputs == nil {
			n.Inputs = map[string]json.RawMessage{}
		}
		g[id] = n
	}
	return g, nil
}

func (c *conn) workflows() ([]map[string]any, error) {
	if c.dir == "" {
		return nil, errors.New("no workflows folder is set in this instance's settings")
	}
	ents, err := os.ReadDir(c.dir)
	if err != nil {
		return nil, fmt.Errorf("workflows folder: %w", err)
	}
	out := []map[string]any{}
	for _, e := range ents {
		if !e.Type().IsRegular() || !fileRe.MatchString(e.Name()) {
			continue
		}
		r := map[string]any{"file": e.Name()}
		if info, err := e.Info(); err == nil {
			r["bytes"] = info.Size()
			r["modified"] = info.ModTime().UTC().Format(time.RFC3339)
		}
		if g, err := c.loadWorkflow(e.Name()); err != nil {
			r["usable"] = false
			r["problem"] = err.Error()
		} else {
			r["usable"] = true
			r["nodes"] = len(g)
		}
		out = append(out, r)
	}
	return out, nil
}

// reseed sets every existing integer seed input to seed and says how many
// it changed. Only numbers are replaced: no input can become text or a link.
func reseed(g map[string]node, seed int64) int {
	n := 0
	for _, nd := range g {
		for _, k := range []string{"seed", "noise_seed"} {
			raw, ok := nd.Inputs[k]
			if !ok {
				continue
			}
			var f float64
			if json.Unmarshal(raw, &f) != nil {
				continue // a link to another node
			}
			nd.Inputs[k] = json.RawMessage(strconv.FormatInt(seed, 10))
			n++
		}
	}
	return n
}

// packs names the custom node packs a workflow uses, from the server's
// node list ("custom_nodes.ComfyUI-Impact-Pack"); core nodes aren't listed.
// unknown is the node classes the server doesn't have.
func (c *conn) packs(ctx context.Context, g map[string]node) (packs, unknown []string, err error) {
	var info map[string]struct {
		Module string `json:"python_module"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/object_info", nil, nil, &info); err != nil {
		return nil, nil, friendly(err)
	}
	ps, us := map[string]bool{}, map[string]bool{}
	for _, n := range g {
		i, ok := info[n.ClassType]
		switch {
		case !ok:
			us[n.ClassType] = true
		case strings.HasPrefix(i.Module, "custom_nodes."):
			ps[strings.TrimPrefix(i.Module, "custom_nodes.")] = true
		}
	}
	for p := range ps {
		packs = append(packs, p)
	}
	for u := range us {
		unknown = append(unknown, u)
	}
	sort.Strings(packs)
	sort.Strings(unknown)
	return packs, unknown, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Limit int    `json:"limit"`
		File  string `json:"file"`
		Seed  *int64 `json:"seed"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "system_stats":
		s, err := c.stats(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		gpus := []map[string]any{}
		for _, d := range s.Devices {
			gpus = append(gpus, map[string]any{"index": d.Index, "name": gpuName(d.Name), "type": d.Type, "vramBytes": d.VRAM, "vramFreeBytes": d.VRAMFree})
		}
		return sdk.JSON(map[string]any{"version": s.System.Version, "python": s.System.Python, "pytorch": s.System.PyTorch, "os": s.System.OS,
			"ramBytes": s.System.RAM, "ramFreeBytes": s.System.RAMFree, "devices": gpus})
	case "queue":
		run, pend, err := c.queue(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"running": run, "pending": pend, "pendingCount": len(pend)})
	case "history":
		if p.Limit <= 0 || p.Limit > 100 {
			p.Limit = 20
		}
		var out map[string]struct {
			Prompt  []json.RawMessage                     `json:"prompt"`
			Outputs map[string]map[string]json.RawMessage `json:"outputs"`
			Status  struct {
				Status    string              `json:"status_str"`
				Completed bool                `json:"completed"`
				Messages  [][]json.RawMessage `json:"messages"`
			} `json:"status"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/history", url.Values{"max_items": {strconv.Itoa(p.Limit)}}, nil, &out); err != nil {
			return sdk.Result{}, friendly(err)
		}
		type item struct {
			PromptID  string   `json:"promptId"`
			Number    int64    `json:"number"`
			Status    string   `json:"status"`
			Completed bool     `json:"completed"`
			Started   string   `json:"started,omitempty"`
			Seconds   float64  `json:"seconds,omitempty"`
			Prompts   []string `json:"prompts"`
			Outputs   []string `json:"outputs"`
		}
		list := []item{}
		for id, h := range out {
			it := item{PromptID: id, Status: h.Status.Status, Completed: h.Status.Completed, Prompts: []string{}, Outputs: []string{}}
			if len(h.Prompt) > 0 {
				_ = json.Unmarshal(h.Prompt[0], &it.Number)
			}
			if len(h.Prompt) > 2 {
				var g map[string]node
				if json.Unmarshal(h.Prompt[2], &g) == nil {
					it.Prompts = texts(g)
				}
			}
			var first, last int64
			for _, msg := range h.Status.Messages {
				if len(msg) < 2 {
					continue
				}
				var t struct {
					Timestamp int64 `json:"timestamp"`
				}
				if json.Unmarshal(msg[1], &t) == nil && t.Timestamp > 0 {
					if first == 0 || t.Timestamp < first {
						first = t.Timestamp
					}
					if t.Timestamp > last {
						last = t.Timestamp
					}
				}
			}
			if first > 0 {
				it.Started = time.UnixMilli(first).UTC().Format(time.RFC3339)
				it.Seconds = float64(last-first) / 1000
			}
			seen := map[string]bool{}
			for _, kinds := range h.Outputs {
				for _, raw := range kinds {
					var files []struct {
						Filename  string `json:"filename"`
						Subfolder string `json:"subfolder"`
						Type      string `json:"type"`
					}
					if json.Unmarshal(raw, &files) != nil {
						continue
					}
					for _, f := range files {
						if f.Filename == "" || f.Type == "temp" {
							continue
						}
						name := f.Filename
						if f.Subfolder != "" {
							name = f.Subfolder + "/" + name
						}
						if !seen[name] {
							seen[name] = true
							it.Outputs = append(it.Outputs, name)
						}
					}
				}
			}
			sort.Strings(it.Outputs)
			list = append(list, it)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Number > list[j].Number })
		if len(list) > p.Limit {
			list = list[:p.Limit]
		}
		return sdk.JSON(list)
	case "workflows":
		w, err := c.workflows()
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(w)
	case "interrupt":
		run, _, err := c.queue(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if len(run) == 0 {
			return sdk.JSON(map[string]any{"interrupted": false, "note": "nothing is running"})
		}
		body := map[string]string{}
		if promptRe.MatchString(run[0].PromptID) {
			// Newer ComfyUI interrupts only this prompt, so a race can't
			// stop the next one instead.
			body["prompt_id"] = run[0].PromptID
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/interrupt", nil, body, nil); err != nil {
			return sdk.Result{}, friendly(err)
		}
		return sdk.JSON(map[string]any{"interrupted": true, "promptId": run[0].PromptID})
	case "clear_queue":
		_, pend, err := c.queue(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			ch := []sdk.Change{}
			for _, q := range pend {
				ch = append(ch, sdk.Change{Target: fmt.Sprintf("#%d %s", q.Number, q.PromptID), Op: "delete"})
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Remove %d waiting generation(s) from the queue on %s", len(pend), c.host), Changes: ch}}, nil
		}
		if len(pend) == 0 {
			return sdk.JSON(map[string]any{"removed": 0})
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/queue", nil, map[string]any{"clear": true}, nil); err != nil {
			return sdk.Result{}, friendly(err)
		}
		return sdk.JSON(map[string]any{"removed": len(pend)})
	case "queue_workflow":
		if p.Seed != nil && (*p.Seed < 0 || *p.Seed > 1<<53-1) {
			return sdk.Result{}, errors.New("the seed is 0 to 9007199254740991")
		}
		g, err := c.loadWorkflow(p.File)
		if err != nil {
			return sdk.Result{}, err
		}
		reseeded := 0
		if p.Seed != nil {
			if reseeded = reseed(g, *p.Seed); reseeded == 0 {
				return sdk.Result{}, errors.New("that workflow has no seed to set")
			}
		}
		if call.DryRun {
			packs, unknown, err := c.packs(ctx, g)
			if err != nil {
				return sdk.Result{}, err
			}
			after := map[string]any{"nodes": len(g), "customNodePacks": packs}
			if p.Seed != nil {
				after["seed"] = *p.Seed
			}
			if len(unknown) > 0 {
				after["missingNodes"] = unknown
			}
			a, _ := json.Marshal(after)
			sum := fmt.Sprintf("Queue %s (%d nodes) on %s", p.File, len(g), c.host)
			if len(packs) > 0 {
				sum += ", running code from the custom node packs " + strings.Join(packs, ", ")
			}
			if len(unknown) > 0 {
				sum += "; the server lacks " + strings.Join(unknown, ", ") + ", so it will be refused"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: p.File, Op: "queue", After: a}}}}, nil
		}
		cid := make([]byte, 16)
		_, _ = rand.Read(cid)
		var out struct {
			PromptID   string                     `json:"prompt_id"`
			Number     int64                      `json:"number"`
			NodeErrors map[string]json.RawMessage `json:"node_errors"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/prompt", nil, map[string]any{"prompt": g, "client_id": "conduit-" + hex.EncodeToString(cid)}, &out); err != nil {
			return sdk.Result{}, friendly(err)
		}
		res := map[string]any{"promptId": out.PromptID, "number": out.Number, "file": p.File}
		if reseeded > 0 {
			res["seed"] = *p.Seed
		}
		return sdk.JSON(res)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
