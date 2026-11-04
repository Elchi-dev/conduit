// Package tdarr works with a Tdarr transcoding server through its API and
// an optional API key: nodes and their workers, libraries with their
// statistics (files, transcodes, space saved), the queue counts, and
// pausing and resuming a node.
package tdarr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Tdarr server.
type Config struct {
	URL                string `json:"url"`    // e.g. http://nas.lan:8265
	APIKey             string `json:"apiKey"` // optional secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Tdarr module.
func New() *Module { return &Module{} }

const maxLibraries = 25

// maxNodes and maxListed cap the nodes (and each node's workers) and the
// libraries in the output.
const (
	maxNodes  = 50
	maxListed = 200
)

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	node := `{"type":"object","required":["node"],"properties":{"node":{"type":"string","minLength":1,"maxLength":100,"description":"Node id or name (from nodes)"}}}`
	return sdk.Manifest{
		ID: "tdarr", Name: "Tdarr", Version: "0.1.0", Category: "Media", Icon: "video",
		Description: "Tdarr: nodes and workers, libraries with files and space saved, queue counts, pause and resume a node.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Tdarr server's address, e.g. http://nas.lan:8265"},
			"apiKey":{"type":"string","x-secret":true,"description":"API key (Tools, API Keys), when authentication is on"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "nodes", Title: "Nodes", Description: "Each node with its name, whether it's paused, worker limits, and its running workers with job type, status, progress, speed, time left and the file's name.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{}}`)},
			{Name: "libraries", Title: "Libraries", Description: "Each library with whether it's processed and watched, priority, and its files, transcodes, health checks and space saved; with the totals for all libraries.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{}}`)},
			{Name: "queue", Title: "Queue counts", Description: "How many files wait for a transcode or health check, how many finished and how many failed, and the space saved.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{}}`)},
			{Name: "pause_node", Title: "Pause a node", Description: "Pauses a node: its workers take no new work. Undo resumes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(node)},
			{Name: "resume_node", Title: "Resume a node", Description: "Resumes a paused node so its workers take work again. Undo pauses it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(node)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like http://nas.lan:8265")
	}
	if c.APIKey != "" && !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	ref := c.APIKey
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v2")
	api := rest.New(u.Scheme+"://"+u.Host+base, func(ctx context.Context, r *http.Request) error {
		if ref == "" {
			return nil
		}
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("x-api-key", strings.TrimSpace(k))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errKey = errors.New("Tdarr refused the request: check the API key (Tools, API Keys)")

func (c *conn) do(ctx context.Context, method, p string, body, out any) error {
	_, err := c.api.Do(ctx, method, "/api/v2"+p, nil, body, out)
	err = scrub(err)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errKey
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no Tdarr API at this address")
	}
	return err
}

func (c *conn) crud(ctx context.Context, data map[string]any, out any) error {
	return c.do(ctx, http.MethodPost, "/cruddb", map[string]any{"data": data}, out)
}

type worker struct {
	File       string          `json:"file"`
	Status     string          `json:"status"`
	Percentage json.RawMessage `json:"percentage"`
	FPS        json.RawMessage `json:"fps"`
	ETA        string          `json:"ETA"`
	Job        struct {
		Type string `json:"type"`
	} `json:"job"`
}

type node struct {
	ID           string            `json:"_id"`
	Name         string            `json:"nodeName"`
	Paused       bool              `json:"nodePaused"`
	Version      string            `json:"nodeVersion"`
	WorkerLimits map[string]any    `json:"workerLimits"`
	Workers      map[string]worker `json:"workers"`
}

type nodeEntry struct {
	key string
	n   node
}

func (c *conn) nodes(ctx context.Context) ([]nodeEntry, error) {
	var raw map[string]node
	if err := c.do(ctx, http.MethodGet, "/get-nodes", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]nodeEntry, 0, len(raw))
	for k, n := range raw {
		if n.ID == "" {
			n.ID = k
		}
		out = append(out, nodeEntry{k, n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].n.Name+out[i].key < out[j].n.Name+out[j].key })
	return out, nil
}

// num reads a number Tdarr may send as a number or a string.
func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	case json.RawMessage:
		var a any
		if json.Unmarshal(x, &a) == nil {
			return num(a)
		}
	}
	return 0
}

func round(f float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(f*p) / p
}

// pathRun is a word with a slash or backslash in a server's error text:
// a file or folder (/media/Family/a.mkv, C:\x\y).
var pathRun = regexp.MustCompile(`[^\s"'<>]*[\\/][^\s"'<>]*`)

// scrub keeps folders out of an error Tdarr sent ("ENOENT … '/media/…'").
func scrub(err error) error {
	var e *rest.Error
	if errors.As(err, &e) {
		return &rest.Error{Status: e.Status, Message: pathRun.ReplaceAllString(e.Message, "[path]")}
	}
	return err
}

// clip redacts a server's text, then keeps it to one line of n bytes.
func clip(s string, n int) string {
	s = rest.Redact(strings.Join(strings.Fields(s), " "))
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// shortName keeps only a file's name: paths say where someone keeps what.
func shortName(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, `\`, "/"))
	if p == "" {
		return ""
	}
	return clip(path.Base(p), 200)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ns, err := c.nodes(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	paused, running := 0, 0
	for _, e := range ns {
		if e.n.Paused {
			paused++
		}
		running += len(e.n.Workers)
	}
	msg := fmt.Sprintf("Tdarr · %d nodes, %d workers running", len(ns), running)
	if paused > 0 {
		msg += fmt.Sprintf(", %d paused", paused)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Node string `json:"node"`
}

func checkNode(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 100 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", errors.New("node is a node's id or name (from nodes)")
	}
	return s, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "nodes":
		ns, err := c.nodes(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i, e := range ns {
			if i == maxNodes {
				break
			}
			ws := []map[string]any{}
			ids := make([]string, 0, len(e.n.Workers))
			for k := range e.n.Workers {
				ids = append(ids, k)
			}
			sort.Strings(ids)
			for j, k := range ids {
				if j == maxNodes {
					break
				}
				w := e.n.Workers[k]
				ws = append(ws, map[string]any{"id": clip(k, 100), "type": clip(w.Job.Type, 40), "status": clip(w.Status, 100), "percent": round(num(w.Percentage), 1),
					"fps": round(num(w.FPS), 1), "eta": clip(w.ETA, 40), "file": shortName(w.File)})
			}
			limits := map[string]float64{}
			for k, v := range e.n.WorkerLimits {
				if len(limits) < 20 {
					limits[clip(k, 40)] = num(v)
				}
			}
			out = append(out, map[string]any{"id": clip(e.n.ID, 100), "name": clip(e.n.Name, 100), "paused": e.n.Paused, "version": clip(e.n.Version, 40),
				"workerLimits": limits, "workersRunning": len(e.n.Workers), "workers": ws})
		}
		res := map[string]any{"total": len(ns), "nodes": out}
		if len(ns) > maxNodes {
			res["note"] = fmt.Sprintf("the first %d nodes only", maxNodes)
		}
		return sdk.JSON(res)

	case "libraries":
		return c.libraries(ctx)

	case "queue":
		var s map[string]any
		if err := c.crud(ctx, map[string]any{"collection": "StatisticsJSONDB", "mode": "getById", "docID": "statistics"}, &s); err != nil {
			return sdk.Result{}, err
		}
		if s == nil {
			return sdk.Result{}, errors.New("unexpected answer: is this Tdarr?")
		}
		// Viewable counts leave out disabled libraries, as Tdarr's own tables do.
		t := func(n int) int64 {
			if v := num(s[fmt.Sprintf("table%dViewableCount", n)]); v > 0 {
				return int64(v)
			}
			return int64(num(s[fmt.Sprintf("table%dCount", n)]))
		}
		return sdk.JSON(map[string]any{
			"transcode":    map[string]int64{"queued": t(1), "done": t(2), "failed": t(3)},
			"healthCheck":  map[string]int64{"queued": t(4), "done": t(5), "failed": t(6)},
			"queued":       t(1) + t(4),
			"failed":       t(3) + t(6),
			"spaceSavedGB": round(num(s["sizeDiff"]), 2),
		})

	case "pause_node", "resume_node":
		return c.pauseResume(ctx, call, p.Node)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type pies struct {
	PieStats struct {
		TotalFiles       any `json:"totalFiles"`
		TotalTranscodes  any `json:"totalTranscodeCount"`
		TotalHealthCheck any `json:"totalHealthCheckCount"`
		SizeDiff         any `json:"sizeDiff"`
	} `json:"pieStats"`
}

func (c *conn) pies(ctx context.Context, lib string) (map[string]any, error) {
	var p pies
	if err := c.do(ctx, http.MethodPost, "/stats/get-pies", map[string]any{"data": map[string]string{"libraryId": lib}}, &p); err != nil {
		return nil, err
	}
	s := p.PieStats
	return map[string]any{"files": int64(num(s.TotalFiles)), "transcodes": int64(num(s.TotalTranscodes)),
		"healthChecks": int64(num(s.TotalHealthCheck)), "spaceSavedGB": round(num(s.SizeDiff), 2)}, nil
}

func (c *conn) libraries(ctx context.Context) (sdk.Result, error) {
	var libs []struct {
		ID         string `json:"_id"`
		Name       string `json:"name"`
		Process    *bool  `json:"processLibrary"`
		Watching   bool   `json:"folderWatching"`
		Priority   any    `json:"priority"`
		StackType  string `json:"pluginStackType"`
		ScanOnBoot bool   `json:"scanOnStart"`
		// The folder, cache and output paths aren't read.
	}
	if err := c.crud(ctx, map[string]any{"collection": "LibrarySettingsJSONDB", "mode": "getAll"}, &libs); err != nil {
		return sdk.Result{}, err
	}
	total, err := c.pies(ctx, "")
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for i, l := range libs {
		if i == maxListed {
			break
		}
		e := map[string]any{"id": clip(l.ID, 100), "name": clip(l.Name, 100), "folderWatching": l.Watching, "priority": num(l.Priority), "type": clip(l.StackType, 40)}
		if l.Process != nil {
			e["processed"] = *l.Process
		}
		if i < maxLibraries && l.ID != "" {
			st, err := c.pies(ctx, l.ID)
			if err != nil {
				return sdk.Result{}, err
			}
			e["stats"] = st
		}
		out = append(out, e)
	}
	res := map[string]any{"total": len(libs), "all": total, "libraries": out}
	if len(libs) > maxListed {
		res["note"] = fmt.Sprintf("the first %d libraries, with statistics for the first %d", maxListed, maxLibraries)
	} else if len(out) > maxLibraries {
		res["note"] = fmt.Sprintf("statistics for the first %d libraries only", maxLibraries)
	}
	return sdk.JSON(res)
}

func (c *conn) find(ctx context.Context, want string) (node, error) {
	ns, err := c.nodes(ctx)
	if err != nil {
		return node{}, err
	}
	var byName []node
	for _, e := range ns {
		if e.n.ID == want || e.key == want {
			return e.n, nil
		}
		if strings.EqualFold(e.n.Name, want) {
			byName = append(byName, e.n)
		}
	}
	switch len(byName) {
	case 1:
		return byName[0], nil
	case 0:
		return node{}, errors.New("there's no such node (see nodes)")
	}
	return node{}, errors.New("several nodes have that name: use the node's id")
}

func (c *conn) pauseResume(ctx context.Context, call sdk.Call, in string) (sdk.Result, error) {
	want := call.Action == "pause_node"
	ref, err := checkNode(in)
	if err != nil {
		return sdk.Result{}, err
	}
	n, err := c.find(ctx, ref)
	if err != nil {
		return sdk.Result{}, err
	}
	name := clip(n.Name, 100)
	verb, back := "Pause", "resume_node"
	if !want {
		verb, back = "Resume", "pause_node"
	}
	if n.Paused == want {
		return sdk.JSON(map[string]any{"node": name, "paused": n.Paused, "note": "nothing to change"})
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]any{"paused": n.Paused, "workersRunning": len(n.Workers)})
		a, _ := json.Marshal(map[string]bool{"paused": want})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s Tdarr node %s", verb, name),
			Changes: []sdk.Change{{Target: "node " + name, Op: strings.TrimSuffix(call.Action, "_node"), Before: b, After: a}}}}, nil
	}
	body := map[string]any{"data": map[string]any{"nodeID": n.ID, "nodeUpdates": map[string]bool{"nodePaused": want}}}
	if err := c.do(ctx, http.MethodPost, "/update-node", body, nil); err != nil {
		return sdk.Result{}, err
	}
	after, err := c.find(ctx, n.ID)
	if err != nil {
		return sdk.Result{}, fmt.Errorf("sent the change, but couldn't read the node back: %w", err)
	}
	if after.Paused != want {
		return sdk.Result{}, fmt.Errorf("Tdarr kept node %s %s", name, map[bool]string{true: "paused", false: "running"}[after.Paused])
	}
	res, err := sdk.JSON(map[string]any{"node": name, "id": n.ID, "paused": after.Paused})
	res.Undo = sdk.UndoWith(back, map[string]string{"node": n.ID}, fmt.Sprintf("%s node %s again", map[bool]string{true: "Resume", false: "Pause"}[want], name))
	return res, err
}
