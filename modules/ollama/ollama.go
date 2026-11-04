// Package ollama manages local AI models served by Ollama: what's installed,
// what's loaded and how much graphics memory it takes, downloading and
// removing models, and a quick test prompt.
package ollama

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Ollama server.
type Config struct {
	URL   string `json:"url"`   // default http://127.0.0.1:11434
	Token string `json:"token"` // secret://, for Ollama behind a proxy that wants a bearer token
}

type conn struct {
	cfg  Config
	base string
	api  *rest.Client
	auth func(context.Context, *http.Request) error
	http *http.Client
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
	// PullTimeout bounds one pull call (tests shorten it).
	PullTimeout time.Duration
}

// New returns the Ollama module.
func New() *Module { return &Module{PullTimeout: 10 * time.Minute} }

var modelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

const modelIn = `{"type":"object","required":["model"],"properties":{"model":{"type":"string","description":"e.g. llama3.2:3b"}}}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "ollama", Name: "Ollama", Version: "0.1.0", Category: "Development", Icon: "chip",
		Description: "Local AI models: what's installed and loaded, graphics memory, download and remove models.",
		Presets:     []string{"developer", "gamer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"url":{"type":"string","default":"http://127.0.0.1:11434"},
			"token":{"type":"string","x-secret":true,"description":"Only if Ollama sits behind a proxy that asks for a bearer token"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "models", Title: "Installed models", Risk: sdk.RiskRead},
			{Name: "running", Title: "Loaded models", Description: "Models in memory now and how much graphics memory each uses.", Risk: sdk.RiskRead},
			{Name: "pull", Title: "Download a model", Description: "Downloads or updates a model. Large models take a while; if it isn't done in 10 minutes, run it again and it carries on.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(modelIn)},
			{Name: "delete", Title: "Remove a model", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(modelIn)},
			{Name: "generate", Title: "Try a prompt", Description: "A short answer from a model, to check it works.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["model","prompt"],"properties":{"model":{"type":"string"},"prompt":{"type":"string","x-multiline":true,"maxLength":4000}}}`)},
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
		c.URL = "http://127.0.0.1:11434"
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("the address is like http://127.0.0.1:11434")
	}
	if c.Token != "" && !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the token in the vault and enter its secret:// reference")
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
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	}
	cn := &conn{cfg: c, base: strings.TrimRight(u.String(), "/"), auth: auth, http: m.HTTP}
	if cn.http == nil {
		cn.http = &http.Client{}
	}
	cn.api = rest.New(cn.base, auth)
	cn.api.HTTP = &http.Client{Timeout: 2 * time.Minute, Transport: cn.http.Transport}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Version string `json:"version"`
	}
	if _, err := c.api.Do(ctx, "GET", "/api/version", nil, nil, &v); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "Ollama " + v.Version}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	needModel := func() error {
		if !modelRe.MatchString(p.Model) {
			return errors.New("give a model name, like llama3.2:3b")
		}
		return nil
	}
	switch call.Action {
	case "models":
		var out struct {
			Models []struct {
				Name       string `json:"name"`
				Size       int64  `json:"size"`
				ModifiedAt string `json:"modified_at"`
				Details    struct {
					Family        string `json:"family"`
					ParameterSize string `json:"parameter_size"`
					Quantization  string `json:"quantization_level"`
				} `json:"details"`
			} `json:"models"`
		}
		if _, err := c.api.Do(ctx, "GET", "/api/tags", nil, nil, &out); err != nil {
			return sdk.Result{}, err
		}
		type model struct {
			Name         string `json:"name"`
			Bytes        int64  `json:"bytes"`
			Family       string `json:"family,omitempty"`
			Parameters   string `json:"parameters,omitempty"`
			Quantization string `json:"quantization,omitempty"`
			Modified     string `json:"modified"`
		}
		list := []model{}
		for _, x := range out.Models {
			list = append(list, model{x.Name, x.Size, x.Details.Family, x.Details.ParameterSize, x.Details.Quantization, x.ModifiedAt})
		}
		return sdk.JSON(list)
	case "running":
		var out struct {
			Models []struct {
				Name      string `json:"name"`
				Size      int64  `json:"size"`
				SizeVRAM  int64  `json:"size_vram"`
				ExpiresAt string `json:"expires_at"`
			} `json:"models"`
		}
		if _, err := c.api.Do(ctx, "GET", "/api/ps", nil, nil, &out); err != nil {
			return sdk.Result{}, err
		}
		type run struct {
			Name      string `json:"name"`
			Bytes     int64  `json:"bytes"`
			VRAMBytes int64  `json:"vramBytes"`
			OnGPU     int    `json:"gpuPercent"`
			UnloadsAt string `json:"unloadsAt"`
		}
		list := []run{}
		var vram int64
		for _, x := range out.Models {
			pct := 0
			if x.Size > 0 {
				pct = int(x.SizeVRAM * 100 / x.Size)
			}
			vram += x.SizeVRAM
			list = append(list, run{x.Name, x.Size, x.SizeVRAM, pct, x.ExpiresAt})
		}
		return sdk.JSON(map[string]any{"models": list, "vramBytes": vram})
	case "pull":
		if err := needModel(); err != nil {
			return sdk.Result{}, err
		}
		return m.pull(ctx, c, p.Model)
	case "delete":
		if err := needModel(); err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Remove the model " + p.Model, Changes: []sdk.Change{{Target: p.Model, Op: "delete"}}}}, nil
		}
		if _, err := c.api.Do(ctx, "DELETE", "/api/delete", nil, map[string]string{"model": p.Model}, nil); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, errors.New("no such model")
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"removed": p.Model})
	case "generate":
		if err := needModel(); err != nil {
			return sdk.Result{}, err
		}
		if strings.TrimSpace(p.Prompt) == "" || len(p.Prompt) > 4000 {
			return sdk.Result{}, errors.New("the prompt is 1 to 4000 characters")
		}
		var out struct {
			Response       string `json:"response"`
			EvalCount      int    `json:"eval_count"`
			EvalDurationNS int64  `json:"eval_duration"`
		}
		body := map[string]any{"model": p.Model, "prompt": p.Prompt, "stream": false, "options": map[string]any{"num_predict": 256}}
		if _, err := c.api.Do(ctx, "POST", "/api/generate", nil, body, &out); err != nil {
			return sdk.Result{}, err
		}
		tps := 0.0
		if out.EvalDurationNS > 0 {
			tps = float64(out.EvalCount) / (float64(out.EvalDurationNS) / 1e9)
		}
		return sdk.JSON(map[string]any{"model": p.Model, "response": out.Response, "tokensPerSecond": tps})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// pull streams Ollama's progress lines and returns when the download is
// done, fails, or the time limit is reached.
func (m *Module) pull(ctx context.Context, c *conn, model string) (sdk.Result, error) {
	limit := m.PullTimeout
	if limit <= 0 {
		limit = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	b, _ := json.Marshal(map[string]any{"model": model, "stream": true})
	req, err := http.NewRequestWithContext(ctx, "POST", c.base+"/api/pull", bytes.NewReader(b))
	if err != nil {
		return sdk.Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.auth(ctx, req); err != nil {
		return sdk.Result{}, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return sdk.Result{}, rest.TransportError(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return sdk.Result{}, fmt.Errorf("Ollama answered %s: %s", res.Status, strings.TrimSpace(string(msg)))
	}
	var last struct {
		Status    string `json:"status"`
		Error     string `json:"error"`
		Total     int64  `json:"total"`
		Completed int64  `json:"completed"`
	}
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var line struct {
			Status    string `json:"status"`
			Error     string `json:"error"`
			Total     int64  `json:"total"`
			Completed int64  `json:"completed"`
		}
		if json.Unmarshal(sc.Bytes(), &line) != nil {
			continue
		}
		if line.Error != "" {
			return sdk.Result{}, errors.New("Ollama: " + line.Error)
		}
		if line.Total > 0 || line.Status != "" {
			last = line
		}
		if line.Status == "success" {
			return sdk.JSON(map[string]any{"model": model, "status": "done"})
		}
	}
	pct := 0
	if last.Total > 0 {
		pct = int(last.Completed * 100 / last.Total)
	}
	if ctx.Err() != nil {
		return sdk.JSON(map[string]any{"model": model, "status": "still downloading", "percent": pct,
			"note": "Stopped waiting after the time limit; run Download again and it continues where it left off."})
	}
	if err := sc.Err(); err != nil {
		return sdk.Result{}, err
	}
	return sdk.Result{}, fmt.Errorf("the download ended early at %d%% (%s)", pct, last.Status)
}
