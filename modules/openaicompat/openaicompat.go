// Package openaicompat talks to any server with an OpenAI-compatible API
// (LM Studio, LocalAI, vLLM, llama.cpp's server, Jan, text-generation-webui
// and many hosted ones): the models it serves, whether it answers, and a
// chat completion whose length is capped by a setting, to a model the
// settings allow (or, with none listed, one the server lists itself).
package openaicompat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one server.
type Config struct {
	// URL is the API base, the part before /models and /chat/completions,
	// e.g. http://127.0.0.1:1234/v1.
	URL    string `json:"url"`
	APIKey string `json:"apiKey"` // secret://, when the server asks for one
	// MaxTokens caps the answer length of chat (default 512, at most 8192).
	MaxTokens int `json:"maxTokens"`
	// TimeoutSeconds bounds one chat call (default 120, 5 to 600).
	TimeoutSeconds int `json:"timeoutSeconds"`
	// Models are the model ids chat may use. Empty: only ids the server
	// lists at /models, without a routing variant such as :online.
	Models []string `json:"models"`
}

type conn struct {
	api       *rest.Client
	chat      *rest.Client
	host      string
	maxTokens int
	allowed   map[string]bool // Config.Models; empty: what the server lists
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the module.
func New() *Module { return &Module{} }

const (
	defaultMaxTokens = 512
	ceilingTokens    = 8192
	maxPrompt        = 16000
	maxSystem        = 4000
	maxAnswer        = 64000
)

var modelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$`)

// variantRe matches the routing variants some hosted servers (OpenRouter)
// accept after any model id without listing them: :online adds a paid web
// search to every call, others pick pricier providers or longer outputs.
// They're used only when the instance's models name them.
var variantRe = regexp.MustCompile(`(?i):(online|nitro|floor|exacto|thinking|extended|beta)$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "openaicompat", Name: "OpenAI-compatible server", Version: "0.1.0", Category: "Development", Icon: "chip",
		Description: "Any OpenAI-compatible model server (LM Studio, LocalAI, vLLM, llama.cpp, Jan): the models it serves, whether it answers, and a chat reply capped in length.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","default":"http://127.0.0.1:1234/v1","description":"API base before /models, e.g. http://127.0.0.1:1234/v1 (LM Studio), http://127.0.0.1:8080/v1 (llama.cpp, LocalAI), http://127.0.0.1:8000/v1 (vLLM), http://127.0.0.1:1337/v1 (Jan)"},
			"apiKey":{"type":"string","x-secret":true,"description":"Only if the server asks for an API key"},
			"maxTokens":{"type":"integer","minimum":1,"maximum":8192,"default":512,"description":"Longest answer chat may ask for, in tokens"},
			"timeoutSeconds":{"type":"integer","minimum":5,"maximum":600,"default":120,"description":"How long one chat may take"},
			"models":{"type":"array","items":{"type":"string"},"maxItems":200,"description":"Model ids chat may use. Empty: only models the server lists, and never a variant such as :online (a paid web search on each call) unless it's named here"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "models", Title: "Models", Description: "The models the server offers, with owner where it says.", Risk: sdk.RiskRead},
			{Name: "chat", Title: "Chat", Description: "Sends one message (and an optional system prompt) to a model and returns its answer and token counts. The answer is capped at the instance's max tokens, and the model is one the instance's models allow (with none set, one the server lists, without a variant such as :online). Write: it uses the server's compute, and on a paid endpoint it costs money.", Risk: sdk.RiskWrite, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["model","prompt"],"properties":{"model":{"type":"string","description":"A model id from models"},"prompt":{"type":"string","x-multiline":true,"maxLength":16000},"system":{"type":"string","x-multiline":true,"maxLength":4000},"maxTokens":{"type":"integer","minimum":1,"maximum":8192,"description":"At most the instance's max tokens"},"temperature":{"type":"number","minimum":0,"maximum":2}}}`)},
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
		c.URL = "http://127.0.0.1:1234/v1"
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.URL), "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is the API base, like http://127.0.0.1:1234/v1 (no user, query or fragment)")
	}
	if strings.HasSuffix(u.Path, "/chat/completions") || strings.HasSuffix(u.Path, "/models") {
		return errors.New("enter the API base (ending in /v1), not an endpoint")
	}
	if c.APIKey != "" && !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	switch {
	case c.MaxTokens == 0:
		c.MaxTokens = defaultMaxTokens
	case c.MaxTokens < 1 || c.MaxTokens > ceilingTokens:
		return fmt.Errorf("max tokens is 1 to %d", ceilingTokens)
	}
	switch {
	case c.TimeoutSeconds == 0:
		c.TimeoutSeconds = 120
	case c.TimeoutSeconds < 5 || c.TimeoutSeconds > 600:
		return errors.New("the timeout is 5 to 600 seconds")
	}
	if len(c.Models) > 200 {
		return errors.New("list at most 200 models")
	}
	allowed := map[string]bool{}
	for _, id := range c.Models {
		id = strings.TrimSpace(id)
		if !modelRe.MatchString(id) || strings.Contains(id, "//") || strings.Contains(id, "..") {
			return fmt.Errorf("%q isn't a model id", id)
		}
		allowed[id] = true
	}
	ref := c.APIKey
	auth := func(ctx context.Context, r *http.Request) error {
		if ref == "" {
			return nil
		}
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
		return nil
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	base := u.String()
	// Every request goes to the configured host only: no redirects
	// elsewhere, and no request path ever comes from the caller.
	api := rest.New(base, auth)
	api.HTTP = rest.SameHostOnly(client)
	api.HTTP.Timeout = 30 * time.Second
	chat := rest.New(base, auth)
	chat.HTTP = rest.SameHostOnly(client)
	chat.HTTP.Timeout = time.Duration(c.TimeoutSeconds) * time.Second
	m.set.Put(id, &conn{api: api, chat: chat, host: u.Host, maxTokens: c.MaxTokens, allowed: allowed})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the server refused the API key")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("the server has no such endpoint or model (is the address the API base, ending in /v1?)")
	}
	return err
}

type modelList struct {
	Data []struct {
		ID      string `json:"id"`
		OwnedBy string `json:"owned_by"`
	} `json:"data"`
}

func (c *conn) models(ctx context.Context) (modelList, error) {
	var out modelList
	_, err := c.api.Do(ctx, http.MethodGet, "/models", nil, nil, &out)
	return out, friendly(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	l, err := c.models(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if len(l.Data) == 0 {
		return sdk.Health{Status: "degraded", Message: c.host + " answers but offers no models (none loaded?)"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s offers %d model(s)", c.host, len(l.Data))}
}

// allow says whether chat may use a model: one the settings list, or with
// none listed, one the server lists itself (never a routing variant).
func (c *conn) allow(ctx context.Context, model string) error {
	if len(c.allowed) > 0 {
		if !c.allowed[model] {
			return fmt.Errorf("this instance's settings don't allow the model %s", model)
		}
		return nil
	}
	if variantRe.MatchString(model) {
		return fmt.Errorf("%s is a routing variant (it can add paid features such as web search); name it in the instance's models to allow it", model)
	}
	l, err := c.models(ctx)
	if err != nil {
		return err
	}
	for _, x := range l.Data {
		if x.ID == model {
			return nil
		}
	}
	return fmt.Errorf("the server doesn't list the model %s; see models, or name it in the instance's models", model)
}

func clip(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s, true
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "models":
		l, err := c.models(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		type model struct {
			ID      string `json:"id"`
			OwnedBy string `json:"ownedBy,omitempty"`
		}
		list := []model{}
		for _, x := range l.Data {
			list = append(list, model{x.ID, x.OwnedBy})
		}
		return sdk.JSON(list)
	case "chat":
		var p struct {
			Model       string   `json:"model"`
			Prompt      string   `json:"prompt"`
			System      string   `json:"system"`
			MaxTokens   int      `json:"maxTokens"`
			Temperature *float64 `json:"temperature"`
		}
		if err := sdk.Decode(call, &p); err != nil {
			return sdk.Result{}, err
		}
		if !modelRe.MatchString(p.Model) || strings.Contains(p.Model, "//") || strings.Contains(p.Model, "..") {
			return sdk.Result{}, errors.New("give a model id from models")
		}
		if strings.TrimSpace(p.Prompt) == "" || utf8.RuneCountInString(p.Prompt) > maxPrompt {
			return sdk.Result{}, fmt.Errorf("the prompt is 1 to %d characters", maxPrompt)
		}
		if utf8.RuneCountInString(p.System) > maxSystem {
			return sdk.Result{}, fmt.Errorf("the system prompt is at most %d characters", maxSystem)
		}
		if p.MaxTokens < 0 {
			return sdk.Result{}, errors.New("max tokens is at least 1")
		}
		if p.MaxTokens > c.maxTokens {
			return sdk.Result{}, fmt.Errorf("this instance allows at most %d tokens per answer", c.maxTokens)
		}
		if p.MaxTokens == 0 {
			p.MaxTokens = c.maxTokens
		}
		if p.Temperature != nil && (*p.Temperature < 0 || *p.Temperature > 2) {
			return sdk.Result{}, errors.New("temperature is 0 to 2")
		}
		if err := c.allow(ctx, p.Model); err != nil {
			return sdk.Result{}, err
		}
		msgs := []map[string]string{}
		if strings.TrimSpace(p.System) != "" {
			msgs = append(msgs, map[string]string{"role": "system", "content": p.System})
		}
		msgs = append(msgs, map[string]string{"role": "user", "content": p.Prompt})
		body := map[string]any{"model": p.Model, "messages": msgs, "max_tokens": p.MaxTokens, "stream": false}
		if p.Temperature != nil {
			body["temperature"] = *p.Temperature
		}
		var out struct {
			Model   string `json:"model"`
			Choices []struct {
				Message struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				Prompt     int `json:"prompt_tokens"`
				Completion int `json:"completion_tokens"`
				Total      int `json:"total_tokens"`
			} `json:"usage"`
		}
		start := time.Now()
		if _, err := c.chat.Do(ctx, http.MethodPost, "/chat/completions", nil, body, &out); err != nil {
			return sdk.Result{}, friendly(err)
		}
		if len(out.Choices) == 0 {
			return sdk.Result{}, errors.New("the server answered without a reply")
		}
		ch := out.Choices[0]
		answer, cut := clip(ch.Message.Content, maxAnswer)
		res := map[string]any{"model": p.Model, "answer": answer, "finishReason": ch.FinishReason, "maxTokens": p.MaxTokens,
			"seconds": float64(time.Since(start).Milliseconds()) / 1000}
		if cut {
			res["truncated"] = true
		}
		if ch.Message.ReasoningContent != "" {
			r, _ := clip(ch.Message.ReasoningContent, maxAnswer)
			res["reasoning"] = r
		}
		if out.Usage != nil {
			res["promptTokens"], res["completionTokens"], res["totalTokens"] = out.Usage.Prompt, out.Usage.Completion, out.Usage.Total
		}
		return sdk.JSON(res)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
