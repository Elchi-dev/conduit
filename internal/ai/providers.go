package ai

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
)

// Provider is a configured model endpoint.
type Provider struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Kind    string            `json:"kind"` // anthropic | openai (any OpenAI-compatible API)
	BaseURL string            `json:"baseUrl"`
	Model   string            `json:"model"`
	APIKey  string            `json:"apiKey,omitempty"` // secret:// reference; empty for local servers
	Headers map[string]string `json:"headers,omitempty"`
	Default bool              `json:"default"`
}

// Presets help people fill in the common providers.
var Presets = []Provider{
	{Name: "Anthropic", Kind: "anthropic", BaseURL: "https://api.anthropic.com", Model: "claude-sonnet-4-5"},
	{Name: "OpenAI", Kind: "openai", BaseURL: "https://api.openai.com/v1", Model: "gpt-5"},
	{Name: "Google Gemini", Kind: "openai", BaseURL: "https://generativelanguage.googleapis.com/v1beta/openai", Model: "gemini-2.5-flash"},
	{Name: "Mistral", Kind: "openai", BaseURL: "https://api.mistral.ai/v1", Model: "mistral-large-latest"},
	{Name: "OpenRouter", Kind: "openai", BaseURL: "https://openrouter.ai/api/v1", Model: "anthropic/claude-sonnet-4.5"},
	{Name: "Ollama (this computer)", Kind: "openai", BaseURL: "http://127.0.0.1:11434/v1", Model: "qwen3:8b"},
	{Name: "LM Studio (this computer)", Kind: "openai", BaseURL: "http://127.0.0.1:1234/v1", Model: ""},
}

// Providers stores provider configurations.
type Providers struct {
	db      *sql.DB
	secrets core.SecretResolver
	HTTP    *http.Client
}

// NewProviders returns the provider store.
func NewProviders(st *core.Store, secrets core.SecretResolver) *Providers {
	return &Providers{db: st.DB, secrets: secrets, HTTP: &http.Client{Timeout: 5 * time.Minute}}
}

// List returns all providers, default first.
func (p *Providers) List(ctx context.Context) ([]Provider, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT id, name, kind, base_url, model, api_key, headers, is_default FROM ai_providers ORDER BY is_default DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Provider{}
	for rows.Next() {
		var pr Provider
		var hdr string
		if err := rows.Scan(&pr.ID, &pr.Name, &pr.Kind, &pr.BaseURL, &pr.Model, &pr.APIKey, &hdr, &pr.Default); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(hdr), &pr.Headers)
		out = append(out, pr)
	}
	return out, rows.Err()
}

// Get returns one provider, or the default when id is empty.
func (p *Providers) Get(ctx context.Context, id string) (Provider, error) {
	list, err := p.List(ctx)
	if err != nil {
		return Provider{}, err
	}
	for _, pr := range list {
		if pr.ID == id || (id == "" && pr.Default) {
			return pr, nil
		}
	}
	if id == "" && len(list) > 0 {
		return list[0], nil
	}
	return Provider{}, errors.New("no AI provider is set up: add one under Assistant → Providers")
}

// Save validates and stores a provider.
func (p *Providers) Save(ctx context.Context, pr Provider) (Provider, error) {
	if pr.Kind != "anthropic" && pr.Kind != "openai" {
		return pr, errors.New(`kind must be "anthropic" or "openai" (any OpenAI-compatible API)`)
	}
	u, err := url.Parse(pr.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return pr, fmt.Errorf("invalid base URL %q", pr.BaseURL)
	}
	if u.Scheme == "http" && !isLocal(u.Hostname()) {
		return pr, errors.New("use https for providers that aren't on this computer or network")
	}
	if pr.APIKey != "" && !strings.HasPrefix(pr.APIKey, "secret://") {
		return pr, errors.New("store the API key in the vault and enter its reference, e.g. secret://ai/openai")
	}
	if pr.Model == "" {
		return pr, errors.New("choose a model")
	}
	if strings.TrimSpace(pr.Name) == "" {
		pr.Name = u.Host
	}
	if pr.ID == "" {
		pr.ID = core.NewID("prov")
	}
	if pr.Headers == nil {
		pr.Headers = map[string]string{}
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return pr, err
	}
	defer tx.Rollback()
	var n int
	_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ai_providers WHERE id != ?`, pr.ID).Scan(&n)
	if n == 0 {
		pr.Default = true
	}
	if pr.Default {
		if _, err := tx.ExecContext(ctx, `UPDATE ai_providers SET is_default = 0`); err != nil {
			return pr, err
		}
	}
	hdr, _ := json.Marshal(pr.Headers)
	_, err = tx.ExecContext(ctx, `INSERT INTO ai_providers (id, name, kind, base_url, model, api_key, headers, is_default, created_at) VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind, base_url=excluded.base_url, model=excluded.model, api_key=excluded.api_key, headers=excluded.headers, is_default=excluded.is_default`,
		pr.ID, pr.Name, pr.Kind, strings.TrimRight(pr.BaseURL, "/"), pr.Model, pr.APIKey, string(hdr), pr.Default, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return pr, err
	}
	return pr, tx.Commit()
}

// Delete removes a provider.
func (p *Providers) Delete(ctx context.Context, id string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM ai_providers WHERE id = ?`, id)
	return err
}

func isLocal(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") {
		return true
	}
	return strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") ||
		strings.HasPrefix(host, "172.16.") || strings.HasPrefix(host, "100.") || host == "::1"
}

// Detect looks for model servers running on this computer.
func (p *Providers) Detect(ctx context.Context) []Provider {
	var found []Provider
	try := func(name, probe, base string, parse func([]byte) []string) {
		cctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		req, _ := http.NewRequestWithContext(cctx, http.MethodGet, probe, nil)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		models := parse(b)
		pr := Provider{Name: name, Kind: "openai", BaseURL: base}
		if len(models) > 0 {
			pr.Model = models[0]
		}
		pr.Headers = map[string]string{"x-detected-models": strings.Join(models, ",")}
		found = append(found, pr)
	}
	try("Ollama (this computer)", "http://127.0.0.1:11434/api/tags", "http://127.0.0.1:11434/v1", func(b []byte) []string {
		var r struct {
			Models []struct{ Name string } `json:"models"`
		}
		_ = json.Unmarshal(b, &r)
		var out []string
		for _, m := range r.Models {
			out = append(out, m.Name)
		}
		return out
	})
	try("LM Studio (this computer)", "http://127.0.0.1:1234/v1/models", "http://127.0.0.1:1234/v1", func(b []byte) []string {
		var r struct {
			Data []struct{ ID string } `json:"data"`
		}
		_ = json.Unmarshal(b, &r)
		var out []string
		for _, m := range r.Data {
			out = append(out, m.ID)
		}
		return out
	})
	return found
}

// --- chat -------------------------------------------------------------------

// Msg is one message in the conversation, provider-neutral.
type Msg struct {
	Role       string     `json:"role"` // user, assistant, tool
	Text       string     `json:"text,omitempty"`
	ToolCalls  []ToolCall `json:"toolCalls,omitempty"`
	ToolCallID string     `json:"toolCallId,omitempty"`
	IsError    bool       `json:"isError,omitempty"`
}

// ToolCall is a model's request to call a tool.
type ToolCall struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

// Complete asks the model for its next message.
func (p *Providers) Complete(ctx context.Context, pr Provider, system string, msgs []Msg, tools []Tool) (Msg, error) {
	key := ""
	if pr.APIKey != "" {
		k, err := p.secrets.Resolve(ctx, pr.APIKey)
		if err != nil {
			return Msg{}, fmt.Errorf("API key: %w", err)
		}
		key = k
	}
	if pr.Kind == "anthropic" {
		return p.anthropic(ctx, pr, key, system, msgs, tools)
	}
	return p.openai(ctx, pr, key, system, msgs, tools)
}

func (p *Providers) post(ctx context.Context, pr Provider, url string, hdr map[string]string, body any, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range pr.Headers {
		if !strings.HasPrefix(k, "x-detected") {
			req.Header.Set(k, v)
		}
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := p.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if res.StatusCode >= 300 {
		var e struct {
			Error json.RawMessage `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		msg := string(e.Error)
		var em struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(e.Error, &em) == nil && em.Message != "" {
			msg = em.Message
		}
		if msg == "" {
			msg = strings.TrimSpace(string(data))
		}
		return fmt.Errorf("%s answered %s: %s", pr.Name, res.Status, truncate(msg, 500))
	}
	return json.Unmarshal(data, out)
}

func (p *Providers) anthropic(ctx context.Context, pr Provider, key, system string, msgs []Msg, tools []Tool) (Msg, error) {
	type block struct {
		Type      string          `json:"type"`
		Text      string          `json:"text,omitempty"`
		ID        string          `json:"id,omitempty"`
		Name      string          `json:"name,omitempty"`
		Input     json.RawMessage `json:"input,omitempty"`
		ToolUseID string          `json:"tool_use_id,omitempty"`
		Content   string          `json:"content,omitempty"`
		IsError   bool            `json:"is_error,omitempty"`
	}
	type message struct {
		Role    string  `json:"role"`
		Content []block `json:"content"`
	}
	var out []message
	for _, m := range msgs {
		switch m.Role {
		case "user":
			out = append(out, message{Role: "user", Content: []block{{Type: "text", Text: m.Text}}})
		case "assistant":
			var bl []block
			if m.Text != "" {
				bl = append(bl, block{Type: "text", Text: m.Text})
			}
			for _, c := range m.ToolCalls {
				bl = append(bl, block{Type: "tool_use", ID: c.ID, Name: c.Name, Input: nonEmpty(c.Args)})
			}
			out = append(out, message{Role: "assistant", Content: bl})
		case "tool":
			res := block{Type: "tool_result", ToolUseID: m.ToolCallID, Content: m.Text, IsError: m.IsError}
			// Consecutive tool results go into one user message.
			if n := len(out); n > 0 && out[n-1].Role == "user" && len(out[n-1].Content) > 0 && out[n-1].Content[0].Type == "tool_result" {
				out[n-1].Content = append(out[n-1].Content, res)
			} else {
				out = append(out, message{Role: "user", Content: []block{res}})
			}
		}
	}
	type tool struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"input_schema"`
	}
	var ts []tool
	for _, t := range tools {
		ts = append(ts, tool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	var resp struct {
		Content []block `json:"content"`
	}
	body := map[string]any{"model": pr.Model, "max_tokens": 4096, "system": system, "messages": out, "tools": ts}
	err := p.post(ctx, pr, pr.BaseURL+"/v1/messages", map[string]string{"x-api-key": key, "anthropic-version": "2023-06-01"}, body, &resp)
	if err != nil {
		return Msg{}, err
	}
	reply := Msg{Role: "assistant"}
	var texts []string
	for _, b := range resp.Content {
		switch b.Type {
		case "text":
			texts = append(texts, b.Text)
		case "tool_use":
			reply.ToolCalls = append(reply.ToolCalls, ToolCall{ID: b.ID, Name: b.Name, Args: b.Input})
		}
	}
	reply.Text = strings.TrimSpace(strings.Join(texts, "\n"))
	return reply, nil
}

func (p *Providers) openai(ctx context.Context, pr Provider, key, system string, msgs []Msg, tools []Tool) (Msg, error) {
	type fn struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	type call struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function fn     `json:"function"`
	}
	type message struct {
		Role       string  `json:"role"`
		Content    *string `json:"content"`
		ToolCalls  []call  `json:"tool_calls,omitempty"`
		ToolCallID string  `json:"tool_call_id,omitempty"`
	}
	str := func(s string) *string { return &s }
	out := []message{{Role: "system", Content: str(system)}}
	for _, m := range msgs {
		switch m.Role {
		case "user":
			out = append(out, message{Role: "user", Content: str(m.Text)})
		case "assistant":
			msg := message{Role: "assistant"}
			if m.Text != "" {
				msg.Content = str(m.Text)
			}
			for _, c := range m.ToolCalls {
				msg.ToolCalls = append(msg.ToolCalls, call{ID: c.ID, Type: "function", Function: fn{Name: c.Name, Arguments: string(nonEmpty(c.Args))}})
			}
			out = append(out, msg)
		case "tool":
			out = append(out, message{Role: "tool", ToolCallID: m.ToolCallID, Content: str(m.Text)})
		}
	}
	type function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	}
	type tool struct {
		Type     string   `json:"type"`
		Function function `json:"function"`
	}
	var ts []tool
	for _, t := range tools {
		ts = append(ts, tool{Type: "function", Function: function{Name: t.Name, Description: truncate(t.Description, 1000), Parameters: t.InputSchema}})
	}
	body := map[string]any{"model": pr.Model, "messages": out}
	if len(ts) > 0 {
		body["tools"] = ts
	}
	hdr := map[string]string{}
	if key != "" {
		hdr["Authorization"] = "Bearer " + key
	}
	var resp struct {
		Choices []struct {
			Message message `json:"message"`
		} `json:"choices"`
	}
	if err := p.post(ctx, pr, pr.BaseURL+"/chat/completions", hdr, body, &resp); err != nil {
		return Msg{}, err
	}
	if len(resp.Choices) == 0 {
		return Msg{}, errors.New("the model returned no answer")
	}
	m := resp.Choices[0].Message
	reply := Msg{Role: "assistant"}
	if m.Content != nil {
		reply.Text = strings.TrimSpace(*m.Content)
	}
	for _, c := range m.ToolCalls {
		reply.ToolCalls = append(reply.ToolCalls, ToolCall{ID: c.ID, Name: c.Function.Name, Args: json.RawMessage(nonEmpty(json.RawMessage(c.Function.Arguments)))})
	}
	return reply, nil
}

func nonEmpty(b json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(b)) == 0 {
		return json.RawMessage(`{}`)
	}
	return b
}
