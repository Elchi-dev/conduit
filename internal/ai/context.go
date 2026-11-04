package ai

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Resource is an MCP resource offered by a module (sdk.AgentContext).
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`

	instance string
	action   string
	input    json.RawMessage
}

// Prompt is an MCP prompt offered by a module.
type Prompt struct {
	Name        string                    `json:"name"`
	Title       string                    `json:"title,omitempty"`
	Description string                    `json:"description,omitempty"`
	Arguments   []sdk.AgentPromptArgument `json:"arguments,omitempty"`

	instance string
	action   string
	input    json.RawMessage
}

type agentCtx struct {
	instance core.Instance
	spec     sdk.AgentContextSpec
	reads    map[string]bool
}

// contexts gathers what every enabled instance the caller may use offers
// agents beyond tools. Entries naming anything but a read action are dropped.
func (t *Toolbox) contexts(ctx context.Context) []agentCtx {
	if t == nil || t.Engine == nil {
		return nil
	}
	var out []agentCtx
	for _, in := range t.Engine.Instances("") {
		if !in.Enabled || (t.Allows != nil && !t.Allows("actions:"+in.Module+":invoke")) {
			continue
		}
		m, ok := t.Engine.Module(in.Module)
		if !ok {
			continue
		}
		p, ok := m.(sdk.AgentContext)
		if !ok {
			continue
		}
		reads := map[string]bool{}
		for _, a := range m.Manifest().Actions {
			if a.Risk == sdk.RiskRead && !a.Sensitive {
				reads[a.Name] = true
			}
		}
		out = append(out, agentCtx{instance: in, spec: p.AgentContext(ctx, in.ID), reads: reads})
	}
	return out
}

// Instructions is the MCP server's instructions: Conduit's own, then a line
// from each module that offers agent context.
func (t *Toolbox) Instructions(ctx context.Context) string {
	parts := []string{instructions}
	for _, c := range t.contexts(ctx) {
		if s := strings.TrimSpace(c.spec.Instructions); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n")
}

// Resources lists the MCP resources the caller can read, sorted by URI.
func (t *Toolbox) Resources(ctx context.Context) []Resource {
	seen := map[string]bool{}
	out := []Resource{}
	for _, c := range t.contexts(ctx) {
		for _, r := range c.spec.Resources {
			if r.URI == "" || !c.reads[r.Action] || seen[r.URI] {
				continue
			}
			seen[r.URI] = true
			name := r.Name
			if name == "" {
				name = r.URI
			}
			out = append(out, Resource{URI: r.URI, Name: name, Title: r.Title, Description: r.Description, MimeType: r.MimeType,
				instance: c.instance.ID, action: r.Action, input: r.Input})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URI < out[j].URI })
	return out
}

// Prompts lists the MCP prompts the caller can get. Names are prefixed with
// the instance like tool names ("standards__frontend-kit").
func (t *Toolbox) Prompts(ctx context.Context) []Prompt {
	seen := map[string]bool{}
	out := []Prompt{}
	for _, c := range t.contexts(ctx) {
		for _, p := range c.spec.Prompts {
			if p.Name == "" || !c.reads[p.Action] {
				continue
			}
			name := toolName(c.instance.ID, p.Name)
			if seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, Prompt{Name: name, Title: p.Title, Description: p.Description, Arguments: p.Arguments,
				instance: c.instance.ID, action: p.Action, input: p.Input})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var errNotFound = errors.New("not found")

// ReadResource runs the resource's read action as the caller and returns
// its text.
func (t *Toolbox) ReadResource(ctx context.Context, uri string) (Resource, string, error) {
	for _, r := range t.Resources(ctx) {
		if r.URI == uri {
			text, err := t.contextText(ctx, r.instance, r.action, r.input)
			return r, text, err
		}
	}
	return Resource{}, "", errNotFound
}

// GetPrompt runs the prompt's read action as the caller, with the
// arguments merged into its input, and returns its text.
func (t *Toolbox) GetPrompt(ctx context.Context, name string, args map[string]string) (Prompt, string, error) {
	for _, p := range t.Prompts(ctx) {
		if p.Name != name {
			continue
		}
		in := map[string]any{}
		if len(p.input) > 0 {
			_ = json.Unmarshal(p.input, &in)
		}
		for _, a := range p.Arguments {
			if v, ok := args[a.Name]; ok {
				in[a.Name] = v
			} else if a.Required {
				return p, "", errors.New("missing argument " + a.Name)
			}
		}
		b, _ := json.Marshal(in)
		text, err := t.contextText(ctx, p.instance, p.action, b)
		return p, text, err
	}
	return Prompt{}, "", errNotFound
}

func (t *Toolbox) contextText(ctx context.Context, instance, action string, input json.RawMessage) (string, error) {
	if len(input) == 0 {
		input = json.RawMessage(`{}`)
	}
	out, err := t.Engine.Invoke(ctx, t.Actor, sdk.Call{Instance: instance, Action: action, Input: input}, core.InvokeOptions{NoWait: true})
	if err != nil {
		r := t.outcome(out, err)
		return "", errors.New(r.Text)
	}
	return outputText(out.Result.Output), nil
}

// outputText turns an action's output into text: a JSON string as is, an
// object's "markdown" field, otherwise indented JSON.
func outputText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		Markdown *string `json:"markdown"`
	}
	if json.Unmarshal(raw, &o) == nil && o.Markdown != nil {
		return *o.Markdown
	}
	var v any
	_ = json.Unmarshal(raw, &v)
	return textJSON(v)
}
