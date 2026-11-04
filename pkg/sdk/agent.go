package sdk

import (
	"context"
	"encoding/json"
)

// AgentContext is optionally implemented by modules that give AI agents
// context of their own, beyond tools: MCP resources, MCP prompts and a line
// in the MCP server's instructions.
//
// The listing comes from the module directly, but content is always fetched
// by running the named read action through the permission engine, so agent
// rules and the audit log apply exactly as for a tool call. Entries that
// name an action that is not a read are ignored.
type AgentContext interface {
	AgentContext(ctx context.Context, instance string) AgentContextSpec
}

// AgentContextSpec is what one instance offers agents.
type AgentContextSpec struct {
	// Instructions is appended to the MCP server's instructions. Keep it to
	// a sentence or two telling agents when to use the module.
	Instructions string          `json:"instructions,omitempty"`
	Resources    []AgentResource `json:"resources,omitempty"`
	Prompts      []AgentPrompt   `json:"prompts,omitempty"`
}

// AgentResource is one readable document, e.g. conduit://standards/a11y.
// Reading it runs Action with Input. An output that is a JSON string, or an
// object with a string "markdown" field, is served as text; anything else as
// JSON.
type AgentResource struct {
	URI         string          `json:"uri"`
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	MimeType    string          `json:"mimeType,omitempty"`
	Action      string          `json:"action"`
	Input       json.RawMessage `json:"input,omitempty"`
}

// AgentPrompt is one ready-made prompt. Getting it runs Action with Input,
// with the prompt's arguments merged in as top-level fields, and the text
// output becomes the prompt's user message.
type AgentPrompt struct {
	Name        string                `json:"name"`
	Title       string                `json:"title,omitempty"`
	Description string                `json:"description,omitempty"`
	Arguments   []AgentPromptArgument `json:"arguments,omitempty"`
	Action      string                `json:"action"`
	Input       json.RawMessage       `json:"input,omitempty"`
}

// AgentPromptArgument is one argument a prompt takes.
type AgentPromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}
