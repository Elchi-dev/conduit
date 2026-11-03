# AI layer

Code: `internal/ai`. Four ways agents work with Conduit, one set of rules.

```
             built-in assistant ──┐
 MCP client ── /mcp (HTTP) ───────┼──▶ Toolbox ──▶ Engine.Invoke (as an agent) ──▶ policy · approvals · audit
 MCP client ── conduitd mcp ──────┘
 outside MCP server ◀── Bridge (mounted as a module, called through the engine like any other)
```

## Toolbox (`tools.go`)

Builds tools from every enabled instance's actions (`<instance>__<action>`,
input schema from the action, `readOnlyHint`/`destructiveHint` from its risk),
filtered by the caller's scopes, plus Conduit's own tools: overview, preview
(dry run), approval status, what changed, timeline, undo and emergency stop.
Calls never wait for approvals; they return the approval id and the plan, and
the agent checks back. Results are text for the model, with timeline entry
numbers and undo hints.

## MCP server (`mcp.go`, `stdio.go`)

Streamable HTTP at `POST /mcp` (JSON responses, stateless, protocol versions
2025-06-18, 2025-03-26 and 2024-11-05), authenticated with an agent key.
`conduitd mcp` relays stdio clients to it. See [docs/api/mcp.md](../api/mcp.md).

## Providers (`providers.go`)

Two adapters cover nearly every model:

| Kind | API | Examples |
| --- | --- | --- |
| `anthropic` | Messages API | Anthropic |
| `openai` | Chat Completions | OpenAI, Gemini (OpenAI endpoint), Mistral, OpenRouter, Groq, Ollama, LM Studio, vLLM, company gateways |

API keys are vault references. Plain `http` is only accepted for hosts on
this machine or a private network. `GET /api/v1/ai/detect` finds Ollama and
LM Studio running locally and lists their models.

## Built-in assistant (`agent.go`)

A drawer available on every screen (and from the command bar: type a
question, choose "Ask the assistant"). Each turn streams steps as NDJSON:
text, tool calls, results and approval requests. It acts as the agent
`assistant-<user>`, so agent rules apply even though a person is typing;
when a call needs approval the drawer shows the approval card, and approving
it tells the assistant to continue. Conversations are stored per user. At
most 12 model round-trips per turn.

## Bridge (`bridge.go`)

Mounts an outside MCP server (a local command over stdio, or a remote HTTP
server) as a module named `mcp-<id>`. Its tools become actions. A tool is a
write unless the server marks it destructive (then destructive) or, when the
person adding the server chose `trustReadOnly`, read-only (then read); the
hints are the server's own claims, so by default a "read-only" tool still
follows the approval rules for changes. `riskOverrides` sets any tool's risk
explicitly. Credentials in environment variables or
headers must be vault references. Only signed-in people can add a server,
because a stdio server runs a command on this machine.

## Signature features here

- **Agent dry-run** (2): `conduit_preview` and plans attached to approvals.
- **What changed?** (4): `conduit_what_changed`, `GET /api/v1/audit/changes`
  and the timeline's "What changed?" panel. Configuration changes (systems,
  rules, automations, MCP servers) are audited so they show up there.
- **Record → automate** (3): tick steps on the timeline and turn them into an
  automation; inputs that contained secrets can't be picked.
