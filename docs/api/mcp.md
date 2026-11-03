# Connecting AI agents over MCP

Conduit is a [Model Context Protocol](https://modelcontextprotocol.io) server.
Every action on every connected system is a tool, plus a few of Conduit's own.

## 1. Create an agent key

**API keys → Create key → An AI agent.** The default scopes let the agent act
(under your agent rules), see what's connected and check its approvals. Tick
"Read the timeline" to give it `conduit_what_changed` and `conduit_timeline`,
and "Undo actions" for `conduit_undo`.

## 2. Point your client at Conduit

**Clients that launch a command** (most desktop apps and coding assistants):

```json
{
  "mcpServers": {
    "conduit": {
      "command": "conduitd",
      "args": ["mcp"],
      "env": { "CONDUIT_API_KEY": "cdt_agent_…", "CONDUIT_URL": "http://127.0.0.1:7600" }
    }
  }
}
```

`conduitd mcp` relays between the client and the running daemon; it holds no
state.

**Clients that speak streamable HTTP** connect directly to
`POST http://127.0.0.1:7600/mcp` with `Authorization: Bearer cdt_agent_…`.

## Tools

| Tool | What it does |
| --- | --- |
| `conduit_overview` | Everything connected, with live health, approvals waiting, the active rules |
| `conduit_preview` | Dry-runs a tool that supports it and returns the exact changes |
| `conduit_approval_status` | Whether a request the agent made was approved |
| `conduit_what_changed` | Changes, failures and blocked attempts around a moment (needs `audit:*:read`) |
| `conduit_timeline` | Recent audit entries (needs `audit:*:read`) |
| `conduit_undo` | Undo a reversible entry (needs `audit:*:undo`) |
| `conduit_emergency_stop` | Freeze everything and revoke agent keys, including its own |
| `<system>__<action>` | One action on one connected system, e.g. `system__processes`, `docker_7k2m…__restart` |

Read-only tools carry `readOnlyHint`, destructive ones `destructiveHint`.

## How approvals look to an agent

A call that needs approval returns at once with an approval id (also in
`structuredContent.approvalId`) and the planned changes. The owner is
notified on every channel that takes approvals. The agent checks back with
`conduit_approval_status` and, once approved, calls the same tool again with
the same arguments. Denials are final; the server instructions tell agents
not to work around them.

## Using other MCP servers through Conduit

**Assistant and agents → Use tools from other MCP servers** mounts any MCP
server (a command such as `npx -y @modelcontextprotocol/server-github`, or an
HTTPS endpoint) as a Conduit module. Its tools then appear to your agents
through Conduit, under your rules and in your timeline.
