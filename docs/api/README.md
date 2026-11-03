# API

Conduit has five API layers behind one key system. Specs live in
`api/openapi/`; the TypeScript client is generated from them, and tests keep the Go routes and the specs in step.

| Layer | Base | Spec |
| --- | --- | --- |
| Daemon API | `<daemon>/api/v1` | `api/openapi/daemon.yaml` |
| Hub API | `<hub>/v1` | `api/openapi/hub.yaml` |
| Agent API | MCP over stdio and HTTP | `docs/api/mcp.md` |
| Module SDK | Go package and JSON-RPC over stdio | `docs/protocol/external-modules.md` |
| Webhooks and events | outbound HTTP signed with HMAC | `docs/api/webhooks.md` |

Daemon API keys (creation, scopes, rotation, revocation, usage logs) are in
[keys.md](keys.md). Hub tokens and hub API key scopes are in
[docs/protocol/hub.md](../protocol/hub.md#parties-and-tokens).

The daemon API is also reachable through a hub's encrypted relay; see
[docs/protocol/hub.md](../protocol/hub.md#what-a-relayed-request-can-do) for
what differs (no cookies, no event stream yet).
