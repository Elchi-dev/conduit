# API

Conduit has five API layers behind one key system. Specs live in
`api/openapi/`; Go handlers and the TypeScript client are generated from them.

| Layer | Base | Spec |
| --- | --- | --- |
| Daemon API | `<daemon>/api/v1` | `api/openapi/daemon.yaml` |
| Hub API | `<hub>/v1` | `api/openapi/hub.yaml` |
| Agent API | MCP over stdio and HTTP | `docs/api/mcp.md` |
| Module SDK | Go package and JSON-RPC over stdio | `docs/protocol/external-modules.md` |
| Webhooks and events | outbound HTTP signed with HMAC | `docs/api/webhooks.md` |

The API key workflow (creation, scopes, rotation, revocation) is documented in
`docs/api/keys.md` once it lands in phase 3.
