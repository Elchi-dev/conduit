# Stability and versioning

What you can build on, and how changes reach you. This applies from
v1.0.0; until then, breaking changes are possible between minor releases
and are listed in the release notes.

## What is stable

| Surface | Stable contract |
| --- | --- |
| Daemon API | everything under `/api/v1` described in `api/openapi/daemon.yaml` |
| Hub API | everything under `/v1` described in `api/openapi/hub.yaml` |
| Agent API (MCP) | tool names and input shapes generated from module manifests; `conduit_*` tools in [mcp.md](mcp.md) |
| Module SDK | `pkg/sdk` (Go), the JSON-RPC protocol for external modules, and the WebAssembly host functions |
| Webhooks | event names, payload shape and the `X-Conduit-Signature` scheme in [webhooks.md](webhooks.md) |
| Relay and sync | the wire formats in `docs/protocol/` (old and new peers interoperate) |
| Data folder | every release opens folders made by earlier releases (tested in CI from every tag) |
| CLI | commands, flags and `--json` output of `conduit` |

Not covered: anything marked experimental in the docs, routes missing from
the OpenAPI specs, the web app's markup, log text, and error message
wording (match on the HTTP status, not on the `error` text).

## The rules

- **Within v1, nothing is removed or changed incompatibly.** New
  endpoints, fields, actions, events, scopes and optional inputs can be
  added at any time, so clients must ignore fields they don't know.
- **Deprecation before removal.** A deprecated endpoint, field or SDK
  function keeps working for at least two minor releases and six months,
  sends a `Deprecation` header (HTTP) or is marked `Deprecated:` (Go), and
  is listed in the release notes with what replaces it.
- **Breaking changes need a new major version** (`/api/v2`, SDK v2). The
  previous major keeps being served alongside it for at least a year.
- **Security fixes are the one exception.** If keeping an old behaviour
  would leave people exposed, it changes in a patch release, explained in
  its notes.
- **Module actions** belong to their module. A built-in module keeps its
  action names and input shapes within a major version; it may add risk
  (an action needing approval) but never lowers it silently.

## Versions

Releases follow [semantic versioning](https://semver.org): patch releases
fix things, minor releases add things, major releases may break things.
The daemon reports its version at `GET /api/v1/version`; the spec it
implements is `api/openapi/daemon.yaml` at that version's tag.

## Support

The latest minor release gets every fix. The previous minor release gets
security fixes for three months after its successor ships.
