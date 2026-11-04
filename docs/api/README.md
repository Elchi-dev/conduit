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
what differs (bearer tokens instead of cookies; the event stream arrives as streamed frames).

What stays stable, and how deprecations work: [stability.md](stability.md).

## Clients and kits

- `conduit`, the command-line client: run actions, follow events, read the
  audit log and approvals from a terminal or a script. See [../cli.md](../cli.md).

- `sdk/clients/typescript`: typed daemon and hub clients generated from the
  specs.
- `sdk/clients/python`: a one-file client for scripts; `invoke()` waits for
  approvals.
- `sdk/external`: starter kits for writing modules in Python, TypeScript and
  Go.
- [Single sign-on](sso.md): sign in to a daemon with Google Workspace, Microsoft Entra ID, Okta, Keycloak, Authentik or another OpenID Connect provider.
- Two-factor sign-in: when an account has it on, `POST /auth/login` (daemon) and `POST /v1/sessions` (hub) answer `{twoFactor: true, challenge}`; finish with `POST /auth/login/2fa` or `POST /v1/sessions/2fa` and a code. Clients that sign in with a password must handle this; API keys are unaffected. See [architecture/daemon.md](../architecture/daemon.md#two-factor-sign-in).
- Passkeys (daemon): `GET /auth/passkeys/available` says whether passkeys work at the address the request came to (only under a host name such as `localhost`, never an IP address). Sign in with `POST /auth/passkeys/login/begin` and `…/finish` (usernameless; answers the same session as `POST /auth/login`, and skips the two-factor code). Manage your own under `/me/passkeys`; adding one needs your password and a signed-in session, not an API key. Changing or resetting a password removes that person's passkeys. See [architecture/daemon.md](../architecture/daemon.md#passkeys).
