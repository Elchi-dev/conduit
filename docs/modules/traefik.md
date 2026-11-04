# Traefik

Reads a Traefik proxy's API (v2 and v3): the overview, routers, services,
middlewares and entry points of the HTTP, TCP and UDP providers, and which of
them are disabled or have warnings, with the error messages. Read-only:
Traefik's API can't change anything.

**Setup.** Enable the API (`api: {}` in the static configuration) and expose
it, either with `api.insecure` on port 8080 or through a router to
`api@internal`, usually with a `basicAuth` middleware. Enter the address
where `/api` is served, such as `https://traefik.example.com` (a trailing
`/dashboard` or `/api` is ignored), and for basic auth the username and the
password as a vault secret. For Traefik's default self-signed certificate,
set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `overview` | read | Version and codename, counts with warnings and errors per protocol, features and providers. |
| `routers` | read | Rule, entry points, service, middlewares, TLS (cert resolver, options, passthrough), priority and status. `protocol` (http, tcp, udp), `search`, `status` and `provider` filter. Every page is read. |
| `router` | read | One router by `name` with its provider (`web@docker`), with errors and the entry points it uses. |
| `services` | read | Type, status, servers with each one's status (UP or DOWN) and the routers using it. |
| `middlewares` | read | Type, status, provider and the routers using it. Their settings aren't shown: a `basicAuth` middleware's holds password hashes. |
| `entrypoints` | read | Name, address, redirections and default TLS resolver. |
| `errors` | read | Every router, service and middleware of every protocol that is disabled or has warnings or errors, disabled ones first, with their messages (a missing service, a bad rule, an unknown middleware). |

Health is degraded when the overview counts errors, and says how many
warnings there are.

**Security.** Basic auth credentials go only to the configured host; the
client won't follow a redirect to another host or from https to http.
Router names are checked (letters, digits, `@ . _ -`) before they go into a
request path.
