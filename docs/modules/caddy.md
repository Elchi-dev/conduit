# Caddy

Caddy's admin API, read-only: the sites and routes it serves and where they
proxy to, the reverse proxy's upstreams and their failures, TLS automation
policies and the local CA.

**Setup.** Caddy's admin API listens on `http://127.0.0.1:2019` by default,
which is also the module's default, so on the same machine there is nothing
to enter. For a Caddy elsewhere, change the admin listener (`admin
0.0.0.0:2019` in the Caddyfile's global options, with `origins` limiting who
may call it) and enter its address; if a reverse proxy guards it with basic
auth, add the username and the password's vault reference. The admin API
has full control over Caddy, so never expose it beyond a trusted network.

| Action | Risk | Notes |
| --- | --- | --- |
| `summary` | read | Apps, servers and their listen addresses, every host, route and upstream counts |
| `routes` | read | Hosts and paths matched, handler types, upstreams, file roots, static status codes; filter by server or host (wildcards match) |
| `upstreams` | read | Each upstream's active requests and recent failures |
| `tls` | read | Automation policies (subjects, issuers, challenge and DNS provider name), names with managed certificates, count of certificates loaded by hand |
| `pki_ca` | read | The internal CA's root and intermediate names and expiry dates |

**Nothing secret leaves Caddy.** The config is decoded only into the fields
above: handler settings (basic auth hashes, header values, forward auth),
DNS provider tokens, EAB credentials, account emails and loaded private
keys are never read out, and the raw config is never returned.

**Why read-only.** Caddy's admin API changes the running server by loading
a whole new config (`POST /load`) or patching it in place, and either is
lost or contradicted on the next restart from the Caddyfile. That belongs
in the Caddyfile or JSON under version control, so this module doesn't
offer it. Caddy has no API that lists the certificates it manages; `tls`
shows which names are managed instead.

Health is *degraded* when an upstream has recent failures (with passive
health checks) or no HTTP server is configured.
