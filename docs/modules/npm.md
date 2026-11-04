# Nginx Proxy Manager

Proxy hosts (list, enable and disable, create, delete) and SSL certificates
with their expiry, through Nginx Proxy Manager's API.

**Setup.** NPM has no API keys, so the module signs in as an account. Create
a user for it (Users, Add user) with only the permissions it needs (Proxy
Hosts: manage; Certificates: view), store its password in the vault and enter
its email and the admin UI's address, such as `http://nas.lan:81`. The
account mustn't use two-factor sign-in. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `proxy_hosts` | read | Domains, forward target, certificate, SSL forced, HTTP/2, HSTS, WebSockets, access list, custom locations, enabled, and nginx's error for a host whose config failed. `query` filters by domain or forward host. |
| `enable` | write | Turns a proxy host on. Refused for a host with custom nginx config or locations, or one forwarding to a loopback address or NPM's admin UI (use `enable_advanced`). Undo disables it (at `disable`'s risk). A host already on is left alone. |
| `enable_advanced` | destructive | `enable` for the hosts it refuses: turning one on runs its custom configuration or publishes its loopback target, as `create_proxy_host_advanced` does. Undo disables it. |
| `disable` | destructive | Turns a proxy host off, so its domains stop being served. Undo enables it, through `enable_advanced` for a host `enable` refuses. A host already off is left alone. |
| `certificates` | read | Name, provider, domains, expiry, days left and how many proxy hosts use each, soonest first. `withinDays` keeps those expiring within that many days, expired ones included. |
| `create_proxy_host` | write | `domains` (wildcards like `*.example.com` work), `forwardScheme`, `forwardHost`, `forwardPort`, an existing `certificateId`, `sslForced`, `http2`, `hstsEnabled`, `websockets`, `blockExploits` (on by default), `accessListId`. Refused when a domain already has a proxy host, when the forward host is a loopback or unspecified address (`localhost`, `127.0.0.0/8`, `::1`, `0.0.0.0`), or when it's NPM's own host on port 81 or the admin UI's port. No custom nginx config or locations. The preview shows everything. Undo deletes it. It doesn't request new certificates. |
| `create_proxy_host_advanced` | destructive | Everything `create_proxy_host` takes, plus `advancedConfig` and `locations`, and loopback targets are allowed. Custom nginx config runs as nginx itself (OpenResty runs Lua; `alias` can serve any file, private keys included), which is why this is destructive. Each location may have only `path` (starting with `/`; letters, digits and `/ . _ ~ -`), `forward_scheme` (`http` or `https`), `forward_host` (a host name or IP address), `forward_port` (a whole number, 1 to 65535) and `advanced_config`; other fields are dropped. The preview shows the advanced config and every location in full. Undo deletes it. |
| `delete_proxy_host` | destructive | With a preview. Undo creates it again with the same domains, target, certificate, flags, access list, advanced config and locations (under a new id), through `create_proxy_host_advanced` when it had custom config, locations or a loopback target, otherwise through `create_proxy_host`. |

Redirection hosts, streams, 404 hosts, access lists and requesting
certificates aren't part of this module.

**Security.** The password is sent only to `/api/tokens`; the token NPM
returns is kept in memory, renewed before it expires and on a 401, and sent
as a bearer token. The client won't follow a redirect to another host.
Proxy host ids must be positive numbers, domains valid names, and the forward
host a plain host name or IP address (it ends up in nginx's configuration)
before anything is sent. Forward host names are compared as given, not
resolved, so a name that resolves to a loopback address isn't caught; give
the module's NPM account only the permissions it needs. Certificates' `meta` is never passed on: for DNS
challenges it holds the DNS provider's API credentials.
