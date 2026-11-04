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
| `enable` / `disable` | write | Turns a proxy host on or off. Each is the other's undo; a host already in that state is left alone. |
| `certificates` | read | Name, provider, domains, expiry, days left and how many proxy hosts use each, soonest first. `withinDays` keeps those expiring within that many days, expired ones included. |
| `create_proxy_host` | write | `domains` (wildcards like `*.example.com` work), `forwardScheme`, `forwardHost`, `forwardPort`, an existing `certificateId`, `sslForced`, `http2`, `hstsEnabled`, `websockets`, `blockExploits` (on by default), `accessListId`, `advancedConfig`, `locations`. Refused when a domain already has a proxy host. The preview shows everything, custom nginx config in full. Undo deletes it. It doesn't request new certificates. |
| `delete_proxy_host` | destructive | With a preview. Undo creates it again with the same domains, target, certificate, flags, access list, advanced config and locations (under a new id). |

Redirection hosts, streams, 404 hosts, access lists and requesting
certificates aren't part of this module.

**Security.** The password is sent only to `/api/tokens`; the token NPM
returns is kept in memory, renewed before it expires and on a 401, and sent
as a bearer token. The client won't follow a redirect to another host.
Proxy host ids must be positive numbers, domains valid names, and the forward
host a plain host name or IP address (it ends up in nginx's configuration)
before anything is sent. Certificates' `meta` is never passed on: for DNS
challenges it holds the DNS provider's API credentials.
