# Auth0

Users, applications and logs of an Auth0 tenant, and blocking and
unblocking users.

**Setup.** In the dashboard, create a Machine to Machine application
(Applications, Create Application) and authorize it for the Auth0 Management
API with the scopes `read:users`, `read:clients`, `read:logs` and
`read:roles`, plus `update:users` to block and unblock. Enter the tenant's
domain, such as `acme.eu.auth0.com`, the application's client id, and its
client secret as a vault reference. Conduit gets a Management API token with
these credentials and keeps it in memory until shortly before it expires.

| Action | Risk | Notes |
| --- | --- | --- |
| `users` | read, sensitive | Total and a list (`search` by the start of a name, nickname or email, `blocked`, `limit` up to 1000) with id, name, nickname, blocked, login count, last login, created and connections. Emails only with `includeEmail`. Personal data, so input and output stay out of the audit log, approvals and events. |
| `clients` | read | Applications: client id, name, description, type, first party, grant types, token endpoint auth method, callbacks and allowed origins. |
| `logs` | read, sensitive | The newest events (`type` code such as `s`, `f`, `fp`, `slo`, `sapi`; `user` id; `limit` up to 100) with date, kind, description, application, user, IP and connection. |
| `block_user` | destructive | By user id (like `auth0\|abc123`) or an email exactly one user has. Stops the user signing in; the account stays. Undo unblocks. |
| `unblock_user` | destructive | Lets a blocked user sign in again (it grants access, hence destructive). Undo blocks them again. |

Users with a role whose name says admin, owner or super are refused unless
`allowAdmins` is on; when the roles can't be read, the change is refused.
Conduit signs in as an application, never as a user, so it can't block
itself. A user already blocked (or unblocked) is reported as "nothing to
change".

**Security.** The domain must be a tenant name under `auth0.com` (with an
optional region such as `eu` or `us`) over https, so a look-alike such as
`acme.auth0.com.evil.test` is refused, and the client secret is sent only
there. The client won't follow a redirect to another host or from https to
http, including for the token request. Searches and log filters are checked
and escaped before they become an Auth0 query. Only harmless fields are
requested, and each is decoded on its own: client secrets, signing and
encryption keys, identity provider tokens, metadata and log request details
are never read.

**Notes.** Custom domains can't be used for the Management API, so enter the
tenant's `auth0.com` domain. A block from brute-force protection (too many
failed logins) is separate from the `blocked` flag and is cleared in the
dashboard.
