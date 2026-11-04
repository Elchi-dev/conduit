# Keycloak

A Keycloak server through its admin REST API: realms, users and their
counts, sessions, disabling and enabling a user, signing a user out of
every session, and clients.

**Setup.** In the realm Conduit signs in to (often `master`, or the realm
you manage), create a confidential OpenID Connect client with *Client
authentication* and *Service accounts roles* on and every other flow off.
On its *Service account roles* tab assign, from `realm-management`,
`view-realm`, `view-users` and `view-clients`, plus `manage-users` for
disabling, enabling and signing out. Store the client secret (Credentials
tab) in the vault. Enter the address (`https://sso.example.com`, or with
`/auth` for Keycloak before 17), the realm to manage, the client's realm if
it's another one (`authRealm`), the client ID and the secret reference. For
a self-signed certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `realms` | read | Realms the service account can see, with display name and whether they're enabled. |
| `users` | read, sensitive | The realm's user count (matching `search`) and, unless `countOnly`, a page (`first`, `max` up to 100) with ID, username, email, names, enabled, email verified, created and whether the user is federated. Sensitive because it's personal data. Never credentials. |
| `sessions` | read | Active and offline sessions per client with totals, or a `user`'s sessions with start, last access and clients. Never IP addresses. |
| `disable_user` | destructive | Turns a `user` (ID or exact username) off so they can't sign in. The preview counts their sessions, which keep working until they expire or `logout_user` ends them, and warns when the user comes from a federated directory. Undo enables them. |
| `enable_user` | destructive | Turns a user back on, which grants access again, so it's destructive too. Undo disables them. |
| `logout_user` | destructive | Ends every session of a user in the realm. The preview counts them. Access tokens already issued stay valid until they expire. |
| `clients` | read | Clients (with a `search` on the client ID): ID, name, protocol, public, confidential or bearer-only, enabled, service account, standard flow, root URL, redirect URIs and authenticator. Never client secrets or registration tokens. |

`disable_user` and `enable_user` read the user's full representation and
send it back with only `enabled` changed (leaving out credentials), because
Keycloak's update replaces the user and could otherwise drop attributes or
required actions.

**Security.** The client secret is used only for the client-credentials
grant at the realm's token endpoint on the configured host; the access
token is kept in memory until shortly before it expires and fetched again
once if Keycloak refuses it. Requests follow redirects only within the same
host and never from https to http, so neither the secret nor the token can
be sent elsewhere. Realm names are checked (and `.` and `..` refused), user
IDs must be IDs Keycloak returned or UUIDs, usernames must be plain text,
and everything is escaped before it reaches a path.
