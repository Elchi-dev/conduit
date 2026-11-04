# Zitadel

Organizations, users, projects and applications of a Zitadel instance, and
deactivating and reactivating users.

**Setup.** In the console, create a service user (Users, Service Users),
add a personal access token, and store it in the vault. Give the service
user a role in the organization: Org User Manager to deactivate and
reactivate users, Org Owner Viewer to only read. Enter the instance's
address, such as `https://auth.example.com` or
`https://my-instance.zitadel.cloud`. Set `orgId` to work in another
organization than the service user's own (one instance per organization).
For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `orgs` | read | Organizations the token can see: id, name, state, primary domain. A token that may not search organizations sees its own. |
| `users` | read, sensitive | Total and a list (`search` in the user name, `state`, `type` human or machine, `limit`) with id, user name, display name, type, state, created and changed. Emails only with `includeEmail`. Personal data, so input and output stay out of the audit log, approvals and events. |
| `projects` | read | Projects (`search` by name) with state, role settings and their applications: type (OIDC, API, SAML), client id, app type, auth method, grant types, redirect URIs, dev mode, and a SAML app's metadata URL without its query. |
| `deactivate_user` | destructive | By `id` or exact `userName`. Stops the user signing in; the account stays. Refused for the token's own service user. Undo reactivates it. |
| `reactivate_user` | destructive | Lets a deactivated user sign in again (it grants access, hence destructive). A locked user is refused: unlock it in Zitadel. Undo deactivates it. |

Deactivating a user doesn't end sessions applications already hold; revoke
those in Zitadel or the application if it matters.

**Security.** The token goes in the `Authorization` header (and the
organization in `x-zitadel-orgid`), and the client won't follow a redirect
to another host or from https to http. User ids must be plain identifiers
and the organization id a number before they reach a request. Application
configs are decoded field by field, so client secrets, keys and SAML
metadata are never read; phone numbers aren't either.
