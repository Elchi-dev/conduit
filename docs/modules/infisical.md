# Infisical

Infisical, cloud or self-hosted, as a machine identity with Universal Auth:
projects and their environments, folders and secret keys under a path, a
secret's version history, and the values of named secrets only through
`reveal_secret`. Values and comments never come from the read actions
(comments often hold secrets too). The module never creates, edits or
deletes secrets and never changes access (identities, client secrets,
roles).

**Setup.** In Infisical, create a machine identity with Universal Auth, add
it to only the projects Conduit should see with a read-only role (Viewer, or
a custom role with read on secrets), and create a client secret. Enter the
`url` (`https://app.infisical.com`, `https://eu.infisical.com` or your own
server), the `clientId`, and the client secret as a `secret://` reference.
Optionally set a default `project` (id or slug) and `environment` (slug,
like `prod`). For a self-signed certificate, enter its SHA-256
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | The server's status message and date, and whether email, Redis and secret scanning are set up. |
| `projects` | read | Name, id, slug, environment slugs and dates of each project the identity is in. |
| `environments` | read | A project's environments with name, slug and id. |
| `secrets` | read | Folders and secret keys under a `path` (`/` when empty) of one `environment`, with id, version, type, tag slugs and dates. Never values or comments; the module asks the server to leave values out (`viewSecretValue=false`) and drops them either way. |
| `versions` | read | A secret's versions (by `key`), newest first: number, type, dates and who made them. Never values. |
| `reveal_secret` | destructive, sensitive | The values of the `keys` named (1 to 10) in one environment and path, and no others; never comments. Keys not found are listed as `missing`. Revealing a credential can't be taken back, so it's destructive. |

**Security.** The client secret goes only to `/api/v1/auth/universal-auth/login`;
the short-lived access token it returns is kept in memory until a minute
before it expires and sent as `Authorization: Bearer`. A refused session
logs in again once. The client follows redirects only within the same host
and never from https to http. Project, environment, folder path and secret
keys are checked (no `..`, slashes in keys, query or control characters)
before they go into a request.
