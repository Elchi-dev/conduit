# Bitwarden Secrets Manager

Bitwarden Secrets Manager as a machine account: the projects it can read,
its secrets' keys, and the values of named secrets only through
`reveal_secret`. Notes are never returned, since they often hold secrets
too. The module never creates, edits or deletes secrets and never changes
access (machine accounts, access tokens, project grants). It is unrelated to
the password manager; see [vaultwarden](vaultwarden.md) for a Vaultwarden
server.

**Setup.** In Secrets Manager, create a machine account, give it **read**
access to only the projects Conduit should see, and create an access token
for it. Store the whole token, `0.<id>.<secret>:<key>`, in Conduit's vault
and enter its `secret://` reference. Pick the `region`: `us` for
bitwarden.com, `eu` for bitwarden.eu, or `self-hosted` with the
`serverUrl` (the API and identity service are taken as `<serverUrl>/api`
and `<serverUrl>/identity`). A self-signed certificate can be trusted by
its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Name, id and dates of each project the machine account can read. |
| `secrets` | read | The keys (names) of all readable secrets, or those of one `project` (name or id), with id, projects and dates. Never values or notes. |
| `reveal_secret` | destructive, sensitive | The values of the secrets named by `ids` or `keys` (up to 10 together), and no others; keys are looked up in a `project` when given. A key that more than one secret has is refused with their ids; names not found are listed as `missing`. Revealing a credential can't be taken back, so it's destructive. |

**Decryption.** Secrets Manager encrypts names and values on the client, so
the server only ever sends ciphertext. The module does what Bitwarden's SDK
does, with Go's standard library: the 16-byte key after the colon in the
access token is stretched (HMAC-SHA256 keyed `bitwarden-accesstoken`, then
HKDF-Expand with `sm-access-token`) into an AES-256 and an HMAC-SHA256 key;
those open the login's `encrypted_payload`, which holds the organization's
key; and that key opens each project name, secret key and, for
`reveal_secret` only, value (AES-256-CBC with PKCS#7, the MAC checked
before decrypting). The derivation is tested against the SDK's own known
answers. Keys are held in memory for the life of the session (an hour) and
never leave the module.

**Security.** The client secret goes only to the identity service's
`/connect/token`, the bearer token only to the API; both clients follow
redirects only within the same host and never from https to http. Ids are
checked as UUIDs before they go into a path. Errors never quote the token.
