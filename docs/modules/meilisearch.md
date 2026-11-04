# Meilisearch

A Meilisearch server: health, indexes with their stats, searching an
index, recent and failed tasks, API keys (never their values), and
deleting an index.

**Setup.** Enter the `url` (such as `http://localhost:7700`) and an
`apiKey` stored in the vault: the master key or an admin key for
everything, or a search key if Conduit should only search (health then
reports `degraded`, since a search key can't read the version, and the
other actions are refused). For a self-signed certificate, enter its
SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `health` | read | Status, version, database size and last update. |
| `indexes` | read | Indexes with primary key, documents, whether they're indexing, created and updated, up to 100. |
| `search` | read, sensitive | Searches an `index` for `q` with an optional `filter` expression, `sort` rules (`year:desc`), `attributes` to return, `limit` (at most 100) and `offset`. Documents can hold personal data, so results stay out of the audit log. |
| `tasks` | read, sensitive | Recent tasks (or one `status`, such as `failed`, or one `index`), up to `limit` (20, at most 100), with type, status, duration and error message (redacted and clipped). Meilisearch's errors can quote documents, so this stays out of the audit log. |
| `keys` | read | API keys by uid, name and description, with their actions, indexes and expiry. Never the key values: Conduit doesn't even decode them. |
| `delete_index` | destructive | Deletes an index with its documents and settings. The preview shows how many documents it holds. The deletion is a Meilisearch task; the result gives its uid. No undo. |

**Security.** The key goes in `Authorization: Bearer …`; the client follows
redirects only within the same host and never from https to http. Index
uids, sort rules and attribute names are checked before they reach a
request.
