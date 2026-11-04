# Appwrite

Databases, collections, documents, functions and their executions, and the
number of users of an Appwrite project (Appwrite Cloud or self-hosted). It
never changes anything.

**Setup.** In the console, open the project's Overview, Integrations, API
keys and create a key with the scopes `databases.read`, `collections.read`,
`documents.read`, `functions.read`, `execution.read` and `users.read`;
store it in the vault. Enter the project id and, if it isn't
`https://cloud.appwrite.io/v1`, the API endpoint shown under Settings (for
example `https://fra.cloud.appwrite.io/v1` or
`https://appwrite.example.com/v1`). For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `databases` | read | Id, name, enabled. |
| `collections` | read | A database's collections with their attributes (key, type, format, required, array) and whether document security is on. |
| `documents` | read, sensitive | Documents with conditions (`where`), a sort (`-$createdAt`), and pages of up to 100. Permissions and other plumbing are left out. |
| `functions` | read | Name, runtime, enabled, live, schedule, events, timeout and the active deployment. |
| `executions` | read | A function's latest executions: when, trigger, status, HTTP status, duration, method and path. |
| `users_count` | read | How many users the project has. |

**Filters.** `where` is a list of conditions that must all hold, each a
`field`, an `op` (`eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `contains`, `empty`,
`notempty`) and a `value`. Conduit checks the field against the
collection's attributes and sends Appwrite's structured JSON queries.

**Security.** Documents are sensitive: their content stays out of the audit
log, approvals and events. Users are only counted, so their e-mails, phone
numbers and password hashes are never read. Functions are decoded field by
field, so their variables are never read, and executions leave out request
headers, response bodies, logs and errors; a query string in the path is
cut. The key goes in the `X-Appwrite-Key` header and the client won't
follow a redirect to another host or from https to http.

**Notes.** Appwrite 1.5 or later (JSON queries). Only reading is offered.
