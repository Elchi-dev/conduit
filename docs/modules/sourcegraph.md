# Sourcegraph

Code search across every repository a Sourcegraph instance indexes
(sourcegraph.com or self-hosted), and its repository list.

**Setup.** In Sourcegraph, open your user menu, Settings, Access tokens and
create a token; store it in the vault. Leave the address as
`https://sourcegraph.com`, or enter your instance's, such as
`https://sourcegraph.example.com`. The token searches what its user can see.
For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `search` | read, sensitive | Runs a query in Sourcegraph's search language (`repo:`, `file:`, `lang:`, `type:`, …) and returns matching files with repository, path and up to 10 matching lines each, cut to 200 characters with anything that looks like a credential masked. `limit` (up to 100) caps both results and lines; repository results are listed by name, commit and diff results are counted. |
| `repositories` | read | Repositories with name, description and address. `name` keeps those whose name contains it; `limit` up to 200. |

`search` is sensitive: code can hold secrets, so its input and output stay
out of the audit log, approvals and events.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Queries are
sent as GraphQL variables, never pasted into the request. The module sets
the result count itself, so a query with `count:` is refused. GraphQL
errors are passed on with credentials masked.

**Notes.** Masking catches keys, tokens and `password=` style values, not
every short secret; keep `search` behind approval where repositories may
hold them. Line numbers count from 1.
