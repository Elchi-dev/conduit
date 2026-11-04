# Codecov

Code coverage from Codecov (cloud) through API v2: an owner's repositories
with their coverage, a branch's or commit's coverage, and how a pull
request changes it. The module is read-only.

**Setup.** In Codecov, open Settings, Access, and create an API access
token. Store it in the vault, and enter its reference with the `service`
(`github`, `gitlab`, `bitbucket`, or their enterprise and server kinds)
and the `owner`: the user or organization whose repositories to read.

| Action | Risk | Notes |
| --- | --- | --- |
| `repos` | read | Repositories active on Codecov (`includeInactive` for all) with coverage, default branch, language and last update |
| `coverage` | read | Coverage totals of a repository's default branch, a `branch` or a commit `sha`: percentage, files, lines, hits, misses, partials |
| `commit` | read | One commit's coverage with its branch, author, CI status and processing state |
| `compare` | read | How a `pullRequest` (or `head` against `base`) changes coverage: base, head, change, patch coverage, and the files (`files`, default 20, up to 100) whose coverage changed most |

Repository names, branches and SHAs are checked before they reach a
request. The token goes as a bearer token, and redirects to another host
are refused.
