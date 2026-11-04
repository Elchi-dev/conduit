# GitGuardian

Secret leak incidents from GitGuardian: what kind of secret leaked, how
severe it is, whether it's still valid, where it was found, and resolving,
ignoring or reopening an incident. The secret itself never leaves
GitGuardian.

**Setup.** In the GitGuardian dashboard, open API, Personal access tokens
(or create a service account) and make a token with the `incidents:read`
scope, plus `incidents:write` to resolve, ignore or reopen incidents; store
it in the vault. Set `region` to `eu` for a workspace on
dashboard.eu1.gitguardian.com; the default, `us`, is dashboard.gitguardian.com.

| Action | Risk | Notes |
| --- | --- | --- |
| `incidents` | read | Incidents, newest first: id, secret type and family, severity, status, validity, number of occurrences, date, tags, and when resolved (and whether the secret was revoked) or ignored (and why). Counted by severity. `status` and `severity` filter; `limit` up to 100. |
| `incident` | read | One incident, a link to it in the dashboard, and up to 50 places it was found: repository, source, file, short commit, date and whether it's still present. |
| `resolve_incident` | destructive | Resolves an open incident; `revoked` says whether the secret was revoked. The preview names the incident with its type, severity and occurrences. Undo reopens it. |
| `ignore_incident` | destructive | Ignores an open incident with a `reason`: `test_credential`, `false_positive`, `low_risk` or `invalid`. Undo reopens it. |
| `reopen_incident` | write | Makes a resolved or ignored incident open again. Undo resolves it (with the same revoked answer) or ignores it with its earlier reason. |

An incident already in the state asked for is left as it is. Resolving or
ignoring works on open incidents (triggered or assigned); one that's
resolved or ignored is reopened first. After a change, the incident is read
back, and a server that kept it as it was makes the action fail with that
explanation.

**Security.** The key goes in the `Authorization` header to the region's
fixed API host, and the client won't follow a redirect to another host or
from https to http. Ids are checked as numbers before they reach a request.
Incidents and occurrences are decoded field by field, so the secret's value,
its hashes, the matched text, the public share link and commit authors are
never read.

**Notes.** Incidents come from one page of up to 100; `truncated` says when
there are more. Self-hosted GitGuardian isn't supported yet.
