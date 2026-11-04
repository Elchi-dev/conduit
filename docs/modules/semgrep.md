# Semgrep

Findings from the Semgrep AppSec Platform: the token's deployment, its
projects, Code and Supply Chain findings counted by severity, and triaging a
finding. Only rules, paths, lines and severities come back, never code.

**Setup.** In Semgrep, open Settings, Tokens and create an API token with
the Web API scope; store it in the vault. `deployment` is optional: the
token's own deployment is used when it's empty.

| Action | Risk | Notes |
| --- | --- | --- |
| `deployments` | read | The deployment the token can access: id, name and slug. |
| `projects` | read | Projects (repositories) with id, name, tags, primary branch, when last scanned and when created. |
| `findings` | read | Findings counted by severity, and the most severe first: id, rule, severity, confidence, repository, path, line, branch, status and triage state (with the reason when ignored); Supply Chain findings add the advisory, package and version. `issue_type` (`sast` or `sca`), `repo`, `status` (default `open`) and `severity` filter; `limit` up to 200. Deduplicated across branches. |
| `triage_finding` | destructive | Sets a finding's triage state to `ignored` (with an optional `reason`: `acceptable_risk`, `false_positive`, `no_time`, `no_triage_reason`, `duplicate`), `reviewing`, `fixing` or `reopened`, with an optional `note`. The preview names the finding's rule, repository, path and line and shows the state before and after. Undo sets the previous state (and reason) back. |

A finding already in the state asked for is left as it is. `triage_finding`
needs the finding's repository (both come from `findings`), since the
finding is looked up there first. The triage request names the finding's id
and also carries the repository filter and a limit of one, so it can't reach
other findings should the id ever be ignored. Semgrep also triages the same
finding on the repository's other branches; if its answer names findings
outside the repository, the action fails and says how many were changed.

**Security.** The token goes in the `Authorization` header to semgrep.dev
only, and the client won't follow a redirect to another host or from https
to http. Deployment slugs, ids and repository names are checked before they
reach a request. Code snippets, autofix suggestions, rule messages (which can
quote the matched code) and triage comments aren't read.

**Notes.** Counts cover up to 5,000 findings per call (`truncated` says when
there are more). Secrets findings use a separate Semgrep API and aren't
included. A finding first triaged as provisionally ignored has no undo.
