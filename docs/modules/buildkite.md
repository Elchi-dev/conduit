# Buildkite

One Buildkite organization through the REST API: pipelines, builds and
their jobs, job log tails, agents, and rebuilding or cancelling builds.

**Setup.** In Buildkite, open Personal Settings, API Access Tokens, and
create a token for the organization with `read_pipelines`, `read_builds`,
`read_build_logs` and `read_agents` (add `write_builds` to rebuild and
cancel). Store it in the vault and enter its reference with the
organization's slug (as in `buildkite.com/<slug>`). Health shows the
token's scopes.

| Action | Risk | Notes |
| --- | --- | --- |
| `pipelines` | read | Pipelines with repository (any user and password in its address removed), default branch, running and scheduled build counts |
| `builds` | read | Recent builds (up to 50) of one `pipeline` or the whole organization, optionally by `branch` and `state` |
| `build` | read | One build with its jobs: ID, name, type, state, exit status, duration |
| `job_log` | read, sensitive | The last lines (default 200, at most 2000) of one script job's log, with terminal colours and timestamp markers removed. At most 32 MiB of a log is read. Kept out of the audit log |
| `rebuild` | destructive | Runs a finished build again as a new build, so its code runs again with the pipeline's secrets and can deploy. Refused while it's still running. Preview first |
| `cancel_build` | destructive | Cancels a scheduled, running, failing or blocked build; jobs in progress are stopped. Preview first |
| `agents` | read | Agents with connection state, host name, version, queue and whether they're running a job (IP addresses are left out) |

Pipeline and organization slugs, build numbers and job IDs (UUIDs) are
checked before they reach a request. Previews show the build's state,
branch and source only. Redirects to another host are refused, including
for logs.
