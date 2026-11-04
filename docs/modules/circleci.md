# CircleCI

Pipelines on CircleCI (cloud) through API v2: a project's pipelines, their
workflows and jobs, workflow insights, and rerunning or cancelling
workflows.

**Setup.** In CircleCI, open User Settings, Personal API Tokens, create a
token, store it in the vault and enter its `secret://` reference. The
token acts as you, on every project you can see.

| Action | Risk | Notes |
| --- | --- | --- |
| `pipelines` | read | A project's recent pipelines (up to 50), optionally of one `branch`: number, state, branch, commit, trigger and who triggered it |
| `workflows` | read | The workflows of one pipeline, by `project` and pipeline `number` or by `pipeline` ID, with status and duration |
| `jobs` | read | One workflow's status and its jobs (status, type, duration) |
| `insights` | read | Per workflow over a `window` (24 hours to 90 days) on the default branch, a `branch` or `allBranches`: runs, success percentage, failures, median, p95 and longest duration, mean time to recovery, credits |
| `rerun_workflow` | destructive | Runs a finished workflow again as a new one, all jobs or only the failed ones (`fromFailed`), so its code runs again with the project's secrets and contexts. Refused while it's still running. Preview first |
| `cancel_workflow` | destructive | Stops a running, failing or on-hold workflow; jobs in progress are killed. Preview first |

`project` is a slug, `vcs/org/repo` (`gh/elchi/conduit`, `bb/team/app`, or
`circleci/<org id>/<project id>`), and workflow and pipeline IDs must be
UUIDs, so input can't reach other API paths. Previews name the project,
pipeline number, workflow name and status only. The token goes in the
`Circle-Token` header, and redirects to another host are refused.
