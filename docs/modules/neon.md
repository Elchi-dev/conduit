# Neon

Neon serverless Postgres through its API: projects, branches, computes
(endpoints) with their state, the current billing period's usage, creating
and deleting branches, and suspending or starting computes.

**Setup.** In the Neon console open Account settings (or Organization
settings), API keys, create a key, store it in the vault and enter its
`secret://` reference. An organization key sees that organization's
projects; with a personal key, set `organization` (its `org-…` id) to work
in an organization rather than your personal account.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Every project: id, name, region, Postgres version, storage, organization and when its compute was last active. |
| `branches` | read | A `project`'s branches: id, name, parent (with its name), default, protected, state, logical size, compute time and creation. |
| `endpoints` | read | A `project`'s computes: id, branch, read-write or read-only, state (`active` or `idle`), host, region, autoscaling range in CU, scale-to-zero delay, pooler, disabled and last activity. |
| `usage` | read | A `project`'s current period: compute and active time, CPU seconds, storage, written data and data transfer, and compute time and size per branch, busiest first. |
| `create_branch` | write | Creates branch `name` from the default branch (or `parent`) with a read-write compute (`compute: false` leaves it out). The preview names the parent. If a branch with that name exists, nothing changes. Undo deletes the new branch, which is destructive and asks again. |
| `delete_branch` | destructive | Deletes a `branch` with its data and computes. The preview shows its size. The project's default branch and protected branches are refused. |
| `suspend_endpoint` | destructive | Suspends a compute: open connections drop and the next connection waits for it to start. Already idle: nothing changes. Undo starts it. |
| `start_endpoint` | write | Starts an idle compute. Already running: nothing changes. Undo suspends it again. |

**Security.** Connection strings, role passwords and connection details are
never returned: answers are decoded field by field, so the connection URIs
Neon includes when a branch is created are never read. The key goes in the
`Authorization` header and the client won't follow a redirect to another
host. Project, branch (`br-…`), compute (`ep-…`) and organization ids are
checked before they reach a request path.

**Notes.** Branch lists follow Neon's pagination (up to 20 pages). Branch creation and computes start asynchronously; the result
lists Neon's operations and their status. Neon itself refuses to delete a
branch that has child branches.

**Presets.** developer.
