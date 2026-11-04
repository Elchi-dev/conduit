# Railway

Railway projects through the public GraphQL API: projects, environments,
services and deployments with their status, a bounded tail of a
deployment's logs, redeploying and restarting.

**Setup.** Create a token in Railway: an account token (Account settings,
Tokens) sees your projects; a workspace token (choose the workspace when
creating it) sees that workspace's projects; a project token (Project
settings, Tokens) sees one project and environment. Store it in the vault,
enter its `secret://` reference and set `tokenType` to `account`, `team` or
`project` (project tokens are sent as `Project-Access-Token`, the others as
a bearer token).

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Projects with their environments and services. |
| `environments` | read | A `project`'s environments. |
| `services` | read | A project's services with each environment's latest deployment: id, status, address. |
| `deployments` | read | A service's recent deployments (`project`, `service`, optional `environment`, `limit` default 10, at most 50): status, commit, branch, first line of the commit message, address. |
| `logs` | read, sensitive | The last `lines` (default 100, at most 500) of a deployment's runtime logs, or its build logs with `build`. Lines are clipped to 2000 characters. Logs can hold secrets and personal data, so they're kept out of the audit log, approvals and events. |
| `redeploy` | destructive | Builds and deploys a `deployment` again, or the latest one of a `service` in an `environment`. Destructive because an older deployment puts its older code live. The preview names the service, environment and deployment. |
| `restart` | destructive | Restarts a deployed (or crashed) deployment's containers without rebuilding; connections drop while it comes back. With a preview. |

There's no undo: a redeploy or restart can't be taken back, and rolling
back is a separate decision best made in Railway.

**Security.** Every query is a constant and ids (UUIDs) are checked and
sent only as GraphQL variables. Deployment metadata is reduced to commit,
branch, message, author and reason, so variables in it never come back, and
the account's email is never returned. The client won't follow a redirect to
another host.

**Presets.** developer.
