# Render

Render services: their state, deploys and recent events, triggering a
deploy, and suspending or resuming a service.

**Setup.** In the Render dashboard open Account settings, API keys, create
a key, store it in the vault and enter its `secret://` reference. The key
reaches every workspace you belong to; enter a workspace (owner) id
(`tea-…` or `usr-…`) to see only that workspace's services, and services
elsewhere are refused.

| Action | Risk | Notes |
| --- | --- | --- |
| `services` | read | Services (`limit`, default 50; `suspended` for only suspended ones): type, address, region, plan, runtime, repository, branch, auto-deploy, suspended. |
| `service` | read | One service by id (`srv-…`, or `crn-…` for a cron job). |
| `deploys` | read | A service's recent deploys: status, trigger, commit and first line of its message, image, start, finish and duration. |
| `deploy` | read | One deploy (`dep-…`). |
| `events` | read | Recent events (deploy started or ended, build, server failed, restarted, suspended…) with their short details. |
| `trigger_deploy` | destructive | Deploys again from the branch head, or a `commit` SHA (any revision, so it is destructive), optionally with `clearCache`. The preview names the branch or commit. Refused while the service is suspended. |
| `suspend` | destructive | Stops the service until resumed. Undo resumes it. |
| `resume` | write | Starts a suspended service; undo suspends it again. |

**Security.** The key goes in the `Authorization` header and the client
won't follow a redirect to another host. Service, deploy and workspace ids
and commit SHAs are checked before they reach a request path. Owner email
addresses are never returned. Render's runtime logs aren't part of this
module.

**Presets.** developer.
