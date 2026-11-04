# Coolify

Servers, projects, applications and deployments of a Coolify server
(self-hosted or Coolify Cloud), and deploying, restarting, stopping and
starting applications.

**Setup.** In Coolify, open Keys & Tokens, API tokens, and create a token;
store it in the vault. A read-only token is enough to look around; deploy
rights are needed to deploy, restart, stop or start. On a self-hosted
Coolify, turn the API on first (Settings, Advanced, API access). Leave the
address as `https://app.coolify.io` for Coolify Cloud, or enter your
dashboard's address, such as `https://coolify.example.com`. For a
self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `servers` | read | Name, address, SSH port and user, reachable, usable, build server and proxy type. |
| `projects` | read | Projects with their environments. |
| `applications` | read | Uuid, name, status (such as `running:healthy`), domains, build pack, Git repository and branch, image, exposed ports, last online. |
| `application` | read | The same fields for one `application`. |
| `deployments` | read | Deployments running or queued now, or the latest `limit` (default 10) of one `application`: status, trigger (webhook, API or dashboard), commit and the first line of its message, server. |
| `deploy_application` | destructive | Builds the application's current source and replaces what runs; `force` skips the build cache. With a preview. |
| `restart_application` | destructive | Restarts the containers without a new build. With a preview. |
| `stop_application` | destructive | Stops the containers. Undo starts it again, which in Coolify is a deployment: it may build newer source than what ran. |
| `start_application` | destructive | Starts a stopped application. Coolify does this by queuing a deployment, which may build the current source, so it's destructive too. Undo stops it. |

Stopping a stopped application or starting a running one reports nothing to
change.

**Notes.** Services and databases (as opposed to applications) aren't part
of this module. A deployment is queued: `deployments` shows how it goes.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Uuids must be
plain identifiers before they reach a request. Applications are read field
by field, so environment variables, webhook secrets, basic-auth passwords
and the Dockerfile never come back; Git addresses lose any user and
password. Servers' private keys and deployment logs are never read.

**Presets.** developer, homelab.
