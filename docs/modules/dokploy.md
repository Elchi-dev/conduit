# Dokploy

Projects, applications, compose services and deployments of a Dokploy
server, and deploying, stopping and starting applications and compose
services.

**Setup.** In Dokploy, open Settings, Profile, API/CLI and generate an API
key; store it in the vault. The key acts with its user's permissions. Enter
your dashboard's address, such as `https://dokploy.example.com`. For a
self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Projects with their environments, and each one's applications and compose services with id, name and status. |
| `application` | read | One `application`: status, source (repository and branch, or image), build type, replicas, domains and the latest five deployments. |
| `compose` | read | One `compose` service: status, source, compose type, domains and latest deployments. |
| `deployments` | read | Deployments of an `application` or a `compose` service, newest first (`limit`, default 10): title, status, time. |
| `deploy_application` | destructive | Builds the application from its source and replaces what runs. With a preview. |
| `stop_application` | destructive | Stops the application. Undo starts it again. |
| `start_application` | write | Starts a stopped application from what was last deployed, without a new build. Dokploy's start runs one instance whatever the replicas, so it's refused for an application with more replicas that isn't `idle` (it would cut it down); deploy instead. Undo stops it. |
| `deploy_compose` | destructive | Pulls the compose service's source and recreates its containers. With a preview. |
| `stop_compose` | destructive | Stops every container of the compose service. Undo starts it again. |
| `start_compose` | write | Starts a stopped compose service from what was last deployed. Undo stops it. |

Status is what Dokploy records: `idle` (stopped or never deployed),
`running` (a deployment is running), `done` or `error` (how the last one
ended). Starting a `done` or `running` one reports nothing to change. The
status is a record rather than what runs (a cancelled deployment leaves
`idle` while the old version runs), so an `idle` service is stopped anyway,
without an undo. Undoing a stop of an application with several replicas
starts one instance; a deploy runs them all.

**Notes.** Databases (PostgreSQL, Redis and the others Dokploy runs) aren't
part of this module. Dokploy versions before environments list services on
the project itself; they show as one environment named `production`.

**Security.** The key goes in the `x-api-key` header, and the client won't
follow a redirect to another host or from https to http. Ids must be plain
identifiers before they reach a request. Services are read field by field,
so environment variables, build arguments, registry passwords, SSH keys and
compose files never come back; Git addresses lose any user and password.
Deployment log paths aren't read.

**Presets.** developer, homelab.
