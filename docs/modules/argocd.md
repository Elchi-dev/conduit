# Argo CD

Argo CD applications with their sync and health status, an app's details
and resource tree, and syncing (with a preview of what's out of sync),
refreshing, rolling back and stopping a running operation. It uses Argo CD's
REST API (`/api/v1`, Argo CD 2.x and 3.x).

**Setup.** Create a local account with the `apiKey` capability (in
`argocd-cm`: `accounts.conduit: apiKey`), give it an RBAC role in
`argocd-rbac-cm` (read-only is `role:readonly`; syncing needs
`applications, sync`, rollback and terminate need `applications, action`
or `update` as your Argo CD version requires), then
`argocd account generate-token --account conduit` and store the token in
the vault. A project role token works too, limited to that project. Enter
the server's address, such as `https://argocd.example.com`, including its
root path if the server runs under one (`https://example.com/argocd`). For
a self-signed certificate, enter its SHA-256 `fingerprint` rather than
turning off verification.

| Action | Risk | Notes |
| --- | --- | --- |
| `applications` | read | Every app with project, sync status, health, deployed revision, auto-sync and the last operation. `project`, a label `selector`, and `problems` (only apps out of sync or not healthy) narrow it. |
| `application` | read | Sources (repository with any credentials in its address removed, path or chart, target revision; never Helm values or plugin parameters, which can hold secrets), destination, auto-sync settings, conditions, images, the last 10 history entries with their ids, resource counts by sync status, and the resources that are out of sync, unhealthy or need pruning. |
| `resource_tree` | read | The live resources (including generated ones such as ReplicaSets and Pods) counted by kind and health, with the unhealthy ones and their messages. |
| `sync` | destructive | Applies the app's target revision, optionally only some `resources`. It never prunes and takes no other revision (a `revision` equal to the app's target is accepted; anything else is refused): deleting resources or deploying an older commit is destructive. The preview lists each out-of-sync resource and whether it's applied, created or kept. Refused while another operation runs. No undo: use `rollback`. |
| `sync_prune` | destructive | Like `sync`, and deletes the resources no longer in Git. The preview lists every resource it would delete. |
| `sync_revision` | destructive | Syncs to `revision` (a branch, tag or commit other than the target), optionally with `prune` and only some `resources`. The preview lists what's applied and what's deleted. |
| `refresh` | write | Makes Argo CD compare the app with Git and the cluster again now (`hard` also drops the manifest cache). Nothing is applied, but it does make the server do work, so it's a write. |
| `rollback` | destructive | Deploys an earlier history entry (`id`, or the previous one), with optional `prune`. Argo CD refuses it while auto-sync is on, and so does the module, with a clear message. The preview shows the deployed and the target revision; undo rolls forward to the entry that was deployed. |
| `terminate_operation` | destructive | Stops a running sync, which can leave resources half applied. The preview shows the operation, who started it and when. |

Apps outside Argo CD's own namespace ("apps in any namespace") are given
as `namespace/name`.

**Security.** The token goes in the `Authorization` header and the client
won't follow a redirect to another host or from https to http. App,
project and namespace names must be valid Kubernetes names before they
reach a request path; revisions, label selectors and resource references
are checked before they're sent.
