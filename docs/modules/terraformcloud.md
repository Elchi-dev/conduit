# HCP Terraform

HCP Terraform (formerly Terraform Cloud) or a Terraform Enterprise
installation through its API (`/api/v2`): organizations, workspaces with
their lock and current run, runs with their plan summary, queueing
plan-only runs, applying a planned run, discarding and cancelling runs,
and locking and unlocking workspaces.

**Setup.** Create a user API token (User settings, Tokens) or use a team's
API token, and store it in the vault. Its permissions decide what works:
reading needs read access to the workspaces, `queue_plan` needs "queue
plans", applying and discarding need "apply runs", locking needs "lock and
unlock workspaces". Organization tokens can't start runs. Leave the host
as `app.terraform.io` (or `app.eu.terraform.io` for the EU region), or
enter your Terraform Enterprise host name; https is always used, and for a
self-signed Terraform Enterprise certificate enter its SHA-256
`fingerprint`. A default `organization` saves naming it in every call.

| Action | Risk | Notes |
| --- | --- | --- |
| `organizations` | read | The organizations the token can see. Never their billing e-mail. |
| `workspaces` | read | An organization's workspaces (`search` by name): locked or not and by whom, current run and its status, resource count, execution mode, Terraform version, auto-apply, VCS repository and branch. |
| `workspace` | read | One workspace (by name or `ws-…` id) with the current run and its plan summary. |
| `runs` | read | A workspace's recent runs with status, source, message, plan-only and destroy flags, plan summary, and which of apply, discard and cancel are possible now. |
| `run` | read | One run with its plan summary: resources to add, change, destroy and import, targets and replacements. |
| `queue_plan` | write | Queues a speculative, plan-only run that can never be applied, with an optional `message`. Providers and data sources still run during a plan. |
| `apply_run` | destructive | Confirms a run waiting for confirmation so Terraform applies it. Refused for plan-only runs and runs not waiting for confirmation. The preview leads with **DESTROYS n resource(s)** (or **DESTROY RUN**) when anything is destroyed, then the counts to add, change, destroy and import, and any targets; destroyed resources get their own line. No undo. |
| `discard_run` | write | Discards a run waiting for confirmation; nothing is applied. |
| `cancel_run` | write | Interrupts a run that's planning or applying; the preview warns that a cancelled apply stops part way. |
| `lock_workspace` | write | Locks a workspace with an optional `reason`, so no run applies; undo unlocks. |
| `unlock_workspace` | write | Unlocks a workspace the token's user locked (the preview names who holds the lock); undo locks it again. A lock held by someone else or by a run needs a force unlock in the web UI, which the module doesn't offer. |

The plan summary is the counts Terraform reports; the resource-by-resource
plan (its JSON output) can hold sensitive values and is served from a
separate storage host, so the module doesn't fetch it. Open the run in the
web UI for the full plan.

**Security.** The token goes in the `Authorization` header to the
configured host only, and the client won't follow a redirect to another
host. Organization and workspace names, workspace ids (`ws-…`) and run ids
(`run-…`) are checked before they reach a request path.
