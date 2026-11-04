# Nomad

A HashiCorp Nomad cluster through its HTTP API: jobs and their status,
allocations, nodes, deployments, and changing them: node eligibility and
draining, restarting, stopping, reverting and dispatching jobs, and
promoting deployments.

**Setup.** Enter the address of a Nomad server or client agent, such as
`https://nomad.example.com:4646`. With ACLs on, create a token whose
policy allows what you want (`read-job` and `node:read` for reading;
`submit-job`, `dispatch-job` and `alloc-lifecycle` for the job actions;
`node:write` for eligibility and draining) and store its secret ID in the
vault. Set the region if it isn't the agent's own, and a default namespace
(`default` unless given). For a self-signed certificate, enter its SHA-256
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `jobs` | read | Jobs (in a `namespace`, or `*` for all; `prefix` narrows) with type, status, priority and allocations counted by state, and whether they're stopped, parameterized, periodic or dispatched from another. |
| `job` | read | Version, status, datacenters, node pool, task groups with count and tasks with their driver, dispatch parameters, the periodic schedule, allocation counts and the latest deployment. Never the task config, environment or templates, which can hold secrets. |
| `allocations` | read | A job's (or the namespace's) allocations, newest first, with group, node, job version, client and desired status and each task's state and restarts. Stopped and finished ones only with `all`. |
| `nodes` | read | Client nodes with status, eligibility, drain, datacenter, class, pool and version. |
| `deployments` | read | Deployments (of one `job`) with status and, per group, desired and placed allocations, healthy and unhealthy ones, canaries and promotion. |
| `node_eligibility` | write | Makes a node eligible or ineligible for new placements; running work stays. Undo sets it back. |
| `drain_node` | destructive | Drains a node: its allocations migrate to other nodes, and whatever is left after `deadlineMinutes` (1 to 1440, 60 by default) is stopped; `ignoreSystemJobs` leaves system jobs. The preview lists every allocation that moves. Undo stops the drain and makes the node eligible again; allocations already moved stay where they went. |
| `cancel_drain` | write | Stops a drain and marks the node eligible. |
| `restart_job` | destructive | Restarts every task of the job's running allocations in place, or only those of one `group` or one `allocation`. The preview lists each allocation. |
| `stop_job` | destructive | Stops the job and all its allocations; the preview lists them. Undo reverts to the version that was running, which starts it again. With `purge` the job and its history are deleted, so there's no undo (the preview says so). |
| `revert_job` | destructive | Submits an earlier `version` of the job again. The preview shows both versions and whether this starts or stops the job. It's tied to the version seen, so a change in between makes Nomad refuse it. |
| `dispatch_job` | destructive | Starts an instance of a parameterized job. `meta` must name the job's required keys and only its optional ones, and a `payload` (text, up to 16 KiB) is refused or required as the job says. The preview shows every value. |
| `promote_deployment` | destructive | Promotes a running deployment's canaries (all groups, or `groups`), which replaces the remaining allocations with the new version. The preview shows canary health per group and calls out unhealthy canaries. |

Nodes, allocations and deployments are given by ID or by their first 8
characters (as Nomad shows them), resolved to exactly one.

**Security.** The ACL token goes in the `X-Nomad-Token` header; since Go
forwards custom headers on redirects, the client follows redirects only
within the same host and never from https to http. Job IDs (dispatched
children like `batch/dispatch-…` included) are checked and escaped,
namespaces and regions are checked, and node, allocation and deployment
IDs must be UUIDs or 8-character hex prefixes before they reach a request.
