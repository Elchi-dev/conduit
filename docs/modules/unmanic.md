# Unmanic

The [Unmanic](https://docs.unmanic.app) library optimiser: its workers and
what they're doing, pending tasks, completed task history, and pausing and
resuming all workers.

**Setup.** Enter Unmanic's address, such as `http://nas.lan:8888`. Unmanic's
API v2 needs no key. For a self-signed certificate (Unmanic behind a
reverse proxy with https), set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `workers` | read | How many workers there are, how many are busy and paused, and each worker's id, name, state, start time and the name of the file it's on. |
| `pending` | read | How many tasks wait, counted by status and by library. |
| `history` | read | How many tasks completed, succeeded and failed, and the most recent ones (`limit`, default 20) with their name, result and finish time. |
| `pause` | destructive | With a preview. Pauses every worker, or only the `workers` given (ids from `workers`, at most 50); tasks in progress halt until resumed. "Nothing to change" when they're all already paused. Undo resumes exactly the workers it paused, so a worker paused before stays paused. |
| `resume` | write | With a preview. Resumes every paused worker, or only the `workers` given. Undo pauses exactly the workers it resumed. |

After a pause or resume the workers are read back, and the action reports
an error if any it changed isn't in the state asked for. When every worker
changes, one call covers them all; otherwise each worker is paused or
resumed on its own.

**Security.** The client won't follow a redirect to another host or from
https to http. Workers and history show only file names, never folders, and
the paths of pending tasks, the worker command lines and log tails aren't
read. Folders and file paths are taken out of Unmanic's error messages, and
names are shortened; at most 50 workers are listed.

**Notes.** Unmanic has no login of its own, so anyone who can reach it can
use it; keep it on a trusted network or behind a proxy. Status and library
counts for pending tasks cover the first 500 tasks; the total is always
exact. Pausing or resuming single workers uses `workers/worker/pause` and
`workers/worker/resume` with a `worker_id`, which wasn't confirmed against a
live server.
