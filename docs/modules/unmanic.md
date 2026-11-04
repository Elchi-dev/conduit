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
| `pause` | destructive | With a preview. Pauses every worker; tasks in progress halt until resumed. "Nothing to change" when all are already paused. Undo resumes them. |
| `resume` | write | With a preview. Resumes every paused worker. Undo pauses them again. |

After a pause or resume the workers are read back, and the action reports
an error if they aren't all in the state asked for.

**Security.** The client won't follow a redirect to another host or from
https to http. Workers and history show only file names, never folders, and
the paths of pending tasks, the worker command lines and log tails aren't
read.

**Notes.** Unmanic has no login of its own, so anyone who can reach it can
use it; keep it on a trusted network or behind a proxy. Status and library
counts for pending tasks cover the first 500 tasks; the total is always
exact.
