# Unraid

An Unraid server through the Unraid API: the array and its disks with
temperatures, error counts and space, parity checks (start, pause, resume,
cancel), Docker containers, virtual machines and notifications. The API is
GraphQL at `/graphql`, built into Unraid 7.2 and later (earlier releases get
it with the Unraid Connect plugin).

**Setup.** In the web UI open *Settings → Management Access → API Keys*,
create a key and store it in the vault. Its role decides what works: a
viewer key is enough for everything read-only; parity checks, containers and
VMs need a key that can update the array, Docker and VMs. Enter the
server's address, such as `https://tower.local`. Unraid's own certificate is
self-signed: enter its SHA-256 `fingerprint` rather than turning off
verification.

| Action | Risk | Notes |
| --- | --- | --- |
| `overview` | read | Server name and version, array state and capacity, disks with problems, the parity check, running containers and VMs, unread notification counts. Parts the key can't read are listed under `unavailable`. |
| `array` | read | Array state and capacity; every parity, data, cache and boot disk with status, temperature (`null` when spun down), read/write/error counts, size and file system use. `problems` lists disks that aren't `DISK_OK`, have errors, or are at or above their temperature thresholds (Unraid's 45 °C / 55 °C when a disk has none of its own). Empty slots are left out. |
| `parity_status` | read | Status, progress, speed, errors found, duration and date of the running or last check. |
| `start_parity_check` | write | A read-only check: reads every disk for hours and slows the array. Refused while one runs or is paused. |
| `start_correcting_parity_check` | destructive | A check that rewrites parity where it doesn't match. |
| `pause_parity_check` / `resume_parity_check` | write | Each one's undo is the other. |
| `cancel_parity_check` | destructive | Progress is lost; the preview says how far it got. |
| `containers` | read | Name, id, image, state, status, autostart and published ports; `search` and `state` narrow it. Labels and environment (which can hold secrets) are never read. |
| `start_container` | write | Undo stops it. |
| `stop_container` | destructive | Undo starts it. |
| `restart_container` | destructive | Stop then start; no undo. |
| `vms` | read | Name, id and state. |
| `start_vm` | write | Undo shuts it down. |
| `stop_vm` | destructive | ACPI shutdown (the guest is asked to shut down). Undo starts it. |
| `notifications` | read | Unread (or `archived`) notifications, newest first, with counts by importance; `importance` and `limit` (up to 100) narrow it. |

Every write and destructive action has a preview showing the current state.
Containers and VMs are given by name or id.

**Security.** The key goes in the `x-api-key` header; the client won't
follow a redirect to another host or from https to http. Container and VM
references are resolved against the server's own list, and ids are sent as
GraphQL variables, never pasted into queries.

**Compatibility note.** The queries follow the Unraid API's published
schema (`array`, `parityCheck`, `docker`, `vm`, `vms`, `notifications`,
`vars`). The Unraid docs couldn't be fetched when the module was written, so
it was built from the schema as documented in the Unraid API repository; if
a field is missing on your release, the action fails with Unraid's own
GraphQL error.
