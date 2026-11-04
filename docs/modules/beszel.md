# Beszel

The systems a Beszel hub monitors, with their CPU, memory, disk, load and
temperature, recent stats, alert rules, and pausing or resuming a system,
through the hub's PocketBase API.

**Setup.** In Beszel, create a user for Conduit (Settings, or the PocketBase
admin at `/_/`), give it the systems it should see, and store its password
in the vault. Enter the hub's address, such as `http://beszel:8090`, and the
user's email. A read-only user is enough to read; pausing and resuming need
a regular user. For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `systems` | read | Id, name, host, status (up, down, paused, pending), CPU, memory and disk use, bandwidth, load average, temperature, GPU, extra disks, uptime, cores, CPU model, kernel and agent version. `status` filters. |
| `system_stats` | read | One system's recent stats records, newest first (`limit` 1 to 100, default 12) at a resolution of `1m`, `10m` (default), `20m`, `120m` or `480m`: CPU, memory, swap, disk, disk I/O, network, load and the hottest sensor. |
| `alerts` | read | Alert rules with their system, metric, threshold, minutes and whether they're triggered now. `triggeredOnly` filters. |
| `pause_system` | destructive | Stops monitoring a system: no stats and no alerts until it's resumed. The preview names the system and its host. Undo resumes it. |
| `resume_system` | write | Starts monitoring a paused system again (it shows as pending until the agent answers). Undo pauses it. |

Pausing silences every alert for the system, so an outage would go
unnoticed: it's destructive. A system that's already paused, or not paused
when resuming, is reported as nothing to change.

**Security.** The module logs in with the email and password and keeps the
session token in memory only, logging in again when it expires. The client
won't follow a redirect to another host or from https to http. System ids
must be PocketBase ids (15 letters and digits) before they reach a request
path or a filter, and the system changed is checked to be the one asked
for. Records are decoded field by field, so user ids and agent keys are
never read.

**Notes.** Beszel says its API's data may change in minor releases; the
module reads the fields Beszel 0.12 uses and leaves out what it doesn't
know.
