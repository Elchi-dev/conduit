# Syncthing

A Syncthing instance through its REST API: status and recent errors,
folders with their state, completion and errors, devices with their
connections, pending devices and folders, pausing and resuming a folder or
a device, and rescans.

**Setup.** In Syncthing open Actions → Settings → General, copy the API key
and store it in the vault. Enter the GUI address, such as
`https://nas.local:8384` (or `http://127.0.0.1:8384` on the same machine).
Syncthing's GUI certificate is self-signed: enter its SHA-256
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | This device's id, version, OS, uptime, discovery, each listener's status and recent errors. |
| `folders` | read | Each folder: id, label, path, type, paused, state (idle, scanning, syncing, error) since when, sizes, what's left to sync, completion across devices, and up to ten file errors. |
| `devices` | read | Remote devices: paused, connected, address, client version, connection type, traffic, last seen, and completion of what they share. |
| `pending` | read | Devices asking to connect and folders offered by other devices, waiting to be accepted in the GUI. |
| `pause` / `resume` | write | Pauses or resumes a `folder` (id or label) or a `device` (id or name). Each one's undo is the other; nothing changes (and there's no undo) when it's already in that state. |
| `rescan` | write | Scans a `folder`, or every folder, for changes now. |

Health is `degraded` while Syncthing reports recent errors.

**Security.** The module never reads the GUI settings (which hold the API
key and the GUI password) or the full config, and doesn't decode folder
encryption passwords from the folder list. The API key goes in the
`X-API-Key` header; the client won't follow a redirect to another host or
from https to http. Folders and devices are looked up in Syncthing's own
lists before an id is put in a URL, and device ids must have the
`XXXXXXX-…` form.
