# Frigate

A Frigate NVR: cameras with their switches and frame rates, detector and
storage stats, recent tracked objects (events) with labels and scores and
snapshot metadata, turning detection or recording on or off per camera, and
keeping events past retention. It uses Frigate's HTTP API (`/api`, Frigate
0.13 and later; 0.14+ for login) and, for the camera switches the HTTP API
doesn't have, its websocket (`/ws`), which takes the same commands as
Frigate's MQTT interface.

**Setup.** Enter Frigate's address. On the authenticated port (8971 in
Frigate 0.14+, e.g. `https://frigate.local:8971`) enter a username and store
its password in the vault; changing cameras needs an admin user. On the
internal unauthenticated port (`http://frigate.local:5000`) leave the
username empty. Frigate's default certificate on 8971 is self-signed: enter
its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `overview` | read | Version (and a newer one, if Frigate knows of it), uptime, cameras with FPS and their detect and record switches, detectors with inference time, storage use. |
| `cameras` | read | Each camera: on, detecting, recording, snapshots, audio, tracked objects, zones, camera and detection FPS. Stream addresses (which hold camera passwords) and the rest of the config are never read out. |
| `stats` | read | Per-camera camera, process, detection and skipped FPS; detectors; storage; temperatures; GPU use. |
| `events` | read | Tracked objects, newest first: camera, label, sub label (e.g. a recognized face), top score, zones, start and end, whether there's a clip and a snapshot, and whether it's kept. `camera`, `label`, `zone`, `hours`, `hasSnapshot`, `inProgress`, `retained` and `limit` (up to 200) narrow it. Thumbnails are never requested. |
| `event` | read | One event with its current and top score, box, region, attributes and where its snapshot and clip are (`/api/events/<id>/snapshot.jpg`), without fetching the images. |
| `set_detection` | write | Turns detection on or off for a camera until Frigate restarts. The module checks the config afterwards and fails if the change didn't show. Undo switches it back. |
| `set_recording` | write | The same for recording. Frigate only switches recording on at runtime for cameras with recording enabled in its config; the module says so when it isn't. |
| `retain_event` / `unretain_event` | write | Keep an event's clip and snapshot regardless of retention, or let retention handle it again. Each one's undo is the other. |

**Security.** With a username, the module logs in at `/api/login` once,
keeps the session cookie Frigate sets, and logs in again once when it
expires. The client won't follow a redirect to another host or from https to
http, and the websocket is dialled with the same client. Camera, zone and
label names and event ids are checked before they're put in a URL or a
topic.
