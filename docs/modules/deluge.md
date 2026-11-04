# Deluge

Transfer speeds and limits, the torrent list, pausing and resuming, adding
torrents by magnet link or URL, and deleting, through the Deluge Web UI's
JSON-RPC interface (Deluge 2).

**Setup.** Turn on the Web UI (the `deluge-web` service, port 8112 by
default), store its password in the vault and enter its address, such as
`http://nas.lan:8112`. The Web UI talks to a Deluge daemon: when it isn't
connected and knows exactly one daemon, the module connects it; with
several, pick one in the Web UI's Connection Manager first. For a
self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `session` | read | Version, download and upload speed, the global limits, DHT nodes, whether incoming connections work, the download folder and free disk space. |
| `torrents` | read | Hash, name, state, progress, size, speeds, ratio, seeds and peers, ETA, label, save path and any error. Filter by `state`, `label` or `query` (name), sort by `sort`, up to `limit`. |
| `pause` | destructive | Pauses up to 100 torrents by hash. The preview lists the ones that change; undo resumes only those. |
| `resume` | write | Resumes torrents; undo pauses only the ones it resumed. |
| `add` | write | Up to 20 `magnet:` links or http(s) URLs of `.torrent` files, optionally `paused`. Magnets already in Deluge are skipped. Deluge returns each new torrent's hash, so undo deletes exactly the added ones and keeps their files. |
| `delete` | destructive | Removes up to 100 torrents, and their downloaded data with `deleteFiles`. With a preview; no undo. |
| `set_speed_limits` | write | The global `downloadKiB` and/or `uploadKiB` limit in KiB/s (0 = unlimited). Undo restores the previous limits. |

**Notes.** New torrents go to Deluge's default download folder. Labels
come from Deluge's Label plugin; without it, `label` is empty. Deluge 1.3
isn't supported.

**Security.** The module signs in with `auth.login`, keeps the session
cookie in memory and signs in again when Deluge reports the session
expired. The client won't follow a redirect to another host or from https
to http. Hashes must be 40 or 64 hex digits, and labels one line, before
anything is sent. Tracker URLs, which carry private tracker passkeys, are
never read; Deluge's error text loses any traceback and passes through the
redaction filter, and previews show added URLs without their query string.
The URLs you add are in the action's input, so they're in the audit log:
prefer magnet links over `.torrent` URLs with a passkey.
