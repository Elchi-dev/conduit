# Transmission

Transfer speeds and limits, the torrent list, pausing and resuming, adding
torrents by magnet link or URL, and deleting, through Transmission's RPC
interface. Works with Transmission 3 and 4, including `transmission-daemon`
on a NAS or in a container.

**Setup.** Enter the web interface's address, such as
`http://nas.lan:9091`; the module adds the RPC path `/transmission/rpc`
(an address that already ends in `/transmission`, `/transmission/web` or
`/rpc` works too). When RPC authentication is on (Preferences, Remote, or
`rpc-authentication-required` in `settings.json`), enter the username and
store the password in the vault. If `rpc-whitelist` is on, add Conduit's
address to it. For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `session` | read | Version, RPC version, download and upload speed, torrent counts (all, active, paused), the global limits, whether the alternative (turtle) limits are on and their values, and the default download folder. |
| `torrents` | read | Hash, name, status, progress, size, speeds, ratio, connected peers, ETA, labels, download folder and any error. Filter by `status` or `query` (name), sort by `sort`, up to `limit`. |
| `pause` | destructive | Stops up to 100 torrents by hash. The preview lists the ones that change; undo starts only those. |
| `resume` | write | Starts torrents; undo stops only the ones it started. |
| `add` | write | Up to 20 `magnet:` links or http(s) URLs of `.torrent` files, optionally `paused`. Magnets already in Transmission are skipped. Transmission names each new torrent's hash, so undo deletes exactly the added ones and keeps their files. |
| `delete` | destructive | Removes up to 100 torrents, and their downloaded data with `deleteFiles`. With a preview; no undo. |
| `set_speed_limits` | write | The global `downloadKBs` and/or `uploadKBs` limit in kB/s (0 = unlimited). Undo restores the previous limits. |

**Notes.** New torrents go to Transmission's default download folder.
Limits are in Transmission's own speed unit (kB/s).

**Security.** Transmission's CSRF protection answers the first request with
409 and a session id; the module keeps that id in memory and fetches a new
one when it changes (after a restart, for example). The password goes in
HTTP Basic authentication, and the client won't follow a redirect to
another host or from https to http. Hashes must be 40 or 64 hex digits
before anything is sent. Tracker URLs, which carry private tracker
passkeys, are never read; error text from trackers is passed through the
redaction filter, and previews show added URLs without their query string.
The URLs you add are in the action's input, so they're in the audit log:
prefer magnet links over `.torrent` URLs with a passkey. Transmission
reads an entry that isn't a `magnet:?` link or a URL it recognises as a
file on its own disk, so entries must start with a lowercase `magnet:?`,
`http://` or `https://`, and URLs may not hold spaces or backslashes.
