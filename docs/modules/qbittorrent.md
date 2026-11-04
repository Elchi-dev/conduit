# qBittorrent

Transfer speeds and limits, the torrent list, pausing and resuming, adding
torrents by magnet link or URL, and deleting, through qBittorrent's Web API
(v2). Works with qBittorrent 4.1 and later, including 5.x (which renamed
pause and resume to stop and start; the module asks for the Web API version
and uses the right one).

**Setup.** Turn on the Web UI (Tools, Options, Web UI), store its password
in the vault and enter the username and the Web UI's address, such as
`http://nas.lan:8080`. For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `transfer` | read | Download and upload speed, data this session, the global limits, whether the alternative limits are on, connection status and DHT nodes. |
| `torrents` | read | Hash, name, state, progress, size, speeds, ratio, seeds and peers, ETA, category, tags, save path. Filter by `filter` (state), `category`, `tag` or `query` (name); `paused`/`stopped` and `resumed`/`running` work on both 4.x and 5.x. |
| `pause` | write | Pauses up to 100 torrents by hash. The preview lists the ones that change; undo resumes only those (not ones that were already paused). |
| `resume` | write | The reverse; undo pauses only the ones it resumed. |
| `add` | write | Up to 20 `magnet:` links or http(s) URLs of `.torrent` files, with optional `savePath`, `category`, `tags` and `paused`. Magnets already in qBittorrent are skipped. Undo deletes the added torrents and keeps their files; for a URL the module waits a few seconds for qBittorrent to fetch it so it can name it in the undo. |
| `delete` | destructive | Removes up to 100 torrents, and their downloaded data with `deleteFiles`. With a preview; no undo. |
| `set_speed_limits` | write | The global `downloadKiB` and/or `uploadKiB` limit in KiB/s (0 = unlimited). When the alternative limits are on, qBittorrent applies it to those. Undo restores the previous limits. |

**Security.** The module signs in with `/api/v2/auth/login`, keeps the
session cookie in memory and signs in again when it expires. Every request
carries the server's own `Referer` and `Origin`, which is what
qBittorrent's CSRF protection requires. Hashes must be 40 or 64 hex digits
(`all` isn't accepted), and categories, tags and paths one line, before
anything is sent. The client won't follow a redirect to another host, so the
password and cookie stay with the server. Torrent magnet URIs and tracker
URLs (which carry private tracker passkeys) aren't part of any output, and
previews show added URLs without their query string. The URLs you add are in
the action's input, so they're in the audit log: prefer magnet links over
`.torrent` URLs with a passkey. After too many failed sign-ins qBittorrent
bans the address for a while; Health says so.
