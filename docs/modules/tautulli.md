# Tautulli

[Tautulli](https://tautulli.com), the Plex monitoring server, through its
API v2: current streams and bandwidth, watch history, the home page's top
lists, Plex server status, and stopping a stream.

**Setup.** In Tautulli open Settings → Web Interface, turn on the API, copy
the API key and store it in the vault. Enter the address, such as
`http://tautulli.local:8181` (with the HTTP root, if you set one).

| Action | Risk | Notes |
| --- | --- | --- |
| `activity` | read, sensitive | Stream counts (direct play, direct stream, transcode), total, LAN and WAN bandwidth in Mbit/s, and each stream: session key and id, user, IP address, LAN or WAN, title, state, progress, player, platform, quality, transcode decision and bandwidth. |
| `history` | read, sensitive | Plays, newest first: when, user, title, player, platform, IP address, duration, paused time, how far, watched, transcode decision. `days`, `user` (Plex username), `mediaType` and `limit` (up to 200) narrow it. |
| `top` | read, sensitive | The home page lists over `days` (default 30), `count` rows each (up to 25), by `plays` or `duration`: most watched and popular movies, shows and music, top users and platforms, libraries, most concurrent streams. |
| `server` | read | Whether Tautulli reaches Plex; the Plex server's name, version, platform, Plex Pass, remote and SSL; Tautulli's version. Addresses are left out. |
| `terminate` | destructive | Stops a stream (by `sessionKey` or `sessionId` from `activity`), with an optional `message` for the viewer. It must be playing now. Plex needs Plex Pass for this. There's no undo. |

`activity`, `history` and `top` are sensitive because they hold people's
names, IP addresses and what they watch, so Conduit keeps their output out
of the audit log. `terminate` isn't: its plan and output name the title and
player only, never the viewer or their address.

Health is `degraded` when Tautulli can't reach Plex.

**Security.** Tautulli only takes its key as the `apikey` query parameter,
so the module strips the query from every error it returns (a network error
would otherwise include the URL with the key). The client won't follow a
redirect to another host or from https to http. Session ids, numbers,
media types and the message are checked before they're sent.
