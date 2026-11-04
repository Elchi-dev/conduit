# Navidrome

A Navidrome music server, or any server with the Subsonic API (Airsonic,
Gonic, ...): what's playing now, recently added or played albums, search,
playlists, and the library scan.

**Setup.** Enter the server's address (with its base path, if any, such as
`https://example.com/music`), a username, and store that user's password in
the vault. The password is never sent: each request carries a fresh random
salt and `md5(password + salt)`, as the Subsonic API's token authentication
asks. Starting a scan needs an admin user. LDAP users of servers that can't
do token authentication won't work.

| Action | Risk | Notes |
| --- | --- | --- |
| `now_playing` | read | What each user is playing, on which player, and how many minutes ago it started. |
| `albums` | read | Albums by list `type`: `newest` (recently added, the default), `recent` (recently played), `frequent`, `highest`, `starred`, `random` or `alphabeticalByName`; up to `limit` (100). |
| `search` | read | Artists, albums and songs matching `query`, up to `limit` (50) of each. |
| `playlists` | read | The playlists the user can see with owner, public, song count and length. |
| `playlist` | read | One playlist's songs, by `id`. |
| `scan_status` | read | Whether a scan is running, the files counted and when the last one ran. |
| `start_scan` | write | Starts a scan for changes; `fullScan` rescans every file (Navidrome). Refused while a scan is running; the preview shows the current status. |

File paths on the server are never read out.

**Security.** The token and salt are in the query string, so the client
won't follow a redirect to another host or from https to http, and network
errors are reported without the request address. Playlist ids, search words
and list types are checked before they're sent.
