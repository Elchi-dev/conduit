# Miniflux

Unread and starred entries in your [Miniflux](https://miniflux.app) feed
reader, feeds that fail to update, marking entries read or unread, starring
them and refreshing feeds.

**Setup.** In Miniflux, open Settings, API Keys, and create a key, then store
it in the vault. It acts as you. Enter Miniflux's address, such as
`https://reader.example.com` (a trailing `/v1` is fine).

| Action | Risk | Notes |
| --- | --- | --- |
| `feeds` | read | Every feed with its category, its address in short form (scheme, host and first path segment, as private feeds carry tokens), unread count, last check and, for failing feeds, the error count and message. `errorsOnly` keeps just the failing ones. |
| `unread` | read | Unread entries, newest first, everywhere or in one `feed` (id): title, link, feed, date and reading time. |
| `starred` | read | Starred entries, newest first. |
| `mark_read` | write | Marks up to 50 `entries` (ids) read. The preview names the entries that change; entries that are already read are left out, and undo marks only the changed ones unread again. |
| `mark_unread` | write | The reverse, with the reverse undo. |
| `star` | write | Stars one `entry`; undo unstars it. Miniflux only has a toggle, so the entry is read first and left alone when it's starred already (no undo then). |
| `unstar` | write | Removes the star; undo stars it again. |
| `refresh_feeds` | write | Asks Miniflux to fetch every feed, or one `feed`, now. It runs in the background and has nothing to undo. |

Listings return titles, links and dates, not article content.

**Security.** The key goes in the `X-Auth-Token` header and the client won't
follow a redirect to another host. Ids are numbers checked before they reach
a request path. For a self-signed certificate, pin its SHA-256
`fingerprint`.
