# Audiobookshelf

An Audiobookshelf server: libraries, the books and podcast episodes in
progress, listening stats, recent listening sessions, and starting a
library scan. It uses Audiobookshelf's REST API with an API token, as the
token's user.

**Setup.** Create an API key (Settings → API Keys, in recent versions),
or copy a user's API token from Settings → Users, and store it in the
vault. Enter the address, such as `https://abs.example.com`. Scans need an
admin.

| Action | Risk | Notes |
| --- | --- | --- |
| `libraries` | read | Libraries with id, media type (book or podcast) and folders. |
| `in_progress` | read | Started, unfinished books and episodes, most recent first: title, author, series, percent, position, time left, last listened. Up to `limit` (100). |
| `listening_stats` | read | Total and today's listening time, each of the last `days` (7, up to 90), and the ten most listened items. |
| `sessions` | read | The latest listening sessions: title, author, time listened, from and to which second, client and device. IP addresses are left out. |
| `scan_library` | write | Scans a library (by name or id) for new and changed items; `force` rescans every item. |

The user's own API token, which `/api/me` returns, is never read out.

**Security.** The token goes in the `Authorization` header; the client won't
follow a redirect to another host or from https to http. Library names are
resolved to ids from the server's own list before one is put in a URL.
