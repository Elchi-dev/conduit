# Komga

Your [Komga](https://komga.org) comics and manga server: libraries, series,
what's new, what you're reading and what's next, and library scans.

**Setup.** In Komga (1.20 or later), open Account settings, API keys, and
create a key, then store it in the vault. On older versions, use your login
(an email address) and store its password in the vault instead. Enter
Komga's address, such as `https://komga.example.com`. The key or login acts
as that user, and Komga shows only the libraries it may see.

| Action | Risk | Notes |
| --- | --- | --- |
| `libraries` | read | Libraries with their root folder, and whether Komga can reach it. |
| `series` | read | Series by title, in one `library` (id) or all, optionally matching a `search`: book counts, how many are read, unread or in progress, and the series status. |
| `recent` | read | The newest books, everywhere or in one `library`. |
| `on_deck` | read | Books you're in the middle of (page, pages and percent, last read), and On Deck: the next book in series you're reading. |
| `scan_library` | write | With a preview naming the library. Asks Komga to look for new, changed and removed files in a `library` now; `deep` re-reads every file. It runs in the background, has nothing to undo and needs an admin account. |

**Security.** The API key goes in the `X-API-Key` header (or the login as
HTTP basic auth) and the client won't follow a redirect to another host.
Library ids are checked before they reach a request path. For a self-signed
certificate, pin its SHA-256 `fingerprint`.
