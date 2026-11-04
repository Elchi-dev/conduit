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
| `scan_library` | write | With a preview naming the library. Asks Komga to look for new, changed and removed files in a `library` now. It runs in the background, has nothing to undo and needs an admin account. Refused, in the preview too, for a `deep` scan and for a library set to empty its trash after a scan (which deletes the books and series whose files are missing, with their read progress): those need `scan_library_full`. |
| `scan_library_full` | destructive | `scan_library` for a `deep` scan (re-reads every file and can rewrite its metadata) or a library that empties its trash after a scan. The preview reads the library's setting and says which applies. |

**Security.** The API key goes in the `X-API-Key` header (or the login as
HTTP basic auth) and the client won't follow a redirect to another host.
Library ids are checked before they reach a request path. For a self-signed
certificate, pin its SHA-256 `fingerprint`.
