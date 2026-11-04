# Kavita

Your [Kavita](https://www.kavitareader.com) reading server for manga, comics
and books: libraries, series, search, what's new, and library scans.

**Setup.** In Kavita, open your user settings and copy your API key (under
3rd Party Clients, or Account on older versions), then store it in the
vault. Enter Kavita's address, such as `https://kavita.example.com`. The key
acts as your user, so Kavita shows only the libraries you may see; scanning
needs an admin. For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `libraries` | read | Id, name, type (manga, comic, book, image, light novel), folders and when each was last scanned. |
| `series` | read | Series by name, in one `library` (id) or all, with format, pages, pages read and percent read and a link to open each. With `search`, the series matching it instead. |
| `recent` | read | The series that got new chapters or volumes most recently, everywhere or in one `library`. |
| `scan_library` | write | With a preview naming the library and its folders. Asks Kavita to look for new and changed files in a `library` now; it runs in the background. `force` re-reads every file rather than only changed folders. |

**Security.** Conduit exchanges the API key for a short-lived token, which
it renews when Kavita refuses it, and sends only that token with requests.
Neither the token nor the key appears in output or errors, and the client
won't follow a redirect to another host or from https to http. Library ids
must be numbers before they reach a request.

**Notes.** Listing series and recently added series uses Kavita's filter API
from version 0.8. A scan removes series whose files are gone from disk, as
every Kavita scan does.
