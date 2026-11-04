# Calibre-Web

Your [Calibre-Web](https://github.com/janeczku/calibre-web) library: search
books, see what's new, and browse your shelves.

**Setup.** Use a Calibre-Web user (a dedicated one with only the rights it
needs works well) and store its password in the vault. Enter Calibre-Web's
address, such as `https://books.example.com`, with its path if it runs
under one. The shelves shown are that user's own and the public ones. For a
self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `search` | read | Books matching a `query` (title, author, series, tag, publisher): authors, tags, languages, publisher, formats and a link to open each. |
| `recent` | read | The newest books in the library. |
| `shelves` | read | Shelf ids and names, with a link to each. |
| `shelf` | read | The books on one `shelf` (id). |

**Security.** The login goes as HTTP basic auth, and the client won't follow
a redirect to another host or from https to http. Shelf ids must be numbers
and searches one short line before they reach a request.

**Notes.** Conduit reads Calibre-Web's OPDS catalog, which shows one page of
books per request (Calibre-Web's "books per page" setting, 60 by default),
so `limit` goes up to that. The catalog is read-only, so this module doesn't
change the library.
