# linkding

Search and browse your [linkding](https://linkding.link) bookmarks and tags,
save links, archive and delete them.

**Setup.** In linkding open Settings → Integrations and copy the REST API
token, then store it in the vault. It acts as you. Enter linkding's address,
such as `https://links.example.com` (with its context path, if it has one).

| Action | Risk | Notes |
| --- | --- | --- |
| `search` | read | linkding's search (words, `#tag`, `!untagged`, `!unread`), newest first; archived ones with `archived`. |
| `recent` | read | The newest bookmarks, or the newest archived ones. |
| `tags` | read | Your tags by name. |
| `add_bookmark` | write | With a preview. Saves an http(s) `url` with an optional `title`, `description`, `tags` (single words) and `unread`. It's never shared. Links to your own network are refused (loopback, private, link-local, carrier-grade NAT and other reserved addresses in any form, `localhost`, single-label names, `.local`, `.internal`, `.lan` and similar names, wildcard DNS names like `127.0.0.1.nip.io`, and names that resolve to a private address), because linkding fetches the page from inside it. linkding's create would overwrite a bookmark that has the URL already, so Conduit checks first and leaves an existing one alone. Undo deletes the new bookmark. |
| `archive_bookmark` | write | With a preview. Moves a bookmark to the archive; undo unarchives it. |
| `unarchive_bookmark` | write | With a preview. Brings it back; undo archives it again. |
| `delete_bookmark` | destructive | With a preview. Deletes the bookmark with its notes and snapshots; linkding can't bring it back. |

Listings return titles, links, tags and dates, not your notes. Sharing
bookmarks isn't offered: shared bookmarks can be public, and publishing is
destructive in Conduit.

**Security.** The token goes in the `Authorization` header and the client
won't follow a redirect to another host or from https to http. Bookmark ids
are integers, and links with a user name or password in them are refused.
For a self-signed certificate, pin its SHA-256 `fingerprint`.
