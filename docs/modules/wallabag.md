# wallabag

Your [wallabag](https://wallabag.org) reading list: unread, starred and
archived articles, saving links, archiving (marking read), starring and
deleting.

**Setup.** In wallabag, open API clients management and create a client. Store
its client secret and your wallabag password in the vault; enter the client
ID (or a `secret://` reference to it), your user name and wallabag's address,
such as `https://wallabag.example.com` (or `https://app.wallabag.it`).
Conduit signs in with the OAuth2 password grant and keeps the access token
in memory, signing in again when it expires or is rejected.

| Action | Risk | Notes |
| --- | --- | --- |
| `entries` | read | Saved articles, newest first: `status` `unread` (the default), `starred`, `archived` or `all`, optionally with one `tag`. Title, link, site, tags and reading time; not the article text or your annotations. |
| `save_url` | write | Saves an http(s) `url` with an optional `title` and `tags`; wallabag fetches the page. Links to your own network are refused: loopback, private, link-local, carrier-grade NAT and other reserved IP addresses (also in numeric forms like `2130706433` or `127.1`), `localhost`, single-label names (`http://nas/`) and `.local`, `.internal`, `.localhost`, `.home.arpa` and `.lan` names, because wallabag's fetcher would reach them from inside it. Conduit asks wallabag whether the link is saved already; if so nothing is created and there's no undo, otherwise undo deletes the new entry. |
| `archive` | write | Moves an `entry` to the archive (wallabag's "mark as read"); undo puts it back in unread. |
| `unarchive` | write | Moves an archived entry back to unread; undo archives it again. |
| `star` | write | Stars an entry; undo unstars it. |
| `unstar` | write | Removes the star; undo stars it again. |
| `delete_entry` | destructive | With a preview. Deletes the entry with its saved copy and annotations; wallabag can't bring it back. |

Archive and star leave an entry alone (and return no undo) when it's
already as asked.

**Security.** Credentials are sent only to wallabag's token endpoint, in the
request body; the client won't follow a redirect to another host. Entry ids
are numbers checked before they reach a request path, and links with a user
name or password in them are refused. For a self-signed certificate, pin
its SHA-256 `fingerprint`.
