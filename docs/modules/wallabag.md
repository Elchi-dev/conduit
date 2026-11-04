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
| `save_url` | write | Saves an http(s) `url` with an optional `title` and `tags`; wallabag fetches the page. Links to your own network are refused: the host is first normalised (IDNA, so full-width digits and other look-alikes become the ASCII the server would use, and that ASCII form is what's sent), then loopback, private, link-local, carrier-grade NAT and other reserved IP addresses (also in numeric forms like `2130706433` or `127.1`, and IPv4-compatible `::/96` and old site-local `fec0::/10` IPv6), `localhost`, single-label names (`http://nas/`), the `.local`, `.internal`, `.localhost`, `.home.arpa`, `.lan`, `.localdomain`, `.svc`, `.cluster.local`, `.home`, `.corp` and `.intranet` suffixes, wildcard-DNS names that embed a reserved address (`127.0.0.1.nip.io`, `app-10-0-0-1.sslip.io`, `xip.io`) or always mean loopback (`lvh.me`, `localtest.me`) are refused. Conduit then resolves the name and refuses it if any address is reserved, or if it doesn't resolve. That is defence in depth: redirects, and a name resolving differently when the server fetches it (DNS rebinding), are for the server's own outbound rules, so configure it to refuse private addresses too. Conduit asks wallabag whether the link is saved already; if so nothing is created and there's no undo, otherwise undo deletes the new entry. |
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
