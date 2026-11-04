# MediaWiki

Search a MediaWiki wiki, read pages as wikitext, and edit existing pages
with a bot password. Edits detect conflicts and can be undone: the undo puts
back the previous revision, as long as nobody has edited the page since.

**Setup.** On the wiki, open Special:BotPasswords, create a bot password
(for example named `conduit`) and give it the grants it needs: basic rights,
and "Edit existing pages" to edit. Enter the login name it shows, such as
`YourName@conduit`, as `username`, and store the password in the vault.
Enter the address of the wiki's `api.php`, such as
`https://wiki.example.com/w/api.php`. `assert` is `user` (the default) or
`bot`; with `bot` the account must have the bot right and edits are marked
as bot edits. For a self-signed certificate, pin its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `search` | read | Pages whose title or text matches, optionally in one `namespace`: title, page id, size, word count and last edit. `limit` up to 50. No page text. |
| `read_page` | read, sensitive | By `title` or `pageid`. The wikitext up to `maxChars` (default 50,000) with its revision id, timestamp, size and content model. Kept out of the audit log, approvals and events. |
| `edit_page` | write | Replaces an existing page's wikitext (`text`, with `summary` and `minor`) on a wiki anonymous visitors can't read. It never creates a page. The preview shows the lines added and removed and the first changed lines; the same text gives "nothing to change". Undo puts back the previous revision. |
| `edit_public_page` | destructive | The same, on a wiki anyone can read: what it writes is public at once. Undo puts back the previous revision. |
| `restore_revision` | write | The undo of an edit: puts the page back to the revision before its latest one. |

**Public or private.** Before each edit the module reads the wiki's user
groups: when the all-users group (`*`) has the `read` right, anyone can read
the wiki, and `edit_page` refuses and points to `edit_public_page`. If the
groups can't be read, the wiki counts as public.

**Edits and undo.** The module signs in with the bot password (login token,
then `action=login`), keeps the session in cookies, and signs in again once
if a request's `assert` says the session lapsed. Each edit gets a fresh
CSRF token and sends `nocreate`, `baserevid`, `basetimestamp` and
`starttimestamp`, so MediaWiki refuses it with an edit conflict if someone
saved the page in the meantime. The undo token names only the page id, the
revision to put back and the revision the edit created; `restore_revision`
goes ahead only while that revision is still the page's latest and the one
to put back is its parent, and then edits the page the same conflict-safe
way. Every request sends `maxlag=5`; when the wiki answers that its
database is lagging, the module waits for `Retry-After` and tries again,
giving up after three tries.

**Privacy.** Reading a page is sensitive. Search results leave out
snippets. Previews quote only lines of the new text; removed lines are
counted and named by line number, never quoted.

**Security.** The password is sent only in the login request's body, and
the client won't follow a redirect to another host or from https to http.
Titles are checked against the characters MediaWiki never allows, page ids
must be positive numbers and text at most 1 MiB, before any request is
sent. Server messages are redacted before they're shortened.

**Notes.** Pages that a private wiki lets anonymous visitors read anyway
(`$wgWhitelistRead`) aren't visible through the API, so they count as
private. Only the main slot's wikitext is read and written. There's no way
to create, move or delete pages here.
