# BookStack

Browse and search a BookStack wiki, read pages as Markdown, and create, edit
and delete pages.

**Setup.** In BookStack, open your profile, then API Tokens, and create a
token. Store it in the vault as `<token id>:<token secret>` (one value,
joined by a colon). It acts with that user's permissions, and the user's
role needs the "Access system API" permission. Enter BookStack's address,
such as `https://wiki.example.com`. For a self-signed certificate, pin its
SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `shelves` | read | Every shelf, by name. |
| `books` | read | Every book, or the books on one `shelf` (id). |
| `book` | read | A book's chapters and pages, in order, with links. |
| `chapter` | read | A chapter's pages. |
| `search` | read | BookStack search syntax works (`[tag=value]`, `{type:page}`). Names, types, book and chapter, tags and links; no page text. |
| `read_page` | read, sensitive | The page exported as Markdown (up to `maxChars`, default 50,000), with its book, chapter, tags and revision count. Kept out of the audit log, approvals and events. |
| `create_page` | write | In a `book` or a `chapter` (ids), with `name`, `markdown` (or `html`) and `tags`. The preview names the book or chapter; undo deletes the page. |
| `update_page` | write | Changes only the `name`, content or `tags` given. The preview shows the old and new name and content length. A change of `name` or `tags` alone can be undone (the old ones are put back); a content change can't be undone here: use the page's revisions in BookStack. |
| `delete_page` | destructive | With a preview. BookStack moves the page to its recycle bin, where an admin can restore it. |

Only pages are created, edited and deleted; shelves, books and chapters are
read-only here.

**Privacy.** Reading a page is sensitive. Writes aren't: what an agent
writes is logged like any other write. The previous content never is, which
is why a content change has no undo here (its token would sit in the audit
log): BookStack keeps every edit in the page's revision history, where you
can restore it.

**Security.** The token goes in the `Authorization` header and the client
won't follow a redirect to another host. Ids must be positive numbers before
they reach a request path, names are at most 255 characters and content at
most 2 MiB.
