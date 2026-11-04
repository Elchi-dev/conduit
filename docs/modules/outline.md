# Outline

Search an Outline knowledge base, read documents as Markdown, and create,
edit, archive, restore and delete them. Works with
[getoutline.com](https://www.getoutline.com) and self-hosted Outline.

**Setup.** In Outline, open Settings, API & Apps, and create an API key
(give it only the scopes you need), then store it in the vault. It acts with
your permissions. Leave the address empty for `app.getoutline.com`, or enter
your own, such as `https://wiki.example.com`.

| Action | Risk | Notes |
| --- | --- | --- |
| `collections` | read | Collections you can see, with your permission on each. |
| `search` | read | Most relevant first, optionally in one `collection` or by `statusFilter` (published, draft, archived). Titles, collections, links and rank; no document text. |
| `recent` | read | Recently updated documents, everywhere or in a `collection`. |
| `read_document` | read, sensitive | Title and Markdown text (up to `maxChars`, default 50,000), with collection, dates and who last edited it. Kept out of the audit log, approvals and events. |
| `create_document` | write | Published in a `collection` (id), optionally under a `parent` document. Undo moves it to the trash. |
| `update_document` | write | Changes the `title` and/or replaces the whole `text`. The preview shows the title and length before and after. When the text changes, undo restores the revision that was current (`restore_revision`, by its id), if Outline has saved one since the last edit; otherwise there's no undo and Outline's document history has the old text. A title-only change is undone by putting the old title back. |
| `restore_revision` | write | Puts a document back as it was in one of its revisions (`revision`, an id): title and text. Used by `update_document`'s undo; its own undo restores the revision that was current. |
| `archive_document` | write | Moves it and its children to the archive; undo restores it. |
| `restore_document` | write | Brings back an archived or trashed document into the collection it was in. A `collection` is accepted only when that one no longer exists (Outline then needs one); the preview names it. Undo archives or trashes it again. |
| `restore_document_to` | destructive | Brings back an archived or trashed document into another `collection`, which changes who can see it. The preview names both collections; undo moves it back. |
| `move_document` | destructive | Moves a document and its children to the top of another `collection`, which changes who can see it. The preview names both collections; undo moves it back. |
| `delete_document` | destructive | Moves it and its children to the trash, which Outline empties after 30 days; undo restores it while it's there. Permanent deletion isn't offered. |

A document is named by its id, its urlId, or its address
(`https://…/doc/title-AbCdE12345`); collections by their id.

**Privacy.** Reading is sensitive. Writes are logged like other writes, so
the text an agent writes appears in the audit log, but the previous text
never does: undo tokens name a revision, not its text.

**Security.** The key goes in the `Authorization` header and the client
won't follow a redirect to another host. Every call is a JSON POST, and ids
are checked before any request.
