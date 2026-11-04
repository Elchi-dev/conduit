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
| `update_document` | write | Changes the `title` and/or replaces the whole `text`. The preview shows the title and length before and after; undo puts the previous ones back. |
| `archive_document` | write | Moves it and its children to the archive; undo restores it. |
| `restore_document` | write | Brings back an archived or trashed document, optionally into another `collection`; undo archives or trashes it again. |
| `delete_document` | destructive | Moves it and its children to the trash, which Outline empties after 30 days; undo restores it while it's there. Permanent deletion isn't offered. |

A document is named by its id, its urlId, or its address
(`https://…/doc/title-AbCdE12345`); collections by their id.

**Privacy.** Reading is sensitive; writes are logged like other writes, so
the text an agent writes and the previous text an undo restores appear in
the audit log.

**Security.** The key goes in the `Authorization` header and the client
won't follow a redirect to another host. Every call is a JSON POST, and ids
are checked before any request.
