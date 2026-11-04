# Paperless-ngx

Search and browse your Paperless-ngx document archive, read a document's
details and text, and tag documents.

**Setup.** In Paperless-ngx, open your profile and create an API auth token,
then store it in the vault. It acts with that user's permissions. Enter the
server address, such as `https://paperless.example.com`.

| Action | Risk | Notes |
| --- | --- | --- |
| `search` | read | Full-text search (Paperless query syntax works), with correspondent, type and tag names and a relevance score. No document text. |
| `recent` | read | The newest documents added. |
| `document` | read | Title, correspondent, type, tags, dates, archive serial number, file name, MIME type, size, pages, language and note count. |
| `document_content` | read, sensitive | The OCR text, up to `maxChars` (default 20,000). Documents often hold personal data, so input and output are kept out of the audit log, approvals and events. |
| `tags` / `correspondents` / `document_types` | read | With document counts. |
| `add_tag` | write | Adds a `tag` (id) to up to 100 `documents`. The preview lists the documents that change. Undo removes it only from the ones that didn't already have it. |
| `remove_tag` | write | The reverse; undo adds the tag back only where it was. |

Uploading documents isn't part of this module.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host. Document and tag ids must be
positive numbers before they reach a request path.
