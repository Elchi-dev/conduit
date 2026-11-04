# Karakeep

Search and browse your [Karakeep](https://karakeep.app) (formerly Hoarder)
bookmarks and lists, save links and tag them.

**Setup.** In Karakeep, open User Settings, API Keys, and create a key, then
store it in the vault. It acts as you. Enter Karakeep's address, such as
`https://bookmarks.example.com`.

| Action | Risk | Notes |
| --- | --- | --- |
| `search` | read | Karakeep's search with its qualifiers (`#tag`, `list:name`, `is:fav`, `after:2026-01-01`), most relevant first. |
| `recent` | read | The newest bookmarks, everywhere or in a `list` (id), optionally only `favourited`; archived ones only with `archived`. |
| `lists` | read | Your lists, nested ones with their parent, smart lists with their query. |
| `bookmark` | read | One bookmark with its description, your note and Karakeep's summary. |
| `add_bookmark` | write | Saves an http(s) `url`, with an optional `title` and `note`; Karakeep fetches the page and tags it in the background. Undo deletes the bookmark, unless the link was already saved (then nothing was created and there's no undo). |
| `tag` | write | Attaches `tags` by name (new ones are created). The preview lists only the tags it adds; undo removes those. |
| `untag` | write | Detaches `tags` (the tags themselves stay); undo attaches them again. |
| `delete_bookmark` | destructive | With a preview. Deletes the bookmark with its archived copy, note and highlights; Karakeep can't bring it back. |

Search and listings return titles, links, tags and dates, not page content
or your notes; `bookmark` returns the note.

**Security.** The key goes in the `Authorization` header and the client
won't follow a redirect to another host. Bookmark and list ids are checked
before they reach a request path, and links with a user name or password in
them are refused. For a self-signed certificate, pin its SHA-256
`fingerprint`.
