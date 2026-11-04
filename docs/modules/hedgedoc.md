# HedgeDoc

HedgeDoc's collaborative Markdown notes: list your notes, read one, and
create new ones. It works with HedgeDoc 2 and an API token, and with
HedgeDoc 1.x through its public API.

**Setup.** For HedgeDoc 2, open your profile's settings, create an API
token and store it in the vault; it acts as you. For HedgeDoc 1.x, set
`version` to `1` and leave the token empty: HedgeDoc 1 has no API tokens.
Enter HedgeDoc's address, such as `https://md.example.com`. For a
self-signed certificate, pin its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `notes` | read | Your notes (HedgeDoc 2): id or alias, title, description, tags and dates. No note text. |
| `read_note` | read, sensitive | By id, alias or address. The Markdown up to `maxChars` (default 50,000) with title, description and dates. On HedgeDoc 1, notes anyone may view. Kept out of the audit log, approvals and events. |
| `create_note` | write | A new note with the Markdown given, at a random address. The preview shows how many lines it has and the first ones. HedgeDoc 2: it belongs to you, with the server's default permissions. HedgeDoc 1: it's anonymous, and anyone who has its address can read and edit it. |

Creating a note is write, not destructive: the note gets a random address
that isn't published or listed anywhere, and its content is what the agent
wrote (and the log shows).

**Endpoints.** HedgeDoc 2: `GET /api/v2/me`, `GET /api/v2/me/notes`,
`GET /api/v2/notes/{note}/metadata` and `/content`, and `POST /api/v2/notes`
with a `text/markdown` body. HedgeDoc 1: `GET /status`,
`GET /{note}/info` and `/download`, and `POST /new` with a `text/markdown`
body, whose answer is a redirect to the new note; the module reads where it
points instead of following it.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Note ids are
checked (letters, digits, `-`, `_`, `.`, `~`; an address must be on this
server) and escaped before they reach a path, and content is at most 1 MiB.

**Notes.** HedgeDoc 2 is in alpha and its API still changes between
releases; the endpoints above are the ones in both v2.0.0-alpha.3 and the
current development branch. Listing notes needs HedgeDoc 2: HedgeDoc 1
keeps a user's notes in a history that only a signed-in browser session can
read. On HedgeDoc 1, notes limited to signed-in users or private ones can't
be read, and creating notes needs the server to allow anonymous notes.
Editing and deleting notes aren't offered.
