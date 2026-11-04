# Gotify

Applications and received messages of a Gotify server, sending a message
and deleting messages.

**Setup.** Gotify has two kinds of token. A client token (Clients, Create
client) reads applications and messages and deletes messages; an
application token (Apps, Create application) sends messages as that
application. Store either or both in the vault and enter their `secret://`
references with your server's address, such as
`https://gotify.example.com`. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `applications` | read | Id, name, description, default priority, internal, last used. Needs the client token. |
| `messages` | read | Received messages, newest first (`limit`, default 20, at most 200), optionally of one `application`: application, title, text (up to 2000 characters), priority and date. `before` gives the next page. Needs the client token. |
| `send_message` | write | Sends a `message` with an optional `title`, `priority` (0 to 10) and `markdown`. With a preview. Undo deletes it from Gotify, when the client token belongs to the same user as the application. |
| `delete_message` | destructive | Deletes one message by `id`; the preview shows it. A message that's already gone reports nothing to change. Needs the client token. |

**Notes.** A Gotify message reaches the devices signed in as the
application token's user, not other people on the server, so sending is
write rather than destructive. High priorities can sound on phones and,
from 8, override do-not-disturb, depending on each phone's settings. Undo
removes the message from Gotify, while a notification a phone already
showed stays there.

**Security.** Tokens go in the `X-Gotify-Key` header, and the client won't
follow a redirect to another host or from https to http. Applications are
read field by field, so their tokens never come back, and message extras
(click links and other client data) are left out.

**Presets.** homelab.
