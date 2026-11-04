# Rocket.Chat

A Rocket.Chat account through the REST API: the channels and private groups
it's in, unread counts, recent messages in the rooms you allow, and sending
messages there.

**Setup.** Use a bot account if you can. In Rocket.Chat open My Account,
Personal Access Tokens, and add a token (two-factor confirmation may be
asked). Rocket.Chat shows the token and a user id: store the token in the
vault and enter its `secret://` reference as `token`, and the user id as
`userId` (it isn't secret). `url` is the server's address. List the rooms
Conduit may use in `allowedRooms` by name, as in the room's address
(`general`, `ops-alerts`); channels and private groups only, never direct
messages. With no allowed rooms the instance is healthy but degraded and can
only list rooms and unread counts. For a self-signed certificate, enter its
SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `channels` | read | Channels and private groups the account is in (name, type, display name, archived) and whether each is allowed. Direct messages aren't listed. |
| `unread` | read, sensitive | Rooms with unread messages, with unread and mention counts and the total. Direct messages are named after the other person, so the output stays out of the audit log. |
| `messages` | read, sensitive | Recent messages in an allowed `room` (`limit` default 30, at most 100), oldest first: id, sender, time, text, thread; system messages (joins, topic changes) are marked by type. |
| `send_message` | write, sensitive | Sends `text` (Markdown, at most 5000 characters) to an allowed `room`, in a `thread` when given. The preview names the room; undo deletes the message. |
| `delete_message` | destructive | Deletes message `id` in an allowed `room` for everyone (others' messages only if the account may). The message must be in that room. The preview names its author and time, not its text. Can't be undone. |

**Security.** The token goes in `X-Auth-Token` and the client won't follow a
redirect to another host, so it only reaches the configured server. Room
names and message ids are checked before any request, and rooms outside
`allowedRooms` are refused before anything is sent; a room looked up must be
a channel or private group of the same name. `unread`, `messages` and
`send_message` are sensitive: message text and names stay out of the audit
log, approvals and events. The undo token holds only the room name and
message id.

**Presets.** team.
