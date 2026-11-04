# Nextcloud Talk

Nextcloud Talk (the spreed app) through its OCS API: conversations and
unread counts, recent messages in the conversations you allow, and sending
messages there. The [Nextcloud](nextcloud.md) module covers files and
shares.

**Setup.** Create an app password (Personal settings, Security, Devices and
sessions; a separate bot user is best), store it in the vault and enter its
`secret://` reference as `appPassword`, with the user name as `user`. `url`
is the Nextcloud address (with its path if it's installed under one). List
the conversations Conduit may read and send to in `allowedConversations` by
token, the part after `/call/` in the conversation's address (`a1b2c3d4`).
With none allowed, or with Talk not installed, the instance is healthy but
degraded. For a self-signed certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `conversations` | read, sensitive | Conversations the account is in, latest activity first: token, name (a one-to-one conversation is named after the other person), type, unread count, mention, read-only, and whether each is allowed. |
| `unread` | read, sensitive | Conversations with unread messages, with unread counts and whether the account was mentioned. |
| `messages` | read, sensitive | Recent messages in an allowed `conversation` (`limit` default 30, at most 100), oldest first: id, sender, time, text with mentions filled in, reply-to; system messages and deleted messages are marked. Doesn't move the read marker. |
| `send_message` | write, sensitive | Sends `text` (Markdown, at most 32000 characters) to an allowed `conversation`, as a reply to message `replyTo` when given. Read-only conversations are refused. The preview names the conversation and its type; undo deletes the message. |
| `delete_message` | destructive | Deletes message `id` in an allowed `conversation` for everyone (Talk allows this for 6 hours, and others' messages only for moderators). The preview names the conversation and message id, not its text. Can't be undone. |

**Security.** The user name and app password are sent as HTTP basic
authentication and the client won't follow a redirect to another host.
Conversation tokens and message ids are checked before any request, and
conversations outside `allowedConversations` are refused before anything is
sent. Listings, messages and sends are sensitive: names and text stay out of
the audit log, approvals and events. The undo token holds only the
conversation token and message id.

**Presets.** homelab, team.
