# Zulip

A Zulip organization through its REST API: subscribed streams (channels),
unread counts, recent messages in the streams and topics you allow, and
sending messages there. Works with Zulip Cloud and self-hosted servers.

**Setup.** A bot is best: in Zulip open Personal settings, Bots, add a
generic bot and subscribe it to the streams it should use. Store its API key
in the vault and enter its `secret://` reference as `apiKey`, and the bot's
email (`conduit-bot@example.zulipchat.com`) as `email`. Your own account
works too (Personal settings, Account and privacy, API key). `url` is the
organization's address. List what Conduit may use in `allowed`: a whole
stream (`general`) or a single topic in one (`general > deploys`, split at
the first `>`). Names are matched without regard to case. With nothing
allowed the instance is healthy but degraded. For a self-signed
certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `streams` | read | Subscribed streams with id, whether each is private or muted, and whether it's allowed (`true`, `false` or `"some topics"`). |
| `unread` | read, sensitive | Unread message counts by stream, with a per-topic breakdown only for allowed streams and topics, and the number of unread direct messages (never their senders or text). Counts the newest 1000 unread messages. |
| `messages` | read, sensitive | Recent messages in an allowed `stream`, or one `topic` in it (`limit` default 30, at most 100), oldest first: id, sender, topic, time and the Markdown source. A stream where only some topics are allowed needs a `topic`. |
| `send_message` | write, sensitive | Sends `content` (Markdown, at most 10000 bytes) to `topic` in an allowed `stream`. Wildcard mentions (`@**all**`, `@**everyone**`, `@**channel**`, `@**stream**`, `@**topic**`, silent ones too), which notify the whole stream or topic, are refused; there's no way to send those from Conduit. The preview names the stream and topic and everyone mentioned (people and `@*groups*`); undo deletes the message. |
| `delete_message` | destructive | Deletes message `id` for everyone, if it's in an allowed stream or topic (the organization's settings decide whose messages the account may delete, and for how long). The preview names its author, time and stream, not its text. Can't be undone. |

**Security.** The email and key are sent as HTTP basic authentication and
the client won't follow a redirect to another host. Stream and topic names
are checked (1 to 60 characters, no control characters) and matched against
`allowed` before any request; messages a narrow returns from outside the
allowed list are dropped. `unread`, `messages` and `send_message` are
sensitive: message text, topics and names stay out of the audit log,
approvals and events. The undo token holds only the message id.

**Presets.** team, developer.
