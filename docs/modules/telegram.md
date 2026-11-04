# Telegram

A Telegram bot through the Bot API: who the bot is, recent messages in the
chats it may read, chat details, and sending, editing, deleting and pinning
messages. The [notifications](notify.md) module can already send alerts to
Telegram; this module is for working with a bot's chats.

**Setup.** Talk to [@BotFather](https://t.me/BotFather), create a bot with
`/newbot`, store the token in the vault and enter its `secret://` reference.
List the chats the bot may use in `allowedChats` (numeric ids; groups and
channels start with `-100`). Every other chat is ignored: its messages are
dropped and nothing can be sent there. To find an id, add the bot to the
chat, send a message and run `messages`; ignored chats are listed by id and
type (without their content) so you can add them. In groups, the bot only
sees every message when its privacy mode is off (`/setprivacy` in
BotFather) or it's an admin.

| Action | Risk | Notes |
| --- | --- | --- |
| `me` | read | The bot's id, username, whether it can join groups and read all group messages, and the allowed chats. |
| `messages` | read, sensitive | Recent messages in the allowed chats (`chat` to narrow to one, `limit` default 20, at most 100), newest last: sender, text or caption, attachment kind, edits, replies. |
| `chat` | read, sensitive | An allowed chat's title, type, description, member count and pinned message. |
| `send_message` | write | `text` (up to 4096 characters), optional `parseMode` (`MarkdownV2` or `HTML`), `silent`, `replyTo`. The preview shows the text; undo deletes the message (Telegram allows that for 48 hours). |
| `edit_message` | write | Replaces the text of a message the bot sent. The preview shows the old text when Conduit knows it (messages it sent or edited since the daemon started), and only then can it be undone. Undo restores the plain text, without formatting. |
| `delete_message` | destructive | Deletes a message for everyone, with a preview. A bot can delete its own messages for 48 hours and others' only as an admin. Can't be undone. |
| `pin_message` | write | Pins silently unless `notify`; undo unpins. |
| `unpin_message` | write | Unpins a `message`, or the latest pin when none is given; undo pins it again. |

**How reading works.** Actions never long-poll. `messages` calls
`getUpdates` with a timeout of 0, at most five pages of 100 updates, and
keeps the offset in memory, so each update is fetched once and confirmed to
Telegram. Messages from allowed chats are kept in memory (the last 500) so
reading them again still shows them; they're gone when the daemon restarts.
Because updates are confirmed, another program reading the same bot's
updates would miss them, and Telegram refuses `getUpdates` while the bot has
a webhook; use a separate bot for Conduit.

**Security.** The token is part of every request URL, so transport errors
are rewritten without the URL and the token never appears in messages or
logs; it's also checked to look like a BotFather token before use. The
client won't follow a redirect to another host. Chat ids must be numbers in
the allow-list before any request is made. `messages` and `chat` are
sensitive: their content stays out of the audit log, approvals and events.

**Presets.** homelab, team.
