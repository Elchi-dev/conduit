# Discord

Post, reply, react and pin in your server, read channels, threads and
members, and moderate with previews and undo.

**Setup.** For posting only, create a webhook (Channel settings,
Integrations) and store its URL in the vault. For everything else, create
a bot (Discord Developer Portal, New Application, Bot), invite it to your
server (OAuth2, URL Generator, scope `bot`, with the permissions below),
store its token in the vault, and enter the server id (Developer Mode,
right-click the server, Copy Server ID).

| Action | Risk | Notes |
| --- | --- | --- |
| `send` | write | Through the webhook, or the bot when `channel` is given. Undo deletes it |
| `delete_message` | destructive | Preview names the author, time and channel |
| `server` | read | Name, members, online now |
| `channels` | read | |
| `messages` | read | Latest messages in a channel (up to 100 a page, `before` for older): author, text shortened to 1000 characters, sent and edited times, attachment names and count. Kept out of logs |
| `threads` | read | Active threads in the server, with their channel, messages and members |
| `reply` | write | Replies to a message. Preview first. Undo deletes the reply |
| `react` / `unreact` | write | The bot's own reaction: a unicode emoji such as 👍, or a server emoji as `name:id`. Each is the other's undo |
| `create_thread` | write | From a message (`id`), or on its own in a channel (`private` for a private one). Preview first. Undo archives it, so what was said stays |
| `archive_thread` | write | Closes a thread until someone posts again |
| `pin_message` / `unpin_message` | write | Each is the other's undo |
| `members` | read | Display names, roles and join dates, up to 1000 a page (`after` for the next). Kept out of logs |
| `timeout_member` | destructive | For a `duration` (`10m`, `2h`, `7d`, at most 28 days) or `until` a time. Preview names the member and server. Undo lifts it, or restores the earlier timeout |
| `remove_timeout` | destructive | Lets the member talk again now. Undo puts the timeout back until it would have ended |
| `kick_member` | destructive | They can rejoin with an invite. Preview first; no undo |
| `ban_member` | destructive | Optionally deletes their messages from the past `deleteMessageHours` (up to 168). Works for people not in the server too. Undo unbans |
| `unban_member` | destructive | Undo bans them again |

Messages and replies notify no one: mentions are shown but don't ping,
and text with `@everyone` or `@here` isn't sent. A message is up to 2000
characters. Moderation actions add an entry to the server's audit log
reading "Conduit", followed by your `reason` when you give one. The server
owner and the bot itself are never moderated. When something is already as
asked (a message already pinned, a member not timed out), the action says
"nothing to change" and leaves it be. Lifting a timeout and unbanning are
destructive too, since they give someone back access.

Ids are checked before anything is sent, the token is used only with
Discord's own address (redirects elsewhere are refused), and error text is
redacted. When Discord asks the bot to slow down, a request is retried
once after a short wait.

## Notes

Conduit works through a bot you invite to your server, which is the way
Discord supports for automation; it never signs in as a person's account.
The bot can do only what its role allows, and its role must sit above a
member's highest role to moderate them.

Permissions each action needs (Server Settings, Roles, or chosen when
inviting the bot):

| Action | Permissions |
| --- | --- |
| `send`, `reply` | View Channel, Send Messages (Send Messages in Threads inside a thread) |
| `delete_message` | Manage Messages for other people's messages; none for the bot's own |
| `messages` | View Channel, Read Message History |
| `threads`, `server`, `channels` | View Channel (only what the bot can see is listed) |
| `react`, `unreact` | Read Message History, Add Reactions |
| `pin_message`, `unpin_message` | Pin Messages, Read Message History |
| `create_thread` | Create Public Threads (Create Private Threads for a private one), Read Message History |
| `archive_thread` | Manage Threads |
| `timeout_member`, `remove_timeout` | Timeout Members (Moderate Members) |
| `kick_member` | Kick Members |
| `ban_member`, `unban_member` | Ban Members |

Two privileged intents are switched on in the Developer Portal (Bot,
Privileged Gateway Intents):

- **Message Content** for `messages` to show what messages say; without it
  the text is empty except for messages that mention the bot.
- **Server Members** for `members`.

The webhook URL contains its own secret, so it lives in the vault like the
bot token.
