# Slack

Post to channels and read what's been said in them.

**Setup.** For posting to one channel, add an incoming webhook (your Slack
app, Incoming Webhooks) and store its URL in the vault. To post anywhere,
reply in threads, list channels and read recent messages, create a Slack app
with a bot token (`xoxb-…`) and these bot scopes: `chat:write`,
`channels:read`, `groups:read`, `channels:history`, `groups:history`. Invite
the bot to each channel it should use (`/invite @yourbot`). Optionally set a
default channel id (it starts with `C`).

| Action | Risk | Notes |
| --- | --- | --- |
| `send` | write | With the bot to `channel` (or the default channel), optionally in a `thread`; otherwise through the webhook. Broadcast mentions (`<!channel>`, `<!here>`, `<!everyone>`, group mentions) are escaped so a message can't ping everyone. Undo deletes a bot message; webhook posts can't be deleted through the API, so they have no undo. |
| `delete_message` | destructive | Only messages the bot posted. |
| `channels` | read | Public and private channels the bot can see, and whether it's in them (bot) |
| `history` | read | Recent messages in a channel, up to 200 (bot) |

Slack reports errors inside a successful HTTP answer (`"ok": false`);
Conduit turns them into plain errors, such as "the bot isn't in that
channel".

**Security.** The bot token and the webhook URL both grant posting rights,
so both live in the vault. Reading history gives whoever holds the module's
read permission the channel's contents; scope the bot to the channels it
needs.
