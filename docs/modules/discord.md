# Discord

Post to channels and see how a server is doing.

**Setup.** For posting only, create a webhook (Channel settings,
Integrations) and store its URL in the vault. For server status, channel
lists and posting to any channel, add a bot token (Discord Developer Portal)
and the server id (Developer Mode, right-click the server, Copy ID).

| Action | Risk | Notes |
| --- | --- | --- |
| `send` | write | Through the webhook, or the bot when `channel` is given. Mentions are disabled so a message can't ping everyone. Undo deletes it. |
| `delete_message` | destructive | |
| `server` | read | Name, members, online now (bot) |
| `channels` | read | (bot) |

The webhook URL contains its own secret, so it lives in the vault like a
token.
