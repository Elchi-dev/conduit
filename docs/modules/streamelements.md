# StreamElements

Your StreamElements channel, read-only: the activity feed (tips, follows,
subs, cheers, raids), the loyalty points leaderboard and the chat bot's
commands.

**Setup.** On streamelements.com, open your avatar, *Account*, *Channels*,
and turn on *Show secrets*. Store the **JWT Token** in the vault (not the
overlay token: the module refuses anything that isn't a JWT before sending
it). The account ID shown beside it is optional; the module reads the
token's own channel. JWT tokens are revoked when you reset them on that
page; health says when the token stopped working.

| Action | Risk | Notes |
| --- | --- | --- |
| `activities` | read, sensitive | The feed of the last `days` (7, up to 30), newest first, up to `limit` (25, up to 100): type, name, amount and currency, tier, gifts, message. `types` narrows it (follow, tip, subscriber, cheer, raid, host, redemption, merch, superchat, sponsor). Sensitive: it names and quotes viewers, with what they paid. |
| `leaderboard` | read, sensitive | Top viewers by loyalty `points` (default), `alltime` points or `watchtime` minutes, up to `limit` (10). Sensitive: it's a list of your viewers. |
| `commands` | read | The bot's custom commands with their replies, cooldowns, cost, who may use them and whether they work online or offline only. |

**Security.** The JWT can change everything in your StreamElements
account; the module only reads with it. The API address isn't a setting
and redirects to another host are refused.
