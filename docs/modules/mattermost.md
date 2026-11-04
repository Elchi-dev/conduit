# Mattermost

Channels and recent posts on a Mattermost server, who's online, and
posting messages (with undo).

**Setup.** Create a personal access token (Profile, Security, Personal
Access Tokens; an administrator may need to allow them) or use a bot
account's token. Store it in the vault, enter the server address, and
optionally a default **team** (its name as in the address, e.g.
`engineering`).

| Action | Risk | Notes |
| --- | --- | --- |
| `channels` | read | Public and private channels the account is in, most recently active first |
| `posts` | read | The latest posts in a channel (up to 200), newest first, with user names and thread ids |
| `statuses` | read | Online, away, do not disturb or offline, for named users or the default team's members |
| `post_message` | write | Markdown; `rootId` replies in a thread. Preview first. Undo deletes the post |
| `delete_post` | destructive | Preview shows the author, time and text |

A channel is its name in the default team (`town-square`), `team/channel`,
or a channel id. Names, ids and user names are checked before anything is
sent, so input can't reach other API paths, and redirects to another host
are refused.
