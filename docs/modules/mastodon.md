# Mastodon

Post to your account and catch up on notifications. Works with any server
with the Mastodon API: Mastodon, GoToSocial, Pleroma, Akkoma.

**Setup.** On your server go to Preferences, Development, New application;
give it the `read` and `write:statuses` scopes, copy the access token into the
vault, and enter your instance (`https://mastodon.social`, or just
`mastodon.social`).

| Action | Risk | Notes |
| --- | --- | --- |
| `post` | destructive | `visibility` is public (default), unlisted, private (followers) or direct. Optional `warning` (content warning) and `replyTo` (a status id: a reply). The preview names the visibility, every `@user` or `@user@server` it mentions and, for a reply, the author being replied to. Undo deletes the post. |
| `delete` | destructive | The preview quotes the post. |
| `notifications` | read | Mentions, follows, boosts and favourites, with the text as plain text. |
| `mine` | read | Your recent posts with reply, boost and favourite counts. |

Posting is `destructive` even though it can be undone: it's public by
default, and whatever the visibility every mentioned account is notified
(a direct post goes only to them), so it can reach strangers. An agent
approved only for `write` can't post.

Status ids must be letters and digits only.
