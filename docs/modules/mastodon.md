# Mastodon

Post to your account and catch up on notifications. Works with any server
with the Mastodon API: Mastodon, GoToSocial, Pleroma, Akkoma.

**Setup.** On your server go to Preferences, Development, New application;
give it the `read` and `write:statuses` scopes, copy the access token into the
vault, and enter your instance (`https://mastodon.social`, or just
`mastodon.social`).

| Action | Risk | Notes |
| --- | --- | --- |
| `post` | write | `visibility` is public (default), unlisted, private (followers) or direct. Optional `warning` (content warning) and `replyTo`. Undo deletes the post. |
| `delete` | destructive | The preview quotes the post. |
| `notifications` | read | Mentions, follows, boosts and favourites, with the text as plain text. |
| `mine` | read | Your recent posts with reply, boost and favourite counts. |

Status ids must be letters and digits only.
