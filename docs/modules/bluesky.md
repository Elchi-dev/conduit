# Bluesky

Your Bluesky account, or an account on any AT Protocol server (PDS): profile,
home timeline, notifications, posting with rich text, replying, deleting a
post and searching posts.

**Setup.** In Bluesky go to Settings, Privacy and security, App passwords,
and add one for Conduit (no need to allow direct messages). Store it in the
vault, enter its `secret://` reference and your handle (`alice.bsky.social`)
or account email as `identifier`. Leave `service` at `https://bsky.social`
for accounts hosted by Bluesky, or enter your own PDS. Only app passwords
(`abcd-efgh-ijkl-mnop`) are accepted: the account's main password is refused
before it's sent, since it could change the account's email, handle and
password.

| Action | Risk | Notes |
| --- | --- | --- |
| `profile` | read | A profile (`actor`: handle or DID; you by default) with name, bio and follower, following and post counts. |
| `timeline` | read | Your home timeline (`limit` default 20, at most 100), newest first, with reposts marked by who reposted. |
| `notifications` | read | Likes, reposts, follows, mentions, replies and quotes, with the text of posts. |
| `post` | destructive | Posts `text` publicly to your feed: at most 300 characters (counted as graphemes, so an emoji with a skin tone or a flag is one). Links, `@handle` mentions and `#hashtags` become rich text (mentions of handles that don't resolve stay plain). Optional `langs` (up to 3). The preview shows the text, its length and every account it mentions (handle and resolved DID), who will be notified; undo deletes the post. |
| `reply` | destructive | Replies publicly to the post at `uri` (an `at://` URI from the other actions), threaded under the conversation's root. The preview also names the author being replied to (handle, DID and the post's URI). Undo deletes the reply. |
| `delete` | destructive | Deletes one of your posts (by `uri`) for good, with its likes and reposts. Other people's posts are refused. The preview quotes the post with its counts. |
| `search` | read | Searches public posts for `query`, sorted by `latest` (default) or `top`. |

Posting and replying are `destructive` even though they can be undone: a
public post is seen (and can be copied) by anyone the moment it's up, and
mentions and replies notify people who never asked to hear from your agent.
An agent approved only for `write` can't post. Deleting is `destructive`
because it can't be taken back.

**How sign-in works.** The module creates a session with the app password
and keeps it in memory; when the access token expires it refreshes the
session (and logs in again only if that fails). Restarting the daemon
starts a new session.

**Security.** The client won't follow a redirect to another host, so the app
password and tokens only go to the configured PDS. URIs, handles, DIDs,
language tags and the search query are checked before a request is made.

**Presets.** team, gamer.
