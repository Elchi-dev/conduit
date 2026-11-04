# Lemmy

A Lemmy account through the instance's API (v3, Lemmy 0.19 and later):
subscribed communities, posts and comments, and posting and commenting.

**Setup.** Enter your instance's address as `url`. Then either your
`username` and `password` (stored in the vault, entered as a `secret://`
reference): Conduit signs in, keeps the session token (JWT) in memory and
signs in again when it expires. Or, for an account with two-factor
authentication, a session `token` instead: copy the `jwt` cookie from a
signed-in browser into the vault. A separate account for your agent is
best. To keep posting to a few places, list them in `allowedCommunities`
(`selfhosted`, or `linux@lemmy.ml` for a community on another instance);
when it's empty, posting may go to any community. For a self-signed
certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `communities` | read | Communities the account is subscribed to (`name@instance`, title) and whether posting there is allowed. |
| `posts` | read, sensitive | Posts from the `subscribed` (default), `local` or `all` feed, or from one `community`, sorted `hot` (default), `new`, `active`, `top_day`, `top_week` or `top` (`limit` default 20, at most 50): id, title, link, text, community, author, score and comment count. |
| `comments` | read, sensitive | Comments on a `post` (sorted `top`, `hot` or `new`, at most 50): id, author, text, score and the comment replied to; removed comments are marked, not shown. |
| `create_post` | destructive, sensitive | Publishes a post with `title` (one line, at most 200 characters), optional `body` (Markdown) and `url`, and `nsfw`, to a `community`. The preview names the community, whether it's hosted on another instance, and that the post is copied to every instance that follows it. No undo. |
| `create_comment` | destructive, sensitive | Comments `text` on a `post`, or replies to comment `parent` on it. Locked posts are refused. The preview names the community and the author replied to, who is notified. No undo. |

Posting and commenting are `destructive`: Lemmy is public and federated, so
a post or comment is copied to other instances the moment it's made (a
later delete is a request they may ignore) and replies notify people. An
agent approved only for `write` can't post. Votes, reports and moderation
aren't offered.

**Security.** The client won't follow a redirect to another host, so the
password and session only reach the configured instance. Community names,
ids and options are checked before any request. A link in `create_post` is
fetched by the instance for its preview, so it must be a public http(s)
address: local and private addresses, names that resolve to them, and links
with a user name or password are refused. Posts, comments and what you post
are sensitive: they stay out of the audit log, approvals and events.

**Presets.** homelab, gamer.
