# Discourse

A Discourse forum through its API: categories, the latest and unread topics,
reading topics in the categories you allow, and replying there.

**Setup.** As an admin, open Admin, API, New API key. Choose a single user
(a bot account is best) and give it read and write scopes, or global access
for that user. Store the key in the vault and enter its `secret://`
reference as `apiKey`, and the user it acts as as `username`. `url` is the
forum's address. List the categories Conduit may read topics in and reply to
in `allowedCategories`, by slug as in their address (`support`) or by id.
A bare slug matches only a top-level category: a subcategory's slug is
unique only within its parent (a private `staff` category can have its own
`general`), so a subcategory is listed as `parent/child`
(`support/billing`) or by id, and allowing `support` doesn't allow
`support/billing`. A path that more than one category has, or a
subcategory whose parent isn't visible, matches nothing. With none allowed, the instance is healthy but degraded
and can only list categories and topics. For a self-signed certificate,
enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `categories` | read | Categories and subcategories with id, slug, parent, whether each is private (read-restricted) and whether it's allowed. |
| `latest` | read, sensitive | Topics with the latest activity (`limit` default 30, at most 100): id, title, category, post and unread counts, closed, archived, pinned, allowed. |
| `unread` | read, sensitive | The account's topics with unread posts, and new topics. |
| `read_topic` | read, sensitive | A `topic` in an allowed category: title, category, whether it's private, closed or archived, and up to 20 posts as plain text (author, time, post number, reply-to), from the start or around `post`. Personal messages are refused. |
| `reply` | destructive, sensitive | Posts `text` (Markdown, at most 32000 characters) to a `topic` in an allowed category, optionally as a reply to post number `replyTo`. Closed and archived topics are refused. The preview names the topic, whether its category is public or private, and the author replied to (who is notified). No undo. |

Replying is `destructive` whatever the category: in a public category
anyone on the internet sees the reply, and watchers of the topic (and the
author replied to) are notified at once, which deleting the post later
can't take back. An agent approved only for `write` can't reply. Flagging,
deleting, closing and other moderation aren't offered.

**Security.** The key goes in the `Api-Key` header and the client won't
follow a redirect to another host. Topic and post numbers are checked
before any request, and a topic's category is checked against
`allowedCategories` before it's shown or replied to. Topic titles, posts
and replies are sensitive: they stay out of the audit log, approvals and
events.

**Presets.** team.
