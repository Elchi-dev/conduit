# Ghost

A [Ghost](https://ghost.org) site through the Admin API: posts, creating
drafts, publishing (with or without emailing a newsletter), unpublishing,
deleting posts, newsletters and members.

**Setup.** In Ghost Admin go to Settings, Integrations, Add custom
integration, and copy its **Admin** API key (`id:secret`; the Content API key
won't do) into the vault. Enter the site's admin address as `url`
(`https://blog.example.com`, `https://example.ghost.io`, or with the path of
a subdirectory install) and the key's `secret://` reference. The module signs
a five-minute token (HS256 JWT) with the key for every request.

| Action | Risk | Notes |
| --- | --- | --- |
| `posts` | read | Posts, most recently updated first (`status`: all, draft, scheduled or published; `limit` default 15), with URL, visibility and dates. |
| `create_draft` | write | Creates a draft `title` from `html`, with optional `excerpt`, `tags` and `visibility` (public, members, paid). Nothing is published or emailed. Undo deletes it. |
| `publish` | destructive | Publishes a draft or scheduled `post` now. With `newsletter` (a slug from `newsletters`) it is also emailed to that newsletter's subscribers (`segment` all, free or paid), which can't be recalled; a post that was already emailed can't be emailed again. The preview says whether an email goes out, with which newsletter and to how many members. |
| `unpublish` | write | Turns a published post back into a draft: it leaves the site and its URL stops working. Undo publishes it again, never with an email. |
| `delete_post` | destructive | Deletes a post for good. The preview names it and its URL when published. |
| `newsletters` | read | Active newsletters with slug and subscriber count. |
| `members_count` | read | How many members the site has: all, free, paid and comped. |
| `members` | read, sensitive | Recent members (`status` to narrow, `limit` default 20) with name, email, status and newsletter count. |

**Why these risks.** Publishing makes a post public and may email every
subscriber, so it is destructive. Unpublishing loses nothing (the post
stays as a draft, and an email already sent can't be affected either way),
so it is write with an undo; the undo goes through `publish`, so it asks
again like any publish.

**Security.** The Admin API key never leaves the module: only the signed,
short-lived token is sent, and the client won't follow a redirect to another
host. Post ids, newsletter slugs, segments, tags and visibility are checked
before a request is made; publishing sends the post's `updated_at`, so a
post edited meanwhile isn't overwritten.

**Presets.** team.
