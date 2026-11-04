# Buttondown

Subscriber counts, emails with their status and analytics, creating drafts
and sending them in a [Buttondown](https://buttondown.com) newsletter.

**Setup.** In Buttondown open Settings, API, copy the API key and store it
in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `subscribers_count` | read | Subscribers of one `type` (`regular` by default, or `premium`, `gifted`, `trialed`, `unactivated`, `unsubscribed`, `churning`, `past_due`). Counts only, no addresses. |
| `emails` | read | Emails, newest first (`status` to narrow, `limit` default 20), with subject, status, type, publish date, and recipients, deliveries, opens, clicks and unsubscribes once sent. |
| `create_draft` | write | Creates a draft with `subject`, `body` and an optional `description`. The preview shows the body in full. Undo deletes the draft. |
| `delete_draft` | destructive | Deletes a draft email; anything else is refused. The preview names it. |
| `send_email` | destructive | Sends a draft now, given its `sha256` from the preview: a public email to regular, premium, gifted and trial subscribers, a premium one to the paying ones. The preview names the newsletter, the subject and the count for each kind of subscriber, and shows the body. An email that has gone out answers "nothing to change". |

**Content.** The body is Markdown, as Buttondown renders it, and HTML inside
it is kept. It is authored content, so the preview shows it exactly as it
will be sent. HTML is checked for anything that would run code in the email's web version
(the archive page or "view in browser", which opens in a browser even
though mail clients don't run scripts): script, iframe, object, embed and
applet elements, `on…` event handler attributes, and `javascript:`,
`vbscript:` and `data:` URLs (other than `data:image/…`) in link and source
attributes, with entities and the spaces browsers skip taken into account.
Markdown link targets (`[t](url)`, `[t]: url`, `<url>`) are checked the same way. Such content is refused; styles, tables, images, forms and ordinary links
are kept.

**What's approved is what's sent.** The preview of `send_email` shows the
email's content in full with a `sha256` over the email's type and filters, subject, description and body. The run must
give that `sha256` and is refused if the email changed since, so an edit made
between the preview (or the approval) and the run can't go out unseen. Every draft is created with its status set to
`draft`, and Conduit checks that Buttondown kept it that way.

**Security.** The key goes in the `Authorization` header and the client
won't follow a redirect to another host or from https to http. Ids, statuses
and one-line subjects are checked before any request is made. Subscribers'
addresses are never read.

**Notes.** Emails with subscriber filters or for other audiences (such as
churning subscribers) are listed here and sent from Buttondown, since Conduit
can only count the standard audiences. Scheduled emails keep their schedule;
scheduling stays in Buttondown.

**Presets.** team, developer.
