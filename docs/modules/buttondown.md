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
| `send_email` | destructive | Sends a draft now: a public email to regular, premium, gifted and trial subscribers, a premium one to the paying ones. The preview names the newsletter, the subject and the count for each kind of subscriber. An email that has gone out answers "nothing to change". |

**Content.** The body is Markdown, as Buttondown renders it, and HTML inside
it is kept. It is authored content, so the preview shows it exactly as it
will be sent. Script tags (remote or inline) are refused, since email
clients don't run them. Every draft is created with its status set to
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
