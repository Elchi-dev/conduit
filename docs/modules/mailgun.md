# Mailgun

A [Mailgun](https://www.mailgun.com) account in the US or EU region:
sending domains, delivery stats, the event log and the suppression lists,
plus removing an address from a suppression list with a preview.

**Setup.** In Mailgun open your account's API keys and copy a **private
API key** into the vault; enter its `secret://` reference and the
`region` the account's domains live in (`us`, the default, or `eu`: a key
used against the wrong region is refused or finds no domains). Optionally
set a default `domain` (e.g. `mg.example.com`) for the per-domain actions;
Health then checks that it exists and is active.

| Action | Risk | Notes |
| --- | --- | --- |
| `domains` | read | Domains with state (`active`, `unverified`, `disabled`), type, creation date and spam action. SMTP credentials are never returned. |
| `stats` | read | For a `domain` over the last `days` (default 7, up to 90): totals and daily rows of accepted, delivered, failed (permanent and temporary), bounced, suppressed bounces and complaints, with the delivered rate. |
| `events` | read, sensitive | The newest events (`limit` up to 300) for a domain, optionally one `event` type or one `recipient`: recipient, time, subject, sender, message id, severity, reason, delivery status and tags. Stored message links are never returned. |
| `suppressions` | read, sensitive | One `list` (`bounces`, `unsubscribes`, `complaints`; `limit` up to 1,000): address, date, and the bounce code and error or the unsubscribe tags. |
| `delete_suppression` | destructive, sensitive | Removes `address` from a `list`, so Mailgun sends to it again: someone who bounced, unsubscribed or reported spam. The preview shows the entry (code, error, tags, date). An address that isn't on the list is reported, not an error. No undo. |

**Why removing a suppression is destructive.** A suppression is what keeps
mail from reaching someone who asked not to get it or whose address
bounced; removing one can get mail to a person who unsubscribed, or hurt
the domain's reputation. Keep `delete_suppression` on ask.

**Personal data.** Events and suppression lists name recipients, so those
actions are sensitive (kept out of the audit log, approvals and events),
and so is `delete_suppression`, whose input is an address. `domains` and
`stats` carry counts and domain names only.

**Safety.** The key is sent with HTTP Basic auth (`api:<key>`) and the
client won't follow a redirect to another host. Domains are checked as
host names, addresses as one plain address (escaped into the path), and
lists and event types against their known values before a request is
made. Mailgun's paging links are never followed.

**Presets.** developer, team.
