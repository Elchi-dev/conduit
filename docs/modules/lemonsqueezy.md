# Lemon Squeezy

A [Lemon Squeezy](https://www.lemonsqueezy.com) account: stores and
revenue, orders, subscriptions, plus refunds and subscription
cancellations with a preview.

**Setup.** In Lemon Squeezy open Settings, API, create an API key, store
it in the vault and enter its `secret://` reference. A key made in test
mode sees only test data, which is a good way to try the module. Optionally
set a default `store` id (see `stores`); Health checks that the key can see
it.

| Action | Risk | Notes |
| --- | --- | --- |
| `stores` | read | Stores with slug, domain, currency, plan, total sales and total revenue. |
| `revenue` | read | Per store (one `store`, the default one, or all): revenue and sales all time and over the last 30 days, formatted and in the smallest unit. |
| `orders` | read, sensitive | Recent orders (`store`, `email`, `status`, `limit` up to 100, `page`): id, number, status, total, tax, refunded amount, product and variant, test mode, customer id and the customer's name and email. Receipt links are never returned. `status` narrows the page that was read. |
| `subscriptions` | read | Subscriptions (`store`, `status`, `limit`, `page`): status, product and variant, customer and order ids, renewal, end and trial dates, whether cancelled or paused. No names, emails, card details or customer portal links. |
| `refund_order` | destructive | Refunds an `order`: the whole remaining amount, or `amount` in the smallest unit (cents) for a partial refund. The preview shows the amount and currency, the order number, the customer id, the product, what was charged and already refunded, and whether it's live. Refuses orders that aren't paid, are fully refunded, or amounts above what's left. Money goes back to the customer: there is no undo. |
| `cancel_subscription` | destructive | Cancels a `subscription`: it runs until the paid period ends, then expires. The preview shows the product, the customer id and the end date. Undo resumes it, during that time. |
| `resume_subscription` | destructive | Takes back a cancellation before the subscription ends, so the customer is billed again at renewal (that's why it's destructive). Refused once the end date has passed. Undo cancels it again. |

Lists return `items`, `page`, `lastPage` and `total`.

**Personal data.** Customer names and emails appear only in `orders`,
which is sensitive (kept out of the audit log, approvals and events).
Refund and cancellation previews name the customer by id, not by name or
email, because previews are kept with approvals. Signed receipt, invoice,
payment-update and customer portal links are never returned.

**Safety.** The key goes in the `Authorization` header, requests use the
JSON:API media type, and the client won't follow a redirect to another
host. Order, subscription and store ids are checked as numbers, emails as
one plain address and statuses against their known values before a
request is made. Keep `refund_order`, `cancel_subscription` and
`resume_subscription` on ask in your policies.

**Presets.** developer, team.
