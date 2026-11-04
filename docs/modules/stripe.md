# Stripe

A Stripe account: balance, payments and charges, customers, subscriptions,
payouts, disputes and invoices, plus refunds and subscription cancellations
with a preview.

**Setup.** Use a **restricted key**. In the Stripe dashboard open
Developers, API keys, Create restricted key, and grant only what you need:
Read on Balance, Charges and Refunds (PaymentIntents), Customers,
Subscriptions (Billing), Payouts, Disputes and Invoices; Write on Refunds
only if agents may refund; Write on Subscriptions only if they may cancel.
Store it in the vault and enter its `secret://` reference. A full secret
key (`sk_…`) works, but it can do anything in the account, and Health says
so; a publishable key (`pk_…`) is refused. Start with a test-mode key
(`rk_test_…`) to try it out. Requests pin Stripe API version `2024-06-20`.

| Action | Risk | Notes |
| --- | --- | --- |
| `balance` | read | Available and pending per currency, and whether the key is live. |
| `payments` | read | Recent payment intents (`limit`, `after`, `customer`): amount, status, customer id, latest charge, failure reason. |
| `charges` | read | Recent charges (`limit`, `after`, `customer`, `payment`): amount, refunded amount, status, dispute flag, risk level, card brand and last four digits. |
| `customers` | read, sensitive | Finds customers by email (exact), a word in the email or name, or a Stripe search query (`email:'a@b.com'`, `metadata['plan']:'pro'`); empty lists the newest. Name, email, phone, balance; addresses only with `includeAddress`. |
| `subscriptions` | read | Status (or `all`), customer, plan items with amount and interval, period end, scheduled cancellation, trial end. |
| `payouts` | read | Amount, status, arrival date, method, failure. |
| `disputes` | read | Amount, reason, status, charge and the evidence deadline. |
| `invoices` | read | Number, status, due, paid and remaining amounts, customer id, subscription, due date. |
| `refund` | destructive | Refunds a payment intent (`pi_…`) or charge (`ch_…`): the whole remaining amount, or `amount` in the smallest unit (cents) for a partial refund, with an optional `reason`. The preview shows the amount and currency, the customer id, what was charged and already refunded, the description and whether it's live. Refuses failed, uncaptured, disputed or fully refunded charges and amounts above what's left. Money goes back to the customer: there is no undo. |
| `cancel_subscription` | destructive | Cancels at the end of the paid period by default (undo keeps the subscription), or `immediately` (optionally `prorate`, `invoiceNow`), which can't be undone. The preview shows the customer id, the plan and the period end. |
| `keep_subscription` | write | Takes back a cancellation scheduled for the period end; undo schedules it again. |

Lists return `items`, `hasMore` and `next` (pass it as `after` for the next
page).

**Personal and card data.** Stripe never returns full card numbers; this
module returns only the brand and last four digits. Billing details,
receipt emails, card fingerprints and expiry dates, invoice links and
metadata are never returned. Customer contact details appear only in
`customers`, which is sensitive (kept out of the audit log, approvals and
events), and addresses only when asked for. Refund and cancellation
previews name the customer by id, not by name or email, because previews
are kept with approvals.

**Safety.** Every POST carries an `Idempotency-Key` (random per call, or
the `idempotencyKey` you pass, so a retried refund can't refund twice).
Ids are checked by prefix and shape before they reach a request path, the
key goes in the `Authorization` header, and the client won't follow a
redirect to another host. Keep `refund` and `cancel_subscription` on ask in
your policies.

**Presets.** team, developer.
