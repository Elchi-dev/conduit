# Paddle

Customers, subscriptions and transactions in Paddle Billing, and pausing,
resuming and cancelling subscriptions.

**Setup.** In Paddle, open Developer tools, Authentication, and create an
API key with the permissions you need (read customers, subscriptions and
transactions; write subscriptions for the changes). Store it in the vault.
Set `environment` to `sandbox` for a sandbox account's key.

| Action | Risk | Notes |
| --- | --- | --- |
| `customers` | read, sensitive | Finds customers by name, email or id, or lists the latest: name, email, status, locale. |
| `subscriptions` | read | Status, customer id, items with product and unit price, billing cycle, next billing date, current period and any scheduled pause or cancellation. Filters for status and customer. |
| `transactions` | read | Newest first: status, origin, total, tax, earnings, invoice number, customer and subscription ids, billing date. Filters for status, customer and subscription. |
| `pause_subscription` | destructive | Pauses at the end of the billing period, or `immediately`. Undo resumes it. |
| `resume_subscription` | destructive | Resumes a paused subscription now (it bills the customer and starts a new period), or takes back a pause or cancellation scheduled for the period end. Undo pauses or cancels it again. |
| `cancel_subscription` | destructive | Cancels at the end of the billing period (undo takes it back until then), or `immediately`. |

Listings page with `after` and take up to 200 records at a time. Each change
says "nothing to change" when the subscription is already in that state.

Every change's preview names the subscription's status and the change
scheduled for the period end (`none`, `pause` or `cancel`), to pass as
`expectedStatus` and `expectedScheduledChange`. To run it, pass the values
the preview shows; the run is refused if the subscription changed in
between. Undo tokens carry the state the change left, so an undo runs only
while that still holds.

**Notes.**

- Pausing while a cancellation is scheduled is refused; take the
  cancellation back with `resume_subscription` first.
- A paused subscription can only be cancelled `immediately` (Paddle's
  rule); without it the request is refused.
- An immediate cancellation can't be undone, and a canceled subscription
  can't be paused or resumed.
- Refunds and credits (Paddle adjustments) are made in the Paddle dashboard.

**Security.** The key goes in the `Authorization` header, only to Paddle's
API, and the client won't follow a redirect to another host. A sandbox key
is refused for the live environment and the other way round. Ids are checked
before they reach a request path. Payment method details, addresses and the
signed customer portal links are never returned.
