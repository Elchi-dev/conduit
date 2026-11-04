# WooCommerce

Orders, products and stock of a self-hosted WooCommerce store through its
REST API, and changing an order's status or refunding it.

**Setup.** In WordPress, open WooCommerce, Settings, Advanced, REST API, and
add a key for a user who manages the shop. Choose Read for a look-only
connection, or Read/Write to change and refund orders. Store the consumer
key (`ck_…`) and consumer secret (`cs_…`) in the vault and enter the store's
address, such as `https://shop.example.com` (a WordPress in a subfolder
works too: `https://example.com/shop`). For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `store` | read | Store address, WooCommerce and WordPress versions, and currency. Needs a key whose user can see the system status. |
| `orders` | read | Newest first: id, number, status, created, paid, total, refunded amount, item count and payment method. Filters for status and a start date; pages with `page`. No customer details. |
| `order` | read, sensitive | One order with line items, refunds, the customer note, and the billing and shipping names, emails, phones and addresses. |
| `products` | read | Name, type, status, SKU, price (and sale price) and stock. `search`, `status` and `stockStatus` filter. |
| `stock` | read | Products whose stock is managed, with the quantity left. `below` keeps only what's running low. |
| `update_order_status` | destructive | Sets an order to pending, processing, on-hold, completed or cancelled. The preview shows the order's total and both statuses. Undo sets the previous status back (not after a cancellation). |
| `refund_order` | destructive | Refunds an amount (like `12.50`, or everything left) in the order's currency, through the payment gateway, or only recorded with `gateway` off. The preview shows the amount, what was refunded before and the gateway. |

Every action with a preview says "nothing to change" when the order already
has that status, and refunds stop at what's left on the order.

**Notes.**

- Status changes are destructive because WooCommerce emails the customer
  about most of them (processing, completed, on-hold), and cancelling
  releases the order's stock. Cancelling refunds nothing; use `refund_order`
  for the money.
- Setting an order to refunded isn't offered: `refund_order` moves the money
  and WooCommerce then marks the order refunded itself.
- WooCommerce has no idempotency keys, so a refund that's retried after a
  lost answer could refund again (always within what's left). Check the
  order's refunds with `order` before trying once more.
- `refund_order` doesn't restock items; restock them in WooCommerce.
- `stock` covers simple products; variations' stock is managed per
  variation in WooCommerce.
- Refunds can't be undone.

**Security.** The keys are sent only over HTTPS, as Basic auth (never in
the query string), and an address that isn't `https://` is refused. The
client won't follow a redirect to another host or from https to http.
Order ids are numbers before they reach a path, and error text from the
store is scrubbed of credentials, emails and phone numbers.
