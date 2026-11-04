# Shopify

The shop, orders, products and inventory levels of a Shopify store through
the Admin GraphQL API, and fulfilling, cancelling and refunding orders.

**Setup.** In the Shopify admin, open Settings, Apps and sales channels,
Develop apps, and create an app. Give it the Admin API scopes you need
(`read_orders`, `read_products`, `read_inventory`, `read_locations`; for the
changes also `write_orders` and
`write_merchant_managed_fulfillment_orders`), install it and store the Admin
API access token (`shpat_…`) in the vault. Enter the store's myshopify name,
such as `acme` or `acme.myshopify.com`.

| Action | Risk | Notes |
| --- | --- | --- |
| `shop` | read | Name, myshopify and primary domain, plan, currency and time zone. |
| `orders` | read | Newest first: name, created, payment and fulfilment status, item count, total, refunded amount, cancellation and whether it's a test order. Filters for status, payment status, fulfilment status and a start date; pages with `after`. No customer details. |
| `order` | read, sensitive | One order (by id or name, like `#1001`) with line items, payments, fulfilments and tracking, and the customer's name, email, phone and shipping address. |
| `products` | read | Title, handle, status, vendor, type, total inventory and up to 20 variants each (SKU, price, stock). `search` and `status` filter. |
| `inventory` | read | Per active location (or one): available, on hand, committed and incoming for each item. `below` keeps only items running low. |
| `fulfill_order` | destructive | Fulfils every open item, with tracking details if given. The customer is emailed only with `notifyCustomer`. When the payment is still authorised (so a store that captures on fulfilment charges now), the preview shows the total and the run must give it as `expectedTotal`. Undo cancels the fulfilment. |
| `cancel_fulfillment` | destructive | Cancels a fulfilment so its items can be fulfilled again. |
| `cancel_order` | destructive | Cancels an order with a reason; `refund` returns what was paid to the original payment methods, `restock` (on by default) puts the items back. The preview shows the total and, with `refund`, what's left to refund (received less earlier refunds), which the run must give as `expectedRefund`. |
| `refund_order` | destructive | Refunds an amount (like `12.50`, or everything left) to the order's payment. The preview shows the amount, currency and gateway. The run must give `expectedTotal` and `expectedRefunded` as the preview showed them (like `49.00 EUR`). Each refund carries an idempotency key, so a retry can't refund twice. |

Every action with a preview says "nothing to change" when the order is
already fulfilled, cancelled or refunded. For the actions that move money,
the preview names the values to pass. To run it, pass the values the
preview shows; the run is refused if the order changed in between.

**Notes.**

- Fulfilling is destructive because it tells the customer and the warehouse
  that goods shipped, and stores that capture payment on fulfilment charge
  the customer then.
- Refunds are in the currency the customer paid in, which in a
  multi-currency store isn't the shop's; the preview, the amount you give
  and the refund sent are all in it.
- Refunds go to the payment with the most left on it; an amount larger than
  that is refused, so split refunds across payments in the Shopify admin.
  Items aren't restocked by `refund_order`.
- Cancelling runs in the background at Shopify; `orders` shows the result a
  moment later.
- A refund retried with a new idempotency key still names what was refunded
  before it (`expectedRefunded`), so if the first try went through, the retry
  is refused instead of refunding again.
- Refunds and cancellations can't be undone.

**Security.** The token goes in the `X-Shopify-Access-Token` header, only to
`<shop>.myshopify.com`, and the client won't follow a redirect to another
host. Every query is a fixed GraphQL document; input travels only in its
variables, after it's checked. Error text from Shopify is scrubbed of emails
and phone numbers.
