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
| `fulfill_order` | destructive | Fulfils every open item, with tracking details if given. The customer is emailed only with `notifyCustomer`. Undo cancels the fulfilment. |
| `cancel_fulfillment` | destructive | Cancels a fulfilment so its items can be fulfilled again. |
| `cancel_order` | destructive | Cancels an order with a reason; `refund` returns what was paid to the original payment methods, `restock` (on by default) puts the items back. The preview shows the total and what happens to the money. |
| `refund_order` | destructive | Refunds an amount (like `12.50`, or everything left) to the order's payment. The preview shows the amount, currency and gateway. Each refund carries an idempotency key, so a retry can't refund twice. |

Every action with a preview says "nothing to change" when the order is
already fulfilled, cancelled or refunded.

**Notes.**

- Fulfilling is destructive because it tells the customer and the warehouse
  that goods shipped, and stores that capture payment on fulfilment charge
  the customer then.
- Refunds go to the order's largest payment; an amount larger than that
  payment is refused, so split refunds across payments in the Shopify admin.
  Items aren't restocked by `refund_order`.
- Cancelling runs in the background at Shopify; `orders` shows the result a
  moment later.
- Refunds and cancellations can't be undone.

**Security.** The token goes in the `X-Shopify-Access-Token` header, only to
`<shop>.myshopify.com`, and the client won't follow a redirect to another
host. Every query is a fixed GraphQL document; input travels only in its
variables, after it's checked. Error text from Shopify is scrubbed of emails
and phone numbers.
