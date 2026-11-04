# BigCommerce

The store, orders, products and inventory of a BigCommerce store, and
changing an order's status.

**Setup.** In the BigCommerce control panel, open Settings, API, Store-level
API accounts and create one with the scopes you need (Orders and Products
read-only for a look-only connection; Orders modify to change statuses).
Store the access token in the vault and enter the store hash, the letters
and digits after `/stores/` in the API path it shows, such as
`abc123de45`.

| Action | Risk | Notes |
| --- | --- | --- |
| `store` | read | Name, domain, address, plan, currency, time zone and status. |
| `orders` | read | Newest first: id, status, created, total, refunded amount, item count, payment method and status. Filters for status and a start date; pages with `page`. No customer details. |
| `order` | read, sensitive | One order with line items, the customer's message, and the billing and shipping names, emails, phones and addresses. |
| `products` | read | Name, SKU, price, visibility, availability, inventory tracking and stock. `search` filters. |
| `inventory` | read | Stock of tracked products, per variant where stock is tracked by variant. `below` keeps only what's running low. |
| `update_order_status` | destructive | Sets an order's status: pending, awaiting payment, fulfilment, shipment or pickup, shipped, partially shipped, completed, cancelled, declined, manual verification or disputed. The preview shows the total in the order's currency and both statuses. The run must give `expectedStatus`, the status the preview showed, and is refused if the order moved on since. Undo sets the previous status back (not after a cancellation or decline), and only while the order still has the status it was set to. |

`update_order_status` says "nothing to change" when the order already has
that status.

**Notes.**

- Status changes are destructive because BigCommerce emails the customer
  about most of them, and cancelling or declining an order can return its
  stock. No money is refunded; refunds are made in BigCommerce.
- The refunded statuses and incomplete (abandoned checkouts) aren't offered,
  so an order never claims a refund that didn't happen.

**Security.** The token goes in the `X-Auth-Token` header, only to
`api.bigcommerce.com`, and the client won't follow a redirect to another
host. The store hash must be plain letters and digits before it becomes
part of an address, and order ids are numbers. Store details are decoded
field by field, so the owner's email, phone and address are never read;
error text is scrubbed of credentials, emails and phone numbers.
