# Printful

Orders, fulfilment status and tracking, and shipping rates of a Printful
store, and confirming a draft order for fulfilment.

**Setup.** In the Printful Developers portal, create a private token with
the scopes you need (`orders`, `stores_list`; `orders` with write access to
confirm orders) and store it in the vault. A token made for one store needs
nothing else; for a token that reaches the whole account, enter the store's
id as `store`.

| Action | Risk | Notes |
| --- | --- | --- |
| `store` | read | The stores the token reaches: id, name and type. |
| `orders` | read | Id, external id, status, created and updated, item count, what Printful charges, retail total, shipping service and shipment count. `status` filters; pages with `offset`. No recipient details. |
| `order_status` | read | One order (by id, or `@` and your external id, like `@1001`): status, costs (subtotal, shipping, tax, VAT, total) and each shipment's carrier, service, tracking number and dates. |
| `order` | read, sensitive | The same with line items and the recipient's name, email, phone and address. |
| `shipping_rates` | read | Shipping options with price and delivery days for catalog variants and quantities to a country (with state, city and zip). Nothing is ordered. |
| `confirm_order` | destructive | Sends a draft order to fulfilment. The preview shows the exact amount Printful charges, in the order's currency, with the cost breakdown. The run must give that amount as `expectedCost` (like `25.22 EUR`) and is refused if the order's cost changed since, so the charge is the one approved. |

`confirm_order` says "nothing to change" when the order is confirmed
already, and refuses failed, cancelled and archived orders.

**Notes.**

- Confirming charges the card (or wallet) on your Printful account and
  starts production, so it's destructive and has no undo. While an order is
  still pending, it can be cancelled in Printful.
- Printful works out costs a moment after an order is created; confirming
  waits until it has.
- US, Canadian and Australian shipping rates need a state code.

**Security.** The token goes in the `Authorization` header, only to
`api.printful.com`, and the client won't follow a redirect to another host.
Order ids, codes and quantities are checked before any request, and error
text is scrubbed of credentials, emails and phone numbers (and, when
confirming, of the order's recipient name and address) before it's
shortened.
