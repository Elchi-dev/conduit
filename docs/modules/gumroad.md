# Gumroad

Products, recent sales and subscriber counts of a Gumroad account, and
turning a product's sales on or off.

**Setup.** In Gumroad, open Settings, Advanced, Applications, create an
application (any name and redirect address will do) and choose Generate
access token. Store the token in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `products` | read | Id, name, published, price, sales count, revenue (in USD, as Gumroad counts it), link, and the billing period of memberships. Deleted products are left out. |
| `sales` | read | Newest first: product, price, date, quantity, and whether the sale was refunded, partly refunded or disputed. Filters for a product and a date range; pages with `pageKey`. No buyer emails, names or countries. |
| `subscribers` | read | How many subscribers a membership product has, in all and by status (active, cancelling, failing payment, cancelled, ended). Counts only. |
| `enable_product` | write | Publishes a product so people can buy it again. The preview shows the price. Undo disables it. |
| `disable_product` | destructive | Unpublishes a product so nobody can buy it; existing buyers keep their access. The preview shows its price, sales count and revenue. Undo enables it. |

Both product actions say "nothing to change" when the product is already
in that state.

**Notes.**

- Disabling is destructive because it stops sales of something people are
  buying; it doesn't touch existing purchases or memberships.
- `subscribers` reads up to 50 pages of a very large membership and says so
  when it stops there.

**Security.** The token goes in the `Authorization` header, only to
`api.gumroad.com`, and the client won't follow a redirect to another host.
Product ids are checked before they reach a path. Sales and subscribers are
decoded field by field, so buyers' emails and names are never read.
