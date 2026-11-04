# Grocy

[Grocy](https://grocy.info) stock, shopping list and chores: what's
expiring, what's below its minimum, adding to the shopping list, using up or
adding stock, and marking chores done. It uses Grocy's REST API with an API
key.

**Setup.** In Grocy open the user menu → Manage API keys, create one and
store it in the vault. Enter Grocy's address, such as
`https://grocy.example.com`. The key acts as your user.

| Action | Risk | Notes |
| --- | --- | --- |
| `stock` | read | Products in stock by name, with amount, stock unit, next due date and how much is opened. |
| `expiring` | read | Products due within `days` (5), overdue and expired, from Grocy's own due-soon view. |
| `below_minimum` | read | Products below their minimum stock and how much is missing. |
| `shopping_list` | read | A shopping `list` (1, the default list) with product, amount, unit and note; `done: false` leaves out items marked done. |
| `add_to_shopping_list` | write | With a preview. Adds a `product` (id or exact name) with an `amount` (1), or a free-text `note`. If the product is on the list already Grocy adds to its amount (the preview shows the change). Undo takes the same amount off again, or deletes the free-text line. |
| `remove_from_shopping_list` | destructive | With a preview. Deletes a line by `item` id, or takes an `amount` of a `product` off (the line goes when nothing's left). Undo adds it back. |
| `consume_product` | write | With a preview. Takes an `amount` out of stock, as used or `spoiled`; refused when there isn't that much. Undo reverts Grocy's booking (its own stock undo), which puts back the same stock entries with their due dates, prices and locations; it goes through `undo_stock_transaction`, so the undo is destructive and needs approval where destructive calls do. Grocy before 3.0 doesn't return the booking; then undo books the same amount as a purchase. |
| `add_stock` | write | With a preview. Books a purchase of an `amount`, with an optional `bestBefore` date. Undo reverts the booking (through `undo_stock_transaction`, destructive). |
| `undo_stock_transaction` | destructive | With a preview. Reverts a booking by transaction id; refused when it's reverted already. It reaches any past booking, not only Conduit's, and a reverted booking can't be booked again as it was, so it's destructive. Transaction ids start with a letter or digit. |
| `chores_due` | read | Chores due within `days` (7), overdue ones first and marked. Chores that are never due are left out. |
| `complete_chore` | write | With a preview. Tracks a `chore` (id or exact name) as done now. Undo reverts that execution (Grocy's own chore undo, through `undo_chore_execution`, so the undo is destructive). |
| `undo_chore_execution` | destructive | Reverts one chore execution by its id. It reaches any past execution and can't be taken back, so it's destructive. |

**Security.** The key goes in the `GROCY-API-KEY` header. Go would forward
that header on any redirect, so the client follows redirects only within the
same host and never from https to http. Ids, amounts, dates and names are
checked before they're sent. For a self-signed certificate, pin its SHA-256
`fingerprint`.
