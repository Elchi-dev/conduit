# Invoice Ninja

Clients, invoices and payments in Invoice Ninja v5 (the hosted service or a
self-hosted server), creating draft invoices, and marking an invoice sent,
emailing it to the client or recording a payment, each with a preview.

**Setup.** In Invoice Ninja, open Settings, Account Management, API Tokens,
create a token and store it in the vault. Leave the address empty for the
hosted service (`https://invoicing.co`), or enter your server's address,
such as `https://invoices.example.com`. The token acts as its user. For a
self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `clients` | read | Active clients: id, number, name, balance, paid to date and contacts (name, email, primary). `query` searches; `includeAddress` adds the address and VAT number. |
| `invoices` | read | Newest invoices: id, number, client, date, due date, amount, balance, status and PO number. Filter by `client` or `status` (`draft`, `sent`, `partial`, `paid`, `unpaid`, `overdue`, `cancelled`). |
| `payments` | read | Newest payments: id, number, client, date, amount, refunded, reference and the invoices it paid. |
| `create_invoice` | write | A draft for `client` from `items` (`description`, `cost`, optional `quantity` and `product`), with optional `date`, `dueDate`, `poNumber` and `publicNotes`. The preview names the client and the total before tax. Nothing is sent. Undo deletes the draft. |
| `delete_invoice` | destructive | Deletes a draft invoice. Anything past draft is refused, so a sent invoice is never removed here. |
| `mark_sent` | destructive | Marks a draft sent without emailing it: it gets its number, counts toward the client's balance and becomes due. The preview names the client and amount. |
| `email_invoice` | destructive | Emails the invoice to the client's contacts with your invoice template (a draft is marked sent). The preview names the client, the recipients, the amount and the balance. |
| `record_payment` | destructive | Records a payment against an invoice: the whole balance by default, or `amount`, with an optional `date` and `reference`. The preview shows the balance before and after. |

Every action is sensitive: client names, contacts and amounts stay out of
the audit log, approvals and events. Amounts go in as decimal strings such as `120.00` and are
computed exactly, never as floating point. Marking sent when the invoice is
already sent, recording a payment on a paid invoice, and deleting a deleted
draft each report that there's nothing to change.

**Security.** The token goes in the `X-API-TOKEN` header, and the client
won't follow a redirect to another host or from https to http. Ids, dates
and amounts are checked before any request, and ids are escaped in paths.
Notes, invitation links and custom fields aren't returned.

**Notes.** Totals in previews are before tax; Invoice Ninja applies taxes
and discounts when it saves the invoice. Amounts are shown without their
currency. A payment may make Invoice Ninja email the client a receipt,
depending on its settings. Mark sent, email and payments have no undo here:
reverse them in Invoice Ninja if needed.
