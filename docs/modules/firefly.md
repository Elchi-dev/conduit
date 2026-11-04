# Firefly III

Your Firefly III books: accounts and balances, recent transactions, budgets
and spending this month, bills due, and recording or deleting transactions.

**Nothing here moves real money.** Firefly III is bookkeeping: a recorded
withdrawal or transfer changes your books only. That's why recording one is
a write with an undo, and why there are no actions that talk to a bank.

**Setup.** In Firefly III, open Options, Profile, OAuth, and create a
personal access token, then store it in the vault. The token has full access
to your books. Enter Firefly III's address, such as
`https://money.example.com`.

| Action | Risk | Notes |
| --- | --- | --- |
| `accounts` | read, sensitive | Accounts of a `type` (asset by default; expense, revenue, liability or all) with their current balance and currency, and totals of your active asset accounts per currency. No IBANs or account numbers. |
| `transactions` | read, sensitive | Newest first, optionally of one `account`, of one `type`, or between `start` and `end`. Splits are summed. |
| `budgets` | read, sensitive | This `month` (or another, `YYYY-MM`): spent, earned and left to spend per currency, and each active budget's limit, spent and left. |
| `bills` | read, sensitive | Active bills with the dates they're expected that month, whether paid, and the next expected date. |
| `create_transaction` | write, sensitive | A `withdrawal`, `deposit` or `transfer` of a positive `amount`, with `description`, `source` and `destination` (account ids, or names: Firefly creates an expense or revenue account for a new name), and optional `date` (today by default), `currency`, `category`, `budget`, `tags` and `notes`. Firefly's rules and webhooks run, and a duplicate of an existing transaction is refused. The preview names the accounts; undo deletes the transaction. |
| `delete_transaction` | destructive, sensitive | Deletes a transaction with all its splits, with a preview of it. Firefly III can't bring it back. |

**Privacy.** Balances, transactions, budgets and bills are financial data,
so these actions' input and output stay out of the audit log, approvals and
events. Recording and deleting a transaction are sensitive too, so their
previews are redacted in the audit log and events. Recording's undo is kept
because it only names the transaction id. An approval keeps the full preview
(amount, accounts, notes) for the people who can decide it, since that's what
they're approving; anyone else sees it redacted. An agent denied
`transactions` (or any other read here) gets previews redacted too.

**Security.** The token goes in the `Authorization` header and the client
won't follow a redirect to another host. Amounts, dates, currency codes and
ids are checked before any request. For a self-signed certificate, pin its
SHA-256 `fingerprint`.
