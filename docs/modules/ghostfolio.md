# Ghostfolio

Your Ghostfolio portfolio (Ghostfolio in the cloud or a self-hosted server):
accounts and balances, the portfolio summary, performance over a range, and
holdings. Everything is read-only.

**Setup.** Store your security token in the vault: it's the token Ghostfolio
showed when the account was created, and a new one can be made under My
Ghostfolio, Access. Leave the address empty for Ghostfolio in the cloud
(`https://ghostfol.io`), or enter your server's address, such as
`https://ghostfolio.example.com`. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `accounts` | read | Id, name, platform, currency, cash balance and value (in the account's and your base currency), number of activities and whether it's excluded, with the totals. Comments are left out. |
| `summary` | read | Current value, investment, net performance (amount and percent, with and without currency effects), annualized performance, dividends, interest, fees, cash, liabilities, net worth, buys and sells, activity count and first activity. |
| `performance` | read | Net performance, investment and value over `range`: `1d`, `wtd`, `mtd`, `ytd`, `1y`, `5y`, `max` (the default) or a year such as `2025`. |
| `holdings` | read | Holdings by value: symbol, name, currency, asset class and subclass, quantity, market price, investment, value, allocation, performance and dividends. `query` filters by symbol or name; `limit` (50 by default, up to 500). |

All four actions are sensitive: balances and holdings stay out of the audit
log, approvals and events. Amounts are passed on exactly as Ghostfolio
reports them.

**Security.** The security token is exchanged for a short-lived session
token, which is kept in memory only and renewed when it expires; neither
appears in results or errors. The client won't follow a redirect to another
host or from https to http.

**Notes.** When Ghostfolio can't price a holding, `summary` and
`performance` say that figures may be incomplete. Servers older than the
holdings endpoint get their holdings from the portfolio details instead.
