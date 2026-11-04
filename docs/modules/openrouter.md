# OpenRouter

An [OpenRouter](https://openrouter.ai/) account: credits left, the key's
limit and usage, the model catalogue with prices, and spend by model and
day. Everything is read-only; nothing here spends credits.

**Setup.** Create a key at openrouter.ai, Keys, and store it in the vault.
`activity` needs a provisioning key (openrouter.ai, Provisioning keys);
the other actions work with any key.

| Action | Risk | Notes |
| --- | --- | --- |
| `credits` | read | Credits bought, used and left, in US dollars. |
| `key_info` | read | The key's label (OpenRouter's masked form), credit limit and what's left, when the limit resets, usage in total, today, this week and this month, and whether it's a free-tier or provisioning key. Never the key. |
| `models` | read | Models with context length, input and output modalities and price per million input and output tokens. `search` in id or name, `free` for free models only, `sort` by `name` or `price` (cheapest first), `limit` (50, at most 200). |
| `activity` | read | Spend, requests and tokens by model and provider for each of the last 30 days (or one `date`), with totals and spend per model. |

**Security.** The key goes in the `Authorization` header to
`openrouter.ai` only; redirects are followed within the same host only.
Searches and dates are checked before they reach a request.
