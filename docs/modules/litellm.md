# LiteLLM

A [LiteLLM](https://docs.litellm.ai/) proxy, through its admin API with the
master key: the models it routes to, spend by model, key, team and
provider, virtual keys (never their values), budgets, a live health check
of every deployment, and blocking or unblocking a key.

**Setup.** The proxy's address (`http://127.0.0.1:4000` by default) and
its master key (`LITELLM_MASTER_KEY`) or another admin key, stored in the
vault. Keys, spend and budgets live in the proxy's database, so those
actions need LiteLLM running with one; Health reports `degraded` when the
database isn't connected.

| Action | Risk | Notes |
| --- | --- | --- |
| `models` | read | Each model name with the provider model behind it, deployment id, provider, mode, context size and price per million input and output tokens. The deployment's `api_base` is shortened; provider keys and other parameters are never passed on. |
| `spend` | read | Spend, requests, failures and tokens for `period` `today`, `month` (from the 1st, UTC) or `custom` (`start` and `end`, YYYY-MM-DD), broken down `by` `model`, `key`, `team` or `provider`, largest first. Reads LiteLLM's daily activity (all pages). |
| `keys` | read | Virtual keys (filter by `team` id, or `search` in the alias): id, LiteLLM's masked form (`sk-...abcd`), alias, team, user, models, spend, budget and how much of it is used, budget period and reset, expiry, blocked. Never the key, never metadata. |
| `budgets` | read | Budgets defined on the proxy (limit, soft limit, TPM and RPM, period) and every team's spend against its budget. |
| `deployment_health` | write | Runs LiteLLM's `/health`: a tiny real request to every deployment, then which are healthy and the first line of each failure (redacted). Write, not read: each check is billed by paid providers (a few tokens) and counts against rate limits, so an agent looping on it costs money. |
| `block_key` | destructive | Blocks a key by `key` (its id from `keys`) or `alias`; requests with it are refused. Preview shows the key, its spend and team. Destructive: it cuts off whatever uses the key. Undo unblocks it. |
| `unblock_key` | destructive | Unblocks a key. Destructive too: it restores access and spending that someone deliberately cut off. Undo blocks it again. |

Blocking a key that is already blocked (or unblocking an unblocked one)
changes nothing and offers no undo. An alias that several keys share is
refused; use the id.

**Security.** The master key goes in the `Authorization` header and only to
the configured address: redirects are followed within the same host only,
never from https to http. Keys are named by LiteLLM's SHA-256 id (which
can't call models) or alias; anything that looks like a key itself
(`sk-…`) is refused before a request, so key values never reach an
approval or the audit log. Ids, aliases, team ids and dates are checked
before they reach a request.
