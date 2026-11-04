# Anthropic

Usage and spend of an Anthropic (Claude API) organization, from the Admin
API's usage and cost reports: tokens by day and by model, workspace or
service tier, spend in US dollars, and the models your API key can use.
Everything is read-only; nothing here creates keys, changes members or
sends prompts.

**Setup.** In the Claude Console, open Settings, Admin keys, create an
Admin API key (it starts `sk-ant-admin`) and store it in the vault as
`adminKey`. Admin keys belong to organizations, so an individual account
needs to set up an organization first. To list models, also store a
regular API key as `apiKey`; usage and spend don't need it.

| Action | Risk | Notes |
| --- | --- | --- |
| `usage` | read | Uncached input, cache write, cache read and output tokens and web searches, in total, per day and per group. `groupBy` is any of `model` (default), `workspace` and `service_tier`; the default workspace shows as `default`. `from` and `to` are days (YYYY-MM-DD, UTC, both included), seven days up to today by default. |
| `costs` | read | Spend in US dollars, in total, per day and per group, as exact decimal strings. `groupBy` is `description` (default: the cost line, with model, cost type and token type) and/or `workspace`. Same `from` and `to`. |
| `models` | read | Models the API key can use, newest first: id, display name, release date and context window. `search` in id or name, `limit` (50, at most 200). Needs `apiKey`. |

Health reads the organization (`/v1/organizations/me`) and shows its name.

**Notes.**

- A range covers at most 93 days and can't end after today. Days are
  whole UTC days, the same as in the Console.
- Usage by API key or by user isn't offered, so no key ids or accounts
  appear in answers. An answer keeps the 200 largest groups;
  `groupCount` says how many there were.
- Anthropic reports costs in cents; they're converted to dollars exactly.
  Priority Tier costs aren't in the cost report (Anthropic bills them
  separately), and code execution appears as its own cost line.
- These are Anthropic's legacy Usage and Cost endpoints, which remain
  supported. Claude Enterprise (claude.ai) organizations use a different
  Analytics API key that this module doesn't take.
- Data appears about five minutes after requests finish.

**Security.** Each key goes in the `x-api-key` header to `api.anthropic.com`
only; redirects are followed within the same host only. Dates and choices
are checked before any request.
