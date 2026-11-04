# OpenAI

Usage and spend of an OpenAI API organization, from its Usage and Costs
endpoints: completions tokens and requests by day and by model, project,
batch or service tier, spend by line item or project, and the models your
API key can use. Everything is read-only; nothing here creates keys,
changes members or sends prompts.

**Setup.** An organization owner opens platform.openai.com, Organization
settings, Admin keys, creates an Admin key and stores it in the vault as
`adminKey`. Project and user keys can't read usage or costs. To list
models, also store a regular API key as `apiKey`.

| Action | Risk | Notes |
| --- | --- | --- |
| `usage` | read | Completions input tokens (cached ones included), cached input tokens, output tokens and requests, in total, per day and per group. `groupBy` is any of `model` (default), `project`, `batch` and `service_tier`; usage outside a project shows as `default`. `from` and `to` are days (YYYY-MM-DD, UTC, both included), seven days up to today by default. |
| `costs` | read | Spend in total, per day and per group, as exact decimal strings with the currency. `groupBy` is `line_item` (default, such as `gpt-6, input`) and/or `project`. Same `from` and `to`. |
| `models` | read | Models the API key can use, by id, with owner and creation date. `search` in the id, `limit` (50, at most 200). Needs `apiKey`. |

Health asks for yesterday's costs, one bucket, to check the Admin key.

**Notes.**

- A range covers at most 93 days and can't end after today; days are whole
  UTC days.
- `usage` covers the completions endpoint (chat, responses and other text
  generation). Embeddings, images, audio and other usage types have their
  own endpoints, which aren't read; their spend is in `costs`.
- Grouping by user or API key isn't offered, so no user or key ids appear
  in answers. Model names and line items are cut to one line of 120
  bytes, with email addresses and anything shaped like a key or a user or
  key id replaced by `[redacted]`; a fine-tuned model's owner that is a
  user or organization id shows as `your organization`. An answer keeps
  the 200 largest groups; `groupCount` says
  how many there were.

- Amounts are read as the exact digits OpenAI sent (never through a
  float), summed exactly per currency and shown with up to 12 decimals.
  An amount that isn't a plain decimal, or a currency that isn't a
  three-letter code, fails the answer.

**Security.** Each key goes in the `Authorization` header to
`api.openai.com` only; redirects are followed within the same host only.
Dates and choices are checked before any request.
