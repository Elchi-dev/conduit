# PostHog

PostHog (US or EU cloud, or self-hosted) through its API: projects, saved
insights, a daily trend of pageviews or any event, the top events, feature
flags with their rollout, switching a flag or changing its rollout, and
recent exceptions from error tracking.

**Setup.** Create a personal API key (Settings, Personal API keys) and store
it in the vault. Give it read scopes for projects, insights, queries and
feature flags, and `feature_flag:write` only if flags may be changed. Set
`host` to `us` (the default), `eu`, or your server's address; the ingestion
address (`us.i.posthog.com`) is refused, since the API isn't there.
Optionally set a default `project` id; otherwise the first project the key
sees is used, and every action takes a `project` too.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | The projects the key can see, with id, name and time zone. |
| `insights` | read | Saved insights, most recently changed first (`limit` up to 100): name, whether favourited, last refresh and a link. |
| `trends` | read | One `event` (`$pageview` by default) per day over the last `days` (up to 90, 7 by default), with distinct users and the total. |
| `events` | read | The most frequent events over the last `days` (up to 90), with counts and distinct users (`limit` up to 100, 20 by default). |
| `flags` | read | Feature flags with key, name, whether on, each release condition's rollout and how many property conditions it has, and counts on and off. |
| `flag` | read | One `flag` (by key or id): the same plus variants and PostHog's status (active, stale, deleted, unknown) with its reason. |
| `set_flag` | destructive | Switches a flag on or off (`active`) and/or sets the `rollout` percentage (0 to 100) of one release condition (`group`, 1 for the first; needed when there are several). The preview shows the old and the new state; undo puts the old state back. Everything else in the flag's conditions is sent back as it was. |
| `errors` | read, sensitive | Exceptions captured over the last `days` (up to 30, 1 by default), grouped by type and message, most frequent first, with occurrences, users and when last seen. A note says so when there are none (error tracking may be off). |

**Why the risks.** Turning a flag on or off, or moving its rollout, changes
what users of your product get in production the moment it's saved, so
`set_flag` is destructive even though it can be undone; its undo is the
same action and is approved again. Everything else only reads.

**Sensitive data.** Exception messages often quote user input, emails or
ids, so `errors` is sensitive and stays out of the audit log; anything that
looks like a credential in a message is also masked. Trends and counts are
aggregates and aren't sensitive.

**Security.** The key goes as a Bearer token and stays in the vault. The
client follows redirects only within the same host and never from https to
http. Queries are built by the module from checked numbers (days, limits)
and the event name is passed as a HogQL placeholder value, never spliced
into the query text. Flag keys are letters, digits, `-` and `_`, project
ids are numbers, and rollouts and groups are range-checked before they
reach a request.
