# Doppler

Doppler through its API: the token's own identity, projects, configs,
secret names, the workplace activity log, and the values of named secrets
only through `reveal_secret`. Notes are never returned. The module never
sets, deletes or rotates secrets and never changes access (tokens, service
accounts, roles).

**Setup.** Store a Doppler token in Conduit's vault and enter its
`secret://` reference. The narrowest choice is a **service token**: it is
read-only and bound to one config, so leave `project` and `config` empty
(or set them to its own) and `projects`, `configs` and `activity` won't
work. A **service account** with a read-only role on chosen projects, or a
personal token, makes every action work. Set a default `project` and
`config` (like `prd`) to skip them in calls.

| Action | Risk | Notes |
| --- | --- | --- |
| `me` | read | The token's type, name, workplace and when it was created and last used. Never the token or its preview. |
| `projects` | read | Slug, name, description and creation time of each project. |
| `configs` | read | A project's configs with environment, root or branch, locked, inheritable and when they were last fetched. |
| `secret_names` | read | The names of a config's secrets. Never values or notes. |
| `activity` | read | Workplace activity, newest first (`page`, `perPage` up to 100), optionally only for one `project`: the entry's text, user name, project, config and time. User emails aren't returned, and anything in the text that looks like a credential is redacted. |
| `reveal_secret` | destructive, sensitive | The values of the `names` given (1 to 10) of one config, and no others: the computed value (references resolved), or the raw one when that's all there is. Names not found are listed as `missing`. Revealing a credential can't be taken back, so it's destructive. |

**Security.** The token goes to `https://api.doppler.com` only, as
`Authorization: Bearer`; the client follows redirects only within the same
host and never from https to http. Secret names must be letters, digits and
underscores, and project and config slugs are checked, before they go into
a query. Doppler's error messages are passed on redacted.
