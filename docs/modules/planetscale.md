# PlanetScale

PlanetScale organizations, databases, branches and deploy requests through
the PlanetScale API, read-only.

**Setup.** In Organization settings, Service tokens, create a token and
grant it `read_database`, `read_branch` and `read_deploy_request` on the
databases it should see (`read_organization` too for `organizations`).
Store the token in the vault and enter its `secret://` reference with the
token's id. Optionally set `organization` so actions don't need to name it.

| Action | Risk | Notes |
| --- | --- | --- |
| `organizations` | read | The organizations the token can see, with plan and database count. |
| `databases` | read | An `organization`'s databases: engine (MySQL or Postgres), state, region, plan, production and development branch counts, and dashboard link. |
| `branches` | read | A `database`'s branches: production or development, ready, parent, region, safe migrations and timestamps. |
| `deploy_requests` | read | A `database`'s deploy requests (optionally `open` or `closed`): number, branch into branch, state, deployment state, approved, author and timestamps. |
| `deploy_request` | read | One deploy request by `number`, with its notes and deployment state. |

**Security.** Passwords and connection strings are never requested, and
answers are decoded field by field. The token id and token go in the
`Authorization` header and the client won't follow a redirect to another
host. Organization and database names are checked before they reach a
request path; deploy request notes are redacted of anything that looks like
a credential.

**Notes.** Only reading is offered: nothing is deployed, merged or deleted.

**Presets.** developer.
