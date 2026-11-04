# Vercel

Projects and deployments: see what's live, redeploy, point production at
another deployment (promote or roll back, with undo), and cancel a build.

**Setup.** Vercel, Account settings, Tokens, Create. Scope the token to
the team it needs and give it an expiry. For a team, also enter its id
(`team_…`, Team settings, General). Store the token in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | With the current production deployment and address |
| `deployments` | read | State, address, target, commit message and branch; filter by project |
| `redeploy` | destructive | Builds the same commit again, as a preview or for production. It can put an older deployment's commit in production. |
| `promote` | write | Points the production domains at a deployment. Undo points them back at the previous one. Preview shows before and after |
| `cancel` | destructive | Stops a deployment that is still building |

Deployment and project ids are checked before they reach the API, so input
can't reach other endpoints. Vercel tokens can't be limited to single
actions; use the agent rules to decide which actions agents may run without
asking.
