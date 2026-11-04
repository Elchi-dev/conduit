# DigitalOcean

Droplets, App Platform apps and your balance: power droplets on and off,
reboot them, take snapshots, and redeploy apps.

**Setup.** DigitalOcean control panel, API, Tokens, Generate New Token.
Prefer a custom-scoped token: `read` scopes for watching, plus
`droplet:update` (power, reboot), `droplet:create` and `snapshot:create`
(snapshots) and `app:update` (redeploy) for changes, with an expiry. Store
it in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `droplets` | read | Status, size, region, public and private IPv4 |
| `snapshots` | read | Droplet and volume snapshots |
| `apps` | read | App Platform apps, live URL, active and in-progress deployment |
| `balance` | read | Month-to-date usage and balance |
| `power_on` | write | Undo shuts it down again (only if it was off) |
| `shutdown` | destructive | Graceful shutdown; undo powers it on. A droplet that is off is still billed. The droplet's services go down until it's powered on. |
| `reboot` | destructive | |
| `snapshot` | write | Billed by size; delete old ones in the control panel |
| `redeploy` | destructive | Builds and deploys the app's current source again; `forceBuild` rebuilds without cache. It puts whatever the source is now live. |

All changes have a preview. Health shows the account's email, or
*degraded* when the account isn't active (for example, payment is due).
