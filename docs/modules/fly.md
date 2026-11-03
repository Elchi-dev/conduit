# Fly.io

Your Fly.io apps and Machines: state, region and image, and start, stop or
restart Machines through the Machines API.

**Setup.** Create an org-scoped token with `fly tokens create org
<org-slug>` (or `fly tokens create deploy -a <app>` for one app) and store
it in the vault, including the `FlyV1 ` prefix if it has one. Enter the
organization's slug (`personal` for your own).

| Action | Risk | Notes |
| --- | --- | --- |
| `apps` | read | Apps in the organization with their Machine count |
| `machines` | read | Id, name, state, region and image of an app's Machines |
| `start` | write | Undo stops it again (only if it was stopped) |
| `stop` | write | Undo starts it again (only if it was running) |
| `restart` | destructive | |

All changes have a preview with the state before and after. App names and
Machine ids are checked before they reach the API.

An org token can do everything `flyctl` can in that organization, including
deploying and destroying apps; Conduit only uses the calls above. Prefer a
deploy token per app when Conduit only needs to manage one app.
