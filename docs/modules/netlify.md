# Netlify

Netlify sites and deploys: what's live, deploy state and build summary,
triggering builds, rolling production back to an earlier deploy, and
locking or unlocking auto-publishing.

**Setup.** In Netlify, open User settings, Applications, Personal access
tokens, create a token with an expiry and store it in the vault. It acts
with your permissions on every team you're in; enter a team slug (as in
`app.netlify.com/teams/<slug>`) to list only that team's sites.

| Action | Risk | Notes |
| --- | --- | --- |
| `sites` | read | Every site with its address, team, repository and branch, the live deploy and whether auto-publishing is locked. |
| `site` | read | One site, by id or domain (`my-site.netlify.app`). |
| `deploys` | read | Recent deploys (`limit`, default 20; `production` for production only): state, context, branch, commit, build time, error, and which one is live. |
| `deploy` | read | One deploy's state and build summary: the messages the build reported (titles, descriptions, details, clipped), the error and timing. Netlify's full build log is only streamed to its web app, not offered through the API. |
| `trigger_build` | destructive | Builds the production branch again, optionally with `clearCache`. The preview names the branch and says when auto-publishing is locked, so the build won't go live by itself. It builds and publishes whatever the branch holds now. |
| `rollback` | destructive | Publishes an earlier ready `deploy` of the site as production, or, without one, the newest ready production deploy older than the live one. Visitors see it at once, hence destructive. The preview shows the live deploy and the one replacing it, and warns when auto-publishing is on (the next production build would replace the rollback; lock it to keep it). Undo publishes the deploy that was live. |
| `lock_publishing` | write | Locks the live deploy so new production builds stop going live by themselves; undo unlocks. |
| `unlock_publishing` | write | New production builds go live again; undo locks again. |

**Security.** The token goes in the `Authorization` header and the client
won't follow a redirect to another host. Site ids or domains, deploy ids
and the team slug are checked before they reach a request path, and a
rollback refuses a deploy that belongs to another site. The account's email
address is never returned.
