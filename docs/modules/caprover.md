# CapRover

Apps of a CapRover server with their domains, instances and deployed
versions, deploying a Docker image or an earlier version, and scaling apps.

**Setup.** Store the CapRover dashboard password in the vault and enter its
`secret://` reference with your dashboard's address, such as
`https://captain.example.com`. CapRover has a single account and no API
keys, so the module signs in with the password and keeps the token CapRover
hands out. For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `apps` | read | Every app: domains with HTTPS, forced HTTPS, container port, instances, persistent data, deployed version and image, Git repository and branch. |
| `app` | read | One `app` with its latest ten versions (image, Git commit, time) and whether a build is running or the last one failed. |
| `deploy_app` | destructive | Deploys an `image` (such as `nginx:1.27`) to the app, or deploys an earlier `version` again, which is how a rollback is done. The preview names the image and how many instances are replaced. Undo deploys the version that ran before. |
| `scale_app` | destructive | Sets the number of `instances` (0 to 50); 0 stops the app. Undo sets the count back. |

Deploying the version already running, the same pinned image again, or
scaling to the current count reports nothing to change. An image with the
`latest` tag (or none) is deployed again, since it may have changed.

**Notes.** Deploying from source (a tarball or a Git push) isn't part of
this module; deploy an image your CI built, or redeploy a version. A
deployment runs in the background: `app` shows when it's done. Two-factor
sign-in can't be used with the module.

**Security.** The password is sent only to `/api/v2/login`; the token is
kept in memory, sent as `x-captain-auth`, and renewed when CapRover stops
accepting it. The client won't follow a redirect to another host or from
https to http. App names and images are checked before anything is sent.
Apps are read field by field, so environment variables, the push webhook's
token and the repository's user, password and SSH key never come back, and
build logs aren't passed on. Scaling uses CapRover's partial update, which
changes only the count; on a CapRover without it, the module sends the
app's settings back unchanged apart from the count, as the full update
replaces them, like the dashboard's Save does. After CapRover refuses the
password, the module doesn't try it again for two minutes, so a wrong or
changed password doesn't keep CapRover's sign-in lockout (30 seconds after
five wrong passwords) on for the dashboard too.

**Presets.** developer, homelab.
