# Sentry

Unresolved errors in your Sentry projects with a summary of their latest
event; resolve or ignore issues. Works with sentry.io and self-hosted Sentry.

**Setup.** In Sentry, Settings, Auth Tokens (or User settings, Personal
Tokens), create a token with `org:read`, `project:read` and `event:write`.
Store it in the vault, enter its `secret://` reference and the organization
slug (as in the address bar). Leave the address as `https://sentry.io`, or
enter your region's (`https://de.sentry.io`) or your self-hosted Sentry's
https address.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | |
| `issues` | read | Unresolved, newest first, with event and user counts. Optional project and extra Sentry search (`level:error`). |
| `issue` | read | The issue and its latest event: time, release, environment and a few tags (no user data) |
| `resolve` | write | Undo marks it unresolved |
| `ignore` | write | Undo marks it unresolved |
| `unresolve` | write | |

**Security.** Give the token only the scopes above; `event:write` is what
resolving and ignoring need, leave it out for a view-only setup. Tokens are
sent only to the address you enter, which must be https.
