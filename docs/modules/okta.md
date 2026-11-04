# Okta

Users, groups and applications of an Okta organization, and suspending and
unsuspending users and ending their sessions.

**Setup.** In the Admin Console, open Security, API, Tokens and create a
token; store it in the vault. A token acts with the permissions of the admin
who created it, so create it as an admin whose role covers what Conduit
should do (a Read-only Administrator to only read, a Help Desk or Group
Administrator to suspend users and end sessions). Enter your organization's
address, such as `https://acme.okta.com` (`oktapreview.com` and
`okta-emea.com` work too; the admin console's `acme-admin.okta.com` is turned
into `acme.okta.com`).

| Action | Risk | Notes |
| --- | --- | --- |
| `users` | read, sensitive | Users (`search` by the start of a name, login or email, `status`, `limit` up to 500) with id, login, name, status, created, last login and last status change, plus a count per status. Emails only with `includeEmail`. Personal data, so input and output stay out of the audit log, approvals and events. |
| `groups` | read | Id, name, type (`okta`, `app`, `built_in`), description and member count. |
| `apps` | read | Id, name, label, status, sign-on mode, created and updated. |
| `suspend_user` | destructive | By id or exact login. Stops an active user signing in; groups, apps and profile stay. The preview names the user and their status. Undo unsuspends. |
| `unsuspend_user` | destructive | Lets a suspended user sign in again (it grants access, hence destructive). Undo suspends them again. |
| `reset_sessions` | destructive | Ends every Okta session of the user; with `revokeTokens` it also revokes the OAuth and OIDC tokens their apps hold. |

All three changes refuse the token's own user, and users that hold any admin
role unless `allowAdmins` is on. When the token may not read a user's roles,
the change is refused rather than guessed, as it is when the token's own
user can't be read. A user who is already in the
requested state is reported as "nothing to change".

**Security.** The organization address must be a single name under an Okta
domain over https, so a look-alike such as `acme.okta.com.evil.test` is
refused. The token goes in the `Authorization` header, and the client won't
follow a redirect to another host or from https to http. User ids and logins
are checked and escaped before they reach a request path. Applications and
users are decoded field by field, so app credentials (client secrets,
signing keys, shared passwords) and recovery answers are never read.

**Notes.** Suspending works on active users only (Okta's rule); deactivating
and deleting users aren't offered. Custom Okta domains aren't accepted as the
address: use the organization's `okta.com` name.
