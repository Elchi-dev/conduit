# authentik

Users, groups, applications, recent events and logins, deactivating and
reactivating users, and the version and status of an authentik server.

**Setup.** In the admin interface, open Directory, Tokens and App passwords,
create a token with the intent API for a user that may do what you want
Conduit to do (reading the directory and events; changing users to
deactivate them), and store it in the vault. Enter the server's address,
such as `https://auth.example.com`. For authentik's self-signed certificate,
set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Running and latest version and whether it's outdated, runtime (Python, environment, platform), server time, worker count and outposts. |
| `users` | read, sensitive | Counts (total, active, inactive, superusers) and a list (`search`, `active`, `type`, `limit`, 0 for counts only) with id, username, name, active, superuser, type, last login and groups. Emails only with `includeEmail`. Personal data, so input and output stay out of the audit log, approvals and events. |
| `groups` | read | Name, parent, member count and whether it grants superuser. |
| `applications` | read | Every application (not only the ones the token's user can open): name, slug, provider, launch URL and group. |
| `events` | read, sensitive | The event log, newest first, filtered by `action` (`login`, `login_failed`, `logout`, `user_write`, `model_updated`, `configuration_error`, ...) and `username`: time, action, user, client IP, country, path, application and message. Usernames and IPs are personal data, so it's kept out of logs like `users`. |
| `deactivate_user` | destructive | By `id` or exact `username`. Stops the user signing in; the account stays. Refused for the token's own user. The preview says if it's a superuser. Undo activates it again. |
| `activate_user` | destructive | Lets a deactivated user sign in again (it grants access, hence destructive). Undo deactivates it. |

Deactivating a user doesn't necessarily end sessions they already have in
applications; revoke those in authentik or the application if it matters.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. User ids must
be positive numbers before they reach a request path, and event kinds plain
words. `status` passes on only the runtime fields: authentik's system
endpoint also echoes the request's headers, including the token. Event
context is cut to a few fields, and users' emails in events are dropped.
