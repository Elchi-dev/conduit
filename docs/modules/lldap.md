# LLDAP

Users and groups of an LLDAP directory, and adding users to groups and
removing them.

**Setup.** Create a user for Conduit in LLDAP and add it to `lldap_admin`
(LLDAP's API needs it to change groups). Store its password in the vault,
then enter the web interface's address, such as `https://ldap.example.com`
or `http://lldap.lan:17170`, and the user name. Conduit signs in with them
and keeps the session token in memory. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `users` | read, sensitive | Users (`search` in the id or display name) with id, display name, created and groups. Emails only with `includeEmail`. Personal data, so input and output stay out of the audit log, approvals and events. |
| `groups` | read | Id, name, created, member count, and whether it's a built-in `lldap_` group. |
| `add_to_group` | destructive | A user (id) and a group (id or exact name). Gives the user the group and whatever it grants in the apps that use LLDAP. The preview shows the groups before and after. Undo removes it. |
| `remove_from_group` | destructive | Takes the group away from the user. Undo adds it back. |

Both changes refuse the user Conduit signs in as (matched by id, and by
email when the configured user name is an email). Changing the built-in
groups (`lldap_admin`, `lldap_password_manager`, `lldap_strict_readonly`)
or the groups of their members needs `allowAdmins`. A user already in (or
out of) the group is reported as "nothing to change".

**Security.** The address can't carry credentials, a query or a fragment.
The password goes only to LLDAP's sign-in, and the client won't follow a
redirect to another host or from https to http. Every value travels as a
GraphQL variable, never in the query text, and is checked before any
request. LLDAP's API doesn't expose password hashes, and the refresh token
isn't kept.

**Notes.** Creating and deleting users and groups isn't offered.
