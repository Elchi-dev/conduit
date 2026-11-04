# Kanidm

People, groups and account status of a Kanidm server, and locking and
unlocking accounts.

**Setup.** Create a service account and an API token for it:

```
kanidm service-account create conduit "Conduit" idm_admin
kanidm service-account api-token generate conduit "conduit" --rw
```

Store the token in the vault. To lock and unlock people, add the service
account to `idm_people_admins` (and to `idm_service_account_admins` for
service accounts); reading needs no extra group. Enter the server's address,
such as `https://idm.example.com`. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `persons` | read, sensitive | People (`search` in the name or display name) with name, display name, SPN, UUID, groups and status. Emails only with `includeEmail`. Personal data, so input and output stay out of the audit log, approvals and events. |
| `groups` | read | Name, UUID, description, member count, and whether it's one of the admin groups. |
| `account_status` | read | Every person and service account, or one (`account`): `active`, `expired` or `not yet valid`, with the expiry and valid-from dates, and a count per status. |
| `lock_account` | destructive | By name, SPN or UUID. Sets the account to expire now, so it can't sign in; credentials and groups stay. Undo unlocks it. |
| `unlock_account` | destructive | Clears an expiry that has passed, so the account can sign in again. Undo locks it again. |

Both changes refuse the token's own service account, and `admin`,
`idm_admin` and members (direct or nested) of `system_admins`,
`domain_admins`, `idm_high_privilege` or any `*_admins` group (such as
`idm_admins`, `idm_people_admins` or `idm_oauth2_admins`) unless
`allowAdmins` is on. An account whose groups the token can't read is
refused too, as is any change when the token's own account can't be told. An account already in
the requested state is reported as "nothing to change".

**Security.** The address can't carry credentials, a query or a fragment.
The token goes in the `Authorization` header, and the client won't follow a
redirect to another host or from https to http. Account names are checked
and escaped before they reach a request path. Entries are read attribute by
attribute, so credentials, passkeys, RADIUS secrets, sessions and API tokens
are never read.

**Notes.** Locking an account that already had a later expiry date replaces
that date, so it offers no undo. Existing sessions end when they next
refresh.
