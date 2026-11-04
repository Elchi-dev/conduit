# Stalwart

Domains, accounts (users and groups) with their storage use, and a summary
of the outgoing queue of a Stalwart mail server, through its JMAP
management API.

**Setup.** Create an API key in Stalwart's web admin for an administrator
(or an account whose role grants the `sysDomainGet`, `sysDomainQuery`,
`sysAccountGet`, `sysAccountQuery`, `sysQueuedMessageGet` and
`sysQueuedMessageQuery` permissions), store it in the vault, and enter the
server's address, such as `https://mail.example.com`. Instead of a key you
can enter the account's name and store its password in the vault. For a
self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `domains` | read | Id, domain, alias domains, enabled, created, description, how DKIM, certificates and DNS are managed (`Automatic` or `Manual`), whether there's a catch-all address, and relaying. |
| `accounts` | read, sensitive | Total and a list (`search`, `type` user or group, `limit`) with id, type, name, address, domain, role, storage used, quota and percent, active alias addresses, group count and created. Personal data, so input and output stay out of the audit log, approvals and events. |
| `queue` | read, sensitive | How many messages wait, recipients by queue and by status (`Scheduled`, `TemporaryFailure` …), total size, the oldest message and the next retry, and counts by sender and recipient domain (the first 1000 messages). |

The health check signs in, reads the JMAP session, and counts domains.

**Security.** The key goes in the `Authorization` header as a bearer token
(or the name and password as basic authentication), and the client won't
follow a redirect to another host or from https to http. Calls go to the
configured address only, never to an address the session names. Each call
asks for the properties it shows and decodes them field by field:
credentials (password hashes, app passwords, API keys, TOTP), DKIM keys,
zone files, message content, the submitting IP and full queued addresses
are never requested or passed on. Server messages are redacted before
they're shortened.

## Notes

- It uses the JMAP management API of Stalwart 0.16 and later (`/jmap/` with
  `urn:stalwart:jmap`). The REST management API of earlier versions
  (`/api/principal`, `/api/queue/messages`) isn't supported; an older server
  is reported as such.
- Changes (disabling accounts, rescheduling or deleting queued messages,
  reloading the configuration) aren't offered.
