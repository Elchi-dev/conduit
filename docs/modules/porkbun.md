# Porkbun

Domains registered at Porkbun through its API v3: expiry and auto-renew,
DNS records, adding records (a fresh name at write risk, anything else
destructive) and deleting them, with previews and undo.

**Setup.** In Porkbun, Account, API Access, create an API key. Store both
the API key (`pk1_…`) and the secret API key (`sk1_…`) in the vault and
enter their `secret://` references; plain keys are refused. Then turn on
**API access** for each domain Conduit should manage (Domain Management,
the domain's Details). Domains without it are still listed, but their
records can't be read or changed.

| Action | Risk | Notes |
| --- | --- | --- |
| `domains` | read | Every domain with status, expiry date, days left, auto-renew, security lock and WHOIS privacy |
| `renewals` | read | Domains expiring within `days` (1 to 730, 60 by default), soonest first, and the ones among them that don't renew automatically |
| `records` | read | A `domain`'s records (id, name, type, content, TTL, priority), optionally one `name` or `type`. Record notes aren't shown |
| `add_record` | write | Creates an A, AAAA, TXT or CNAME record at a name that nothing answers for yet. Refused: the domain itself, `_acme-challenge` and `_domainkey` names, wildcards, names a wildcard covers today, names that already have records of any type, and names at or below an NS delegation. Undo deletes it |
| `add_record_any` | destructive | Creates a record of any type Porkbun takes (A, AAAA, CNAME, ALIAS, TXT, NS, MX, SRV, TLSA, CAA, HTTPS, SVCB, SSHFP) at any name, also next to existing records of the same name and type. These can delegate a subdomain, take mail, allow certificates or override a wildcard; the preview says what it overrides. Undo deletes it |
| `delete_record` | destructive | Deletes one record by `id`. The preview shows the record and warns for the domain itself, MX and NS. Undo adds it again through `add_record_any` (with a new id) |

Names are relative (`www`), `@` or empty for the domain itself, or the full
name (`www.example.com`). Both add actions refuse a CNAME next to other
records, other records next to a CNAME, and an exact duplicate. MX and SRV
need `prio`; other types refuse it. TTL is 600 (Porkbun's minimum, and the
default) to 604800 seconds. A and AAAA content must be an address of that
family; CNAME, ALIAS, NS and MX content a host name.

Health pings the API with the key pair.

**Recommended policy.** Allow `add_record` for agents that publish
services or verify domains through TXT records; keep `add_record_any` and
`delete_record` on ask. A domain's mail, certificates and delegation hang
off records `add_record` refuses.

**Security.** Porkbun takes the key pair in each request's JSON body, which
a 307 or 308 redirect sends again, so the client follows redirects only
within the same host and never from https to http; requests time out after
30 seconds. Domains, names, record ids, types, content, TTLs and
priorities are checked before anything is sent. Error messages from
Porkbun are passed on redacted.
