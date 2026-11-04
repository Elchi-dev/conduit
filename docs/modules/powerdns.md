# PowerDNS

A PowerDNS Authoritative server through its HTTP API: zones and records,
adding an address, text or alias record at a fresh name, adding any other
record set, replacing and deleting record sets (with previews and undo),
and sending NOTIFY or rectifying a zone.

**Setup.** Turn the API on in `pdns.conf` (`api=yes`, `api-key=…`,
`webserver=yes`, `webserver-address` and `webserver-allow-from` set to where
Conduit runs), store the key in the vault, and enter the webserver's address
(`http://ns1.example.com:8081`) with its reference. The server id is
`localhost` unless you changed it.

| Action | Risk | Notes |
| --- | --- | --- |
| `zones` | read | Name, kind, serial, DNSSEC |
| `records` | read | A zone's record sets, optionally one name or type, with comments; disabled records are marked |
| `add_record` | write | A, AAAA, TXT or CNAME only, at a name nothing answers for yet. Refused (pointing at `add_record_any`): the zone apex, `_acme-challenge*` and `_domainkey` names, wildcard owners, names a wildcard at any ancestor covers, names that already have records of another type, and names at or below a delegation (a non-apex NS). An existing name and type is refused with a pointer to `replace_rrset`. Undo deletes it |
| `add_record_any` | destructive | Any editable type (NS, DS, MX, CAA, TLSA, HTTPS, SVCB, SRV, NAPTR, ALIAS, SSHFP, LOC, PTR, SPF…) and the names `add_record` refuses. The preview says what it overrides: the wildcard that answers today, the other types at the name, the delegation, the apex. An existing name and type still goes to `replace_rrset`. Undo deletes it |
| `replace_rrset` | destructive | Sets every record of a name and type. Preview shows old and new records and TTL. Undo puts the old ones back, disabled flags and TTL included |
| `delete_rrset` | destructive | Preview shows what goes. Undo puts it back |
| `notify` | write | NOTIFY for a primary zone |
| `rectify` | write | Recompute DNSSEC ordering for a signed zone |

**Names and contents.** Names can be relative (`www`), `@` for the zone, or
absolute; they must lie inside the zone. Contents are checked per type and
written the way PowerDNS stores them: A and AAAA must be addresses of the
right family, targets of CNAME, NS, PTR, ALIAS, MX and SRV get their
trailing dot, TXT text is quoted (and split into 255-byte strings), CAA
must be `flags tag "value"`. SOA and the DNSSEC types PowerDNS manages are
refused, and so are changes to secondary zones, whose records come from
the primary.

**Why only some adds are write.** Adding an address, text or alias at a
name nobody answers for changes no answer anyone relied on, and its undo
removes it. Everything else can take something over even when it's "new":
NS and DS delegate a subtree to another server, MX takes mail, CAA and
`_acme-challenge` decide who gets certificates, `_domainkey` lets mail be
signed for the domain, HTTPS and SVCB redirect clients, a record under a
wildcard replaces the wildcard's answer, a second type at a name changes
what that name is, a record below a delegation contradicts the server it
was delegated to, and the apex carries mail and verification records.
Those go through `add_record_any`, and replacing or deleting changes or
removes answers that are live; all three need approval under every preset
except full autonomy.
