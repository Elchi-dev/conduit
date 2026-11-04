# PowerDNS

A PowerDNS Authoritative server through its HTTP API: zones and records,
adding a record set that doesn't exist yet, replacing and deleting record
sets (with previews and undo), and sending NOTIFY or rectifying a zone.

**Setup.** Turn the API on in `pdns.conf` (`api=yes`, `api-key=…`,
`webserver=yes`, `webserver-address` and `webserver-allow-from` set to where
Conduit runs), store the key in the vault, and enter the webserver's address
(`http://ns1.example.com:8081`) with its reference. The server id is
`localhost` unless you changed it.

| Action | Risk | Notes |
| --- | --- | --- |
| `zones` | read | Name, kind, serial, DNSSEC |
| `records` | read | A zone's record sets, optionally one name or type, with comments; disabled records are marked |
| `add_record` | write | Only when no record set with that name and type exists (and no CNAME conflict); otherwise refused with the existing records and a pointer to `replace_rrset`. Undo deletes it |
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

**Why add is write and replace is destructive.** Adding a record set that
didn't exist changes no answer anyone relied on, and its undo removes it.
Replacing or deleting changes or removes answers that are live, so those
need approval under every preset except full autonomy.
