# Cloudflare

DNS zones and records, and cache purges. Record changes preview as a diff and
can be undone.

**Setup.** Create an API token (My Profile, API Tokens) with Zone:Read and
DNS:Edit for the zones you want, plus Cache Purge if agents may purge. Store
it in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `zones` | read | |
| `records` | read | Filter by type and name |
| `set_record` | write | Changes the one record with that type and name, or creates it. Dry run shows before and after. Undo restores the old value, or removes a new record. Refuses when several records share the type and name. |
| `delete_record` | destructive | Dry run shows the record; undo recreates it |
| `restore_record` | write | Used by undo |
| `purge_cache` | write | Given URLs, or everything |

Names may be relative (`www`), absolute (`www.example.com`) or `@` for the
apex. Only A, AAAA and CNAME records can be proxied.
