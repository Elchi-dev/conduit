# Cloudflare

DNS zones and records, and cache purges. Record changes preview as a diff and
can be undone. It also reads Zero Trust tunnels (cloudflared) and their
connectors.

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
| `tunnels` | read | Zero Trust tunnels: healthy, degraded, down or inactive (problems first), dashboard- or locally-managed, live connections and edge locations |
| `tunnel` | read | One tunnel by name or id: its connectors (cloudflared version, platform, start time, edge connections) and, for dashboard-managed tunnels, its public hostnames and the services behind them |

Names may be relative (`www`), absolute (`www.example.com`) or `@` for the
apex. Only A, AAAA and CNAME records can be proxied.

**Tunnels.** Give the token *Account: Cloudflare Tunnel: Read* as well. When
the token sees one account, that account is used; otherwise enter the
**Account ID** (shown on the dashboard's account overview).
