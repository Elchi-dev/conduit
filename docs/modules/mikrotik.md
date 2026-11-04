# MikroTik

A MikroTik router through the RouterOS v7 REST API: system resources and
identity, interfaces with their traffic, DHCP leases, firewall address
lists (adding and removing entries, with undo), how many wireless clients
are connected, and restarting the router.

**Setup.** The REST API comes with RouterOS 7.1 and later and is served by
the `www-ssl` service (or `www`, without TLS; not recommended outside a lab).
Create a group with the `read`, `api` and `rest-api` policies (add `write`
for address list changes and `reboot` to restart it), a user in it, store
the password in the vault, and enter the router's address
(`https://192.168.88.1`) with the user name and the password's reference.
RouterOS uses a self-signed certificate: copy its SHA-256 fingerprint into
**Fingerprint** (`openssl s_client -connect 192.168.88.1:443 </dev/null | openssl x509 -noout -fingerprint -sha256`).

| Action | Risk | Notes |
| --- | --- | --- |
| `system` | read | Identity, version, board, uptime, CPU load, memory and disk |
| `interfaces` | read | Type, running or disabled, MAC, MTU, bytes and errors since boot |
| `leases` | read | Address, MAC, host name, status, server, expiry |
| `address_lists` | read | Each list with its number of entries (and how many are dynamic) |
| `address_list_entries` | read | One list's entries with comments and timeouts |
| `add_address_list_entry` | destructive | Preview shows the list before and after. Optional comment, timeout and `disabled`. Undo removes it |
| `remove_address_list_entry` | destructive | Preview first. Undo adds it back with its comment, its disabled flag and the time it had left |
| `wireless_clients` | read | Clients per interface from the wifi, wifiwave2, wireless and CAPsMAN registration tables, whichever exist |
| `reboot` | destructive | Preview names the router. The network behind it is cut off for a minute or two |

**Address lists.** Entries are an IP address, a network (written in
canonical form, so `10.1.2.3/8` becomes `10.0.0.0/8`), a range
(`10.0.0.1-10.0.0.9`) or a DNS name; nothing with separators or line breaks
gets through, so one call changes one entry. Firewall rules usually match
on address lists, so adding or removing an entry changes who can reach
what: both are destructive and need approval under every preset except
full autonomy. Undoing a removal puts the entry back as it was: its
comment, whether it was disabled, and the time a counting-down timeout had
left (milliseconds rounded down), so a temporary entry never comes back
permanent. When the remaining time can't be read, the removal has no undo.

**Secrets stay on the router.** The module only asks for the paths above;
it never reads `/user`, `/ppp/secret`, wireless security profiles,
certificates or an export, so passwords, PPP secrets and Wi-Fi keys never
pass through Conduit. RouterOS error details are passed on redacted.

Health is *degraded* when the CPU is at 90% or more, or less than 5% of
memory is free.
