# OPNsense

An OPNsense firewall: firmware and update status, interfaces, gateways,
DHCP leases and firewall aliases, adding and removing alias entries (with
undo), and restarting the firewall.

**Setup.** In OPNsense, System, Access, Users, edit a user and add an API
key; the downloaded file holds the key and the secret. Store both in the
vault and enter their references with the firewall's address
(`https://192.168.1.1`). Give that user only the privileges Conduit needs
(for example *Diagnostics*, *Status*, *Firewall: Alias: Edit*, *System:
Firmware*). OPNsense uses a self-signed certificate by default: copy its
SHA-256 fingerprint into **Fingerprint** (System, Trust, Certificates, or
`openssl s_client -connect 192.168.1.1:443 </dev/null | openssl x509 -noout -fingerprint -sha256`).

| Action | Risk | Notes |
| --- | --- | --- |
| `firmware` | read | Version, update status from the last check, whether a restart is needed |
| `interfaces` | read | Device, state, IPv4 and IPv6 addresses, MAC (OPNsense 23.7+) |
| `gateways` | read | Online or down, loss and latency |
| `leases` | read | From ISC DHCP, Kea or Dnsmasq, whichever answers |
| `aliases` | read | Name, type, description, number of entries |
| `alias_entries` | read | One alias's entries (the live table for external aliases) |
| `add_alias_entry` | destructive | Preview shows the entries before and after. Undo removes it |
| `remove_alias_entry` | destructive | Preview first. Undo adds it back |
| `reboot` | destructive | Preview first. The network behind the firewall is cut off for a few minutes |

**Aliases.** Host, network, port and MAC aliases are changed in the
configuration and applied at once (`reconfigure`), so the change survives a
restart. *External (advanced)* aliases are filled at run time, so their
entries are changed in the live table (`alias_util`), which is what that
type is for. Other types (GeoIP, URL tables, ...) can't be changed from
here. Each entry is checked against the alias type (an address, a network,
a host name, a port or range, a MAC address) and can't carry separators,
so one call changes exactly one entry. Alias entries change who can reach
what, so both actions are destructive: agents need approval for them under
every preset except full autonomy.

Health is *degraded* while a gateway is down, and mentions waiting updates
and a pending restart.
