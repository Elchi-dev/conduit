# NetBox

NetBox, the network source of truth: search, devices, IP addresses,
prefixes and their free addresses, sites and VLANs; reserving the next free
address in a prefix and changing a device's status, both with undo.

**Setup.** Create an API token (your profile, API Tokens), store it in the
vault, and enter NetBox's address (`https://netbox.example.com`) with its
reference. A read-only token is enough for everything but `reserve_ip`,
`delete_ip_address` and `set_device_status`. Both v1 tokens (`Token`) and
NetBox 4.5's v2 tokens (`nbt_…`, sent as `Bearer`) work.

| Action | Risk | Notes |
| --- | --- | --- |
| `search` | read | Devices, IP addresses, prefixes, sites and VLANs matching some text |
| `devices` | read | Filter by text, site, role and status |
| `device` | read | One device (by id or exact name) with its interfaces and their addresses |
| `ip_addresses` | read | Filter by text, parent prefix, site and status |
| `prefixes` | read | Site, VRF, VLAN, role, status |
| `available_ips` | read | Free addresses in a prefix (by CIDR, or by id when it exists in several VRFs) |
| `sites` | read | With device counts |
| `vlans` | read | Filter by text, site and VLAN id |
| `reserve_ip` | write | Preview shows the address it would take. NetBox picks and creates it in one locked step. Undo deletes it |
| `delete_ip_address` | destructive | Preview shows the record. Used as the undo of `reserve_ip` |
| `set_device_status` | write | Preview shows old and new status. Undo puts the old one back |

**What changes.** Only NetBox's records change: reserving an address
doesn't configure it anywhere, and a device's status is documentation
(automation that reads NetBox may act on it, which is why it's previewed
and undoable). Deleting an address record is destructive.

**What's left out.** Answers carry names, statuses, addresses and
relations; custom fields, config contexts, comments and local context data
are never returned, since people keep all sorts in them (SNMP communities,
passwords).
