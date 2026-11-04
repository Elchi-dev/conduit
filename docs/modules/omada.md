# TP-Link Omada

Sites, devices (gateways, switches, access points) and clients of a TP-Link
Omada controller (software controller, OC200 or OC300, or Omada Cloud),
restarting a device, and blocking or unblocking a client.

**Setup.** On the controller, open Settings, Platform Integration, Open API
and add an application in **Client** mode with access to the sites it
should manage. Enter the controller's address
(`https://192.168.0.2:8043`), the **Omada ID** shown on that page, the
application's client id, and the reference to its client secret in the
vault. With several sites, set **site** to the one actions use by default
(each action can also name one). For the controller's self-signed
certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `sites` | read | Id, name, region, time zone, scenario |
| `devices` | read | Name, type, model, MAC, address, status, firmware, uptime, CPU and memory use, clients |
| `clients` | read, sensitive | Name, host name, MAC, address, wired or wireless, SSID and access point (or switch and port), signal, traffic, blocked, guest. Up to `limit` (100) |
| `reboot_device` | destructive | By MAC address. Preview names the device and how many clients it has |
| `block_client` | destructive | By MAC address. Preview first. Undo unblocks it |
| `unblock_client` | write | Lets a blocked client connect again. Undo blocks it |

**Blocking.** A blocked client loses the connection at once, so blocking is
destructive. Unblocking only gives back access the client had before, so
it's a write, with a preview and an undo. A client that's already in the
asked state answers "nothing to change". MAC addresses are accepted with
colons or dashes and sent the way Omada writes them (`AA-BB-CC-DD-EE-FF`).

**Keeping the connection.** Blocking the client that has the controller's
own address (a software controller running on a machine on this network)
is refused, since it would cut Conduit off from the controller.

**Security.** The access token is fetched with the client credentials, kept
in memory, renewed when it expires, and sent only to the controller; the
client won't follow a redirect to another host or from https to http. MAC
addresses and site names are checked before they reach a request path.

## Notes

- The OpenAPI comes with controller 5.9 and later.
- Omada's client listing shows clients that are connected now, so the
  "nothing to change" check for unblocking sees only those.
