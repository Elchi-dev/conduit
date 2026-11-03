# UniFi Network

Gateways, switches and access points on a UniFi OS console (Dream Machine,
Cloud Gateway, Cloud Key, UniFi OS Server): which are online, who's
connected, restart a device, block a client.

**Setup.** The console's `https://` address and:

- an **API key** (UniFi Network, Settings, Control Plane, Integrations) for
  devices, clients and restarts, and/or
- a **local account** (username and password) to block and unblock
  clients, which the API key can't do. Create one with the least role that
  works (Site Admin for the Network application).

Both secrets go in the vault. Consoles use a self-signed certificate: pin it
with its SHA-256 fingerprint (`openssl s_client -connect 192.168.1.1:443 |
openssl x509 -noout -fingerprint -sha256`) rather than switching off
certificate checks.

| Action | Risk | Notes |
| --- | --- | --- |
| `devices` | read | Name, model, MAC, IP, state, uptime, firmware |
| `clients` | read | How many are connected and the busiest ones (traffic numbers need the local account) |
| `restart_device` | destructive | By id or MAC; its clients lose the connection for a minute or two. Preview first |
| `block_client` | write | By MAC; undo unblocks |
| `unblock_client` | write | Undo blocks again |

Health is *degraded* while a device is offline.
