# wg-easy

A wg-easy WireGuard server: clients with their addresses, last handshake,
whether they're connected and their traffic, turning clients on or off,
creating and deleting them, and a client's configuration file. Private and
preshared keys are never part of any answer except the sensitive `config`
action's.

**Setup.** Enter the web UI's address, such as `https://vpn.example.com` or
`http://server:51821`, and pick the version:

- **15** (the default): wg-easy 15 and later. Enter the admin username and
  store its password in the vault. The API takes basic auth, which wg-easy
  refuses for users with two-factor sign-in, so use an admin without it.
- **14**: wg-easy 14 and earlier. Store the web UI password in the vault;
  the module signs in at `/api/session` and keeps the session cookie,
  signing in again when it expires.

For a self-signed certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `clients` | read | Every client with id, on/off, IPv4 (and IPv6) address, public key, latest handshake, `online` (a handshake in the last 3 minutes), endpoint, bytes received and sent, created and expiry dates. `search` and `online` narrow it. |
| `traffic` | read | Bytes received and sent per client, largest first, with totals and how many are connected. |
| `enable_client` / `disable_client` | write | The preview says when a client is connected now and would be cut off. Each one's undo is the other. |
| `create_client` | write | Creates a client with new keys and the next free address, with an optional `expiresAt` date. Names must be unique. The answer has its id and address but never its keys; use `config` to get its configuration. Undo deletes it. |
| `delete_client` | destructive | Deletes the client and its keys. Can't be undone: a new client gets new keys, so the device would need a new configuration. |
| `config` | destructive, sensitive | The client's configuration file, with its private key. It reveals a secret, so it's destructive (asks by default), and its output never reaches the audit log. |

Clients are given by name or id; a name that several clients share is
refused.

**Security.** The client won't follow a redirect to another host or from
https to http. Client references are resolved against the server's own list
before an id is put in a URL.
