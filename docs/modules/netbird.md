# NetBird

Peers, groups, access policies, routes and setup keys of a NetBird network
(NetBird Cloud or a self-hosted management server), and approving or
disabling peers.

**Setup.** In the dashboard, open Team, Users (or Service Users for a
dedicated account), choose a user and create a personal access token; store
it in the vault. Leave the address as `https://api.netbird.io` for NetBird
Cloud, or enter your management server's address, such as
`https://netbird.example.com`. The token acts with its user's role: an admin
is needed to approve or disable peers. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `peers` | read | Id, name, hostname, NetBird address, DNS name, connected, last seen, OS, NetBird version, groups, SSH, login expiration and whether it expired, whether it waits for approval, and how many peers it can reach. `connected` filters. The user id, location and serial number are left out. |
| `groups` | read | Id, name, peer names and count, resource count, and where the group comes from (`api`, `jwt`, `integration`). |
| `policies` | read | Each policy with its rules: action, protocol, ports and port ranges, bidirectional, and source and destination group names. |
| `routes` | read | Network or domains, network id, routing peer (by name) or peer groups, distribution and access control groups, metric, masquerade, enabled. |
| `setup_keys` | read | Name, type, valid, revoked, state, expiry, uses and limit, last use, ephemeral and auto-assigned groups. The key is never returned. |
| `approve_peer` | destructive | Lets a peer waiting for approval join. The preview names the peer, its address and groups. Undo disables it again. |
| `disable_peer` | destructive | Sets the peer back to waiting for approval, which cuts it off from the network until someone approves it. Undo approves it. |

Peer approval is a NetBird Cloud feature (Settings, Authentication, peer
approval). A server that keeps the peer's approval as it was makes either
action fail with that explanation rather than report a change it didn't
make. The update sends the peer's other settings (name, SSH, login and
inactivity expiration) back unchanged, since NetBird's update replaces them.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Peer ids must
be plain identifiers before they reach a request path. Setup keys are
decoded field by field, so the key itself is never read.
