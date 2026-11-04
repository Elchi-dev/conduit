# Headscale

Nodes, users, routes and pre-auth keys of a Headscale control server, and
expiring, renaming and approving or withdrawing routes of its nodes.
Works with Headscale 0.23 and later (routes are read from the nodes on
0.26 and later, from the routes API before).

**Setup.** On the server, create an API key with
`headscale apikeys create --expiration 90d` and store it in the vault.
Enter the server's address, such as `https://headscale.example.com`. For a
self-signed certificate, set `fingerprint`. The key has full control of the
server, so policies decide what agents may do with it.

| Action | Risk | Notes |
| --- | --- | --- |
| `nodes` | read | Id, name, hostname, user, addresses, online, last seen, created, key expiry (`never`, or a time and `expired`), tags, and advertised and approved routes. `user` filters by user name. |
| `users` | read | Id, name, display name, provider and node count. Emails and profile pictures are left out. |
| `routes` | read | One row per node and prefix: advertised, approved, serving, whether it's an exit route, and whether the node is online. |
| `preauth_keys` | read | Every user's pre-auth keys: id, user, reusable, ephemeral, used, expiry (and `expired`), tags. The key is never returned. |
| `rename_node` | write | Sets the node's name (its MagicDNS name): lowercase letters, digits and dashes. The preview shows the old and new name; undo renames it back. |
| `expire_node` | destructive | Logs the node out: it must authenticate again. The preview names the node and its user. No undo. |
| `enable_route` | destructive | Approves a route the node advertises, so it serves it to the tailnet. An exit route (`0.0.0.0/0` or `::/0`) is approved as the pair. Undo withdraws it. |
| `disable_route` | destructive | Withdraws an approved route; clients using it lose that network. Undo approves it again. |

Routes change who can reach which networks, so both route actions are
destructive, previewed, and reversible.

**Security.** The key goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Node ids must
be numbers, names DNS labels and routes canonical prefixes before anything
reaches the server. Node keys, machine keys and the pre-auth key a node
registered with are never decoded, nor are pre-auth key values.
