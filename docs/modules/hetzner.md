# Hetzner Cloud

Your Hetzner Cloud servers: status, type, addresses and location, power
them on and off, take and delete snapshots, and see firewalls.

**Setup.** In the Hetzner Cloud console, open the project, Security, API
tokens, and generate a token. *Read* is enough to watch; *Read & Write* is
needed to power servers and take snapshots. Tokens are per project, so add
one instance per project. Store the token in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `servers` | read | Status, type, IPv4/IPv6, datacenter |
| `images` | read | Snapshots and backups with size and source server |
| `firewalls` | read | Rules and what they apply to |
| `power_on` | write | Undo shuts the server down again (only if it was off). Preview shows the state change |
| `shutdown` | destructive | Asks the OS to shut down (ACPI). Undo powers it on (only if it was running). A server that is off is still billed. The server's services go down until it's powered on. |
| `reboot` | destructive | Restarts the OS. Preview available |
| `snapshot` | write | Snapshots are billed by size. Undo deletes the snapshot |
| `delete_image` | destructive | Snapshots and backups only, never system images |

Health reports how many servers exist and how many aren't running.

A Read & Write token can also delete servers through the API; Conduit has
no action for that, but treat the token as powerful and give agents only
the actions you want through the agent rules.
