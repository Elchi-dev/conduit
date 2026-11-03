# Proxmox VE

Nodes, virtual machines and containers of a Proxmox cluster: power actions,
snapshots and storage.

**Setup.** In the Proxmox web interface, open Datacenter, Permissions, API
Tokens and add a token (for example `root@pam!conduit`, or better a token of
a dedicated user). Give it a role on `/`: `PVEAuditor` is enough for the
read actions; power actions need `VM.PowerMgmt` and snapshots
`VM.Snapshot`. Store the token secret in the vault.

Proxmox uses a self-signed certificate by default. Copy its fingerprint
from Datacenter, Certificates (or `pvenode cert info`) into `fingerprint`;
Conduit then trusts exactly that certificate. If the node has a certificate
from a public authority (ACME), leave the fingerprint empty.

| Action | Risk | Notes |
| --- | --- | --- |
| `nodes` | read | CPU and memory use, CPU count, uptime |
| `guests` | read | Every VM and container in the cluster with node, state, CPU and memory use, tags |
| `start` | write | Undo shuts it down again. Does nothing if it is already running. |
| `shutdown` | write | A clean shutdown through the guest's OS. Undo starts it again. |
| `reboot` | destructive | Only for a running guest |
| `stop` | destructive | Immediate power-off; unsaved work in the guest is lost |
| `snapshots` | read | Name, description and when it was taken |
| `snapshot` | write | `name` (letters, digits, `-`, `_`), optional `description`. Undo deletes it. |
| `delete_snapshot` | destructive | |
| `storage` | read | Used and free space per storage and node |

Guests are addressed by `vmid`; Conduit finds the node and whether it is a
VM or a container itself. Power and snapshot actions answer with the Proxmox
task id (`UPID`) and return before the task finishes. Every change has a
preview.

**Security.** The token secret stays in the vault. Prefer the fingerprint
pin over `insecureSkipVerify`: with checks off, anyone on the network path
can take the token. Give the token only the privileges you want agents to be
able to use.
