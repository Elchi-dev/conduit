# IONOS Cloud

IONOS Cloud data centers, servers (state, start, stop, reboot) and volumes,
through the Cloud API v6.

**Setup.** Create an API token in the Data Center Designer (Management,
Token Manager) or with `ionosctl token generate`, preferably for a user
with access to only the data centers Conduit should see. Store it in the
vault and enter its `secret://` reference; a plain token is refused.

| Action | Risk | Notes |
| --- | --- | --- |
| `datacenters` | read | Id, name, location and state |
| `servers` | read | Id, name, data center, type, VM state, cores, memory, availability zone, CPU family and state. Every data center, or one with `datacenter` |
| `volumes` | read | A data center's volumes: name, type, size, licence, availability zone, bus, boot server and state |
| `start_server` | write | Starts a stopped (`SHUTOFF`) server; its cores and memory are billed again. Undo stops it |
| `stop_server` | destructive | Shuts a server off and deallocates it; its services go down and a dynamic IP may change. Undo starts it |
| `reboot_server` | destructive | Hard-reboots a running server |

Power actions have previews, answer "nothing to change" when the server is
already in the asked state, and are refused when the state doesn't fit.
Health reports how many data centers the token can see, and is degraded
when one has failed.

**Security.** The token goes in the `Authorization` header; the client
never follows a redirect to another host or from https to http. Data
center and server ids must be UUIDs before they reach a request path.
Volume user data (cloud-init), SSH keys and image passwords are never read.

**Notes.** Cube servers are suspended rather than stopped in IONOS, so
`stop_server` refuses them.
