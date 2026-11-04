# Scaleway

Scaleway Instances in one zone: state, commercial type, addresses and tags,
power on, power off and reboot; Kubernetes Kapsule clusters and Object
Storage buckets in the zone's region.

**Setup.** In the Scaleway console, IAM, create an application with a
policy and generate an API key for it. *InstancesReadOnly* and
*KubernetesReadOnly* are enough to watch, *InstancesFullAccess* to power
servers, *ObjectStorageReadOnly* to list buckets. Store the **secret key**
in the vault and enter its `secret://` reference (a plain one is refused).
The **access key** (`SCW…`) isn't secret: enter it as it is, and only if
you want buckets listed. Set `projectId` to limit everything to one
project, and `zone` (default `fr-par-1`; e.g. `nl-ams-1`, `pl-waw-1`). Add
one instance per zone.

| Action | Risk | Notes |
| --- | --- | --- |
| `servers` | read | Instances in the zone: state, type, architecture, public and private addresses, tags |
| `clusters` | read | Kapsule clusters in the region: status, Kubernetes version, type, CNI and whether an upgrade is available. Never kubeconfigs, tokens or the API endpoint: there's no action that fetches them |
| `buckets` | read | Object Storage buckets in the region and when they were created. Needs the access key |
| `power_on` | write | Starts a stopped `server`. Undo powers it off again |
| `power_off` | destructive | Stops a running server and releases it from its hypervisor: its services go down until it's powered on, and an address that isn't a flexible IP may change. Undo powers it on |
| `reboot` | destructive | Reboots a running server |

Power actions have previews and are refused when the server isn't in a
state they apply to (`power_on` only from stopped, `reboot` only when
running). With `projectId` set, a server of another project is refused.
Health reports how many servers the zone has and how many aren't running.

**Security.** Server ids must be UUIDs; the zone, project id and access key
are checked when the settings are saved. The secret key travels in the
`X-Auth-Token` header, which Go would forward on any redirect, so the
client follows redirects only within the same host and never from https to
http; requests time out after 30 seconds. Bucket listing is signed with
SigV4 against `s3.<region>.scw.cloud`; the secret key itself never leaves
Conduit there.
