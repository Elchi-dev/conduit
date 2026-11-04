# Xen Orchestra

Pools, hosts and VMs of XCP-ng and XenServer through Xen Orchestra's REST
API: power state, starting, cleanly shutting down and rebooting VMs, and VM
snapshots.

**Setup.** In Xen Orchestra, open your user's settings and create an
authentication token (or run `xo-cli create-token`); store it in the vault.
The token acts with its user's permissions. Enter Xen Orchestra's address,
such as `https://xo.lan`. For a self-signed certificate, set `fingerprint` (it needs an
`https` address; over plain `http` the token travels unencrypted, so keep
that to a trusted network).

| Action | Risk | Notes |
| --- | --- | --- |
| `pools` | read | Id, name, description, master host, high availability, platform version and tags. |
| `hosts` | read | Pool, power state, enabled, address, product and version, CPUs, memory and percent used, uptime and whether it needs a reboot. |
| `vms` | read | Pool, host, power state, CPUs, memory, main IP address, OS, tags and snapshot count. `state` (`Running`, `Halted`, `Paused`, `Suspended`) filters. |
| `start` | write | Starts a halted VM. Undo shuts it down again. |
| `shutdown` | destructive | A clean shutdown through the guest's OS (it needs the guest tools). The VM's services go down until it's started. Undo starts it. |
| `reboot` | destructive | A clean reboot of a running VM. |
| `snapshots` | read | Newest first: name, description, when it was taken and the VM it belongs to. `vm` filters. |

VMs are given by their id (a UUID, from `vms`). Each power action shows the
VM and its state before and after in its preview, reports nothing to change
when the VM is already in that state, and reads the state back after the
change (for up to 20 seconds; a slow guest is reported as still on its way;
a reboot is read back once).

**Security.** The token is sent as Xen Orchestra's `authenticationToken`
cookie, and the client won't follow a redirect to another host or from
https to http. VM ids must be UUIDs before they reach a request path. Lists
ask Xen Orchestra for named fields only, and single VMs are decoded field
by field, so a VM's configuration data (cloud-init, xenstore data, boot
arguments) is never read into a result.

## Notes

- Forced (hard) shutdown and reboot, pausing, suspending, migrating,
  deleting, the console and taking or reverting snapshots aren't offered.
