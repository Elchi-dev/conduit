# Incus

Containers and virtual machines on an Incus server (or LXD, which speaks the
same API): their state, starting, stopping and restarting them, and
listing and taking snapshots.

**Setup.** Incus authenticates clients by TLS certificate. Make a client
certificate and key (for example with
`openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout conduit.key -out conduit.crt -days 3650 -subj /CN=conduit`)
and store both PEM blocks together in one vault secret. Then either add the
certificate on the server (`incus config trust add-certificate conduit.crt`),
or create a trust token with `incus config trust add conduit` and store it
in the vault as `trustToken`: Conduit uses it once to add its certificate.
The address is the server's `core.https_address`, such as
`https://incus.lan:8443`. Choose a `project` if it isn't `default`.

Incus uses a self-signed certificate. Copy its fingerprint (`incus info`
shows `certificate_fingerprint`) into `fingerprint`; Conduit then trusts
exactly that certificate.

| Action | Risk | Notes |
| --- | --- | --- |
| `instances` | read | Name, state, type (container or virtual-machine), cluster member, architecture, profiles, ephemeral, description, created and last used. `state` filters. |
| `start` | write | Undo stops it again. |
| `stop` | destructive | A clean shutdown; with `force`, an immediate stop that loses unsaved work. Undo starts it. |
| `restart` | destructive | Only a running instance; `force` as for stop. |
| `snapshots` | read | Newest first: name, when taken, expiry, size and whether it holds the running state. |
| `snapshot` | write | Takes a snapshot `name` of the instance's disks. Undo deletes it. |
| `delete_snapshot` | destructive | Deletes one snapshot; the instance itself is untouched. Here as the undo of `snapshot`. |

Each change shows the instance and its state in its preview, reports
nothing to change when the instance is already in that state, waits for
Incus to finish the operation and reads the result back.

**Security.** The certificate and key are read from the vault for each TLS
handshake and never leave it otherwise; the server is pinned by its
fingerprint, and the client won't follow a redirect to another host.
Instance and snapshot names must be plain names before they reach a request
path. Instances and snapshots are decoded field by field, so their
configuration (cloud-init user data, devices, keys) is never read into a
result, and neither are certificate fingerprints.

## Notes

- Console, exec, file access, creating, deleting or rebuilding instances
  and restoring snapshots aren't offered.
- Stateful (memory) snapshots aren't offered.
