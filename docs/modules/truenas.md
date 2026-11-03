# TrueNAS

Pools, datasets, alerts and snapshots of a TrueNAS SCALE system, plus its
apps and virtual machines.

**Setup.** In TrueNAS, open the user menu (top right), API Keys, and add a
key. Store it in the vault and enter its `secret://` reference with the
system's address (`https://truenas.lan`). TrueNAS uses a self-signed
certificate by default: copy its SHA-256 fingerprint (System, Certificates,
or `openssl s_client -connect truenas.lan:443 </dev/null | openssl x509 -noout -fingerprint -sha256`)
into **Fingerprint**, so Conduit trusts exactly that certificate. Skipping
certificate checks is possible but not recommended.

| Action | Risk | Notes |
| --- | --- | --- |
| `system` | read | Version, hostname, uptime, memory, cores |
| `pools` | read | Status, health, size, used and free space, last scan |
| `datasets` | read | Used and available space of each dataset |
| `alerts` | read | Alerts that haven't been dismissed |
| `snapshots` | read | Snapshots of one dataset |
| `snapshot` | write | Takes `<dataset>@<name>`. Preview first; undo deletes it. |
| `delete_snapshot` | destructive | Preview first |
| `scrub` | write | Starts a scrub of a pool: hours of heavy disk activity. Preview first. |
| `apps` | read | Installed apps and their state |
| `vms` | read | Virtual machines, state, memory and vCPUs |

Health is degraded while there are serious (error or critical) alerts.

**Security.** A TrueNAS API key acts with the full rights of the user who
created it. Create a dedicated, non-administrator user with only the roles
Conduit needs (on 24.10 and later, a read-only role is enough for viewing),
create the key as that user, and keep it in the vault.
