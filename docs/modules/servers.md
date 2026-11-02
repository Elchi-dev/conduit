# Server (SSH)

A Linux machine reached over SSH: health, systemd services, journal logs,
files and commands. Add one instance per server.

## Settings

| Setting | Meaning |
| --- | --- |
| Host, Port, User | Where to connect (port 22 and `root` by default) |
| Private key | Vault reference to a PEM private key (recommended) |
| Password | Vault reference, if you don't use a key |
| Host key fingerprint | `SHA256:…`; see below |
| Use sudo for services | Prefix service changes and journal reads with `sudo -n` |

### Host key pinning

Conduit never trusts a server silently. Leave the fingerprint empty and save:
the server's lamp turns amber and shows its fingerprint. Compare it with the
output of `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server,
then paste it into settings. If the key ever changes, Conduit refuses to
connect and says so.

## Actions

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Uptime, load, CPUs, memory, disks |
| `services` | read | All systemd services, or only failed ones |
| `service_status` | read | `systemctl status` output |
| `logs` | read | Journal lines for a service or the whole system, with `since` |
| `files` | read | Directory listing |
| `read_file` | read | First 512 KiB of a file |
| `service_start` | write | Undo stops it |
| `service_stop` | destructive | Undo starts it |
| `service_restart` | destructive | Dry run shows the current state |
| `run` | destructive | Any shell command |

Service names are validated and every argument is shell-quoted, so input
can't inject extra commands. Health reflects `systemctl is-system-running`:
green when running, amber when degraded (some service failed).
