# Synology DSM

A Synology NAS through the DSM Web API: system information and load,
volumes, storage pools and disks, installed packages, Container Manager
containers, and restarting or shutting down the NAS.

**Setup.** Enter the NAS address with its DSM port (`https://nas.lan:5001`,
or `http://nas.lan:5000`), a DSM user name and the `secret://` reference of
its password. Reading storage and restarting need an administrator; a
dedicated account for Conduit is best. DSM uses a self-signed certificate
by default: copy its SHA-256 fingerprint
(`openssl s_client -connect nas.lan:5001 </dev/null | openssl x509 -noout -fingerprint -sha256`)
into **Fingerprint** so Conduit trusts exactly that certificate. Skipping
certificate checks is possible but not recommended.

**Two-step verification.** If the account has it on, store the account's
TOTP secret (the text behind the QR code shown when you set it up, or the
`otpauth://` link) in the vault and enter its reference as **Two-step
secret**. Conduit computes the code when it signs in and asks DSM for a
device token, so later sign-ins skip the code. Without the secret, sign-in
fails with a message saying so.

| Action | Risk | Notes |
| --- | --- | --- |
| `system` | read | Model, DSM version, uptime, temperature, memory |
| `utilization` | read | CPU percent and load averages, memory, network and disk throughput |
| `storage` | read | Volumes (used space, file system, status), storage pools, disks (status, SMART, temperature) |
| `packages` | read | Installed packages, running or stopped |
| `containers` | read | Container Manager (Docker) containers; a clear message when the package isn't installed |
| `reboot` | destructive | Preview names the model, address and uptime |
| `shutdown` | destructive | Preview first. The NAS stays off until powered on (or woken with Wake-on-LAN) |

Health is *degraded* when a volume, pool or disk isn't normal, a volume is
95% full or more, or DSM warns about the temperature.

**How it signs in.** The password goes in a POST body to
`/webapi/entry.cgi`, never in a URL; the session id is sent the same way.
An expired session signs in again once. Redirects to another host are
refused, so neither can leave the NAS. Closing the connection signs out.
The NAS can sit inside a WireGuard network (see
[networks](../architecture/networks.md)).
