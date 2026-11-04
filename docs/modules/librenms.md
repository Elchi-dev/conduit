# LibreNMS

Devices, ports and alerts from a LibreNMS network monitor, and
acknowledging or unmuting an alert.

**Setup.** In LibreNMS, open Settings, API, API Settings, create an API
access token and store it in the vault. Enter LibreNMS's address
(`https://librenms.example.com`) and the token's reference. The token acts
with its user's rights: acknowledging alerts needs a user allowed to.
For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `devices` | read | Id, name, host name, system name, OS and version, hardware, type, location, up or down (with the reason), uptime, last polled, disabled, ignored. `down` filters |
| `ports` | read | One `device` (id or host name) or all: name, alias, admin and operational status, speed, traffic rates, errors. Deleted ports are left out; `down` keeps ports that are up by admin but down |
| `alerts` | read | `state`: alerting (default), acknowledged or all. Id, rule name, device, severity, state, since when |
| `ack_alert` | destructive | Stops the alert's notifications. Optional `note`; `untilClear` (default true) notifies again if it clears and comes back. Undo unmutes it |
| `unmute_alert` | write | Puts an acknowledged alert back to alerting. Undo acknowledges it |

**Acknowledging.** An acknowledged alert stops notifying anyone, so
acknowledging is destructive and needs approval under the usual policies.
The preview names the rule, device and severity. Unmuting only turns
notifications back on, so it's a write. An alert already in the asked state
answers "nothing to change"; an alert that has cleared can't be
acknowledged.

**Secrets stay in LibreNMS.** Devices are decoded field by field, so SNMP
communities and SNMPv3 passwords, which LibreNMS returns with each device,
never pass through Conduit. The token goes in the `X-Auth-Token` header and
the client won't follow a redirect to another host. Device names are
checked before they reach a request path.
