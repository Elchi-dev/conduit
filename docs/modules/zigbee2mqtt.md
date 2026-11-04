# Zigbee2MQTT

Zigbee2MQTT through its MQTT broker: the bridge's info and devices (from
its retained `bridge/info` and `bridge/devices` topics), a device's state,
setting a device, and permitting new devices to join. Locks, covers,
thermostats, sirens and child locks are set only through a separate
destructive action. It uses the same connection code as the
[MQTT](mqtt.md) module: each call opens its own short connection with a
clean session.

**Setup.** Enter the broker Zigbee2MQTT uses (`mqtt://broker.local:1883`,
or `mqtts://` with a `fingerprint` for a self-signed certificate), a
username, and its password in the vault. `baseTopic` is Zigbee2MQTT's
`mqtt.base_topic` (`zigbee2mqtt`). Give the broker user access to
`<base>/#` only.

`criticalDevices` lists friendly names or IEEE addresses of devices whose
every change needs `set_critical`: a relay on a garage door, a water valve,
a heater's plug. Locks, covers and thermostats don't need listing: they're
recognised from what they expose.

| Action | Risk | Notes |
| --- | --- | --- |
| `bridge` | read | Version, commit, coordinator (type, IEEE, revision), channel, log level, whether joining is permitted (and until when), restart required, and online/offline. Zigbee2MQTT's configuration (network key, MQTT password) is never read out. |
| `devices` | read | Every device with name, IEEE address, type, model, vendor, description, power source, supported, interviewed, disabled, the properties it can set (`writable`) and `critical`. |
| `state` | read | A `device`'s last state and availability. When nothing is retained, the module asks the device for its readable properties (a `/get` request, which only reads) and waits up to `seconds` (3) for the answer. Sleeping battery devices answer only when they wake. |
| `set_device` | write | Publishes `payload` to `<base>/<device>/set`. Every key must be a property the device exposes as writable, and each value is checked against the device's own limits (numbers within their range, on/off values, enum values, colour objects). Refused when it touches a lock, cover or thermostat (`climate`), a siren or alarm (`warning`, `squawk`, `alarm`), a child lock, or a device in `criticalDevices`. Waits up to 3 s for Zigbee2MQTT to report the new state. Undo puts the previous values back when the device's state was known for every key. |
| `set_critical` | destructive | The same, for what `set_device` refuses: unlocking, opening a cover or garage, changing a thermostat's mode or setpoint, sounding or silencing an alarm. Undo goes through `set_critical` too. |
| `permit_join` | destructive | Lets new devices join for `seconds` (1–254), or closes joining with 0. While it's open, anything in radio range that's pairing can join the network. Waits for Zigbee2MQTT's response. Undo closes it. Health is `degraded` while joining is open. |

**Security.** Devices are looked up in Zigbee2MQTT's own device list before
anything is published, so only topics of real devices are written to.
Friendly names with `+`, `#`, control characters, a leading `$` or `/`, or
a `set`, `get`, `availability` or `bridge` level are refused. Payloads are
limited to 20 keys and 4 KB. The coordinator and disabled devices can't be
set. Messages over 1 MiB end a read before they're allocated.
