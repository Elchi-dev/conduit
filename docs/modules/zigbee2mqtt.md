# Zigbee2MQTT

Zigbee2MQTT through its MQTT broker: the bridge's info and devices (from
its retained `bridge/info` and `bridge/devices` topics), a device's state,
setting a device, and permitting new devices to join. `set_device` (write)
is default-deny: it sets lights, fans and plain switches and plugs, and
nothing else; locks, covers, thermostats, valves, sirens, keypads, garage
triggers, PIN codes and everything else go through the destructive
`set_critical`. It uses the same connection code as the
[MQTT](mqtt.md) module: each call opens its own short connection with a
clean session.

**Setup.** Enter the broker Zigbee2MQTT uses (`mqtt://broker.local:1883`,
or `mqtts://` with a `fingerprint` for a self-signed certificate), a
username, and its password in the vault. `baseTopic` is Zigbee2MQTT's
`mqtt.base_topic` (`zigbee2mqtt`). Give the broker user access to
`<base>/#` only.

`criticalDevices` lists friendly names or IEEE addresses of devices whose
every change needs `set_critical`: a relay on a garage door, a door strike,
a water valve, a heater's plug. Locks, covers, thermostats, valves, sirens,
keypads and garage openers don't need listing: they're recognised from what
they expose, and a switch whose device's description, model or friendly
name starts a word with valve, garage, gate, door, lock, opener, strike,
latch, barrier, irrigation, sprinkler, shutoff, water, gas, siren, alarm,
heater or boiler counts as critical too ("Outdoor plug" doesn't). German
names count as well, also inside compounds: Tür, Tor, Hoftor, Schloss, Riegel,
Öffner, Fenster, Heizung, Sirene, Ventil, Kamera, Rauchmelder, Bewässerung,
Wasser, Schranke … (but not Motor or Monitor).

**What `set_device` sets.** Only properties under a `light`, `switch` or
`fan` expose, plus `brightness`, `color`, `color_temp`, `color_xy`,
`color_hs` and `effect` at the top level of a device with a light expose.
Nothing at all on a critical device: one in `criticalDevices`, one with a
writable property under a `lock`, `cover`, `climate` or `valve` expose, one
with a writable property whose name has one of the words `lock`, `unlock`,
`relock`, `auto_relock`, `child_lock`, `pin_code`, `user_code`, `code`,
`trigger`, `garage`, `gate`, `door`, `valve`, `silence`, `mute`,
`self_test`, `test`, `arm`, `arm_mode`, `disarm`, `alarm`, `siren`,
`warning`, `squawk` or `system_mode` (between underscores or digits, e.g.
`valve_state_l2`), or a switch named as above. When two exposes list the
same property, it's critical if either is. Everything else
(`power_on_behavior`, a keypad's `arm_mode`, a lock's `pin_code`, a smoke
alarm's `silence`, a garage opener's `trigger`) needs `set_critical`.

| Action | Risk | Notes |
| --- | --- | --- |
| `bridge` | read | Version, commit, coordinator (type, IEEE, revision), channel, log level, whether joining is permitted (and until when), restart required, and online/offline. Zigbee2MQTT's configuration (network key, MQTT password) is never read out. |
| `devices` | read | Every device with name, IEEE address, type, model, vendor, description, power source, supported, interviewed, disabled, the properties it can set (`writable`) and `critical` (only `set_critical` changes it). |
| `state` | read | A `device`'s last state and availability. When nothing is retained, the module asks the device for its readable properties (a `/get` request, which only reads) and waits up to `seconds` (3) for the answer. Sleeping battery devices answer only when they wake. |
| `set_device` | write | Publishes `payload` to `<base>/<device>/set`. Every key must be a property the device exposes as writable, that `set_device` sets (above), on a device that isn't critical; each value is checked against the device's own limits (numbers within their range, on/off values, enum values, colour objects). Waits up to 3 s for Zigbee2MQTT to report the new state. Undo puts the previous values back when the device's state was known for every key. |
| `set_critical` | destructive | The same, for anything `set_device` refuses: unlocking, adding a PIN code, turning off auto-relock, opening a cover or garage, closing a valve, arming or disarming a keypad, changing a thermostat's mode or setpoint, sounding or silencing an alarm, any other property. Undo goes through `set_critical` too. |
| `permit_join` | destructive | Lets new devices join for `seconds` (1–254), or closes joining with 0. While it's open, anything in radio range that's pairing can join the network. Waits for Zigbee2MQTT's response. Undo closes it. Health is `degraded` while joining is open. |

**Security.** Devices are looked up in Zigbee2MQTT's own device list before
anything is published, so only topics of real devices are written to.
Friendly names with `+`, `#`, control characters, a leading `$` or `/`, or
a `set`, `get`, `availability` or `bridge` level are refused. Payloads are
limited to 20 keys and 4 KB. The coordinator and disabled devices can't be
set. Messages over 1 MiB end a read before they're allocated, except the
retained `bridge/devices` list, which can be several MiB on a large network
and is read on a connection of its own with a 16 MiB limit.
