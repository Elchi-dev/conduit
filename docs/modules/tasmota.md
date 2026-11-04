# Tasmota

Tasmota plugs, relays and meters through the HTTP command API
(`/cm?cmnd=…`): status, relays on/off/toggle with undo, energy metering, a
few read-only queries and a restart. There's no free-form command action:
every command is built by the module from a fixed list.

**Setup.** Enter the device's address (`http://tasmota-plug.local`). If the
web admin password is set (`WebPassword`, Configuration → Other), store it
in the vault; the user is `admin`. The password is sent as HTTP basic
authentication, never as `user=`/`password=` URL parameters, so it can't
end up in a URL in an error or a log. Tasmota serves plain HTTP, so keep it
on a network you trust (or reach it through one of Conduit's networks).

`criticalRelays` lists relays (1–8) that power something that mustn't go
off by accident; `set_power` won't turn them off or toggle them, and
`power_off_critical` (destructive) does.

`lockedRelays` lists relays wired to a garage door opener, a gate, a door
strike or a valve. Any change to them (on, off or toggle) is refused by
`set_power`; `power_locked` (destructive) does it. A relay with a
**nonzero `PulseTime`** (it switches off by itself after a moment, the usual
setup of an opener) is treated as locked even when it isn't listed, and so
is every relay when `PulseTime` can't be read. `notLocked` lists relays
with a `PulseTime` that drive nothing that opens or unlocks; it doesn't
unlock a relay in `lockedRelays`.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Device name, firmware, hardware, uptime, last restart reason, boot count, hostname, IP and MAC, Wi-Fi (SSID, signal) and each relay's state (from `Status 0`). |
| `power` | read | Each relay with its friendly name, on/off, `critical` and `locked`. |
| `set_power` | write | `relay` (1) and `state`: `on`, `off` or `toggle`. A toggle is sent as the explicit on or off the preview showed. Critical relays only turn on here; locked relays don't change here at all (the module reads `PulseTime` first). Undo puts it back (through `power_off_critical` when that means turning a critical relay off). |
| `power_off_critical` | destructive | Turns off a relay in `criticalRelays`. Undo turns it on. Refused for a locked relay. |
| `power_locked` | destructive | `relay` and `state` (`on` or `off`): switches a locked relay. The preview names it and says it may open or unlock what it drives or shut off a supply. No undo (a pulsed relay goes back by itself). |
| `energy` | read | Power (W), apparent power, power factor, voltage, current, and energy today, yesterday and in total (kWh), from `Status 10`. |
| `command` | read | One query without arguments: `State`, `Status` and `Status 0`–`11` (not `Status 12`, the crash dump, which holds memory contents), `Power`/`Power1`–`8`, `Dimmer`, `CT`, `Color`, `HSBColor`, `Timers`, `Timezone`. Values under password-, key- or token-like names, and the OTA URL, are redacted. |
| `restart` | destructive | `Restart 1`. Relays follow their power-on state while the device boots. |

**Refused commands.** Anything outside the list above is never sent. The
`command` action names why for the dangerous ones: `Reset` (erases the
configuration), `Upgrade` and `OtaUrl` (firmware), `Backlog` (would chain
any of these), `WifiConfig` and `SSId` (can drop the device off Wi-Fi),
`Restart` (use `restart`), `Password`, `WebPassword` and `MqttPassword`,
`Module`, `Template` and `GPIO`, `Rule` and `Script`, `SetOption`/`SO…`,
`Sleep` and `DeepSleep`, `Webserver`, `Publish`, `Interlock` and
`PowerOnState`. Queries with arguments, separators (`;`) or control
characters are refused too.

**Security.** The client doesn't follow a redirect to another host or from
https to http. A device that asks for credentials answers with a warning
that's reported as a refused password. With a password on an `http://`
address, health is `degraded` ("password sent without encryption"): basic
authentication over http can be read by anyone on the network path.
