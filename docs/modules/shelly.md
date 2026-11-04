# Shelly

Shelly Gen2 and Gen3 devices (Plus, Pro, Mini and Gen3 relays, plugs, PM
and EM meters, shutter controllers) through their local RPC API (`/rpc`):
device info, switches with power metering, covers, the firmware check and
a reboot. Gen1 devices speak a different API and aren't supported.

**Setup.** Enter the device's address, such as `http://shelly-plug.local`.
If authentication is on (Settings → Authentication in the device's web
page), store its password in the vault; the user is always `admin` and the
login is HTTP digest (SHA-256), so the password isn't sent in the clear even
over http.

- `criticalSwitches`: switch ids (0 for the first) whose output powers
  something that mustn't go off by accident — a server, a router, a fridge,
  a pump. `set_switch` refuses to turn them off; `switch_off_critical`
  (destructive) does it.
- `garageCovers`: cover ids that drive a garage door or gate instead of
  blinds. Conduit never opens, closes or moves them.
- `lockedSwitches`: switch ids wired to a garage door opener, a gate, a door
  strike or a valve. Any change to them, on or off, is refused by
  `set_switch`; `switch_locked` (destructive) does it. A switch with
  **auto-off and a momentary or detached input** (the usual pulse wiring of
  an opener) is treated as locked even when it isn't listed, and so is every
  switch when the device's configuration can't be read.
- `notLocked`: switch ids that look locked (auto-off with a momentary or
  detached input) but drive nothing that opens or unlocks; `set_switch` may
  change them. It doesn't unlock a switch in `lockedSwitches`.

| Action | Risk | Notes |
| --- | --- | --- |
| `device` | read | Name, id, model, generation, app, firmware, MAC, whether authentication is on, uptime, a pending restart, the updates the device knows of, and Wi-Fi (SSID, signal). |
| `switches` | read | Each switch with its name, on/off, power (W), voltage, current, energy (kWh), temperature, `critical` and `locked`. |
| `set_switch` | write | `id` and `on`. Turning off a critical switch is refused, and so is any change to a locked one. Nothing is sent when it's already in that state. Undo puts it back (undoing turning a critical switch on goes through `switch_off_critical`). |
| `switch_off_critical` | destructive | Turns off a switch in `criticalSwitches`; the preview shows what it draws now. Undo turns it on. Refused for a locked switch. |
| `switch_locked` | destructive | `id` and `on`: switches a locked switch. The preview names it and says it may open or unlock what it drives or shut off a supply. No undo (a pulsed relay goes back by itself). |
| `power` | read | Every metering channel (switches, covers, PM1, EM and EM1 meters) with power, voltage, current and energy, and the total power. |
| `covers` | read | Each cover with state (`open`, `closed`, `opening`, `stopped`, …), position (0 closed – 100 open, when calibrated), power, and `garage`. |
| `cover` | write | `id` and `action`: `open`, `close`, `stop` or `position` (with `position`, calibrated covers only). Garage covers are refused. Undo moves it back to its old position (or opens/closes it again when it isn't calibrated); `stop` has no undo. |
| `check_update` | read | The firmware running and the stable and beta versions available (`Shelly.CheckForUpdate`). Nothing is installed: there's no update action. |
| `reboot` | destructive | Restarts the device after a second; outputs may switch while it boots (they follow their power-on setting). |

Health reports the model, firmware and number of switches and covers, and
checks the password (device info answers without one). With a password on
an `http://` address it's `degraded` ("password sent without encryption"):
digest login keeps the password itself off the wire, but the session can be
watched and replayed on the network; use https or keep the device on a
network you trust.

**Security.** Only fixed RPC method names are sent, with ids checked as
numbers from 0 to 99 and checked against the device's own components
before anything changes. The client doesn't follow a redirect to another
host or from https to http. Errors from the device are passed on redacted.
