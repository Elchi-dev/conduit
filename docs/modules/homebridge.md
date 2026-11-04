# Homebridge

Homebridge accessories with their characteristics, setting a characteristic,
and restarting the bridge, through the Homebridge UI.

**Setup.** Enter the Homebridge UI's address, such as
`http://homebridge.local:8581`, a UI user's name, and store its password in
the vault; Conduit signs in for a token and renews it. Listing and setting
accessories needs insecure mode (Homebridge Settings, Homebridge Insecure
Mode); restarting needs an admin user. List accessories that power
something important or open something behind a plain switch in
`criticalAccessories` (by id or name). For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `accessories` | read | Each accessory service: id, name, type, accessory, manufacturer, model, bridge, current values and whether it's critical. `type` and `search` filter. |
| `accessory` | read | One service with every characteristic: value, format, range, step, unit, valid values and whether it can be set, and why it's critical. |
| `set_characteristic` | write | Sets one characteristic (`On`, `Brightness`, `TargetTemperature` …), checked against its format, range and valid values. Critical accessories are refused. Undo sets the previous value. |
| `set_critical_characteristic` | destructive | Sets a characteristic of a critical accessory. The preview says what it does: unlocks or locks, opens or closes, arms or disarms, turns a camera on or off. Undo sets the previous value. |
| `restart_bridge` | destructive | Restarts Homebridge; its accessories don't respond in HomeKit until it's back. |

**Critical accessories** are locks, garage doors, doors, windows, security
systems, valves, faucets, irrigation, cameras and doorbells; any service
with a lock, door, alarm or camera characteristic; anything whose name
contains garage, gate, door, lock, valve, siren, alarm, security, camera,
sprinkler or irrigation; and what's listed in `criticalAccessories`. A false
match only means the destructive action. Setting a value a characteristic
already has reports "nothing to change".

**Security.** The password goes only to the sign-in, the token only to
Homebridge, and the client won't follow a redirect to another host or from
https to http. Accessory ids and characteristic types are checked and
escaped before any request, and values never reach Homebridge outside the
characteristic's range. Serial numbers and the bridge's pairing details
aren't returned.

**Notes.** A UI user with two-factor sign-in can't be used. Child bridges
restart with the main bridge.
