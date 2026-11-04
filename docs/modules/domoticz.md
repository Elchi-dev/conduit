# Domoticz

Devices with their status, scenes and groups of a Domoticz server; switching
devices on or off and activating scenes, through Domoticz's JSON API.

**Setup.** Enter Domoticz's address, such as `https://domoticz.local:8443`,
a Domoticz user (Setup, More options, Users) with access to the devices, and
store its password in the vault. List devices that power something important
or open something behind a plain switch in `criticalDevices` (by idx or
name). For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `devices` | read | Each device in use: idx, name, type, subtype, switch type, status, data, hardware, last update, and whether it's protected or critical. `filter` (`light`, `weather`, `temp`, `utility`) and `search` narrow it. |
| `device` | read | One device, and why it's critical. |
| `scenes` | read | Each scene and group: idx, name, type, status and last update. |
| `switch_device` | write | Turns an on/off switch or dimmer `On` or `Off`. Critical devices are refused. The answer reads the status back. Undo switches it back. |
| `switch_critical_device` | destructive | Turns a critical device `On` or `Off`, including door locks, sirens, blinds and push buttons. The preview says what it does: locks or unlocks, sounds or silences, opens or closes. Undo switches it back when its status was On or Off. |
| `activate_scene` | destructive | Activates a scene or switches a group on, which switches every device in it. The answer reads the status back. |

**Critical devices** are door locks, sirens, security panels, thermostats,
setpoints and heating; devices whose type, switch type or name contains
lock, door, gate, window, alarm, siren, security, camera, valve, heat,
HVAC, radiator, boiler, thermostat, garage, sprinkler, irrigation or smoke;
and what's listed in `criticalDevices`. A false match only means the
destructive action. A device without a switch type, sensors (contacts,
motion, smoke), selectors and media players aren't switched. Switching a
device to the status it has reports "nothing to change".

**Security.** The password goes only to Domoticz, in the `Authorization`
header, and the client won't follow a redirect to another host or from
https to http. Idx numbers are checked before any request, and the device
switched is always the one asked for.

**Notes.** Over plain http, Domoticz accepts Basic authentication only when
"Allow Basic-Auth authentication over plain HTTP" is on in its settings;
https is better. Devices and scenes protected by a passcode are switched in
Domoticz itself. Domoticz's OAuth2 sign-in isn't used: its access tokens
last an hour, and a user's password works everywhere.
