# ioBroker

States of an ioBroker installation found by id pattern, with their values
and definitions, and setting writable states, through the simple-api
adapter.

**Setup.** Install the simple-api adapter in ioBroker and enter its address,
such as `http://iobroker.local:8087`. When the adapter has authentication
on (recommended), enter an ioBroker user and store its password in the
vault. List states that power something important or open something behind
a plain switch in `criticalStates`, by id or by the id of a device or
channel (everything below it counts). For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `states` | read | States whose id matches `pattern` (`*` for any part, such as `hue.0.*` or `zigbee.0.*.state`): value, acknowledged, last change, name, role, type, unit, whether it can be set and whether it's critical. Up to 500. |
| `state` | read | One state with its type, role, unit, range, step, allowed values, whether it can be set, and why it's critical. |
| `set_state` | write | Sets a writable state as a command (not acknowledged), checked against its type (`boolean`, `number`, `string`), range and allowed values. Critical states are refused. The answer reads the value back. Undo sets the previous value. |
| `set_critical_state` | destructive | Sets a writable state of a critical device. The preview says what it can do: turn on or off, open or unlock, change a position, mode or temperature. Undo sets the previous value. |

**Critical states** are those whose role, name or id, or the name or role of
a device or channel above them, contains lock, door, gate, window, alarm,
siren, security, camera, valve, heat, HVAC, radiator, boiler, thermostat,
temperature, boost, garage, sprinkler, irrigation or smoke (or the same in
German: Tür, Tor, Schloss, Fenster, Heizung, Ventil …), whose role opens
something (`button.open`), whose allowed values name such a thing
(`unlatch`), whose unit is °C or °F, that turn a script on or off
(`javascript.N.scriptEnabled.*`), and what's listed in `criticalStates`. An
alias (`alias.N.*`) is judged by the state it points at too, and one that
points at a `system.*` or `admin.*` state, or at nothing, is never set. A
false match only means the destructive action. When a device or channel
above a state, or an alias's target, can't be read, the state isn't set. Only
states with `common.write` set are written; `system.*` and `admin.*` states
never are, nor states without a type or of type `json`, `array`, `object`,
`file` or `mixed`. Setting a value a state already has reports "nothing to
change", except for a button (role `button*`), which is pressed again and
has no undo.

**Security.** The password goes only to ioBroker, in the `Authorization`
header (never as `user` and `pass` in the address, which servers log), and
the client won't follow a redirect to another host or from https to http.
State ids and patterns are checked and escaped before any request.
Objects' `native` settings, which can hold device passwords, aren't
returned.

**Notes.** States whose id has characters other than letters, digits, `_`,
`-` and dots are left out. The
separate REST API adapter isn't used: simple-api's routes are the ones its
documentation describes in full.
