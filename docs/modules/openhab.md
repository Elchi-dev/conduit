# openHAB

Items with their state, things and their status, and rules of an openHAB
server; sending commands to items and running rules, through openHAB's REST
API.

**Setup.** In openHAB's main UI, open your profile, create an API token and
store it in the vault. Enter openHAB's address, such as
`http://openhab.local:8080`. Listing things and rules needs an admin's
token. List items that power something important or open something behind a
plain switch in `criticalItems` (by name or label). For a self-signed
certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `items` | read | Each item: name, label, type, state, category, tags, groups and whether it's critical. `type`, `tag` and `search` filter. |
| `item` | read | One item with its range, step and options, whether it can be commanded, and why it's critical. |
| `things` | read | Each thing: id, label, type, bridge, location and status with its detail and description. The things' configuration isn't read. |
| `rules` | read | Each rule: id, name, description, tags and status. The rules' scripts aren't read. `search` filters. |
| `send_command` | write | Sends a command checked against the item's type: `ON`/`OFF` for a switch; a percentage, `INCREASE` or `DECREASE` for a dimmer; hue,saturation,brightness for a colour; `UP`, `DOWN`, `STOP` or a position for a rollershutter; a number (with its unit) within the item's range; a text among the item's options. Critical items are refused. The answer reads the state back. Undo sends the previous state. |
| `send_critical_command` | destructive | Sends a command to a critical item. The preview says what it can do: open or unlock, start or stop, move a door or gate. Undo sends the previous state. |
| `run_rule` | destructive | Runs a rule's actions now, whatever its triggers and conditions. The preview names the rule; the answer reads its status back. |

**Critical items** are groups (a command reaches every member);
temperatures (`Number:Temperature`, such as a heating setpoint); items
whose tag, category, name or label contains lock, door, gate, window, alarm,
siren, security, camera, valve, heat, HVAC, radiator, boiler, thermostat,
garage, sprinkler, irrigation or smoke; every item inside a group like that
(the equipment of openHAB's semantic model, such as a switch in a
`GarageDoor` group); and what's listed in `criticalItems`. A false match
only means the destructive action. An item whose type openHAB doesn't give,
a read-only item, and contacts, dates, locations, images and calls aren't
commanded. A command that matches the current state reports "nothing to
change".

**Security.** The token goes only to openHAB, as the basic-auth user name
openHAB expects, and the client won't follow a redirect to another host or
from https to http. Item names and rule ids are checked and escaped before
any request.

**Notes.** openHAB applies commands asynchronously, so the state read back
can still show the old value for a moment.
