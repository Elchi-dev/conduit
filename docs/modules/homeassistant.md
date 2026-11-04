# Home Assistant

Lights, switches, scenes and any other service in Home Assistant. Locks,
doors, garages, gates, alarms, cameras, valves and heating need approval:
agents turn them on or off with `turn_critical`, which says what it will do
before it does it.

**Setup.** In Home Assistant, open your profile, Security, and create a
long-lived access token. Store it in the vault; set `url` to Home
Assistant's address (for example `http://homeassistant.local:8123`). List
anything else that needs approval in `criticalEntities`, by entity id or a
pattern such as `switch.garage_*`: a plug feeding a server, or a gate
opener behind a plain relay.

| Action | Risk | Notes |
| --- | --- | --- |
| `entities` | read | Filter by domain (`light`, `sensor`) or search. Critical entities are marked. |
| `state` | read | One entity with its attributes, and why it's critical |
| `turn_on`, `turn_off`, `toggle` | write | Lights, switches, fans and other everyday entities. Undo puts the previous on/off state back. Critical entities are refused with a pointer to `turn_critical`. |
| `turn_critical` | destructive | `entity` and `action` (`on`, `off` or `toggle`). Opens or closes covers and valves, turns sirens, cameras, heating and critical switches on or off. The preview says exactly what changes, such as "closed → open; this opens the garage door". It reads the state back, and undo puts the previous state back where that's exact. `toggle` needs the current state to be known on or off. |
| `set_light` | write | Colour by name (red, green, amber, orange, yellow, blue, purple, white) or `#rrggbb`, brightness in percent. Undo restores colour, brightness and on/off. Used by the ambient status light. A light listed in `criticalEntities` is refused, as with `turn_off`. |
| `scene` | write | Activates `scene.*`. A scene that sets a critical entity is refused, and so is one that doesn't list its entities (scenes some integrations provide) or whose entities can't be read: activate those with `call_service` (`scene.turn_on`), which is destructive. |
| `call_service` | destructive | Any service (`lock.unlock`, `alarm_control_panel.alarm_disarm`…), so agents ask first. Locks and alarm panels, which have no on or off, use this. |

**Critical entities** are:

- by domain: `lock`, `cover`, `alarm_control_panel`, `valve`, `climate`,
  `water_heater`, `camera`, `siren`, `humidifier` and `script` (a script
  can call any service);
- by device class: `garage`, `garage_door`, `gate`, `door`, `window`,
  `lock`, `shutter`, `gas` and `water`, so a relay set up as a gate is
  critical whatever it's called (`outlet` and `switch` aren't);
- by name: an entity id or friendly name containing garage, gate, door,
  lock, window, alarm, siren, security, camera, valve, heat, thermostat,
  sprinkler or irrigation, in English or German (Tor, Hoftor, Garagentor,
  Tür, Schloss, Riegel, Öffner, Fenster, Heizung, Sirene, Ventil, Kamera,
  Rauchmelder, Bewässerung …; Motor and Monitor don't count). A false match
  only means asking first. Lights are judged by domain and
  `criticalEntities` alone, so a garage or outdoor light stays an everyday
  write;
- anything in `criticalEntities`;
- anything whose state can't be read, or is `unknown` or `unavailable`:
  what it controls can't be checked, so it's treated as critical.

**Undo.** `turn_critical` undoes to the previous state when turning back
restores it exactly: on/off, or open/closed for covers and valves. Heating
and water heaters turned off from a mode (heat, eco …) aren't undone, as
they may come back in another mode; turning them on from off is. A state
that couldn't be read gets no undo.
