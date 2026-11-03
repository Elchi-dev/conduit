# Home Assistant

Lights, switches, scenes and any other service in Home Assistant.

**Setup.** In Home Assistant, open your profile, Security, and create a
long-lived access token. Store it in the vault; set `url` to Home
Assistant's address (for example `http://homeassistant.local:8123`).

| Action | Risk | Notes |
| --- | --- | --- |
| `entities` | read | Filter by domain (`light`, `sensor`) or search |
| `state` | read | One entity with its attributes |
| `turn_on`, `turn_off`, `toggle` | write | Undo puts the previous on/off state back |
| `set_light` | write | Colour by name (red, green, amber, orange, yellow, blue, purple, white) or `#rrggbb`, brightness in percent. Undo restores colour, brightness and on/off. Used by the ambient status light. |
| `scene` | write | Activates `scene.*` |
| `call_service` | destructive | Any service (`lock.unlock`, `alarm_control_panel.disarm`…), so agents ask first |
