# Ambient status

Signature feature 9: Conduit's state outside the app. Everything is boiled
down to one of four states, recomputed every 15 seconds and on approval,
emergency-stop and up/down events:

| State | Colour | When |
| --- | --- | --- |
| `ok` | green | nothing needs you |
| `attention` | amber | approvals waiting, or a connection degraded |
| `down` | red | a connection is down |
| `stopped` | purple | the emergency stop is on |

On every change (not at start-up) it pushes to:

- **A smart light** through Home Assistant: set `light.instance` (the Home
  Assistant connection's ID) and `light.entity` (`light.desk`). Uses the
  `set_light` action, so the change is audited and can be undone.
- **A webhook**: `webhook` receives the state as JSON
  (`{state, color, summary, approvalsWaiting, down, since}`). It may be a vault
  reference when the URL carries a token. Works with Home Assistant
  automations, Node-RED, IFTTT-style services, LED controllers like WLED via
  a small bridge, or your own script.
- **Discord**: `discord` names a Discord connection; each change is posted.

Devices that poll instead (a Stream Deck key, a status bar, a Raspberry Pi
with an LED) read `GET /api/v1/ambient` with any key that has
`modules:*:read`. A Stream Deck plugin scaffold is in
`integrations/streamdeck`. The tray icon in the desktop app shows the same
signals.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | The current state |
| `push` | write | Sends the current state to every target now (useful to test). The light and Discord are changed as the caller, through their own actions, so the caller's rules on Home Assistant and Discord apply; the automatic pushes on a change are Conduit's own |

| Event | When |
| --- | --- |
| `status.changed` | the state changed |
