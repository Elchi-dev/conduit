# Philips Hue

A Philips Hue bridge through its local CLIP v2 API: lights (on/off,
brightness, colour and colour temperature), rooms and zones, scenes,
sensors and batteries. Every change has a preview, and undo puts back each
light it touched as it was. Lights listed in `criticalLights` are only
turned off through a destructive action.

**Setup.**

1. Find the bridge's address (the Hue app: Settings → My Hue system → the
   bridge → i) and its bridge id. The id is 16 hex digits; open
   `https://<bridge>/api/0/config` in a browser (accept the certificate
   warning) and take `bridgeid`, or read it on the bridge's label.
2. Press the round link button on top of the bridge, then within 30
   seconds create an application key:

   ```
   curl -k -X POST https://<bridge>/api \
     -d '{"devicetype":"conduit#home","generateclientkey":true}'
   ```

   The answer is `[{"success":{"username":"…","clientkey":"…"}}]`. The
   `username` is the application key (the `clientkey` is for the
   entertainment API and isn't needed). Before pressing the button the
   answer is `"link button not pressed"`.
3. Store the key in the vault and enter its `secret://` reference as
   `applicationKey`, the address as `url` (`https://192.168.1.20`) and the
   bridge id as `bridgeId`.

The bridge's certificate isn't signed by a public authority, so Conduit
checks it against what you enter, and one of these is required:

- `bridgeId` alone: the certificate's common name must be that id **and**
  the certificate must be signed by the Hue bridge root CA, which Conduit
  carries (Philips Hue `root-bridge`, for the square bridge since its 2020
  firmware, and Signify `Hue Root CA 01`, for the Bridge Pro). Health also
  checks the bridge reports the same id. The id alone proves nothing (the
  bridge announces it on the network, and anyone can make a self-signed
  certificate carrying it), which is why the signature is checked.
- `fingerprint`, the certificate's SHA-256 fingerprint, with or without
  `bridgeId`. A bridge whose certificate is self-signed (older firmware)
  needs this; Health says so when the root CA check fails.

  ```
  openssl s_client -connect <bridge>:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
  ```

  The bridge keeps its certificate across restarts; after a factory reset,
  take the fingerprint again.

`criticalLights` lists lights (ids or names, or their device's name) that
power something that mustn't go off by accident, typically a smart plug
feeding a fridge, a pump or a server. `set_light`, `set_group`,
`activate_scene` and `restore_lights` never turn them off;
`light_off_critical` (destructive) does.

| Action | Risk | Notes |
| --- | --- | --- |
| `lights` | read | Every light with id, name, room, type, product, on, brightness (%), xy colour or colour temperature (kelvin) and whether the bridge can reach it. `room` narrows to one room or zone. |
| `rooms` | read | Rooms and zones with their lights, how many are on, and the group's on and brightness. |
| `scenes` | read | Scenes with their room or zone, number of lights and whether they're active (`static`, `dynamic_palette`). `room` narrows. |
| `sensors` | read | Per sensor device: motion (and when it changed), temperature (°C), light level (lux), contact state, battery level and state. |
| `batteries` | read | Battery devices by charge, lowest first, with the bridge's `normal`/`low`/`critical`. |
| `set_light` | write | One `light` (id or exact name): `on`, `brightness` (0–100), and one of `color` (`#ff8800`), `xy`, `kelvin` (2000–6500) or `mirek`; `transitionMs`. Changing brightness or colour turns the light on unless `on` is false. Checked against what the light can do (dimmable, colour, its colour temperature range). `on: false` on a critical light is refused. Undo restores it (through `light_off_critical` when that turns a critical light off again). |
| `set_group` | write | A room or zone (`group`): `on` and/or `brightness` for all its lights through its grouped light. Turning off a room or zone that has a critical light sends each of its other lights its own change instead and leaves the critical ones on; the preview and the answer (`skippedCritical`) name them. Undo restores each light. |
| `activate_scene` | write | Recalls a `scene` (id or name; `room` picks among scenes with the same name). Refused when one of the scene's actions turns off a critical light. The preview lists each light's before and after; undo restores every light of the scene. |
| `restore_lights` | write | Sets up to 100 lights to given states (`id`, `on`, `brightness`, `xy` or `mirek`) — what the other actions' undo sends. Turning off a critical light is refused. It has its own undo. |
| `light_off_critical` | destructive | Turns off a critical `light`, or sets `lights` to given states as `restore_lights` does, including turning critical ones off (what undo sends when it has to). Refused when nothing critical is turned off. The preview names the critical lights. Undo puts them back on. |

Light commands are sent at most ten a second, as the bridge asks.

**Security.** The application key travels in the `hue-application-key`
header, which Go would forward on a redirect, so redirects to another host
(or from https to http) are refused. Lights, rooms and scenes are resolved
from the bridge's own lists; only their UUIDs go into request paths, never
what was typed. Names are matched exactly (ignoring case), and two items
with the same name must be picked by id.
