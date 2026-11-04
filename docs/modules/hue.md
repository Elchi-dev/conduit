# Philips Hue

A Philips Hue bridge through its local CLIP v2 API: lights (on/off,
brightness, colour and colour temperature), rooms and zones, scenes,
sensors and batteries. Every change has a preview, and undo puts back each
light it touched as it was.

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
checks it against what you enter: `bridgeId` (the certificate's common name
must be that id, and Health checks the bridge reports the same id) and/or
`fingerprint`, its SHA-256 fingerprint:

```
openssl s_client -connect <bridge>:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

The fingerprint is the stronger check: anyone on your network can make a
certificate with your bridge id in it, but not one with the same
fingerprint. The bridge keeps its certificate across restarts; after a
factory reset, take the fingerprint again. One of the two is required.

| Action | Risk | Notes |
| --- | --- | --- |
| `lights` | read | Every light with id, name, room, type, product, on, brightness (%), xy colour or colour temperature (kelvin) and whether the bridge can reach it. `room` narrows to one room or zone. |
| `rooms` | read | Rooms and zones with their lights, how many are on, and the group's on and brightness. |
| `scenes` | read | Scenes with their room or zone, number of lights and whether they're active (`static`, `dynamic_palette`). `room` narrows. |
| `sensors` | read | Per sensor device: motion (and when it changed), temperature (°C), light level (lux), contact state, battery level and state. |
| `batteries` | read | Battery devices by charge, lowest first, with the bridge's `normal`/`low`/`critical`. |
| `set_light` | write | One `light` (id or exact name): `on`, `brightness` (0–100), and one of `color` (`#ff8800`), `xy`, `kelvin` (2000–6500) or `mirek`; `transitionMs`. Changing brightness or colour turns the light on unless `on` is false. Checked against what the light can do (dimmable, colour, its colour temperature range). Undo restores it. |
| `set_group` | write | A room or zone (`group`): `on` and/or `brightness` for all its lights through its grouped light. Undo restores each light. |
| `activate_scene` | write | Recalls a `scene` (id or name; `room` picks among scenes with the same name). The preview lists each light's before and after; undo restores every light of the scene. |
| `restore_lights` | write | Sets up to 100 lights to given states (`id`, `on`, `brightness`, `xy` or `mirek`) — what the other actions' undo sends. It has its own undo. |

Light commands are sent at most ten a second, as the bridge asks.

**Security.** The application key travels in the `hue-application-key`
header, which Go would forward on a redirect, so redirects to another host
(or from https to http) are refused. Lights, rooms and scenes are resolved
from the bridge's own lists; only their UUIDs go into request paths, never
what was typed. Names are matched exactly (ignoring case), and two items
with the same name must be picked by id.
