# ESPHome

ESPHome devices through the REST API of their `web_server` component:
entities and their states, switches, lights and buttons. Buttons and
switches that restart, reset, shut down, enter safe mode or reflash a
device are kept apart behind a destructive action.

**Setup.** Add the web server to the device's YAML and flash it:

```yaml
web_server:
  port: 80
  auth:            # optional
    username: admin
    password: !secret web_password
```

Enter the device's address (`http://living-room.local`). With `auth`,
enter the username and store the password in the vault. ESPHome's web
server uses HTTP basic authentication over plain HTTP, so the password can
be read by anyone on the path: keep the device on a network you trust, or
reach it through one of Conduit's networks.

Entities are found by reading the device's `/events` stream for a few
seconds (the device sends every entity's state when a client connects);
`log` events on the stream are never read. To skip that, list them in
`entities` as `domain.object_id` (`sensor.temperature`, `switch.relay`).
The object id is the entity's name in lowercase with spaces as `_`.

`criticalEntities` lists switches and buttons that need `press_critical`
on top of the ones recognised by name, for example `switch.server_power`
or `button.open_gate`. By name, a button or switch is critical when a word
of its object id is `restart`, `reboot`, `reset`, `factory`,
`factory_reset`, `shutdown`, `safe_mode`, `firmware`, `ota`, `update` or
`flash`.

| Action | Risk | Notes |
| --- | --- | --- |
| `entities` | read | Every entity with domain, object id, name (when the device sends it), state and value; critical switches and buttons are marked. `domain` narrows. |
| `state` | read | One `entity` (`sensor.temperature`). |
| `set_switch` | write | `id` (`relay` or `switch.relay`) and `on`. Critical switches are refused. Undo puts it back. |
| `set_light` | write | `id`, `on` (default true), `brightness` (0–100 %), `color` (`#rrggbb`), `transition` (seconds). Undo restores on/off, brightness and colour. Lights in `criticalEntities` are refused. |
| `press_button` | write | Presses a button. Critical buttons are refused. No undo. |
| `press_critical` | destructive | Presses a critical button, or (with `domain: switch`) turns on a critical switch such as ESPHome's restart, factory-reset, shutdown or safe-mode switches. Refused for entities that aren't critical. |

Covers, locks, valves, fans, climate and numbers are read only: the module
has no action that changes them.

**Security.** Object ids are checked (lowercase letters, digits, `_`, `-`)
before they go into a request path, and the domain comes from the action,
never from input. The client doesn't follow a redirect to another host or
from https to http. Each request has a 10-second limit and the event stream
a few seconds and 500 entities.
