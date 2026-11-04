# HomeWizard Energy

A HomeWizard Energy device on your network (P1 meter, Energy Socket, kWh
meter, water meter) through its local API: device info, live power and
meter readings, and switching an Energy Socket on or off.

**Setup.** In the HomeWizard Energy app, open Settings, Meters, the device,
and turn on Local API. Enter the device's address on your network, such as
`http://192.168.1.50` or `http://energysocket-1a2b3c.local`.

- **API v1** (no login): the `http://` address, nothing else.
- **API v2** (with a token): the `https://` address and a token stored in
  the vault. The device's certificate isn't from a public authority, so set
  `fingerprint` to its SHA-256 fingerprint.
- `critical`: the socket powers something that mustn't go off by accident —
  a server, a router, a fridge. Conduit then never switches it off.

| Action | Risk | Notes |
| --- | --- | --- |
| `device` | read | Product, type (`HWE-P1`, `HWE-SKT`, …), serial, firmware and API version; for a socket, whether it's critical. |
| `measurements` | read | Power (W, per phase), voltage, current, frequency, energy imported and exported (kWh, total and per tariff), the tariff, the 15-minute average and monthly peak where the meter has them, Wi-Fi signal, and gas or water from meters connected to a P1 meter. |
| `plug` | read | Whether the socket is on, its switch lock, the ring's brightness, and `critical`. |
| `plug_on` | write | Switches the socket on. Nothing is sent when it's already on. Undo switches it off again (through `plug_off`). |
| `plug_off` | destructive | Switches the socket off, cutting power to what's plugged in; the preview shows what it draws now. Refused for a critical socket. Nothing is sent when it's already off. Undo switches it back on. |

Both switching actions are refused when the socket's switch lock (set in the
app) is on, and for devices that aren't an Energy Socket. The new state is
read back from the socket, so a switch that didn't happen is reported.

Health reports the product, serial, firmware and power now, and reads a
measurement, so it checks the token as well.

**Security.** The address must be on your network (a private, loopback or
link-local IP address, a single-label name, or a `.local`, `.lan` or
`.home.arpa` name) and can't carry a user, query or fragment. Only fixed
paths are called. With API v2 the token goes in the `Authorization` header
over https, and the client won't follow a redirect to another host or from
https to http. Meter ids and the Wi-Fi name are left out of measurements.

**Notes.** Switching uses API v1, the only version with the socket's state;
on API v2 the switching actions explain this. A critical socket that
Conduit switched on has no undo, since switching it off is left to you.
