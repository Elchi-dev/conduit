# FRITZ!Box

An AVM FRITZ!Box through TR-064: device information, the internet
connection, the hosts on the network, the wireless networks, turning the
guest network on or off, and reconnecting to the internet.

**Setup.** On the FRITZ!Box, turn on Home Network, Network, Network
Settings, **Allow access for applications** (TR-064). Create a user under
System, FRITZ!Box Users with the **FRITZ!Box Settings** right, store its
password in the vault, and enter the user name and the password's
reference. The address is `http://fritz.box:49000` by default; for TLS use
`https://fritz.box:49443` with the box's certificate fingerprint in
**Fingerprint**.

| Action | Risk | Notes |
| --- | --- | --- |
| `device_info` | read | Model, FRITZ!OS version, hardware version, uptime |
| `wan_status` | read | Access type (DSL, cable, fibre), link, connection type, status, uptime, last error, line speeds, public IPv4 address |
| `hosts` | read, sensitive | Name, IP and MAC address, interface, speed and guest flag of each connected host; `all` adds the ones seen before |
| `wifi` | read | Each wireless network: SSID, on or off, status, channel, standard, security type, guest |
| `guest_wifi_on` | write | Preview shows the SSID and security, and warns when the guest network is open. Undo turns it off |
| `guest_wifi_off` | destructive | Disconnects everyone on the guest network. Undo turns it on |
| `reconnect` | destructive | Drops and redials the internet connection; the public address usually changes. Preview first |

**Guest network.** The FRITZ!Box keeps the guest network apart from the
home network, so turning it on brings back a network that's already set up:
a write, with its security shown in the preview. Turning it off disconnects
people, so it's destructive. When it's already in the asked state, the
answer is "nothing to change". The main wireless networks aren't switched
by this module.

**Keeping the connection.** `reconnect` is refused when Conduit reaches the
FRITZ!Box over the internet (a MyFRITZ! address, or the box's own public
address), since reconnecting would cut off this connection and usually
change the address.

**Secrets stay on the box.** The module never calls the actions that
return passwords: the wireless keys (`GetSecurityKeys`), the PPPoE login
(it reads the connection with `GetStatusInfo`, not `GetInfo`), VPN or user
settings. The serial number and device log aren't passed on either.
Requests use HTTP digest authentication; SOAP requests are built with
`encoding/xml`, so every value is escaped, and digest values from the box
are checked before they're used. The client won't follow a redirect to
another host.

## Notes

- FRITZ!OS marks the guest network in its extended wireless information;
  on versions without it, the last wireless network counts as the guest
  one, which is how FRITZ!OS numbers them.
