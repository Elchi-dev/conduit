# OpenWrt

An OpenWrt router through ubus over HTTP: board and system information,
network interfaces, wireless radios and their networks, DHCP leases,
bringing a radio up or down, and restarting the router.

**Setup.** ubus over HTTP comes with LuCI (`uhttpd-mod-ubus` and `rpcd`).
Enter the router's address (`https://192.168.1.1`), a login and the
reference to its password in the vault. `root` works; a dedicated login is
better: add it to `/etc/config/rpcd` and give it an ACL in
`/usr/share/rpcd/acl.d/` that allows `system` (`board`, `info`, `reboot`),
`network.interface` (`dump`), `network.wireless` (`status`, `up`, `down`)
and `luci-rpc` (`getDHCPLeases`). OpenWrt uses a self-signed certificate:
copy its SHA-256 fingerprint into **Fingerprint**.

| Action | Risk | Notes |
| --- | --- | --- |
| `system` | read | Host name, model, board, release, target, kernel, uptime, load averages, memory |
| `interfaces` | read | Up or down, protocol, device, uptime, IPv4 and IPv6 addresses, DNS servers |
| `wireless` | read | Each radio (up, disabled, band, channel, width, country) and its networks: SSID, mode, encryption type, networks, hidden. Never the key |
| `leases` | read, sensitive | IPv4 and IPv6 leases with address, MAC, host name and expiry. From `luci-rpc`, or dnsmasq's lease file when LuCI's RPC isn't installed |
| `wifi_up` | write | Brings a radio and its networks up. Preview first. Undo brings it down |
| `wifi_down` | destructive | Disconnects every client on the radio. Preview names its SSIDs. Undo brings it up |
| `reboot` | destructive | Preview names the router. The network behind it is cut off for a minute or two |

**Radios.** `wifi_up` and `wifi_down` work like `wifi up radio0`: they
change the running state, not the configuration, so a restart brings the
configured state back. A radio that's already in the asked state answers
"nothing to change". `wifi_up` is a write: it only restores networks that
are already configured (their SSID and encryption are shown first), and a
radio disabled in the configuration is refused. `wifi_down` cuts people
off, so it's destructive.

**Keeping the connection.** `wifi_down` is refused when Conduit reaches the
router through that radio: when the address in the settings sits on an
interface carried directly by one of the radio's wireless networks (a
router on a wireless uplink, or a wireless-only network).

**Secrets stay on the router.** Wireless networks are decoded field by
field, so keys are never read into Conduit. The rpcd session lives in
memory, is renewed before it expires and never appears in output or
errors. The client won't follow a redirect to another host.

## Notes

- The connection check needs the router's address as an IP address in the
  settings; behind a bridge with wired ports (such as `br-lan`) it can't
  tell whether Conduit is wired, so it lets the action through.
- Leases need `luci-mod-rpc` (installed with LuCI), or read access to
  `/tmp/dhcp.leases` through the `file` object.
