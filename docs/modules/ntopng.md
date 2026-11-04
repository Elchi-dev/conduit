# ntopng

Monitored interfaces and their traffic, the busiest hosts, and alerts from
an ntopng traffic monitor, through its REST API v2.

**Setup.** In ntopng, open your user menu, then API Token, create a token
and store it in the vault. Enter ntopng's address (`http://192.168.1.5:3000`,
or the path behind a reverse proxy, such as `https://example.com/ntopng`)
and the token's reference. The token acts with its user's rights; a user
limited to some networks or interfaces sees only those. For a self-signed
certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `interfaces` | read | Id, name, device, throughput, hosts (and local ones), devices, flows, bytes, packets, drops, engaged alerts and alerted flows |
| `top_hosts` | read, sensitive | The hosts with the most traffic on an interface: address, name, bytes sent and received, throughput, flows, score, local, country, OS, MAC. `limit` (10), `localOnly` |
| `alerts` | read, sensitive | Engaged or past (`engaged: false`) alerts of one `family` (host, flow, interface, network, system, MAC, SNMP device, active monitoring, user) from the last seven days, newest first: time, severity, type, score, entity and message |

`interface` picks an interface by its id from `interfaces`; without it, the
first one is used. Host lists and alerts name devices and their addresses,
so they're sensitive and stay out of the audit log.

**Security.** The token goes in the `Authorization` header. ntopng answers
a refused token by redirecting to its login page; the module stops there
and says the token was refused. The client won't follow a redirect to
another host. Alert messages are passed on redacted.

## Notes

- Needs ntopng 5 or later (REST API v2 and API tokens).
