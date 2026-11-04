# Tailscale

The devices of your tailnet: who's online, addresses, OS, tags and key
expiry; authorize, tag, expire or remove devices. Health warns 14 days
before a device key expires.

**Setup.** Preferred: an OAuth client (admin console, Settings, OAuth
clients) with the `devices:core` scope (read for viewing, write for
changes) and `dns:read` and `policy_file:read` if you want those. Enter the
client id and store the secret in the vault. Or use an API access token
(Settings, Keys); these expire after at most 90 days. Leave the tailnet as
`-` for the key's own tailnet.

| Action | Risk | Notes |
| --- | --- | --- |
| `devices` | read | Online state, last seen, OS, user, addresses, authorization, tags, key expiry (flagged when within 14 days) |
| `dns` | read | Nameservers, MagicDNS, search domains |
| `acl` | read | The access policy file |
| `authorize` | destructive | For tailnets that require device approval: it lets the device join (like NetBird's `approve_peer`) |
| `set_tags` | destructive | Replaces a device's tags (`tag:server`). Preview shows before and after; undo restores the old tags. |
| `expire_key` | destructive | The device has to log in again |
| `delete` | destructive | Removes the device from the tailnet |

**Security.** Tags decide what the access policy lets a device reach, so
`set_tags` is a real permission change and, like `authorize`, follows the
approval rules for destructive actions. An OAuth client with only the scopes you need is safer than an API
token, which acts with its creator's full rights and stops working when
that person leaves.
