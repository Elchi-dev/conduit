# Signal

Signal through a self-hosted
[signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api):
the accounts on the server, receiving messages for one number, sending to
the recipients you allow and listing groups.

**Setup.** Run signal-cli-rest-api and register a number or link it as a
secondary device (`/v1/qrcodelink`). Enter the API's `address`
(`http://signal-cli:8080`), the `number` in international format
(`+4915112345678`) and, in `allowedRecipients`, the numbers, account UUIDs or
group ids (`group.…`, from `groups`) Conduit may send to. The API has no
authentication of its own; if a reverse proxy guards it, enter a `username`
and `password` (basic auth) or a bearer `token`, both as `secret://`
references. For a self-signed certificate, enter its SHA-256 `fingerprint`.
Use the API's `normal` or `native` mode: in `json-rpc` mode messages only
arrive over its websocket, so `receive` doesn't work (health says so).

| Action | Risk | Notes |
| --- | --- | --- |
| `accounts` | read, sensitive | Numbers registered or linked on the server, marking this instance's. |
| `receive` | read, sensitive | Fetches new messages for the number and shows the recent ones (`limit` default 20, at most 200), oldest first: sender, name, text, group, attachment count, and messages you sent from another device. Receipts and typing notices are skipped; attachments and stories aren't downloaded; no read receipts are sent. |
| `send` | write | Sends `text` (up to 4000 characters) to 1 to 20 `recipients`, each of which must be in `allowedRecipients`. The preview lists the recipients. Can't be undone from here. |
| `groups` | read, sensitive | Groups the number is in, with id, name, member count and whether each is allowed. |

**Receiving consumes messages.** signal-cli-rest-api hands each message out
once: after `receive`, nothing else polling this number gets it. The module
keeps the last 200 received messages in memory so reading again still shows
them (`new` says how many arrived this time); they're gone when the daemon
restarts. Don't give Conduit a number another program reads.

**Security.** The client won't follow a redirect to another host, so
credentials only go to the configured API. Recipients outside the allow-list
are refused before anything is sent. `accounts`, `receive` and `groups` are
sensitive: their content stays out of the audit log, approvals and events.

**Presets.** homelab.
