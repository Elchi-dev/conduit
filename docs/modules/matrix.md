# Matrix

A Matrix account through the client-server API: the rooms it has joined,
recent messages in the rooms you allow, sending and redacting messages there,
and member counts. Works with Synapse, Conduit/conduwuit, Dendrite and other
homeservers. The [notifications](notify.md) module can already send alerts
to a Matrix room; this module adds reading and redaction.

**Setup.** Use a bot account if you can. Get its access token (Element:
Settings, Help and About, Access token), store it in the vault and enter its
`secret://` reference. `homeserver` is the client-server API address
(`https://matrix.example.org`), which can differ from the server name in
user ids; it isn't discovered through `.well-known`. List the rooms Conduit
may use in `allowedRooms` by room id (`!abc:example.org`, in the room's
settings under Advanced); aliases aren't accepted. With no allowed rooms the
instance is healthy but degraded and can only list rooms. For a self-signed
certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `rooms` | read, sensitive | Joined rooms with their names (looked up for the first 50) and whether each is allowed. |
| `messages` | read, sensitive | Recent messages in an allowed `room` (`limit` default 20, at most 100), oldest first: sender, time, type, text; redacted messages are marked. End-to-end encrypted messages can't be read (Conduit holds no device keys) and are counted instead. |
| `send_message` | write | Sends `text` to an allowed `room`, as `m.notice` with `notice` (what bots should use) or `m.text`. The preview shows the text; undo redacts the message. |
| `redact` | destructive | Removes a message's content (`event`) for everyone in an allowed `room`, with an optional `reason`. The preview quotes the message. Can't be undone. |
| `members` | read | How many members have joined an allowed `room` (the count only). |

**Security.** The token is sent as a bearer token and the client won't follow
a redirect to another host. Room and event ids are checked and escaped
before a request is made, and rooms outside `allowedRooms` are refused
before anything is sent. `rooms` and `messages` are sensitive: their content
stays out of the audit log, approvals and events.

**Presets.** homelab, team.
