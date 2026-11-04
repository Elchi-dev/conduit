# MQTT

Any MQTT broker (Mosquitto, EMQX, HiveMQ, VerneMQ, the Home Assistant
add-on, ...) over MQTT 3.1.1: read what arrives on a topic filter for a few
seconds, take a snapshot of the retained messages under a prefix, and
publish to the topics you allow. Every call opens its own short connection
with a clean session and a random client id, so nothing stays subscribed
and no session state is left on the broker.

**Setup.** Enter the broker as `mqtt://broker.local:1883`, or
`mqtts://broker.local:8883` for TLS (`tcp://`, `ssl://` and `tls://` work
too; WebSocket brokers don't). With a username, store its password in the
vault. A broker with its own certificate: enter its SHA-256 `fingerprint`.
Publishing is off until you list the topic filters it may use in
`publishTopics`, such as `zigbee2mqtt/+/set` or `conduit/#`; the retain flag
needs `allowRetain` too. Give the broker user only the topics you need: its
access rules apply on top of the module's.

| Action | Risk | Notes |
| --- | --- | --- |
| `subscribe_once` | read, sensitive | Subscribes to `filter` (`+` and `#` allowed), collects what arrives (retained messages first) for `seconds` (3, up to 30), then disconnects. Stops early at `maxMessages` (100, up to 1000) or `maxBytes` of payload (256 KiB, up to 1 MiB); `stoppedBy` says which. QoS 0 or 1. |
| `retained` | read, sensitive | The retained messages on `prefix` and below, one per topic, sorted. It waits until they stop arriving (up to `seconds`, 5); `complete` is false when a limit cut it short. Empty prefix: everything but `$SYS`. |
| `publish` | destructive | Publishes `payload` (`encoding` `text` or `base64`) to a `topic` matched by `publishTopics`, QoS 0–2 (1 by default). With `retain` (needs `allowRetain`), the preview shows the retained message it replaces and undo puts that one back (or clears the new one). |
| `clear_retained` | destructive | Removes the retained message on a topic in `publishTopics` (needs `allowRetain`). Undo publishes it again. |

Payloads that are valid UTF-8 come back as `payload`, others as
`payloadBase64`. Reads are marked sensitive: retained messages often hold
locations, device configuration or network keys (zigbee2mqtt's bridge
topics, for one), so they're kept out of the audit log.

**Topics.** Topics and filters are checked before anything is sent: UTF-8,
no NUL or other control characters, at most 1024 bytes; a topic to publish
to has no wildcards and doesn't start with `$`; in a filter `+` is a whole
level and `#` the whole last level. Filters and prefixes may start with `$`
only under `$SYS/`: `$share/…` and `$queue/…` would join a shared
subscription and take messages away from its real consumers. Publishing to a topic no
`publishTopics` filter matches is refused without connecting.

**Physical things.** A topic can open a garage door or unlock a lock
(`zigbee2mqtt/front_door/set`). That's why `publish` is destructive: agents
need approval for it unless you give them full autonomy. Keep topics that
move physical things out of `publishTopics` anyway.

**Security.** The password is sent only in the CONNECT packet; use `mqtts://`
when the broker isn't on the same machine or network. Connections go through
the instance's network, if it has one. The client fails the connection
before reading a packet larger than 1 MiB instead of allocating it; a
retained message over 1 MiB on the topic a retained `publish` or
`clear_retained` would replace is an error, so its undo is never built from
a message that wasn't read. MQTT
3.1.1 brokers drop publishes their access rules refuse without telling the
client, so a publish that succeeded here was accepted on the wire, not
necessarily delivered.
