# Notifications

Sends alerts and approval requests to a phone, a chat or any webhook. Add one
instance per channel.

| Channel | You need |
| --- | --- |
| ntfy | A topic (hard to guess), optionally a server and access token. Install the ntfy app and subscribe to the topic. |
| Telegram | A bot token from @BotFather (vault) and your chat ID |
| Discord | A channel webhook URL (vault) |
| Slack | An incoming-webhook URL (vault) |
| Webhook | Any URL; optionally a signing key |
| Desktop | Nothing; the Conduit desktop app shows it |

## Approval requests on your phone

Tick **Send approval requests here** and set **Conduit address** to where
your devices reach Conduit (for example the hub relay address, or
`http://my-pc:7600` on your network). Every approval request and every
emergency stop is sent with a link straight to the approvals screen.

**Hide details** sends only "Something needs your attention" and the link.
Use it for servers you don't run: a public ntfy server sees every message it
relays.

### One-tap setup for the Android app

Settings, Remote access, **Phone notifications** (or
`POST /api/v1/notify/phone`) creates an ntfy channel with a random topic,
turns on approval forwarding and Hide details, sends a test message, and
shows a QR code and an `ntfy://` link that subscribe the phone's ntfy app
(F-Droid or Google Play). Notifications open Conduit through
`conduit://open/<page>` links, so tapping one lands on the approvals screen.
This needs no Google services and works while Conduit is closed. Use your own
ntfy server for full privacy.

## Signed webhooks

With a signing key, each request carries
`X-Conduit-Signature: sha256=<hex HMAC-SHA256 of the raw body>`. Verify it
before trusting the payload:

```python
expected = "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()
hmac.compare_digest(expected, request.headers["X-Conduit-Signature"])
```

## Actions

| Action | Risk |
| --- | --- |
| `send` | write: title, message, priority (low, normal, high, urgent), link |
| `test` | write: sends a test message |

Messages below the channel's minimum priority are skipped.
