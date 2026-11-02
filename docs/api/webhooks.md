# Webhooks

## Incoming: start an automation

An automation with a **webhook** trigger gets a secret address:

```
POST https://<your daemon or hub relay>/hooks/<48-character token>
Content-Type: application/json

{"any": "payload"}
```

- The token is the credential; treat the address like a password. Only
  signed-in people can see it (API keys and agents get it blanked).
- The JSON body is available to steps as `{{trigger.body.<path>}}`.
- Answers `202` immediately; the run appears under the automation's runs.
- Unknown, disabled or rate-limited hooks all answer `404` (10 calls per
  minute per hook).

## Outgoing: signed notifications

The Notifications module's webhook channel signs each body with
`X-Conduit-Signature: sha256=<hex HMAC-SHA256>`; see
[notify](../modules/notify.md).
