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
- Unknown and disabled hooks answer `404`. Each hook takes 10 calls a
  minute; more answer `429` with `Retry-After`.

## Outgoing: events to your URL

A webhook sends every event whose type starts with one of its filters (all
events if it has none) to a URL. Manage them in Settings, Webhooks, or with
`/api/v1/webhooks` (`admin:*:*`, and only signed-in people can add, change or
remove one, since a webhook sees everything it matches).

```http
POST /your/endpoint
Content-Type: application/json
X-Conduit-Event: action.ok
X-Conduit-Delivery: dlv_8f2k1c…
X-Conduit-Signature: t=1793700000,v1=5f1d…

{"id":"dlv_8f2k1c…","type":"action.ok","module":"docker","instance":"…","at":"2026-11-03T09:40:00Z","data":{…}}
```

**Verify every delivery.** Compute `HMAC-SHA256(secret, t + "." + body)` over
the raw body, hex-encode it, compare it with `v1` in constant time, and
reject a `t` more than five minutes from your clock. The secret (`whsec_…`)
is shown once when the webhook is created; `POST /webhooks/{id}/rotate`
replaces it.

```python
import hmac, hashlib, time

def verify(secret: str, header: str, body: bytes) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    if abs(time.time() - int(parts["t"])) > 300:
        return False
    want = hmac.new(secret.encode(), f"{parts['t']}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, parts["v1"])
```

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

export function verify(secret: string, header: string, body: Buffer): boolean {
  const p = Object.fromEntries(header.split(",").map((x) => x.split("=", 2)));
  if (Math.abs(Date.now() / 1000 - Number(p.t)) > 300) return false;
  const want = createHmac("sha256", secret).update(`${p.t}.`).update(body).digest("hex");
  return want.length === p.v1.length && timingSafeEqual(Buffer.from(want), Buffer.from(p.v1));
}
```

In Go, use `webhooks.Verify` from `internal/webhooks` as a reference.

**Delivery.** Answer with any 2xx within 10 seconds. Anything else is retried
after 2, 20 and 120 seconds with the same `X-Conduit-Delivery` id, so
deduplicate on it. Redirects aren't followed. After 25 failed deliveries in a
row the webhook switches off; switching it back on resets the count. The last
500 deliveries per webhook are kept (`GET /webhooks/{id}/deliveries`), and
`POST /webhooks/{id}/test` sends a `webhook.test` event at once.

**Events.** The same events the live stream carries (`GET /api/v1/events`).
Among them:

| Prefix | Events |
| --- | --- |
| `action.` | `ok`, `error`, `denied`, `planned`: every module call, with its audit entry |
| `approval.` | `requested`, `decided` |
| `panic.` | `on`, `off` |
| `automation.run.` | `ok`, `error`, `denied` |
| `instance.` | `saved`, `deleted` |
| module events | `mail.received`, `server.down`, `web.down`, `web.up`, `web.cert_expiring`, `files.backup_ok`, `files.backup_failed`, `games.started`, `games.stopped`, `vault.leak`, `status.changed`, `update.available` |

Secret values never appear in events.

The Notifications module's webhook channel is separate: it sends one
message per notification, signed with `X-Conduit-Signature: sha256=<hex>`; see
[notify](../modules/notify.md).
