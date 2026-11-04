# Cal.com

Event types, bookings and open slots in Cal.com (cal.com or a self-hosted
API v2), and cancelling or rescheduling bookings.

**Setup.** In Cal.com, open Settings, Developer, API keys, create a key and
store it in the vault. Leave the address as `https://api.cal.com` for
cal.com, or enter your self-hosted API v2 address, such as
`https://cal-api.example.com`. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `event_types` | read | Id, title, slug, length and whether it's hidden. |
| `bookings` | read, sensitive | Upcoming (or recurring, past, cancelled, unconfirmed) bookings: title, start and end, status, event type, hosts and attendees with name, email and time zone. Pages with `limit` and `skip`. |
| `availability` | read | Free slots of an event type between two dates (up to 31 days, a week from today by default) in a time zone. |
| `cancel_booking` | destructive | Cancels a booking with an optional reason; Cal.com tells the attendees. The preview shows the time and how many attendees it reaches. |
| `reschedule_booking` | destructive | Moves a booking to a new start; Cal.com tells the attendees. Says "nothing to change" when it starts then already; undo moves it back. |

**Notes.**

- Cal.com gives a rescheduled booking a new uid; the undo works on that one.
- A cancelled booking can't be brought back, so `cancel_booking` has no
  undo.
- Booking titles usually contain the attendees' names, so they appear only
  in `bookings`; previews and the change actions refer to the booking's uid.

**Security.** The key goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Uids, ids,
dates and time zones are checked before they reach a request. Meeting links
are never returned, and error text from Cal.com is scrubbed of emails.
