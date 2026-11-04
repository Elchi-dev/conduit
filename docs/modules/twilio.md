# Twilio

The balance, phone numbers, messages and calls of a Twilio account, and
sending an SMS.

**Setup.** In the Twilio Console, copy the account SID (`AC…`) and store the
auth token in the vault. Set `from` to one of your numbers (`+15551234567`)
or a messaging service SID (`MG…`) to send from it by default. To keep texts
to known people, list their numbers in `allowedRecipients`.

| Action | Risk | Notes |
| --- | --- | --- |
| `balance` | read | The account's balance and currency. |
| `numbers` | read | The account's phone numbers: number, name, status, and whether they handle voice, SMS and MMS. |
| `messages` | read, sensitive | Sent and received messages, newest first: from, to, text, status, segments, price and error code. Filters for `to`, `from` and a start date; `next` gives the following page. |
| `calls` | read, sensitive | Calls, newest first: from, to, direction, status, start, duration and price. Filters for `to`, `from` and status. |
| `send_sms` | destructive, sensitive | Texts one number. The preview shows the recipient, sender, text and about how many SMS parts it takes. |

**Notes.**

- A sent text reaches the person right away and can't be taken back, so
  `send_sms` has no undo.
- With `allowedRecipients` set, any other number is refused before anything
  is sent.
- Trial accounts can only text verified numbers.
- Without `allowedRecipients`, any number can be texted. Turn on only the
  countries you need in Twilio's SMS Geo Permissions to keep costs
  predictable.
- The part count follows the GSM-7 alphabet: one character outside it (a
  backtick, most accents, an emoji) sends the whole text as UCS-2, 70
  characters a part instead of 160, and `{}[]~^|\€` take two places.

**Security.** The SID and token go in the `Authorization` header, only to
`api.twilio.com`, and the client won't follow a redirect to another host.
Numbers and dates are checked before they reach a request. Webhook addresses
of your numbers aren't returned, and error text from Twilio is scrubbed of
phone numbers.
