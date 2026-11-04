# Pushover

Notifications to your own phones and computers through Pushover, a check of
your user key and the application's monthly allowance.

**Setup.** On pushover.net, create an application (Your Applications,
Create an Application) and copy its API token; your user key is on your
dashboard. Store both in the vault and enter their `secret://` references.
Notifications go to the devices of that user key.

| Action | Risk | Notes |
| --- | --- | --- |
| `validate_user` | read | Whether the user key is valid and has an active device: your device names and licensed platforms. The key shows as its first four characters. Sends nothing. |
| `limits` | read | The application's monthly `limit`, `remaining` messages and when it `reset`s. |
| `send_notification` | write | Sends a `message` (up to 1024 characters) with an optional `title` (250), `priority` -2 to 1, one `device`, a `url` (http or https, 512) and `urlTitle` (100), a `sound`, `html` and a `ttl` in seconds. With a preview. |
| `send_emergency` | destructive | An emergency (priority 2) notification: it sounds again every `retry` seconds (at least 30) until it's acknowledged or `expire` seconds pass (at most 10800, 3 hours), past quiet hours. With a preview; returns the `receipt`. |

**Notes.** Sending reaches only the devices of your own user key, so it's
write; an emergency keeps alerting until someone acknowledges it, so it's a
separate destructive action. Pushover has no way to take a delivered
notification back, so neither has an undo, and cancelling an emergency by
its receipt isn't offered yet. Enter a user key, not a group key: a group
key would reach the group's members. Attachments, monospace text, custom
timestamps and acknowledgement callbacks aren't offered.

**Security.** The token and user key travel in the request body (and the
token in the query of the allowance check, as Pushover requires); the
client won't follow a redirect to another host or from https to http. The
user key never appears in full in output, and Pushover's error text is
redacted before it's shortened.

**Presets.** homelab, developer.
