# Calendar

Your agenda from any CalDAV server or private ICS address.

| Mode | Works with | Can add events |
| --- | --- | --- |
| CalDAV | iCloud (`https://caldav.icloud.com`), Fastmail, Nextcloud, Radicale, Baikal, mailbox.org | yes |
| ICS | Google Calendar and Outlook "secret address in iCal format", any `.ics` feed | no |

Store the CalDAV password (an app password for iCloud) or the private ICS
address in the vault; the ICS address is a secret because anyone with it can
read your calendar.

## Actions

| Action | Risk | Notes |
| --- | --- | --- |
| `today`, `agenda` | read | Occurrences in your time zone, recurring events expanded |
| `calendars` | read | Calendars on the account |
| `create_event` | write | Times like `2026-11-05T14:00`, or a date for all day. Undo removes it. |
| `delete_event` | destructive | Only events inside your own calendars |

Google Calendar over CalDAV needs OAuth, which is planned; use the ICS address
to read it today.
