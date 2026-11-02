# Automations

Code: `internal/automation`. An automation is a trigger plus up to 20 steps.

## Triggers

| Kind | Fires |
| --- | --- |
| `schedule` | a five-field cron expression in a time zone |
| `event` | an event whose type starts with `event`, optionally only when dotted paths in the event equal given values |
| `webhook` | a POST to `/hooks/<token>` (see [webhooks](../api/webhooks.md)) |
| `manual` | only when run from the app or API |

## Steps

Each step is an engine call (`instance`, `action`, `input`) made as the actor
`automation:<id>`, so policy, approvals, audit and undo all apply. Strings in
the input may reference `{{trigger.<path>}}` and `{{steps.<n>.output.<path>}}`;
a string that is exactly one placeholder keeps the value's type. A failing step
stops the run unless it has `continueOnError`.

## Trust

- Saved or enabled by a **signed-in person**: Conduit adds policy rules for
  exactly this automation and exactly these actions, so it runs unattended.
  Editing replaces the rules; deleting removes them.
- Saved by an **agent or API key** (through the `automations` module or the
  API): stored disabled and untrusted. Only a person can enable it, which is
  when its steps become trusted. Until then any step that needs approval asks.
- The emergency stop freezes automations like any other non-human actor.

## Loop protection

Events produced by actions that an automation itself ran never trigger
automations, `automation.*` events are ignored, and each automation runs at
most once every 5 seconds.
