# Architecture decision records

One file per decision that is not obvious from the code. Copy the format of an
existing record: context, decision, consequences. Never edit an accepted
record's decision; supersede it with a new one.

| # | Decision | Status |
| --- | --- | --- |
| [0001](0001-go-backend-tauri-shell.md) | Go for daemon, hub and APIs; Tauri as a thin shell | accepted |
| [0002](0002-stdlib-http-router.md) | Standard library HTTP routing | accepted |
| [0003](0003-api-contract-and-sse.md) | Hand-written handlers checked against the spec; server-sent events | accepted |
| [0004](0004-frontend-libraries.md) | Small routing and styling layer for the web app | accepted |

Shorter records of these and every later choice, newest first, are in
[DECISIONS.md](../../DECISIONS.md).
