# Moonraker (Klipper)

A Klipper 3D printer through Moonraker, the API behind Mainsail and Fluidd:
the printer's status and heaters, any printer object's status, the job queue
and print history, pausing, resuming and cancelling a print, and setting
heater targets.

**Setup.** Enter Moonraker's address, such as `http://voron.local:7125`, or
the Mainsail or Fluidd address that proxies it. If Conduit's address isn't
in `trusted_clients` in `moonraker.conf`, copy the API key (Mainsail or
Fluidd settings, or `~/printer_data/.moonraker.key`) and store it in the
vault. For a self-signed certificate, set `fingerprint`. `maxHotend`
(default 260 °C) and `maxBed` (default 110 °C) are the highest targets
`set_temperature` accepts.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Klipper's state, the print's state (`standby`, `printing`, `paused`, `complete`, `cancelled`, `error`), file, message, progress, print and total time and filament, and each extruder's and the bed's temperature, target and power. `objects` adds up to 20 more printer objects, like `toolhead` or `temperature_sensor chamber`. |
| `objects` | read | The printer's object names and its heaters. |
| `job_queue` | read | The queue's state and the files waiting, with when they were added and how long they've waited. |
| `history` | read | Recent prints, newest first (`limit` 1–100, default 20): file, result, start and end, print and total time, filament and whether the file still exists. |
| `pause_print` | destructive | Pauses the running print. The preview names the file and its progress. Undo resumes it. |
| `resume_print` | destructive | Resumes a paused print; the printer heats and moves again. Undo pauses it. |
| `cancel_print` | destructive | Cancels the running or paused print. The preview says it can't be finished afterwards. |
| `set_temperature` | destructive | Sets `extruder`, `extruder1` … or `heater_bed` to `target` °C (0 turns it off). Targets above `maxHotend` or `maxBed` are refused. The preview shows the current temperature and target. Undo sets the previous target. |

Each action checks the printer first: pausing what's already paused, or
setting the target a heater already has, reports "nothing to change", and
when Klipper isn't ready its state (`shutdown`, `error`, `startup`) is
reported.

**Security.** The key goes in the `X-Api-Key` header, and the client won't
follow a redirect to another host or from https to http. Object and heater
names are checked before any request. The heater command is built from a
checked heater name and a number only. Object values are redacted and
shortened, and `configfile` (the whole configuration) isn't offered.

**Notes.** There's no action that sends G-code, and the emergency stop isn't
offered: it halts Klipper until a firmware restart and belongs to someone at
the printer. `cancel_print` stops a print safely, and Klipper's own heater
checks handle thermal faults. Starting prints and heater_generic heaters
aren't offered; the job queue and history need `[job_queue]` and `[history]`
in `moonraker.conf`.
