# OctoPrint

A 3D printer through OctoPrint: its state and temperatures, the current job
and its progress, the uploaded files, pausing, resuming and cancelling a
print, starting one from an uploaded file, and setting heater targets.

**Setup.** In OctoPrint, open Settings, Application Keys and create a key
for Conduit (or copy your user's key from User Settings, API Key); store it
in the vault. Enter OctoPrint's address, such as `http://octopi.local`
(with its path if it runs under one, like `http://pi.local/octoprint`). For a
self-signed certificate, set `fingerprint`. `maxHotend` (default 260 °C) and
`maxBed` (default 110 °C) are the highest targets `set_temperature` accepts;
set them to what your printer is built for.

| Action | Risk | Notes |
| --- | --- | --- |
| `printer` | read | Connected, state text, printing, paused, ready, error, and each heater's (`tool0` …, `bed`, `chamber`) temperature and target. |
| `job` | read | File, path, origin and size, progress, time printed and time left, estimated print time and filament length. |
| `files` | read | Every uploaded file, folders flattened (up to 1000): path, name, origin, size, upload date, estimated print time and filament. `origin` limits it to `local` or `sdcard`. Free space. |
| `pause_print` | destructive | Pauses the running print. The preview names the file and its progress. Undo resumes it. |
| `resume_print` | destructive | Resumes a paused print; the printer heats and moves again. Undo pauses it. |
| `cancel_print` | destructive | Cancels the running or paused print. The preview says it can't be finished afterwards. |
| `start_print` | destructive | Selects an uploaded G-code file (`path` from `files`, `origin` `local` or `sdcard`) and prints it. Refused while a print runs or the printer isn't ready. The preview names the file, its estimated time and the current temperatures, and reminds you to clear the bed. |
| `set_temperature` | destructive | Sets `tool0` … `tool9` or `bed` to `target` °C (0 turns it off). Targets above `maxHotend` or `maxBed` are refused. The preview shows the current temperature and target. Undo sets the previous target. |

Each action checks the printer first: pausing what's already paused, or
setting the target a heater already has, reports "nothing to change", and a
printer that isn't connected is reported rather than acted on.

**Security.** The key goes in the `X-Api-Key` header, and the client won't
follow a redirect to another host or from https to http. File paths are
checked (G-code extensions, no `..` or hidden parts) and escaped before they
reach a request path; heater names and targets are checked before any
request. Server text is redacted before it's shortened.

**Notes.** There's no action that sends G-code: only the fixed commands
above. Uploading files and chamber heaters aren't offered.
