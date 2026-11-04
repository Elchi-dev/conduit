# Scrutiny

Disk health from a [Scrutiny](https://github.com/AnalogJ/scrutiny) server:
every drive with its SMART and Scrutiny status, the attributes that are
failing or close to it, one drive's latest SMART results, and temperature
history. It is read-only.

**Setup.** Enter Scrutiny's web address, such as `http://nas.local:8080`
(with its base path if you set one; a trailing `/web` is dropped). Scrutiny
has no login of its own; if a reverse proxy in front of it asks for one
(basic auth), enter the username and store the password in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `devices` | read | Every drive: WWN, device name, host, label, model, serial, capacity, protocol, firmware, rpm, status (`passed`, `failed (SMART)`, `failed (Scrutiny)` or both), temperature, power-on hours and when it was last checked. Archived drives only with `includeArchived`. |
| `failures` | read | For each drive that isn't archived (or one `device`), the attributes from its latest SMART run that failed SMART's or Scrutiny's thresholds, and with `includeWarnings` (the default) those Scrutiny warns about: name, value, worst, threshold, raw value, reason and the observed failure rate. Drives with nothing wrong are left out. Up to 50 drives are checked. |
| `device` | read | One drive (WWN, `sda` or `/dev/sda`, serial or label) with its latest SMART results: every attribute (up to 200), power cycles and the SMART status. |
| `temperatures` | read | Each drive's minimum, maximum, average and latest temperature over a `week` (default), `month`, `year` or `forever`, with up to `maxPoints` (default 100, at most 1,000; 0 for only the summary) readings spread evenly over the window. |

Health is `degraded` while a drive that isn't archived or muted is failing.

**Security.** Drives are looked up in Scrutiny's own list before a WWN is
put in a URL path, and the WWN must be letters, digits, `.`, `_`, `:` and
`-`. The client won't follow a redirect to another host or from https to
http.
