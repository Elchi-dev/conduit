# Files and backups

Watched folders with free space, and backup jobs with restic, rsync or your
own command.

**Folders** are `{name, path, minFreeGB}`. `folders` reports size, file count,
the latest change and free space on the drive (walks stop after five seconds
on huge folders and say so).

**Jobs** are one of:

- `restic`: `repo`, `password` (vault), `paths`. Runs `restic backup`.
  Cloud storage credentials go in `env` (for example
  `AWS_ACCESS_KEY_ID: secret://b2-key`).
- `rsync`: `paths` and `target`; runs `rsync -a --delete-after`.
- `command`: any program and arguments, run without a shell.

`env` values may be vault references. `maxAgeHours` marks a job overdue when
its last success is older.

| Action | Risk | Notes |
| --- | --- | --- |
| `folders` | read | |
| `jobs` | read | Last run, result, overdue, running |
| `run_job` | write | One run at a time per job, six-hour limit; output tail kept |
| `snapshots` | read | restic jobs |

| Event | When |
| --- | --- |
| `files.backup_ok` | a job finished |
| `files.backup_failed` | a job failed |

Health is degraded when a job failed, a job is overdue or a drive is below its
free-space warning. Schedule runs with an automation (for example every
night at 03:00, `run_job`).
