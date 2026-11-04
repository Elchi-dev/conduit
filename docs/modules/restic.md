# restic

A restic repository, through the `restic` program installed on the computer
the daemon runs on: snapshots, repository size, integrity checks, and
forgetting and pruning old snapshots after a preview of what would go. One
instance is one repository. (restic's rest-server only stores data and has
no API of its own, so the module drives restic itself; for the backup jobs
that run restic on a schedule, see [files](files.md).)

**Setup.** Install restic (0.16 or later), store the repository's password
in the vault, and enter the repository as `restic -r` takes it:
`/srv/backup`, `sftp:user@host:/srv/restic`, `s3:s3.amazonaws.com/bucket`,
`b2:bucket:path`, `rest:https://host:8000/`. Backend credentials go in
`env` (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `B2_ACCOUNT_ID`,
`B2_ACCOUNT_KEY`, `AZURE_ACCOUNT_KEY`, `RESTIC_REST_USERNAME`,
`RESTIC_REST_PASSWORD`, `GOOGLE_*`, `OS_*`, `ST_*`, `RCLONE_*`); a setting
whose name says it's a credential (KEY, SECRET, PASSWORD, TOKEN) must be a
`secret://` reference. Set `binary` if restic isn't on the daemon's PATH.
`warnAfterHours` makes health degraded when the newest snapshot is older.

| Action | Risk | Notes |
| --- | --- | --- |
| `snapshots` | read | Newest first (`limit`, default 50): short id, time, host, user, paths, tags, and what the backup added (new and changed files, bytes added, files and bytes processed). Filters `host`, `tag`, `path`. Runs without taking the lock. |
| `stats` | read | `mode` raw-data (as stored, the default) or restore-size, for all snapshots or one (`snapshot`, an id or `latest`): bytes, uncompressed bytes, files, blobs, snapshots, compression ratio and saving. Can take a while; allowed 30 minutes. |
| `check` | write | Checks the repository's structure; `readData` also reads back a share of the data, at most a tenth (`2.5%`, `1/20`). It changes nothing, but takes the repository's lock and can run long, so it's write. A check that finds errors answers `ok: false` with the end of restic's report. |
| `forget` | destructive | By keep policy (`keepLast`, `keepHourly`, `keepDaily`, `keepWeekly`, `keepMonthly`, `keepYearly`, `keepWithin` like `30d`, `keepTags`, with `host`, `tag`, `path` filters) or by `ids`. The preview runs `restic forget --dry-run` and lists every snapshot that would go, with its host, paths and time. The data stays until `prune`. |
| `prune` | destructive | Deletes data no snapshot uses. The preview runs `restic prune --dry-run` and shows what would be deleted and repacked, and what remains. |

`check`, `forget` and `prune` may run for `timeoutMinutes` (default 120);
one of them at a time per instance. On a timeout restic is interrupted
first, so it can remove its lock, and killed 30 seconds later.

**Security.** restic is run directly with explicit arguments, never through
a shell. The repository and its password reach it through its environment
(`RESTIC_REPOSITORY`, `RESTIC_PASSWORD`), never its arguments, which other
users can read in the process list; a password in the repository address
(`rest:https://user:pass@host/`) is refused for the same reason. restic gets
a fresh environment: the daemon's own variables don't reach it beyond
`PATH`, `HOME`, the temporary and cache directories and `LANG`, and `env`
only takes backend settings, so `LD_PRELOAD` or `RESTIC_PASSWORD_COMMAND`
can't be set. Every input is checked (host names, tags, absolute paths,
hex snapshot ids, durations, read-data shares) and passed as `--flag=value`
before restic runs. Output is capped (32 MB of JSON, 64 KB of messages),
error text is redacted and cut to its last lines, and snapshot excludes
(which can name private paths) aren't returned.
