# rclone

An rclone remote-control server: remotes, transfer stats, jobs, folder
listings, and sync or copy as background jobs, each previewed with
rclone's own dry run.

**Setup.** Run `rclone rcd --rc-addr=localhost:5572 --rc-user=conduit
--rc-pass=…` (or add `--rc` with the same flags to a running rclone), store
the password in the vault, and enter the address, user and its `secret://`
reference. `allowedRemotes` limits the instance to some remotes;
`localRoots` lists the local folders (absolute paths) that paths without a
remote may be in, and local paths are refused while it's empty. For a
self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `remotes` | read | Names of the configured remotes and whether this instance may use each. Never their settings. |
| `stats` | read | Bytes, speed, ETA, transfers, checks, deletes, renames, errors and how many transfers are running, for the server or one `job`. File names are left out. |
| `jobs` | read | Background jobs, newest first: id, running or finished, success, start, end, duration and error. |
| `job_status` | read | One job, with its transfer stats. |
| `list` | read, sensitive | Files and folders at a `location` (`remote:path`, or a local folder under a root): name, path, size, modified. `recursive` walks subfolders; `limit` caps the rows (default 500). |
| `sync` | destructive | Makes `destination` match `source` as a background job, deleting what's at the destination but not in the source. The preview runs rclone's dry run and reports how many files it would copy and delete. Returns the job id. |
| `copy` | destructive | Copies new and changed files from `source` to `destination` as a background job; changed files there are replaced, nothing is deleted. Previewed like `sync`. |
| `stop_job` | destructive | Stops a running job; what it transferred so far stays. A finished job is left as it is. |

**Previews.** A preview starts the same transfer with rclone's `DryRun`
option as a job, waits up to 20 seconds for it, and turns its stats into
the plan. When the dry run finds nothing to transfer or delete, the plan
says so. A dry run that takes longer is stopped and the plan reports what
it had found so far. Previews need rclone v1.55 or later (the first to
take `_config`): an older rclone ignores the setting and would run the
transfer for real, and a dry run's stats count what it would transfer, so
they can't show afterwards which one ran. On an older or unidentified
server the preview is refused before anything starts.

**Security.** Only a fixed list of rc methods is called: `core/version`,
`core/stats`, `config/listremotes`, `job/list`, `job/status`, `job/stop`,
`operations/list`, `sync/sync` and `sync/copy`. Nothing that reads or
changes rclone's configuration (`config/dump`, `config/get`), runs commands
(`core/command`, `backend/command`), sets options or deletes files directly
is ever called, so remote credentials never reach Conduit. Locations must
name a configured remote or a local folder under a root; `..` parts,
relative local paths, and connection-string or on-the-fly remotes
(`:s3,…:`, `remote,param=…:`) are refused before any request. The client
won't follow a redirect to another host or from https to http.

## Notes

- A remote of type `local` or `alias` (or `union`, `combine`, `crypt` over
  a local folder) reaches whatever folder it points to, outside
  `localRoots`; Conduit can't see a remote's type without reading its
  configuration, so use `allowedRemotes` to keep such remotes out of an
  instance.
- A Windows drive path in `localRoots` (`C:/…`) only means a local folder
  when rclone runs on Windows; elsewhere rclone reads `c:` as a remote
  named `c`.
- Undo isn't offered for `sync` or `copy`: files replaced or deleted at the
  destination can't be brought back through rclone.
- Finished jobs are kept by rclone for a while (`--rc-job-expire-duration`,
  one minute by default), then disappear from `jobs`.
