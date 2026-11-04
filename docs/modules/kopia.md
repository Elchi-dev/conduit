# Kopia

A Kopia repository server (`kopia server start`): sources and their state,
snapshots, policies, repository and maintenance status, and starting a
snapshot of a source.

**Setup.** Run the server with a UI user, for example
`kopia server start --address=0.0.0.0:51515 --tls-generate-cert
--server-username=kopia --server-password=…`, and store the password in the
vault. Enter the server's address, such as
`https://backup.example.com:51515`, and the username if it isn't `kopia`.
With a generated certificate, set `fingerprint` to the SHA-256 fingerprint
the server prints.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Whether the server is connected to a repository; its storage type, format version, hash, encryption, ECC, splitter, description, read-only, and the user and host it acts as. |
| `sources` | read | Each source (user, host, path) with its state (idle, pending, uploading, paused, failed), next scheduled snapshot, last snapshot (start, end, bytes, files, directories, errors, why it's incomplete) and upload progress while uploading. |
| `snapshots` | read | Snapshots of one source (`userName`, `host`, `path`) or of every source, newest first (`limit` per source, default 20): id, start, end, bytes, files, directories, errors, retention reasons, pins, description. |
| `policies` | read | Every policy by target (global, `@host`, `user@host`, `user@host:/path`): retention, scheduling, compression, file rules, error handling, upload, splitter and logging. Snapshot actions (commands run before and after) and notification settings are left out, since they can hold credentials. |
| `maintenance` | read | The server's recent maintenance runs, newest first: description (quick or full), status, start, end, duration and error. Kopia runs maintenance only on the repository's maintenance owner. |
| `start_snapshot` | write | Starts a snapshot of one source, which must be one of the server's sources. All three parts are required: Kopia would snapshot every source without them. Expiring old snapshots follows the source's policy as on any scheduled run. |

Health is degraded when the server isn't connected to a repository, or a
source's last snapshot failed or had errors.

**Security.** The password is sent with basic auth; Kopia's API also wants
the session cookie and CSRF token its web page hands out, which the module
fetches once and refreshes when the server restarts. The client won't
follow a redirect to another host or from https to http. Sources are
checked (user and host plain names, an absolute path) before any request.
The repository status's config file path and API server URL aren't decoded.
