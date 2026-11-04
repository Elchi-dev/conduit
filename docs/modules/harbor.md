# Harbor

A Harbor container registry through its v2.0 API: projects, repositories,
artifacts with their vulnerability scan summary, starting a scan, deleting
an artifact or a tag, and robot accounts.

**Setup.** Enter Harbor's address, such as `https://harbor.example.com`, and
an account: ideally a robot account (`robot$conduit`) with only the
permissions you want (`project:read`, `repository:list`, `artifact:list`,
`scan:create`, `tag:create`/`tag:delete`, `artifact:delete`,
`robot:list`). Store its secret (or a user's password) in the vault. For a
self-signed certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Projects (a `name` filter narrows) with ID, public or private, repository count, owner, auto scan and whether it's a proxy cache, and the total. |
| `repositories` | read | Repositories of a `project` with artifact and pull counts, last update and description. |
| `artifacts` | read | The newest 50 artifacts of a `repository`: digest, tags, type, size, push and pull time, and the scan summary: status, highest severity, total and fixable vulnerabilities, counts by severity, scanner and when it finished. |
| `scan` | write | Starts a vulnerability scan of one artifact (`reference`: tag or digest). The preview shows the last scan's status. |
| `delete_artifact` | destructive | Deletes an artifact and every tag on it; its blobs go at the next garbage collection. The preview lists the tags, size and push time, and calls out immutable tags (Harbor refuses those). The delete goes by digest, so a tag moved in between can't take another artifact. No undo. |
| `delete_tag` | destructive | Removes one `tag`; the artifact stays under its digest and other tags. The preview warns when it would be left untagged (retention rules may then remove it). Undo adds the tag back to the same digest. |
| `add_tag` | destructive | Adds a `tag` to an artifact given by digest or another tag. Destructive because a tag such as `latest` or `prod` can be what deploy automation (Argo CD Image Updater, Flux, Watchtower, a webhook) pulls or watches, so a new tag can roll the artifact out. The preview warns when the tag is on another artifact. Undo removes it. |
| `robots` | read | Robot accounts, system-wide or of one `project`, with level, permissions (resource:action), disabled, expiry and whether they've expired. Never their secrets. |

**Security.** Credentials go as HTTP basic auth, and the client follows
redirects only within the same host and never from https to http. Project
names, repository names (Docker's grammar, encoded twice as Harbor wants),
tags and `sha256:` digests are checked before they reach a path, and
`X-Is-Resource-Name` makes Harbor treat a project given by name as a name
even when it's all digits.
