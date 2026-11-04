# Backblaze B2

Backblaze B2 through its native API (v3): buckets, files and their
versions, how much each bucket holds, hiding files and deleting file
versions. For plain object access through B2's S3-compatible endpoint, the
[S3 module](s3.md) works too; this one sees versions, hide markers and
what an application key is allowed to do.

**Setup.** In the B2 web console, App Keys, add an application key (limited
to one bucket if you like). Enter its **keyID** and store the key itself in
the vault. Listing needs `listBuckets` and `listFiles`; hiding needs
`writeFiles`; deleting versions needs `deleteFiles`.

| Action | Risk | Notes |
| --- | --- | --- |
| `buckets` | read | Name, id, type, file lock, number of lifecycle rules |
| `files` | read | One folder level (or `recursive`), up to 1000 per page with a `next` cursor. `versions` lists every version and hide marker with file ids |
| `usage` | read | Visible files, versions, hide markers, total bytes (all versions) and current bytes, per bucket. Counted from the version listing, up to `maxFiles` (default 100000) per bucket; `truncated` says when it stopped early |
| `hide_file` | write | Adds a hide marker; versions stay. Preview first. Undo removes the marker |
| `delete_file_version` | destructive | Removes one version for good (or a hide marker, which unhides the file). Preview shows the version; the file name must match the version id |

Health checks the key and says when it lacks `listBuckets` or `listFiles`.
The authorization token is renewed transparently when it expires (every 24
hours). Listings are B2 class C transactions; `usage` on a large bucket
makes one per 10000 versions.
