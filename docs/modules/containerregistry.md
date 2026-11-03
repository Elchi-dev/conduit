# Container registry

Look up image tags and digests on Docker Hub, GHCR, Quay, Harbor, GitLab or
your own `registry:2`, and spot newer versions. Read-only: it never pushes or
deletes.

**Setup.** Enter the registry (`docker.io`, `ghcr.io`, `quay.io`,
`harbor.example.com:8443`, or `http://localhost:5000` for a local one). Public
images need nothing else. For private images (or to get past Docker Hub's
anonymous rate limit) add a username and store the password or access token
in the vault. For GHCR that's a token with `read:packages`.

| Action | Risk | Notes |
| --- | --- | --- |
| `tags` | read | Up to 5,000 tags, following the registry's pages. |
| `manifest` | read | The digest a tag points to. For multi-platform images, each platform with its digest and size; otherwise total size and layer count. |
| `newer` | read | Version tags newer than `tag` in the same style: `1.2.3` is compared with `1.2.10`, not with `1.3` or `1.2.4-alpine`. Says whether the newest is a major update. |

On Docker Hub a bare name like `nginx` means `library/nginx`. Sign-in follows
the registry's `WWW-Authenticate` challenge (Bearer token service or Basic),
and tokens are reused until they expire. Repository names follow the OCI
grammar and tags the OCI tag rules, so input can't reach other paths.
