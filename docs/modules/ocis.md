# ownCloud Infinite Scale

Spaces (personal, project and share spaces) and their quotas, and folder
listings, on an ownCloud Infinite Scale (oCIS) server through its Graph API
and WebDAV.

**Setup.** Enter your server's address, such as `https://ocis.example.com`.
For a lasting credential, create an app token (`ocis auth-app create
--user-name=alice`, or from the account page where the auth-app service is
on with `PROXY_ENABLE_APP_AUTH=true`), store it in the vault, and enter the
user name it belongs to as `user`. Without `user`, the token is sent as an
OIDC bearer access token. For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `drives` | read, sensitive | Spaces you can reach (`all` lists every space, for an admin): id, name, type, alias, last change, whether it's disabled, and its quota. `type` filters, e.g. `project`. Owners and members aren't decoded. |
| `quota` | read | Used, total and remaining bytes, percentage and the quota state (`normal`, `nearing`, `critical`, `exceeded`) of your personal space, or of the space `drive` names. |
| `list` | read, sensitive | Files and folders in a folder of a space: name, path, type, size, modified, MIME type and file id. `limit` caps the rows (default 500). |

Health signs in, counts your spaces, and reports degraded when your
personal space's quota is critical or exceeded.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Space ids
and paths are checked (no `..` parts, no control characters) before any
request, and each path part is escaped. A folder listing is a WebDAV
PROPFIND of depth 1, read up to 8 MB; hrefs naming another host or
outside the listed folder's space are skipped.

## Notes

- An OIDC access token expires within minutes; use an app token for an
  instance that should keep working.
- Very large folders (beyond 8 MB of listing) are refused; list a
  subfolder.
