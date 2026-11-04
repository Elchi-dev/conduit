# Dropbox

Your Dropbox files: list folders, search, look up a file, and create or
revoke shared links.

**Setup.** In the Dropbox App Console, create an app (Scoped access; Full
Dropbox or App folder) and enable the permissions below on its Permissions
tab. Copy the app key, store the app secret in the vault, and get a
refresh token by signing in once with `token_access_type=offline` (the
authorization code flow); store it in the vault too. Enter `appKey`,
`appSecret` and `refreshToken`.

| Action | Risk | Notes |
| --- | --- | --- |
| `list_folder` | read | Files and folders in a folder (`path`, empty for the top), optionally `recursive`: type, name, path, id, size and modified time. `more` says there were more than `limit`. Sensitive. |
| `search` | read | Files and folders matching `query` by name or content, optionally under `path`. Sensitive. |
| `metadata` | read | One file or folder by path or file id (`id:…`): name, path, id, size, modified, content hash. Sensitive. |
| `create_shared_link` | destructive | A view-only link with the account's default audience, with an optional `expires`: anyone who has it on a personal account, but a Dropbox team's sharing policy can limit it to members. The result names the audience and access Dropbox gave it. A file that already has a link gets that one back ("nothing to change"; an `expires` asked for isn't applied to it). Undo revokes every direct link to the file. Sensitive. |
| `revoke_shared_link` | destructive | Revokes one link (`url`), or every link to a file (`id`). The preview counts the links; a link that's already gone is "nothing to change". Sensitive. |

**Security.** The app secret and refresh token are only accepted as
`secret://` references. Access tokens live in memory per instance until
shortly before they expire, and a refused one is dropped and fetched again
once. The client won't follow a redirect to another host or from https to
http, and errors name only Dropbox's error tag (`path/not_found`) or the OAuth
error code, never a token. Paths travel in request bodies and are checked first (absolute, no
`..` or control characters); links must be `https://…dropbox.com` links.
The undo carries the file id alone, so the audit log never holds the link
itself.

## Notes

- Permissions to enable: `account_info.read`, `files.metadata.read`,
  `sharing.read`, `sharing.write`.
- An expiry on a link needs a paid plan; Dropbox refuses it otherwise.
- Undo of `create_shared_link` revokes every direct link to that file,
  including any made later.
