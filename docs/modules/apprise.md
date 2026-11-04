# Apprise

Notifications through a self-hosted Apprise API server: send to the
services of a stored configuration by tag, and see what each configuration
holds.

**Setup.** Run the Apprise API server with stored configurations (stateful
mode) and save one or more configurations on it, each under a key. Enter the
server's address, such as `https://apprise.example.com`, and the `keys` this
connection may use. For a server behind basic authentication, add a
`username` and the `secret://` reference of its password. For a self-signed
certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `configs` | read | For each allowed key: its tags, how many services it holds and their kinds (`mailto`, `tgram`, `discord`…). Never the stored URLs. |
| `notify` | destructive | Sends a `body` with an optional `title`, `type` (`info`, `success`, `warning`, `failure`) and `format` (`text`, `markdown`, `html`) through a `key` to the services matching `tag`: one tag, `a b` for both, `a, b` for either, or `all`. The preview shows how many services and which kinds match; the run must give that number as `expectedServices` and is refused if it changed. |

**Notes.** One Apprise configuration can reach email, SMS and chats of
anyone, so sending is destructive, and a tag is always required so the
destinations are explicit. Apprise matches tags itself; the preview counts
the services the server reports for the same tag. Listing every key on the
server isn't offered (its documented list is meant for the web page);
the keys come from the settings instead. Attachments, templates and
stateless sends to URLs given in the call aren't offered.

**Security.** Stored Apprise URLs contain each service's credentials:
configurations are read with Apprise's privacy option and reduced to their
schemes at once, so no URL reaches output, previews or the audit log. Keys
and tags are checked before they reach a request, the password goes in the
`Authorization` header, and the client won't follow a redirect to another
host or from https to http.

**Presets.** homelab.
