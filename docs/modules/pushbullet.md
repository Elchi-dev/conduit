# Pushbullet

Your Pushbullet devices, pushing a note to them, recent pushes and deleting
pushes you sent.

**Setup.** On pushbullet.com, open Settings, Account and create an access
token. Store it in the vault and enter its `secret://` reference.

| Action | Risk | Notes |
| --- | --- | --- |
| `devices` | read | Your active devices: id, nickname, maker, model, app version, icon and whether it can send SMS. Push tokens and key fingerprints are left out. |
| `push_note` | write | Pushes a note (`body`, optional `title`) to all your devices or one `device`. With a preview naming the device. Undo deletes it. |
| `pushes` | read, sensitive | Recent pushes, newest first (`limit` up to 100, default 20; `cursor` for the next page): type, direction (`self`, `outgoing`, `incoming`), sender name, title, text and link (each up to 2000 characters), file name and date. Email addresses are left out. |
| `delete_push` | destructive | Deletes a push you sent, by `push` id, everywhere it shows. The preview names its type, direction and date, not its text. Pushes someone else sent you are refused. |

**Notes.** A note goes only to the token's own devices: the module never
sets an email, channel or client target, so sending is write. Pushes are
private, so reading them is a sensitive action and their text appears
nowhere else. `delete_push` looks through your 500 most recent pushes; an
older one reports nothing to change. Undo removes the note from Pushbullet,
while a notification a device already showed may stay. Pushing links,
files and SMS isn't offered.

**Security.** The token goes in the `Access-Token` header, and the client
won't follow a redirect to another host or from https to http. Ids must be
plain identifiers before they reach a request path.

**Presets.** homelab, developer.
