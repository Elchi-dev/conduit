# FileFlows

The [FileFlows](https://fileflows.com) file processing server: the
processing status with the queue and the files in progress, the processing
nodes and the libraries.

**Setup.** In FileFlows, open Config, API, turn on Enabled and save; FileFlows
creates an API token. Store the token in the vault. Enter FileFlows'
address, such as `http://nas.lan:19200` (with its sub path if it's behind a
reverse proxy). For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | How many files wait, are being processed and were processed, the processing time, and each file in progress with its name, library, step and progress. |
| `nodes` | read | Each processing node with its id, name, whether it's enabled, how many files it runs at once (runners), version and operating system. |
| `libraries` | read | Each library with its id, name, whether it's enabled, its flow, priority, scan interval and last scan. |

**Security.** Every request is signed with the token as FileFlows asks
(HMAC-SHA256 over method, path, time and a fresh nonce); the token itself is
never sent. The client won't follow a redirect to another host or from https
to http. Files in progress show only their name, never their folder, and
library folders, node addresses, temp paths and path mappings aren't read.
Folders and file paths are taken out of FileFlows' error messages, a node's
operating system and priority are shown only as a number or a short word,
and at most 100 files, nodes and libraries are listed.

**Notes.** FileFlows' API needs a FileFlows license; without one, or with
the API off, every request answers "not found", which the module reports as
such. Signed requests need this computer's clock within five minutes of the
server's. Nodes are read from `agent` (FileFlows 26.09 and later) or `node`
(earlier). Pausing and resuming processing isn't offered yet: FileFlows
documents its endpoints only on each server (`/api/help`), and the pause
endpoint couldn't be confirmed.
