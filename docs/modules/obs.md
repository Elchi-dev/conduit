# OBS Studio

Switch scenes, start and stop streams and recordings, and control audio
inputs in OBS Studio, from the app, an automation or an agent.

**Setup.** OBS 28 and later include the WebSocket server. In OBS, open
Tools, WebSocket Server Settings, turn on the server and keep authentication
on. Store the password in the vault and enter its `secret://` reference with
the address (default `ws://127.0.0.1:4455`; use the PC's address to reach OBS
on another machine on your network).

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Streaming and recording, with their running time, and the current scene |
| `scenes` | read | In the order OBS shows them |
| `switch_scene` | write | Undo switches back to the scene that was live before |
| `start_stream` | write | Undo stops the stream |
| `stop_stream` | destructive | Ends the live broadcast for your viewers |
| `start_record` | write | Undo stops the recording |
| `stop_record` | destructive | Returns the path of the saved file. It ends the recording in progress, so it is destructive like `stop_stream`. |
| `toggle_mute` | write | For an input such as `Mic/Aux`; undo toggles it back |
| `set_volume` | write | In dB from -100 to 26; undo restores the previous level |

Health checks the connection and reports the OBS version.

**How it connects.** Each call opens a connection, completes the
obs-websocket v5 handshake (the password is never sent; OBS sends a
challenge and Conduit answers with a hash of it), makes its requests and
closes. When OBS isn't running, calls fail with a clear message and health
shows the module as down; nothing retries in the background.

**Security.** Anyone who can reach the WebSocket port with the password can
control OBS, including starting a stream. Keep authentication on, and don't
expose port 4455 beyond your local network.
