# Stream Deck plugin (scaffold)

Shows Conduit's ambient status on a key and opens Conduit when pressed. It
polls `GET /api/v1/ambient` every 10 seconds.

1. In Conduit, create an API key with only `modules:*:read`.
2. Copy `dev.elchi.conduit.sdPlugin` into the Stream Deck plugins folder
   (`%APPDATA%\Elgato\StreamDeck\Plugins` on Windows,
   `~/Library/Application Support/com.elgato.StreamDeck/Plugins` on macOS)
   and restart Stream Deck.
3. Drag "Conduit → Status" onto a key and enter the address and key.

Status: works with the legacy HTML plugin runtime; not yet packaged with the
Elgato CLI or listed in the marketplace. Other devices can use the same
endpoint (see docs/modules/status.md).
