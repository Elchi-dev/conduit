# Conduit for gamers

You'll watch your PC while you play, pause heavy background work during a
game, keep an eye on your Minecraft or Source server, and change your Twitch
title from your phone.

## 1. Your PC

**This computer** is set up from the start: CPU, GPU, memory, disks,
temperatures and running processes. Pin **Status → gpu.temperature** (or
any value) to your board.

## 2. Game mode

**Games** finds your Steam library and notices when a game starts and
stops. **This computer → Game mode** pauses the processes you list (backup
tools, indexers, sync clients) and undoes itself when you're done; an
automation on `games.started` can also pause Docker containers or set a
"do not disturb" light, and undo it on `games.stopped`.

## 3. Your game server

**Game servers** checks Minecraft (server list ping) and Source games
(Valve's A2S query) without any login. Add the RCON password (stored in the
vault) to whitelist players, broadcast a message, or run console commands.
Console commands are marked *destructive* and always ask first, even for
you, unless you change the rule.

## 4. Streaming

- **OBS Studio**: switch scenes, start and stop the stream or recording,
  mute sources. Undo puts the previous scene back.
- **Twitch**: see who's live and change your title or category; undo
  restores the old ones.
- **Discord**: post to your server through a webhook or a bot.
- **Spotify**: what's playing, skip, volume.

## 5. On your phone

1. **Settings → Remote access → Pair a device** and scan the code with the
   Conduit app. Everything between your phone and your PC is end-to-end
   encrypted, even through a hub.
2. **Phone notifications** sets up the free ntfy app so alerts and
   approvals reach you even when Conduit is closed, with no Google services
   involved.
