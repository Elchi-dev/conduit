# Roadmap

<p align="center"><img src="images/ori/searching.svg" width="120" alt="Ori looking through a telescope"></p>

What comes next, in order, with the reason for the order. Each step ships on
its own.

## Done

0.1 to 0.3.1 and 1.0 are out; see the [changelog](../CHANGELOG.md). 1.1 is
finished on main: 331 built-in modules, two sweeps of every action's risk
and undo, and security reviews 8 to 47. It passes the full local check.

## Next, in this order

1. **Ship 1.1.0.** The notes are written ([releases/v1.1.0.md](releases/v1.1.0.md)) and main is
   verified. The release workflow builds and signs it as soon as GitHub
   Actions runs jobs for the repository again, either by making it public or
   by raising its Actions spending limit. First, because 1.1 also carries the
   fix that makes nested calls run as the caller, which 1.0 users want.
2. **Live-tested module packs.** Many modules were built from each vendor's
   documented API and tested against faithful fakes. Next they get confirmed
   against live services, pack by pack, starting with the pages whose Notes
   name what is still to confirm (Unraid, Railway, Supabase usage, Speedtest
   Tracker, Tautulli, the FileFlows pause endpoint). Second, because it turns
   the widest catalog into the most trusted one.
3. **The Android app on real phones.** Run the signed APK on devices and
   polish what that shows. The in-app update check then reads releases
   straight from GitHub once the repository is public.
4. **Undo when a secret is replaced.** `vault.set` and `vault.import_env`
   keep the earlier value so replacing it can be undone, the same care
   modules such as `github.set_secret` already take. Here, because the vault
   is the one place where a mistake should always be reversible.
5. **Passkeys in the desktop app and through the relay.** Daemon passkeys
   work under a host name today. Next, a way for the desktop app (which
   talks to `127.0.0.1`) and relayed sessions to use them too.
6. **Tighter Cloudflare record edits.** `set_record` gets the same guard for
   every record that DNS control names (`_dmarc`, `mta-sts` and the like)
   already have, so a change reaches only the record it names.
7. **Clearer ambient status.** Refine how the ambient status lists
   connections that are down, so a light or a webhook says exactly what
   needs you.
8. **Shared rules for agent-supplied links.** One rule for download clients
   that fetch links an agent hands them on the local network, and a
   recipient allow-list for Twilio on top of Twilio's Geo Permissions.
9. **Changing the vault passphrase.** The format already supports it
   without re-encrypting secrets: only the data key is wrapped again.

Later, when it is worth it: a default hub hosting and domain.
