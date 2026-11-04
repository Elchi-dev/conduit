# Protocol

Conduit's protocol is open, like git's. The default hub is one implementation;
anyone can run another, and daemons work without any hub.

Specifications, versioned as they land:

| Spec | File | Status |
| --- | --- | --- |
| External modules (JSON-RPC over stdio) | [external-modules.md](external-modules.md) | v1 |
| Hub: accounts, pairing, relay, sync, registry, update feed | [hub.md](hub.md) | v1 |
| Updates: keys, release payloads, feeds, self-update and rollback | [updates.md](updates.md) | v1 |
| Sandboxed modules: WebAssembly, permissions, host functions | [sandbox.md](sandbox.md) | v1 |
| Module marketplace: listings, ratings, reports, moderation | [marketplace.md](marketplace.md) | v1 |
