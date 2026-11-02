# Protocol

Conduit's protocol is open, like git's. The default hub is one implementation;
anyone can run another, and daemons work without any hub.

Specifications, versioned as they land:

| Spec | File | Status |
| --- | --- | --- |
| External modules (JSON-RPC over stdio) | external-modules.md | phase 2 |
| Daemon ↔ hub: pairing, relay, sync | hub.md | phase 10 |
| Update feed and signatures | updates.md | phase 11 |
| Registry packages | registry.md | phase 10 |
