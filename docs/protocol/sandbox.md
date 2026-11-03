# Sandboxed modules (WebAssembly)

Version 1. Signature feature 12: modules you don't fully trust (from the
registry, from someone else) run as WebAssembly with only the permissions
they declare.

## What a sandboxed module is

A WASI preview 1 (`wasip1`) program that speaks the
[external-module protocol](external-modules.md) on stdin and stdout. The
daemon runs it in [wazero](https://wazero.io), a pure-Go runtime, so nothing
extra is installed and the daemon stays one static binary. To the engine it
is a module like any other: every action still goes through policy,
approvals and the audit log.

Inside the sandbox a module has:

| Resource | Access |
| --- | --- |
| Files | none (no directories are mounted) |
| Environment | only `CONDUIT_MODULE_PROTOCOL` |
| Sockets | none |
| Network | HTTPS through the host, to granted hosts only |
| Secrets | the host callback, limited to vault references in its own instance settings |
| Memory | 64 MiB by default, at most 512 |
| Clock, randomness | yes (wall clock, monotonic clock, crypto randomness) |

## Permissions

Put `<name>.wasm` in `<data>/modules/`, with an optional `<name>.json`:

```json
{ "permissions": { "network": ["api.example.com", "*.example.org"], "memoryMB": 64 } }
```

No `network` entry means no network at all. Requests must use `https://`;
granted names that resolve to loopback, private, link-local, multicast,
carrier-grade NAT (100.64.0.0/10, which includes Tailscale), NAT64, 6to4,
Teredo, benchmarking or unique-local addresses are refused, so a module can't
be aimed at your local network. Redirects are followed (at most 5) only to
`https://` URLs on granted names. Responses are capped at 4 MiB and 20
seconds.

## Host functions

The host module is `conduit`:

- `http_request(ptr, len) -> n` takes a JSON request
  `{method, url, headers, body(base64)}` and returns the length of the JSON
  response `{status, headers, body(base64)}` or `{error}`;
- `http_response(ptr)` copies that response into a buffer of length `n`.

Go modules don't touch these directly: import
`github.com/elchi-dev/conduit/pkg/sdk/wasm`, call `wasm.Serve(module)` from
`main`, and `wasm.HTTP(wasm.Request{...})` to make requests. Build with
`GOOS=wasip1 GOARCH=wasm go build -o mymodule.wasm`. The same source also
runs as a normal external module when built for a real platform (without
host HTTP). `internal/sandbox/testdata/echo` is a complete example.

Other languages work as long as they target wasip1, read and write
newline-delimited JSON-RPC on stdin and stdout, and keep stdin non-blocking
or handle one message at a time.

## Status

Loading from `<data>/modules/` works; installing `wasm` artifacts from the
hub registry, and showing a module's permissions for approval before it
loads, come next.

## Installing from a registry

**Modules → Add modules from your hub** (or `/api/v1/registry/*`) browses
the registry of the hub this daemon is linked to and installs sandboxed
builds (artifact platform `wasm`). Only signed-in people can install.

- The version payload must be signed by the author's ed25519 key. The
  daemon shows the key's fingerprint and installs only if it's the one the
  person saw. The key is **pinned** on first install: a later version
  signed by another key is refused, so a hub can't swap an author's build
  for someone else's. Remove the module first if the author really changed
  keys.
- The download must be https and match the signed SHA-256.
- The module's permissions come from the signed manifest
  (`{"permissions": {"network": [...], "memoryMB": n}}`) and are shown
  before installing.
- The module must use ids starting with its author's handle and a dash
  (`acme-weather` for `acme/weather`), so it can't impersonate a built-in
  module or another author's.
- Installed modules live in `<data>/modules/<author>__<module>.wasm` with
  their permissions file next to them, and load at every start like any
  other sandboxed module. Updates replace them in place; removing stops the
  module and deletes its instances.

Native (non-sandboxed) modules are never installed from a registry: install
those by hand after reading them.
