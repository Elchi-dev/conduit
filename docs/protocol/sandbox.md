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
