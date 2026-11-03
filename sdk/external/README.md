# External module starter kits

Write a module in any language: it's a program that speaks JSON-RPC on stdin
and stdout ([protocol](../../docs/protocol/external-modules.md)). These kits
do the protocol so you only write the manifest and the actions.

| Kit | Files | Run |
| --- | --- | --- |
| Python 3.9+ | `python/conduit_module.py`, example `example_weather.py` | `chmod +x`, drop both in `<data>/modules/` |
| TypeScript (Node 22+) | `typescript/conduit-module.ts`, example `example-uptime.ts` | same; the example's shebang runs Node with type stripping |
| Go | `pkg/sdk` (and `pkg/sdk/wasm` for the sandbox) | see `go/README.md` |

Each kit is tested against the real engine in `internal/core/kits_test.go`.

Every action declares a risk (`read`, `write`, `destructive`); Conduit's
policy, approvals and audit log apply to your module exactly as to the
built-in ones. Credentials go in the instance settings as `secret://name`
references and are resolved with `host.secret`, so they never sit in your
module's config.
