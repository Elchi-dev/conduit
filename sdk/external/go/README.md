# Go starter

Go modules use `github.com/elchi-dev/conduit/pkg/sdk` directly: implement
`sdk.Module` and call `sdk.Serve(m, os.Stdin, os.Stdout)` from `main`. Build
for your platform and drop the binary in `<data>/modules/`.

To run sandboxed instead, import `pkg/sdk/wasm`, call `wasm.Serve(m)`, build
with `GOOS=wasip1 GOARCH=wasm`, and put `name.wasm` (plus `name.json` with its
permissions) in the same folder. `internal/sandbox/testdata/echo` is a
complete example; `docs/protocol/sandbox.md` explains the limits.
