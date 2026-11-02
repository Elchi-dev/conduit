# External modules — protocol v1

An external module is any executable that speaks JSON-RPC 2.0 over its stdin
and stdout, one JSON object per line. Conduit starts every executable in
`<data dir>/modules/` at launch and treats it exactly like a built-in module:
same policies, same audit log, same UI.

Anything written to stderr is forwarded to the daemon log. Lines on stdout
that are not JSON-RPC are ignored, but don't rely on that; log to stderr.

The environment variable `CONDUIT_MODULE_PROTOCOL` holds the protocol version.

## Daemon → module

| Method | Params | Result |
| --- | --- | --- |
| `initialize` | `{"protocolVersion":"1"}` | `{"protocolVersion":"1","manifest":Manifest}` |
| `configure` | `{"instance":"id","config":{…}}` | `{}` or an error |
| `invoke` | `Call` | `Result` |
| `health` | `{"instance":"id"}` | `{"status":"ok|degraded|down|unconfigured","message":"…"}` |
| `close` | `{"instance":"id"}` | `{}` |

`Manifest`, `Call` and `Result` are the JSON forms of the types in
`pkg/sdk/module.go`. An action's result may carry a `plan` (for dry runs) and
an `undo` token.

## Module → daemon

| Method | Kind | Params | Result |
| --- | --- | --- | --- |
| `host.secret` | request | `{"ref":"secret://name"}` | the secret value as a JSON string |
| `host.publish` | notification | `Event` | — |
| `host.log` | notification | `{"level":"info","msg":"…","kv":[…]}` | — |

A module may only resolve secrets referenced by its own instance's
configuration; the vault enforces this.

## Errors

Use JSON-RPC error objects. `-32601` means unknown method; any other code is
treated as an action failure and shown to the user with its message.

## Example session

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1"}}
← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"1","manifest":{"id":"weather","name":"Weather","version":"0.1.0","actions":[{"name":"now","title":"Current weather","risk":"read"}]}}}
→ {"jsonrpc":"2.0","id":2,"method":"configure","params":{"instance":"weather_x1","config":{"city":"Zurich","apiKey":"secret://weather"}}}
← {"jsonrpc":"2.0","id":2,"result":{}}
→ {"jsonrpc":"2.0","id":3,"method":"invoke","params":{"instance":"weather_x1","action":"now"}}
← {"jsonrpc":"2.0","id":1,"method":"host.secret","params":{"ref":"secret://weather"}}
→ {"jsonrpc":"2.0","id":1,"result":"…"}
← {"jsonrpc":"2.0","id":3,"result":{"output":{"tempC":9}}}
```

Request ids are independent in each direction.

## Writing one in Go

```go
func main() { sdk.Serve(myModule{}, os.Stdin, os.Stdout) }
```

Starter kits for Python and TypeScript live in `sdk/external/`.
