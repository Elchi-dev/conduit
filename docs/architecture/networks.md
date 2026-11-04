# Networks

A network is a WireGuard tunnel that module instances can be attached to, so
a module reaches hosts that only exist inside a WireGuard network (a Forgejo
server in a homelab, an SSH host behind a VPN, a Docker daemon on a private
address) without a VPN client on the machine running Conduit.

## How it works

- **Userspace, pure Go.** Each network is a `wireguard-go` device on a gVisor
  netstack (`golang.zx2c4.com/wireguard/tun/netstack`). There is no kernel
  interface, no root, no route and no DNS change on the host: the only thing
  the operating system sees is one UDP socket. The daemon still builds with
  `CGO_ENABLED=0`.
- **Split tunnel by AllowedIPs.** An attached instance's connections whose
  destination is inside a peer's `AllowedIPs` go through the tunnel; every
  other destination is dialled directly, as without a network. With
  `AllowedIPs = 0.0.0.0/0` everything goes through it. Names are resolved by
  the network's DNS servers first (through the tunnel), then by the system
  resolver.
- **Lazy start.** A tunnel comes up the first time an instance dials through
  it (the vault may be locked when the daemon starts), or when someone opens
  its status with `connect=1` or restarts it. Saving a network takes its
  tunnel down; the next dial brings it up with the new settings.
- **Keys live in the vault.** A network stores only `secret://` references.
  Raw keys sent to the API (a pasted wg-quick file, a typed key, "make a new
  key") are stored as `networks/<id>/private-key` and
  `networks/<id>/psk-<hash>` and never returned; deleting the network deletes
  them. References to existing secrets go through the same restricted-folder
  check as instance settings.

## Configuration

A network has a name, the interface's private key (reference), its addresses
inside the network, optional DNS servers, MTU (default 1420) and listen port,
and one or more peers (public key, optional preshared key reference,
endpoint `host:port`, `AllowedIPs`, persistent keepalive). The public key is
derived and shown so it can be added on the server.

A standard wg-quick `.conf` can be pasted instead. `[Interface]` PrivateKey,
Address, DNS, MTU and ListenPort and `[Peer]` PublicKey, PresharedKey,
Endpoint, AllowedIPs and PersistentKeepalive are read; settings only wg-quick
itself acts on (`PostUp`, `PreDown`, `Table`, `FwMark`, `SaveConfig`) and DNS
search domains are ignored and reported. Anything else is an error, so a typo
isn't silently dropped.

## Attaching instances

`core.Instance` has a `network` field (column `instances.network`, migration
0013). `PUT /api/v1/instances/{id}` with `{"network": "<id>"}` attaches it,
`""` detaches it and leaving the field out keeps it. Changing it is for
people only, like every other instance setting.

Modules get the network through their host, without knowing about WireGuard:

```go
sdk.HTTPClient(h, 30*time.Second) // an http.Client dialling the instance's way
sdk.Transport(h)                  // the same as an *http.Transport to customise
sdk.DialContext(h)                // raw connections: SSH, TCP sockets
```

These use the optional `sdk.NetHost` interface (`Network()`,
`DialContext()`), which the engine's host implements; with a host that
doesn't (tests, older embedders) they fall back to a plain dialer, so the
change is backwards compatible. The host looks the instance's network up on
every dial, so a client made in `Configure` follows later changes. On a
network the environment's HTTP proxy is not used.

Modules wired so far: GitHub (Enterprise servers), Gitea/Forgejo, Websites
and APIs (checks and requests), Servers (SSH, through `internal/sshx`, which
also covers Docker over SSH) and Docker (`tcp` mode). External modules run
as separate processes with their own sockets and can't be attached.

## Sandboxed modules

A WebAssembly module's only way out stays the host's `http_request`, with its
host allow-list and https-only rule. When the instance a request is made for
(the `instance` field of `wasm.Request`; optional when the module has one
instance) is attached to a network, the request goes through it, and the
reserved-address rule changes in one way only: addresses inside the network's
`AllowedIPs` are reachable through the tunnel even when they are private
(that is the point of the network). Every other destination, including
private addresses outside those ranges, is still refused. Each network gets
its own HTTP client, so pooled connections never cross networks.

## API

Under `/api/v1/networks` (admins; creating, changing, restarting and
deleting are for people only, not agents or keys): list, create (fields or
`conf`), get, update, delete (refused with 409 while instances are attached),
`GET /{id}/status` (running, error, and per peer the last handshake, its age
and bytes received and sent) and `POST /{id}/restart`. Changes are audited
as `network_created`, `network_saved`, `network_deleted` and
`network_restarted`, with names, addresses and peer public keys but never
key material.

## Web app

Networks (admin navigation) lists each network with its state and peers,
and adds or edits one by pasting a wg-quick file or by hand. A connection's
settings have a Network picker.

## Tests

`internal/wgnet` brings up two tunnels in one process that are each other's
peer over loopback UDP and makes an HTTP request through them to a server
listening on the other tunnel's netstack; it also covers split routing, the
manager's lazy start and errors, and wg-quick parsing.
