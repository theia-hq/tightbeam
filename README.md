# tightbeam

Reach a service on a machine with no public IP: no port forwarding, no VPN, no cloudflared. Expose a
local service by its public key on one machine, reach it as a local port on another, peer to peer with
nothing in between. `ssh -L` shaped, but pubkey-addressed.

> Experimental. Works for TCP over the iroh transport; not ready for production use.

## Installation

Not yet published. Build from a checkout:

```sh
cargo install --path .
```

## Usage

Expose one or more local services (on the machine that has them). A target may be a `host:port` or a
`unix:<path>` socket:

```sh
tightbeam expose ssh=127.0.0.1:22 web=127.0.0.1:80 docker=unix:/var/run/docker.sock
```

Reach a service from another machine, bound to a local port:

```sh
tightbeam connect <node-id> --service ssh --to 2222
```

A bare address exposes the `default` service, which `connect` reaches without `--service`:

```sh
tightbeam expose 127.0.0.1:22      # on the host
tightbeam connect <node-id> --to 2222
```

Restrict who may connect with `--allow <node-id>` (repeatable), or `--pair` to approve peers on
first contact (`tightbeam approve <node-id>`).

## Compose an overlay exit

tightbeam does not ship a proxy; it tunnels any existing one. To route traffic out through a remote
peer, run a proxy on the exit host and expose it (`ssh` provides a SOCKS5 proxy on any machine):

```sh
# on the exit host
ssh -D 1080 -N localhost        # or dante / Caddy / mitmproxy
tightbeam expose 127.0.0.1:1080

# on your machine
tightbeam connect <exit-node-id> --to 1080   # then point apps at socks5://127.0.0.1:1080
```

## Things to know

- Built on `bifrost` (reach): each proxied connection is one bidirectional stream. It is transport-blind
  and rides any bifrost transport.
- Only a peer holding the key can dial, and authorization (allowlist / pairing) is enforced by nauthy on
  the identity the handshake proves.
- TCP and unix-socket (`unix:<path>`) targets are supported.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
