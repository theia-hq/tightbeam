# tightbeam

Private peer-to-peer tunnels over the bifrost overlay. Expose a local service by its public key on one
machine, and reach it as a local port on another, with no public internet in between. `ssh -L` /
cloudflared shaped, but p2p and pubkey-addressed.

> Experimental. Works for TCP over the iroh transport; not ready for production use.

## Installation

Not yet published. Build from a checkout:

```sh
cargo install --path .
```

## Usage

Expose a local service (on the machine that has it):

```sh
tightbeam expose 127.0.0.1:22
```

Reach it from another machine, bound to a local port:

```sh
tightbeam connect <node-id> --to 2222
```

## Things to know

- Built on `bifrost` (reach): each proxied connection is one bidirectional stream. It is transport-blind
  and rides any bifrost transport.
- Only a peer holding the target's key can dial it; reach is the authorization.
- TCP first; unix sockets and named services come later.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
