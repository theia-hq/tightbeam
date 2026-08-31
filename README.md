# tightbeam

Reach a service on a machine with no public IP: no port forwarding, no VPN, no cloudflared. Serve a
local service under your public key on one machine, reach it as a local port on another, peer to peer
with nothing in between. `ssh -L` shaped, but pubkey-addressed.

tightbeam is two things: the raw forward (bind a local `host:port` or Unix socket and splice it to a
reaching peer) and a registry that a node serves named services from. It owns the forward and the naming;
the services themselves (a shell, an HTTP fetch, link diagnostics) are handlers injected by whoever
builds the node. In theia, that node is [swoosh](https://github.com/theia-hq/swoosh).

Powered by [bifrost](https://github.com/theia-hq/bifrost) for the keyed connection and
[nauthy](https://github.com/theia-hq/nauthy) for authorizing who may connect.

**The name.** A tightbeam is a tight, aimed beam: a private point-to-point link that goes only where
you point it, not out to everyone. That is what this does, one machine's service reaching exactly
one other, addressed by key.

> Experimental. Works for TCP over the iroh transport; not ready for production use.

## Installation

Not yet published. Build from a checkout:

```sh
cargo install --path .
```

## Usage

Serve one or more local forwards (on the machine that has them). A target may be a `host:port` or a
`unix:<path>` socket:

```sh
tightbeam serve ssh=127.0.0.1:22 web=127.0.0.1:80 docker=unix:/var/run/docker.sock
```

Reach one from another machine, bound to a local port:

```sh
tightbeam connect <node-id> --service ssh --to 2222
```

A bare address serves the `default` name, which `connect` reaches without `--service`:

```sh
tightbeam serve 127.0.0.1:22       # on the host
tightbeam connect <node-id> --to 2222
```

> The port-forward leaf's exact word (`connect` or `forward`) is a founder taste call, written here as
> `connect` for now.

By default a service is gated to this node's signet, set once by `swoosh adopt`: it admits the owner's
own devices and anyone they delegate a capability to (below), and refuses everyone else. Pass
`--public` to open a service to anyone, unauthenticated, the one deliberate opt-out.

`serve --quiet` suppresses the readiness banner, so the node's key never lands in a log, for unattended
or CI use. The forward runs the same either way.

For worked examples of what to run over a forward (stream a movie, pipe a raw stream, reach a database
port), see [examples.md](examples.md).

## Share a service as a capability

The default gate already accepts capabilities: a signed, expiring, attenuable link rooted at this
node's signet, verified offline with no server and no allowlist to sync. Mint one with `share` and
hand it to someone outside your own devices.

```sh
# on the host: serve ssh, gated to your signet by default
tightbeam serve ssh=127.0.0.1:22

# mint a share-link for ssh, valid two hours, that the holder may narrow and hand on
tightbeam share ssh --expires 2h --delegable      # prints sheer:<node>.<token>

# a holder narrows it further, offline, before delegating (no key, no network)
tightbeam attenuate <link> --service ssh --expires 30m

# anyone holding the link connects with it; it carries the node to dial and the token to present
tightbeam connect <link> --to 2222
```

The link works only for the service it grants, expires on its own, and can be narrowed and delegated
without the host's involvement. Drop `--delegable` to seal a link so its recipient can use but not
re-share it. `tightbeam revoke <link>` cuts a link off at once, without waiting for its expiry; short
expiry backs that up. There is no server to ask, only a node-local denylist. See
[DEMO-WEDGE.md](DEMO-WEDGE.md) for a full run over iroh.

## ssh over the overlay

ssh to a machine with no public IP, by its key. Serve its sshd as a service on the host, then point
ssh's `ProxyCommand` at `connect --stdio`: tightbeam pipes the overlay stream over ssh's stdin/stdout,
so ssh talks to the far sshd as if it were local.

On the host, serve sshd:

```sh
tightbeam serve ssh=127.0.0.1:22
```

`--stdio` pipes the service over stdin/stdout instead of binding a local port, which is exactly what an
ssh `ProxyCommand` wants. You cannot type `ssh alice/desk` directly: `/` is not legal in a hostname (and
it is theia's device separator), so ssh cannot parse it. Give ssh a legal alias in `~/.ssh/config`
instead:

```
Host alice-desk
    ProxyCommand tightbeam connect <peer> --service ssh --stdio
```

Then:

```sh
ssh alice-desk
```

`<peer>` is the host's node id, or a `sheer:` capability link (`tightbeam share ssh …`). With a link,
auth composes for free: the link names the node to dial and carries the token, so a link that reaches
only ssh and expires in an hour becomes an ssh `ProxyCommand` with nothing else to configure.

## Compose an overlay exit

tightbeam does not ship a proxy; it forwards any existing one. To route traffic out through a remote
peer, run a proxy on the exit host and serve it (`ssh` provides a SOCKS5 proxy on any machine):

```sh
# on the exit host
ssh -D 1080 -N localhost        # or dante / Caddy / mitmproxy
tightbeam serve 127.0.0.1:1080

# on your machine
tightbeam connect <exit-node-id> --to 1080   # then point apps at socks5://127.0.0.1:1080
```

## Things to know

- Built on [`bifrost`](https://github.com/theia-hq/bifrost) (reach): each forwarded connection is one
  bidirectional stream. It is transport-blind and rides any bifrost transport.
- Only a peer holding the key can dial, and authorization is enforced by the
  [`nauthy`](https://github.com/theia-hq/nauthy) crate: the default gate admits a presented `sheer:`
  token rooted at this node's signet (a device's membership badge or a delegated service slip);
  `--public` is the only opt-out.
- TCP and unix-socket (`unix:<path>`) targets are supported.
- Named services beyond a raw forward (a keyless shell, an HTTP fetch, a file source) are handlers a node
  injects into the registry. tightbeam knows the contract, never what a service does; see
  [swoosh](https://github.com/theia-hq/swoosh) for the services a real node serves.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
