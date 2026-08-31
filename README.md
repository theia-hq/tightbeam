# tightbeam

Reach a public key, prove you belong at its gate, and get a raw byte-stream to a named service behind it,
over any transport, across any NAT. That is the whole of what tightbeam is: one primitive, a forwarded
stream to a service someone named.

A machine exposes local services under its public key, each behind a gate. Another machine, holding the
key and passing the gate, reaches a service and gets a plain bidirectional stream to it, bound to a local
port or piped over stdin/stdout. No port forwarding, no VPN, no public IP. `ssh -L` shaped, but
pubkey-addressed and peer to peer.

Powered by [bifrost](https://github.com/theia-hq/bifrost) for the keyed connection and
[nauthy](https://github.com/theia-hq/nauthy) for authorizing who may connect.

**The name.** A tightbeam is a tight, aimed beam: a private point-to-point link that goes only where you
point it, not out to everyone. That is what this does, one machine's service reaching exactly one other,
addressed by key.

> Experimental. Works for TCP over the iroh transport; not ready for production use.

## Installation

Not yet published. Build from a checkout:

```sh
cargo install --path .
```

## Usage

Expose one or more local services (on the machine that has them). A target may be a `host:port`, a
`unix:<path>` socket, a `file:`/`fifo:` byte source, or `stdin:` (whatever a producer pipes in):

```sh
tightbeam expose ssh=127.0.0.1:22 web=127.0.0.1:80 docker=unix:/var/run/docker.sock
```

Reach one from another machine, bound to a local port:

```sh
tightbeam connect <node-id> --service ssh --to 2222
```

A bare address serves the `default` name, which `connect` reaches without `--service`:

```sh
tightbeam expose 127.0.0.1:22       # on the host
tightbeam connect <node-id> --to 2222
```

`connect` is tightbeam's own word for reaching a service and binding it locally. (In swoosh, the same
leaf is called `forward`; see the closing section.)

By default a service is gated to this node's signet, set once by `swoosh adopt`: it admits the owner's
own devices and anyone they delegate a capability to (below), and refuses everyone else. Pass `--public`
to open a service to anyone, unauthenticated, the one deliberate opt-out.

`expose --quiet` suppresses the readiness banner, so the node's key never lands in a log, for unattended
or CI use. The forward runs the same either way.

For worked examples of what to run over a forward (stream a movie, pipe a raw stream, reach a database
port), see [examples.md](examples.md).

## Share a service as a capability

The default gate already accepts capabilities: a signed, expiring, attenuable link rooted at this node's
signet, verified offline with no server and no allowlist to sync. Mint one with `share` and hand it to
someone outside your own devices.

```sh
# on the host: expose ssh, gated to your signet by default
tightbeam expose ssh=127.0.0.1:22

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

## What the primitive reaches

Every example below is the same one move: forward a stream to a service named behind the family gate.
None of these is a tightbeam feature with a verb of its own. They are what a raw forwarded stream lets
you do.

**ssh to a machine with no public IP.** Expose the host's own sshd as a service, then point ssh's
`ProxyCommand` at a forwarded stream. `--stdio` pipes the service over stdin/stdout instead of binding a
port, which is exactly the shape a `ProxyCommand` wants: ssh talks to the far sshd through the stream as
if it were local.

```sh
tightbeam expose ssh=127.0.0.1:22       # on the host: forward its real sshd
```

`/` is not legal in a hostname (and it is theia's device separator), so you cannot type `ssh alice/desk`
directly. Give ssh a legal alias in `~/.ssh/config` instead:

```
Host alice-desk
    ProxyCommand tightbeam connect <peer> --service ssh --stdio
```

Then `ssh alice-desk` reaches the far machine by key. `<peer>` is the host's node id or a `sheer:`
capability link. With a link, auth composes for free: the link names the node to dial and carries the
token, so a link that reaches only ssh and expires in an hour becomes an ssh `ProxyCommand` with nothing
else to configure.

**Expose any local service to someone by key.** A database, a media server, a Unix socket. Expose the
address; the other side binds it to a local port and points a normal client at it.

```sh
tightbeam expose db=127.0.0.1:5432        # on the host
tightbeam connect <peer> --service db --to 5432    # on your machine; then: psql -h 127.0.0.1 -p 5432
```

**HTTP through a node.** tightbeam ships no proxy and no fetcher; it forwards one someone runs. Run an
HTTP egress on a remote host, expose it, and forward to it: your traffic exits from that node.

```sh
# on the exit host: run any egress (an ssh SOCKS proxy here; dante / Caddy / mitmproxy also work)
ssh -D 1080 -N localhost
tightbeam expose 127.0.0.1:1080

# on your machine: bind it locally, then point apps at socks5://127.0.0.1:1080
tightbeam connect <exit-node-id> --to 1080
```

## From primitive to product: swoosh

tightbeam is the primitive. [swoosh](https://github.com/theia-hq/swoosh) is the product: it drives the
tightbeam library and turns the patterns above into clean, first-class verbs. Exposing a service is
`swoosh serve`; reaching an sshd is `swoosh ssh`; HTTP through a node is `swoosh fetch`; binding a
service to a local port is `swoosh forward`. Where tightbeam shows you the raw mechanism, swoosh gives
you the ergonomic tool built on it.

Reach for tightbeam when you want the primitive itself. Reach for swoosh when you want the polished
commands.

## Things to know

- Built on [`bifrost`](https://github.com/theia-hq/bifrost) (reach): each forwarded connection is one
  bidirectional stream. It is transport-blind and rides any bifrost transport.
- Only a peer holding the key can dial, and authorization is enforced by the
  [`nauthy`](https://github.com/theia-hq/nauthy) crate: the default gate admits a presented `sheer:`
  token rooted at this node's signet (a device's membership badge or a delegated service slip);
  `--public` is the only opt-out.
- Targets tightbeam forwards on its own: a `host:port` or `unix:<path>` (spliced to a local address), a
  `file:<path>` or `fifo:<path>` (a path's raw bytes sourced to the peer), and `stdin:` (whatever a
  producer pipes into `expose`, sourced to the peer; single-consumer, one reader takes it).
- A named service beyond a raw forward (a keyless shell, an HTTP fetcher, link diagnostics) is a handler
  a node injects into the registry. tightbeam knows the contract, never what such a service does, and
  ships none of its own; see [swoosh](https://github.com/theia-hq/swoosh) for the services a real node
  serves.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
