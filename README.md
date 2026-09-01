# tightbeam

Reach a public key, prove you belong at its gate, and get a raw byte-stream to a named service behind it,
over any transport, across any NAT. That is the whole of what tightbeam is: one primitive, a forwarded
stream to a service someone named.

A machine exposes local services under its public key, each behind a gate. Another machine, holding the
key and passing the gate, reaches a service and gets a plain bidirectional stream to it. No port
forwarding, no VPN, no public IP. `ssh -L` shaped, but pubkey-addressed and peer to peer.

tightbeam is a Rust library. You embed it: build an `Exposer` to serve services behind a gate, or a
`Connector` to reach one and get a stream back. It ships no services of its own and prints nothing; the
program that embeds it supplies the services, the identity, and the output.

Powered by [bifrost](https://github.com/theia-hq/bifrost) for the keyed connection and
[nauthy](https://github.com/theia-hq/nauthy) for authorizing who may connect.

**The name.** A tightbeam is a tight, aimed beam: a private point-to-point link that goes only where you
point it, not out to everyone. That is what this does, one machine's service reaching exactly one other,
addressed by key. The word is borrowed from The Expanse, where a tightbeam is a directed transmission
aimed at a single ship, not a broadcast. The privacy is in the aim; the security, here, is in the key at
each end.

> Experimental. Works for TCP over the iroh transport; not ready for production use.

## The CLI is swoosh

tightbeam is the library. The command-line tool built on it is
[swoosh](https://github.com/theia-hq/swoosh): `swoosh serve` exposes services, `swoosh ssh` reaches an
sshd, `swoosh forward` binds a service to a local port, `swoosh fetch` sends HTTP through a node. If you
want a tool to run, reach for swoosh. If you want to build reaching a keyed service into your own program,
read on.

## Add it as a dependency

Not yet published. Point at a checkout:

```toml
[dependencies]
tightbeam = { path = "../tightbeam" }
```

You also depend on `bifrost` (to bind an overlay node) and `nauthy` (to build the gate).

For the whole expose-then-reach flow in one runnable file, see
[`examples/reach_a_service_by_key.rs`](examples/reach_a_service_by_key.rs): `cargo run --example
reach_a_service_by_key` exposes a local service on one node and reaches it by key from another, no network
needed.

## Serve services behind a gate

An `Exposer` accepts overlay sessions from permitted peers and forwards each inbound stream to the
service it asks for. You build it from three things: the services to publish, a `Registry` of handlers
for the named ones, and the `Gate` that decides who may reach them.

```rust
use nauthy::{Denylist, Gate};
use tightbeam::tunnel::{resolve_gate, Exposer, Registry, Services};

// Parse `name=addr` entries. A `host:port` or `unix:<path>` is a raw forward tightbeam
// serves itself; a bare `scheme:` names a handler you register below.
let services = Services::parse(&["web=127.0.0.1:8080".into(), "ssh=sshd:".into()])?;

// The gate: `resolve_gate(public, signet, denylist)` applies one policy. `public = true`
// opens it to anyone; otherwise it admits the signet's own devices and their delegates.
let gate = resolve_gate(false, Some(signet), Denylist::default())?;

// Serve `web` (a raw forward) and `ssh` (a handler you inject, next).
let exposer = Exposer::new(services, registry, gate)?;
exposer.run(&node).await?;   // runs until cancelled; prints nothing
```

## Inject a named service

A raw forward (a `host:port` or `unix:<path>`) tightbeam splices on its own. Anything else is a handler
you register: a name maps to code that consumes one admitted stream. tightbeam knows only that contract,
never what a handler does, and ships none of its own.

```rust
use std::sync::Arc;
use futures::FutureExt as _;
use tightbeam::tunnel::{Handler, Registry, ServeFn};

// A handler receives the gate's `Admitted` witness (proof this stream passed the gate) and
// the raw stream halves. It does whatever the service is.
let serve: ServeFn = Arc::new(|_admitted, writer, reader| {
    async move { my_shell(writer, reader).await }.boxed()
});

// `gated` marks a handler that has no auth of its own (a shell is remote code execution):
// an open gate over it is refused at `Exposer::new`. `open` marks one safe to expose publicly.
let registry = Registry::new().with("sshd", Handler::gated(serve));
```

The `Admitted` witness is single-use and moved into the handler by value, so a handler cannot run for a
peer the gate did not admit: "authorize before serve" is a compile-time precondition, not a check you
remember to write.

## Reach a service, get a stream

A `Connector` reaches one exposed service on a peer and hands back a bidirectional stream. Build it from a
node id (optionally presenting a `sheer:` capability token) or from a `sheer:` link that carries both the
node to dial and the token.

```rust
use tightbeam::tunnel::Connector;

// Reach `ssh` on a peer, bind it to local port 2222, forward every connection.
let connector = Connector::to_node(peer_id, "ssh".into(), None);
let forward = connector.preflight(&node, 2222).await?;   // proves the gate admits us first
forward.run().await?;

// Or reach it via a capability link, which supplies the node and the token together.
let connector = Connector::from_link("sheer:<node>.<token>", "ssh".into())?;
```

`preflight` proves admission before returning: a refusal (wrong service, a revoked or non-granting token,
an unauthorized identity) surfaces as an error from that call, carrying the host's reason, not as a
silently reset connection later. `pipe_stdio` streams the service over this process's stdin/stdout
instead of binding a port, which is the shape an ssh `ProxyCommand` wants. `open_service` returns a
`ServiceSession` whose every stream rides the gate, for a protocol that is generic over a bifrost session.

## Capabilities: hand out an expiring key

The default gate accepts `sheer:` capability tokens: a signed, expiring, attenuable link rooted at a
node's signet, verified offline with no server and no allowlist to sync. tightbeam exposes the offline
operations on them as plain functions.

```rust
use core::time::Duration;
use tightbeam::tunnel::{mint_link, narrow_link, revoke_into};

// Mint a link granting one service, valid two hours, that the holder may narrow and hand on.
let link = mint_link(&identity, &service, Duration::from_secs(2 * 3600), true)?;

// A holder narrows it further, offline, before delegating (no key, no network).
let tighter = narrow_link(&link, Some(&service), Some(Duration::from_secs(1800)))?;

// Revoke a link into a denylist, so the gate refuses it and everything attenuated from it.
revoke_into(&mut denylist, &link).await?;
```

The link works only for the service it grants, expires on its own, and can be narrowed and delegated
without the host's involvement. Revoking cuts it off at once; short expiry backs that up.

## What a forward carries

A forward carries bytes. Anything that speaks over a TCP port or a Unix socket rides it unchanged: the
program on each end does not know the overlay is there. The service on the host is one of:

- a `host:port` or `unix:<path>` (spliced to a local address), tightbeam's own raw forward;
- a `file:<path>` or `fifo:<path>` (a path's raw bytes sourced to the peer), or `stdin:` (whatever a
  producer pipes in). A `stdin:`/`fifo:` source is single-consumer by default; `+lossy` opts it into
  fan-out to many (see below);
- a named handler you injected (a keyless shell, an HTTP fetcher, link diagnostics).

For worked scenarios (ssh with no public IP, reach a database port, HTTP through a node), see
[examples.md](examples.md). Those are shown as swoosh commands, since swoosh is the tool; each is the same
one library move underneath.

## Fan-out (opt-in, loss-tolerant only)

By default a `stdin:` or `fifo:` source serves ONE consumer: the second connector is refused. Add `+lossy`
to send one live source to many consumers at once, dropping bytes for any consumer that falls behind:

```sh
# one webcam, many viewers; a slow viewer drops frames, it never stalls the others
ffmpeg ... | swoosh serve cam=stdin:+lossy
```

A consumer that reads too slowly has its oldest unread bytes discarded and jumps to the live edge. The
producer never waits on a consumer, and one slow consumer never gaps another. A late joiner starts from
now, not the beginning.

Use `+lossy` only for content where a dropped byte does not matter: a webcam, an audio feed, a log tail.
Never use it for EXACT bytes. A `tar`, a file, any byte-precise stream: a dropped byte is silent
corruption, not a skipped frame. Those stay single-consumer, or use `file:`, which re-opens per reader so
each gets the whole thing. Only the operator knows whether the content tolerates loss, so only the operator
can declare it: `+lossy` is refused on any scheme other than `stdin:`/`fifo:`, and refused under `--public`.

## The thin binary

There is a `tightbeam` binary, but it is a thin bridge, not the product: it drives the library over an
empty registry, so it serves only raw forwards. Its one real use is as an ssh `ProxyCommand` (reach an
sshd over a stream), before swoosh is on a machine. swoosh owns the full CLI.

## The honest limit

A capability is a bearer token: whoever holds an unexpired, un-revoked one gets that one service until it
expires or you revoke it. Short expiry and revocation are how you bound that.

## Things to know

- Built on [`bifrost`](https://github.com/theia-hq/bifrost): each forwarded connection is one
  bidirectional stream. It is transport-blind and rides any bifrost transport.
- Authorization is enforced by [`nauthy`](https://github.com/theia-hq/nauthy): the default gate admits a
  presented `sheer:` token rooted at the node's signet (a device's membership badge or a delegated service
  slip); an open gate is the only opt-out, and a handler with no auth of its own may not sit behind one.
- A named service (a keyless shell, an HTTP fetcher, link diagnostics) is a handler a caller injects into
  the registry. tightbeam knows the contract, never what such a service does, and ships none of its own;
  see [swoosh](https://github.com/theia-hq/swoosh) for the services a real node serves.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
</content>
</invoke>
