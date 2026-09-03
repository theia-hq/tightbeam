# tightbeam

Reach a service on a machine by its public key, prove you belong at its gate, and get a raw bidirectional
byte stream to it, over any transport and across any NAT. That is the whole of tightbeam: one primitive, a
forwarded stream to a service someone named, addressed by key rather than by host and port.

A machine exposes local services under its public key, each behind a gate. Another machine, holding the key
and passing the gate, reaches one service and gets a plain byte stream to it. Anything that speaks over a
TCP port or a Unix socket rides it unchanged. No port forwarding, no VPN, no public IP.

tightbeam is a Rust library you embed. You build an `Exposer` to serve services behind a gate, or a
`Connector` to reach one and get a stream back. It ships no services of its own and prints nothing: the
program that embeds it supplies the services, the identity, and the output. The keyed connection underneath
is [bifrost](https://github.com/theia-hq/bifrost)'s; who may pass a gate is
[nauthy](https://github.com/theia-hq/nauthy)'s.

**The name.** A tightbeam is a tight, aimed beam: a private point-to-point link that goes only where you
point it, not out to everyone. That is what this does, one machine's service reaching exactly one other,
addressed by key. The word is borrowed from The Expanse, where a tightbeam is a directed transmission aimed
at a single ship, not a broadcast. The privacy is in the aim; the security, here, is in the key at each end.

> Experimental. Works for TCP over the iroh transport; not ready for production use.

## Add it as a dependency

Not yet published. Point at a checkout:

```toml
[dependencies]
tightbeam = { path = "../tightbeam" }
```

You also depend on `bifrost` (to bind an overlay node) and `nauthy` (to build the gate and mint
capabilities). Three runnable examples show the whole library, no network needed (`cargo run --example
<name>`):

- [`reach_by_key`](examples/reach_by_key.rs): expose a service on one node and reach it by key from another
  (the core loop).
- [`gate_a_service`](examples/gate_a_service.rs): put it behind a signet gate, mint a capability, and watch
  it admitted with the cap and refused without.
- [`named_handler`](examples/named_handler.rs): inject your own `Handler` and reach it by name (the
  extension point every named service is built on).

## Reach a service, get a stream

A `Connector` reaches one exposed service on a peer and hands back a bidirectional stream. Build it from a
node id (optionally presenting a capability token) or from a `sheer:` link that carries both the node to
dial and the token.

```rust
use tightbeam::tunnel::Connector;

// Reach `web` on a peer, bind it to local port 8080, forward every connection.
let forward = Connector::to_node(peer_id, "web".into(), None)
    .preflight(&node, 8080)   // proves the gate admits us before it returns
    .await?;
forward.run().await?;

// Or reach it via a capability link, which supplies the node and the token together.
let forward = Connector::from_link("sheer:<node-id>.<token>", "web".into())?
    .preflight(&node, 8080)
    .await?;
```

`preflight` proves admission before it returns: a refusal (a service you cannot reach, a revoked or
non-granting token, an unauthorized identity) surfaces as an error from that call, carrying the host's
reason, not as a silently reset connection later. Two other shapes reach the same service differently:
`pipe_stdio` streams it over this process's stdin and stdout instead of binding a port (the shape an ssh
`ProxyCommand` wants), and `open_service` returns a `ServiceSession` whose every stream rides the gate, so
any protocol generic over a bifrost session runs over the tunnel unchanged.

## Serve services behind a gate

An `Exposer` accepts overlay sessions from permitted peers and forwards each inbound stream to the service
it names. You build it from three things: the services to publish, a `Registry` of handlers for the named
ones, and the `Gate` that decides who may reach them.

```rust
use nauthy::Denylist;
use tightbeam::tunnel::{self, CancellationToken, Exposer, Registry, Services};

// `name=addr` entries. A `host:port` or `unix:<path>` is a raw forward tightbeam splices itself;
// a bare `<name>:` scheme names a handler you register (see below).
let services = Services::parse(&["web=127.0.0.1:8080".into(), "shell=sh:".into()])?;

// The gate is the node's family authority, rooted at its signet (its own devices and their
// delegates). An unprovisioned node fails loud here rather than falling open. The caller loads the
// denylist from wherever it persists revocations and passes it in.
let gate = tunnel::resolve_gate(Some(signet), denylist)?;

let exposer = Exposer::new(services, registry, gate)?;
exposer.run(&node, CancellationToken::new()).await?;   // runs until cancelled; prints nothing
```

`Exposer::new` is a fully-gated node: every service faces the family gate. Opening a service to strangers is
a deliberate second step, `Exposer::with_public(PublicRequest::new([...]))`, which proves each named service
is exposed and safe to open before the node serves it. A handler with no authorization of its own (a keyless
shell) can never be opened this way. The `CancellationToken` is the node's teardown seam: a caller may hold
a clone and fire it to stop the accept loop.

## Inject a named service

A raw forward (a `host:port` or `unix:<path>`) tightbeam splices on its own. Anything else is a `Handler`
you register: a name maps to code that consumes one admitted stream. tightbeam knows only that contract,
never what a handler does, and ships none of its own.

```rust
use nauthy::Admitted;
use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, Registry};

struct Shell;

impl Handler for Shell {
    // Whether this handler may EVER face a stranger is a compile-time property, stated once as a
    // type. A keyless shell is remote code execution, so it names `Never`: an open gate over it is
    // refused at `Exposer::new`. A legitimately public responder names `OptIn` instead. There is no
    // default and no runtime flag, so "a keyless service mislabeled open" does not compile.
    type Public = Never;

    async fn serve(&self, admitted: Admitted, writer: BoxWrite, reader: BoxRead) -> eyre::Result<()> {
        // `admitted` is the gate's single-use witness, moved in by value: this code cannot run for a
        // peer the gate did not admit. "Authorize before serve" is a precondition the compiler enforces.
        run_shell(admitted, writer, reader).await
    }
}

let registry = Registry::new().with("sh", Shell);
```

## Hand out an expiring key

A gate rooted at a node's signet admits the node's own devices and their delegates. A delegate holds a
`sheer:` capability: a signed, expiring, attenuable link the gate verifies offline, with no server in the
loop and no allowlist to sync. tightbeam exposes minting, narrowing, and revoking as plain operations over
these links.

```rust
use core::time::Duration;
use tightbeam::tunnel::{mint_bound_link, mint_link, mint_signet_link, narrow_link, revoke_into};

// A delegable link granting one service for two hours; the holder may narrow it and hand it on.
let link = mint_link(&identity, &service, Duration::from_secs(2 * 3600), true)?;

// Bind a link to one device, so a copy observed in flight or at rest grants no one.
let bound = mint_bound_link(&identity, &service, device_key, Duration::from_secs(3600))?;

// Issue once to a whole fleet: every device that fleet vouches for may use it, and only when the
// presenter ALSO proves membership under that fleet (the two-token admission the wire carries below).
let slip = mint_signet_link(&identity, &service, fleet_root, Duration::from_secs(3600))?;

// A holder narrows a link further, offline, before delegating (no key, no network).
let tighter = narrow_link(&link, Some(&service), Some(Duration::from_secs(1800)))?;

// Revoke a link into a denylist, so the gate refuses it and everything attenuated from it.
revoke_into(&mut denylist, &link).await?;
```

A link works only for the service it grants, expires on its own, and can be narrowed and delegated without
the host's involvement. Revoking cuts it off at once; short expiry backs that up.

## What a forward carries

A forward carries bytes. The program on each end does not know the overlay is there. The service on the host
is one of:

- a `host:port` or `unix:<path>`, spliced to a local address: tightbeam's own raw forward;
- a `file:<path>` or `fifo:<path>` (a path's raw bytes sourced to the peer), or `stdin:` (whatever a
  producer pipes in). A `stdin:` or `fifo:` source serves ONE consumer by default; `+lossy` opts it into
  fan-out to many, dropping bytes for any consumer that falls behind (a live feed, never exact bytes: a
  dropped byte in a `tar` is silent corruption, so `+lossy` is refused on any other scheme and under an open
  gate);
- a named `Handler` you injected (a shell, or any code that consumes one admitted stream).

## The wire

Each stream opens with a small versioned preamble, `TB03`, before any bytes flow: the service name, an
optional capability in slot 1, and an optional membership badge in slot 2. The host replies reached or
refused, then the transparent byte pipe begins.

- **Two-cap admit.** A signet-bound slip in slot 1 grants a service to a whole fleet without naming a
  device. The host admits it only when slot 2 also proves the presenter is a member of that fleet, ANDing
  the two. Every plain dial presents slot 1 alone, and the host never consults slot 2.
- **One uniform refusal.** A dialer the gate does not admit gets a single indistinguishable "refused": no
  reason that separates a stranger from a revoked token from a wrong service, and no service menu. The
  existence and shape of a service are revealed only after the gate admits you for it, so the wire is not a
  capability-enumeration or revocation oracle. The real reason still reaches the host's own logs.
- **The catalog is member-only.** A member may read the node's `ServiceCatalog`: its served service names
  and the `Posture` (gated or open) a dialer faces for each. A stranger cannot.

## The thin binary

There is a `tightbeam` binary, but it is a thin bridge, not the product: it drives the library over an empty
registry, so it serves only raw forwards. Its one real use is as an ssh `ProxyCommand`, reaching an sshd
over a stream. The library is the product; the binary is a way to exercise it from the shell.

## The honest limit

A capability is a bearer token: whoever holds an unexpired, un-revoked one gets that one service until it
expires or you revoke it. A device-bound or signet-bound link narrows that (a copy alone grants no one), and
short expiry and revocation bound the rest.

## A tool built on this

swoosh is a command-line tool built on tightbeam; see
[swoosh](https://github.com/theia-hq/swoosh) for a worked consumer that drives this library end to end.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
