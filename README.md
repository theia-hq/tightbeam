# tightbeam

A node serves named services behind one gate, addressed by its public key. Another machine that holds the
key and passes the gate gets a raw byte stream to the one service it asked for, and nothing else. Anything
that speaks over a TCP port or a Unix socket rides it unchanged; a handler you write serves anything else.
No port forwarding, no VPN, no public IP.

tightbeam is a Rust library you embed. A `Router` binds each name to a service and proves the node once at
`expose()`; a `Connector` reaches one service on a peer and hands back the stream.

```rust
use tightbeam::tunnel::Router;

let node = Router::new(gate)                        // one gate in front of every route
    .service("ssh".parse()?, Sshd::new(host_seed))? // a handler you import; never opens
    .forward("web".parse()?, "tcp:127.0.0.1:8080")? // a local port, spliced
    .echo("demo".parse()?)?                         // a built-in
    .public(["demo".parse()?])                      // opened to anyone, by name
    .expose()?;                                     // proves every route before it serves
node.run(&bifrost_node, cancel).await?;
```

It prints nothing and ships only its own built-ins (`echo:`, forwards, raw streams): the program that
embeds it supplies the identity, the other services, and the output. The keyed connection underneath is
[bifrost](https://github.com/theia-hq/bifrost)'s; who may pass a gate is
[nauthy](https://github.com/theia-hq/nauthy)'s; the engines a node commonly serves are in
[services](https://github.com/theia-hq/services).

> Experimental. Works for TCP over the iroh transport; not ready for production use.

## Add it as a dependency

Git-only for now, not published to crates.io. Point at the repo:

```toml
[dependencies]
tightbeam = { git = "https://github.com/theia-hq/tightbeam", tag = "v0.5.1" }
```

A service crate that implements the contract without the rest of tightbeam depends on `tightbeam-handler`
alone: the `Handler` trait, the `Never`/`OptIn` markers, and the served proof, with no backends and no
binary (`tightbeam-handler = { git = "https://github.com/theia-hq/tightbeam", tag = "v0.5.1" }`).
`tightbeam` re-exports the same items at their original paths.

You also depend on `bifrost` (to bind an overlay node) and `nauthy` (to build the gate and mint
capabilities). Three runnable examples show the whole library, no network needed (`cargo run --example
<name>`):

- [`reach_by_key`](examples/reach_by_key.rs): expose a service on one node and reach it by key from another
  (the core loop).
- [`gate_a_service`](examples/gate_a_service.rs): put it behind a signet gate, mint a capability, and watch
  it admitted with the cap and refused without.
- [`named_handler`](examples/named_handler.rs): inject your own `Handler` and reach it by name (the
  extension point every named service is built on).

This page describes the default branch; the released docs are at the newest tag.

## Reach a service, get a stream

A `Connector` reaches one exposed service on a peer and hands back a bidirectional stream. Build it from a
node id (optionally presenting a capability token) or from a link that carries both the node to
dial and the token. A dial that presents a credential has a compile-time-checked form,
`PresentingConnector`: it requires the transport to prove the peer, so a credential over a transport that
only announces the peer does not compile. The unbounded `Connector` carries the same rule at run time, for
a transport chosen dynamically.

```rust
use nauthy::Link;
use tightbeam::tunnel::{Connector, PresentingConnector};

// Reach `web` on a peer, bind it to local port 8080, forward every connection.
let forward = Connector::to_node(peer_id, "web".parse()?, None)
    .preflight(&node, 8080)   // proves the gate admits us before it returns
    .await?;
forward.run().await?;

// Or reach it via a capability link, which supplies the node and the token together.
let link: Link = "<key>.<token>".parse()?;
let forward = PresentingConnector::from_link(&link, "web".parse()?)
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

A [`Router`](src/tunnel/router.rs) is one route table: bind each served name to a handler, a local forward, a
raw-stream source, or the built-in loopback reflector, then prove the whole node once with `.expose()`. The
proved [`Exposer`](src/tunnel/exposer.rs) accepts overlay sessions from permitted peers and forwards each inbound
stream to the service it names.

```rust
use tightbeam::tunnel::{self, CancellationToken, Router};

// `echo` is the built-in loopback reflector: it opens no host resource, so it is the safe public demo.
// `forward` is the built-in local forward. A `handler` you wrote binds the same way (see below).
let gate = tunnel::resolve_gate(Some(signet), denylist)?;   // family gate on the node's signet
let exposer = Router::new(gate)
    .echo("demo".parse()?)?
    .forward("web".parse()?, "tcp:127.0.0.1:8080")?
    .expose()?;
exposer.run(&node, CancellationToken::new()).await?;   // runs until cancelled; prints nothing
```

`Router::new(gate)` is a fully-gated node: every route faces the family gate. Opening a legitimate service
to strangers is a deliberate second step, `.public(names)` (a safe handler opened per service), which
`.expose()` proves before the node serves it. A handler that declares itself closed (`Never`: a keyless
shell) is refused when the proof is prepared, and a raw byte source (`file:`/`fifo:`/`stdin:`) is
redirected to the distinct, louder `.public_unsafe(names)` opt-in. `.parse(&["web=tcp:127.0.0.1:8080".into()])`
absorbs the `name=target` grammar, where every target carries a scheme and the set is closed: an unknown
scheme is an error naming the legal set, since handlers bind by value. The `CancellationToken` is the
node's teardown handle: a caller may hold a clone and fire it to stop the accept loop.

The exposer proves the transport as well: `Exposer::run` refuses to arm a rooted gate over a transport
that does not prove the peer, and `Exposer::prove_security::<T>()` exposes the same check to a caller that
announces readiness before `run`.

## Inject a named service

tightbeam knows only the [`Handler`](tightbeam-handler/src/lib.rs) contract, never what a handler does. A handler names its
`Exposure` ceiling as a type (`Never` for a keyless shell, `OptIn` for a legitimately public responder),
declares its `Metering` if it bounds callers, and serves one admitted stream from the `Served<Self>` proof
the gate prepared for it. The declaration is the author's: the marker prevents an omitted choice and a
third variant, not a mislabeled one.

```rust
use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, ServeError, Served};

struct Shell;

impl Handler for Shell {
    // Whether this handler may EVER face a stranger is a compile-time property, stated once as a type. A
    // keyless shell is remote code execution, so it names `Never`: an open gate over it is refused when
    // the proof is prepared. A legitimately public responder names `OptIn`. The choice cannot be omitted
    // and the marker set is sealed, so there is no default and no third marker; the declaration is the
    // author's, and an `OptIn` service still takes a deliberate operator opt-in to reach a stranger.
    type Exposure = Never;

    async fn serve(
        &self,
        served: Served<Self>,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> Result<(), ServeError> {
        // `served` carries the gate's single-use witness: this code cannot run for a peer the gate did
        // not admit. An engine whose safety rests on a ROOT-verified peer narrows it with
        // `served.into_rooted()?` (an open witness is refused).
        let rooted = served.into_rooted()?;
        run_shell(rooted, writer, reader)
    }
}

let exposer = Router::new(gate).service("sh".parse()?, Shell)?.expose()?;
```

## Hand out an expiring key

A gate rooted at a node's signet admits the node's own devices and their delegates. A delegate holds a
capability: a signed, expiring, attenuable link the gate verifies offline, with no server in the
loop and no allowlist to sync. The link is a [`nauthy::Link`], and minting, narrowing, and revoking are
methods on it.

```rust
use core::time::Duration;
use nauthy::Link;

// A delegable link granting one service for two hours; the holder may narrow it and hand it on.
let link = Link::mint(&identity, &service, Duration::from_secs(2 * 3600))?;

// Bind a link to one device, so a copy observed in flight or at rest grants no one.
let bound = Link::mint_bound(&identity, &service, device_key, Duration::from_secs(3600))?;

// Issue once to a whole fleet: every device that fleet vouches for may use it, and only when the
// presenter ALSO proves membership under that fleet (the two-token admission the wire carries below).
let slip = Link::mint_signet(&identity, &service, fleet_root, Duration::from_secs(3600))?;

// A holder narrows a link further, offline, before delegating (no key, no network).
let tighter = link.narrow(Some(&service), Some(Duration::from_secs(1800)))?;

// Revoke a link into a denylist, so the gate refuses it and everything attenuated from it.
link.revoke(&mut denylist).await?;
```

A link works only for the service it grants, expires on its own, and can be narrowed and delegated without
the host's involvement. Revoking cuts it off at once; short expiry backs that up.

## What a forward carries

A forward carries bytes. The program on each end does not know the overlay is there. The service on the host
is one of:

- a `tcp:<host>:<port>` or `unix:<path>`, spliced to a local socket: the built-in `Forward` service;
- a `file:<path>` or `fifo:<path>` (a path's raw bytes sourced to the peer), or `stdin:` (whatever a
  producer pipes in). A `stdin:` or `fifo:` source serves one consumer at a time. `stdin:+lossy` or
  `fifo:<path>+lossy` fans it out to many, dropping bytes for a consumer that falls behind: a live feed,
  never exact bytes (a dropped byte in a `tar` is silent corruption), with the host log noting each
  lapse. A `fifo:+lossy` source re-opens for the next consumer; a `stdin:+lossy` source is one session,
  over for good once its last consumer leaves. A raw source opens to anyone only through
  `--public-unsafe`;
- a named `Handler` you bound with `.service(name, handler)` (a shell, or any code that consumes one
  admitted stream).

## The wire

Each stream opens with a small versioned preamble, `TB04`, before any bytes flow: the service name, an
optional capability in slot 1, and an optional membership badge in slot 2. The host replies reached or
refused, then the transparent byte pipe begins.

- **Two-cap admit.** A signet-bound slip in slot 1 grants a service to a whole fleet without naming a
  device. The host admits it only when slot 2 also proves the presenter is a member of that fleet, ANDing
  the two. Every plain dial presents slot 1 alone, and the host never consults slot 2.
- **One uniform refusal.** A dialer the gate does not admit gets one payload-free refusal (`Refused`): no
  reason that separates a stranger from a revoked token from a wrong service, and no service menu. The
  existence and shape of a service are revealed only after the gate admits you for it, so the wire is not a
  capability-enumeration or revocation oracle. The real reason still reaches the host's own logs.
- **The catalog is member-only.** A member may read the node's `ServiceCatalog`: its served service names
  and the `Posture` (gated or open) a dialer faces for each. A stranger cannot.

## The binary

The library is the product, but the `tightbeam` binary is a real command-line tool that drives it from the
shell, and the [getting-started walkthrough](examples.md) runs entirely on it. It exposes services (raw
`tcp:` / `unix:` forwards, and the `echo:` / `stdin:` / `file:` / `fifo:` sources), gated by default or
opened with `--public` (and `--public-unsafe` for a raw source); it reaches them with `connect`; and it
mints, shares, and revokes links. It registers no `Handler` of its own, so a named handler (a
shell, say) is something a library embedder adds in code. On its own the binary already covers forwarding,
raw streams, and an ssh `ProxyCommand`.

## The limit

A capability is a bearer token: whoever holds an unexpired, un-revoked one gets that one service until it
expires or you revoke it. A device-bound or signet-bound link narrows that (a copy alone grants no one), and
short expiry and revocation bound the rest.

## The name

A tightbeam is a tight, aimed beam: a private point-to-point link that goes only where you
point it, not out to everyone. That is what this does, one machine's service reaching exactly one other,
addressed by key. The word is borrowed from The Expanse, where a tightbeam is a directed transmission aimed
at a single ship, not a broadcast. The privacy is in the aim; the security, here, is in the key at each end.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
