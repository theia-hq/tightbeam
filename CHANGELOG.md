# Changelog

All notable changes to tightbeam, newest first.

## Unreleased

### Fixed
- **A disabled service is checked after admission, not before.** The enabled oracle ran ahead of the
  gate, so a stranger could tell a disabled name from a gated one by timing; it now runs after the gate
  admits, and both refuse on the same uniform class.
- **A `fifo:+lossy` source re-arms.** A failed first open (the path absent) left the source disarmed for
  every later dial; it now retries the open on the next consumer, and a session whose pump has ended
  re-opens the FIFO for the next one instead of refusing until restart. `stdin:+lossy` stays one
  session, as documented.
- **A lagging `+lossy` consumer is reported.** The host log warns once per lapse with the dropped-byte
  count, and the shared ring evicts the slowest cursor before it grows, so a stalled reader cannot hold
  bytes the feed has moved past.

### Changed
- **Pinned to the bifrost and nauthy revs that carry raw bind truth.** `bifrost::Transport` now requires
  `bound_sockets()`, so a program that brings its own transport to `Peer::discovery` must implement it; in
  return the composed mDNS discovery advertises the sockets the node actually bound, expanding a `0.0.0.0`
  bind into this host's own addresses instead of publishing the loopback address `local_addr` rewrites it
  to, and the outcome is logged rather than assumed. `nauthy::Link` is pointer-sized and reaches its `Cap`
  through `Link::cap()`.
- **`Router::catalog` no longer takes a gate.** The router has held its base gate since `Router::new`, so
  the catalog reads its own; `Router::gate()` hands that gate back for a program composing a node from it.
- **The public stream pool is pinned by test.** Four connected public streams fill the node-wide pool on
  any mix of public services; the fifth is refused on the uniform class and a released slot admits the
  next.

## v0.5.1

A dial-only `connect` no longer overwrites the address record a live `expose` node published.

### Fixed
- **The dialing bind publishes nothing.** `connect` binds under n0 discovery without the address-record
  publisher, so a short-lived client process cannot replace a serving node's relay path with its own; the
  role is chosen per verb (`expose` serves and publishes, `connect` dials and resolves only).

## v0.5.0

One route table, a handler contract that carries its exposure as a type, and a refusal the client matches
rather than parses.

### New
- **The `Router` route table.** `Router::new(gate)` binds each served name to a handler (`.service`), the
  loopback reflector (`.echo`), a local forward (`.forward`), or a raw-stream source (`.raw_stream`), then
  proves the node once with `.expose()`; `.catalog()` reads back the served names and each route's
  `Posture`. A handler serves the `Served<Self>` proof the gate prepared for it, which carries the
  single-use admission witness and narrows to a rooted one with `into_rooted()`; `ServeError` reports a
  served-stream failure and `Metering` declares a handler's own bound.
- **The rooted-witness handoff.** `RootedAdmitted::into_admitted` hands a rooted proof back to the untyped
  gate witness for a handler that does not take `RootedAdmitted` yet; only a rooted admission can produce
  one, so the handoff cannot widen.
- **The `EnabledServices` gate oracle.** A `Revocations`-shaped, mtime-watched trait (with a
  `FileDisabledList` impl and an `AllEnabled` default), overlaid on an `Exposer` via `with_enabled`, that
  lets a consumer disable a served service live: the gate refuses a disabled service with the same uniform
  refusal a gate miss gives, fail-closed (a read error keeps the last-known set), restored on re-enable with
  no restart.
- **The `tightbeam-handler` crate.** The handler contract now lives in its own lean crate in this repo:
  the `Handler` trait, the `Never`/`OptIn` exposure markers, the serving proofs, and the erased dispatcher
  bridge. A service crate can depend on it directly, without tightbeam's backends or binary; tightbeam
  re-exports the same author-facing items at their original paths.
- **`PresentingConnector`.** The credential-bearing dial in compile-time-checked form: every dial method
  requires the transport's declared profile to prove the peer (`T::Security: PeerProven`), so presenting a
  capability over a self-announced transport does not compile. The unbounded `Connector` carries the same
  rule at run time.
- **Member-only routes.** `Router::member_service` binds a route reachable only by a peer the gate admitted
  as a whole-node member. The floor is checked once after admit and before any `Response::Ok`, and a miss
  takes the same uniform refusal as a gate miss.

### Changed
- **BREAKING: `Router` replaces the `Registry`/`Services` assembly, and the scheme indirection leaves the
  public surface.** A route binds a handler by value or parses `name=target`; a bare `<name>:` no longer
  resolves, and the binary refuses a bad entry before it prints its ready banner. `Echo` and `Forward` are
  first-party handlers; `RawStream` stays a native target.
- **The public path is bounded: 32 public sessions and 4 public streams.** The pool is taken where a
  public session is admitted, refused past the cap with the same uniform refusal a gate miss gives, never
  queued, and released on close, so a stranger flood cannot starve members.
- **A credential moves only over a transport that proves the peer.** A request that presents a capability
  or a membership badge is refused before its first byte when the session's declared profile does not prove
  the peer; a rooted admission refuses such a session before minting a witness; and a rooted exposer
  refuses to arm over one (`Exposer::prove_security`), so a gated node never serves over a transport that
  only announces the peer. The default iroh transport is unaffected.
- **The typed `Link` and `Service` surface.** The public API carries `Service` and typed `Link` values and
  converts to raw text only at the request edge. The raw-string mint, narrow, and revoke free functions are
  gone in favor of `nauthy::Link` methods, and `EnabledServices` keys on `Service`.
- **`TB04`: the refusal crosses the wire typed.** A response is reached or refused, and a refusal is a
  class plus a bounded detail instead of a free-form string, so a client matches the class rather than
  parsing text. A `TB03` peer is not wire compatible: the two ends of one tunnel are one release.
- **`type Exposure` replaces `type Public`.** A handler's open-safety ceiling is now named `Exposure`, the
  legitimacy ceiling ("may this ever face a stranger"), not `Public` ("is it public"). The marker values
  and the compile-time refusal are unchanged.

### Fixed
- **The binary's identity file fails closed and writes atomically.** A present key file that does not
  decode is an error, never silently replaced by a fresh key; the write stages a sibling temp, fsyncs, and
  renames over the target, so a crash leaves the old key or the complete new one, and a group- or
  world-readable file is refused.
- **Diagnostics no longer ride stdout.** The binary's tracing subscriber writes to stderr, so a log line
  cannot interleave with a verb's stdout: the `connect --to -` bridge carries the peer's bytes there
  unbroken, and `tree` and banner output stay parseable.

## v0.4.0

### New
- **The `Handler` trait.** A named service is any type that consumes one admitted stream, injected through
  a `Registry`. It carries its open-safety as a type: `type Public = Never` (a handler that may never face
  a stranger, such as a keyless shell) or `OptIn` (a legitimately public responder). An open gate over a
  `Never` handler is refused at `Exposer::new`, so a keyless service mislabeled open does not compile.
- **`ServiceCatalog`.** A node's served service names and the `Posture` (gated or open) a dialer faces for
  each. A member may read it; a stranger cannot, so it never becomes a service-enumeration oracle.
- **Device-bound and signet-bound link mints.** `mint_bound_link` binds a `sheer:` link to one device, so
  a copy observed in flight or at rest grants no one. `mint_signet_link` issues one link to a whole fleet:
  every device that fleet vouches for may use it, and only when the presenter also proves membership under
  that fleet.
- **The `TB03` wire and the two-cap admit.** Each stream opens with a small versioned preamble carrying
  the service name, an optional capability in slot 1, and an optional membership badge in slot 2. A
  signet-bound slip in slot 1 is admitted only when slot 2 also proves the presenter is a member of that
  fleet, ANDing the two. Every plain dial presents slot 1 alone, and the host never consults slot 2.
- **Open a service to strangers.** `Exposer::with_public` overlays named public services on the base gate;
  each is proven exposable and safe to open first, and a `Never` handler can never be opened this way.
- **`ServiceSession`.** `Connector::open_service` hands back a session whose every stream rides the gate,
  so any protocol generic over a bifrost session runs over the tunnel unchanged.
- **More raw-stream sources.** A `stdin:` source streams whatever a producer pipes in; guarded `file:` and
  `fifo:` sources stream a path's bytes to the peer. Single-consumer by default.
- **An `echo:` source.** A zero-argument symmetric reflector that sends back whatever a peer sends. It is
  safe to open to strangers as-is, so it is the one raw stream a plain `--public` may serve, with no
  `--public-unsafe`: the ideal first thing to try on one machine.
- **`--public` and `--public-unsafe` in the binary.** `--public` opens the node's handlers and forwards
  (and `echo:`) to strangers. Serving a raw `file:`/`fifo:`/`stdin:` source to strangers additionally
  requires naming it under `--public-unsafe`, since those hand out bytes with no responder to gate them; a
  keyless shell is refused outright.
- **`+lossy` raw-stream fan-out.** One source serves many consumers over unreliable datagrams, dropping
  bytes for a consumer that falls behind. A live feed, never exact bytes, so it is refused on any other
  scheme and under an open gate.
- **Dotted handler schemes.** A handler name may split into a method (`diag.ping`, `diag.speed`), so one
  service can carry several methods.

### Changed
- **A pure library, not a CLI.** tightbeam prints nothing and ships no services of its own. The
  command-line surface moved into a thin binary; the embedding program supplies the services, the identity,
  and the output.
- **One uniform refusal.** A dialer the gate does not admit gets a single indistinguishable "refused": no
  reason that separates a stranger from a revoked token from a wrong service, and no service menu. A
  service's existence and shape are revealed only after the gate admits you for it, so the wire is not a
  capability-enumeration or revocation oracle. The real reason still reaches the host's own logs.
- **A forward proves admission up front.** `preflight` returns only after the gate admits, so a refusal
  (unreachable, revoked, or unauthorized) surfaces from that call rather than as a silently reset
  connection later.

### Fixed
- **No leaked threads on `fifo:`/`stdin:` sources.** Those sources open nonblocking, and concurrent
  raw-stream opens are capped, so a stalled or flooded source cannot exhaust threads.
- **A `file:` source now serves on Linux.** A regular file cannot register with epoll (it returns `EPERM`),
  which had made `file:` sources fail to start on Linux while working on macOS. Regular files now read
  through a blocking path instead of the readiness poller.
- **Graceful shutdown.** On a termination signal the binary closes the node before exiting, so the iroh
  endpoint tears down cleanly rather than leaving a peer to time out a dropped connection.
