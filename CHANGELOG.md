# Changelog

All notable changes to tightbeam, newest first. This first entry reaches back over the arc since v0.3.0,
so nothing user-facing is lost.

## v0.4.0 - 2026-09-05

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
