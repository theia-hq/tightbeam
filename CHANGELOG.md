# Changelog

All notable changes to tightbeam, newest first.

## v0.14.0

A live session ends when its access does, and `stdin:` is handed on instead of used up.

### Added
- **A live session is cut when its access ends.** Before, a revocation only refused the next stream,
  and a session already open ran until its peer left. Now `Exposer::with_live_cuts(cuts)` re-checks every
  live session about once a second and closes it, with every stream on it, when:
  - a capability it was admitted on is revoked;
  - its root key is disabled; or
  - every grant it was admitted on has expired. Expiry is read from the whole chain, so a holder's
    narrower attenuation ends the session at its own instant.

  `LiveCuts` is the rule and `AdmittedChains` what a session keeps for it; both are exported from
  `tightbeam::tunnel`. `LiveCuts` is implemented for nauthy's `FileDenylist`, for `Latch` and for an
  `Arc` of either. Without `with_live_cuts` nothing is armed and sessions end as before. A session keeps
  at most 1,024 revocation ids; a stream past that is refused as a gate miss is. A cap whose expiry reads
  in a shape nauthy never writes, or past the clock's range, is refused at admission.
- **`tightbeam expose` loads `~/.config/tightbeam/disabled_roots`** beside `revoked`, gates on both, and
  cuts live sessions from the same store. Under `--public` nothing is ruled on, so nothing is cut.

### Changed
- **`stdin:` is handed to the next peer when a viewer leaves.** One peer reads it at a time. When that
  peer leaves, however it leaves, the next one to dial gets the stream from about where the last one
  stopped; bytes written while nobody was attached are not replayed. A peer that connects, reads nothing
  and leaves no longer uses up the input.
  - **A paused viewer keeps the stream** for as long as nobody else wants it. It loses it only when a
    different peer dials while it has taken less than about 128 KiB in 90 seconds, and that peer gets
    the stream at once. A reading viewer keeps it against any dialer, and a peer re-dialing never
    displaces itself.
  - **The refusals say which case it is:** "stdin: is held by another peer and serves one at a time;
    retry, or serve it as `stdin:+lossy` to fan out", and, once input has ended, "stdin: has reached end
    of input; restart to serve again". A late dialer is never handed an empty stream.
- **`stdin:+lossy` pumps for the life of the process.** Viewers come and go; a joiner after end of input
  is refused. `fifo:+lossy` still lets go of its fifo when nobody is watching.
- **`resolve_gate` takes any revocation store** (`impl Revocations`), so a caller can pass a `Latch`.

### Fixed
- **A handshake in flight is no longer dropped by the exposer's loop.** `accept` was rebuilt on every
  turn of the select loop, so a handshake that straddled a turn was lost. The accept future is now kept
  until it completes.
- **The non-unix build compiles,** checked on Windows in CI.
- Requires nauthy v0.6.0.

## v0.13.0

The key file goes through bifrost's keystore, and the public stream limits say what they cover.

### Changed
- **The identity key file is read and written by bifrost's `keystore` crate.** Its format, its
  owner-only permission check and its atomic writes are now the ones every bifrost key file uses. A
  missing file still mints and saves a fresh key; a file that is present but does not load is an error
  naming the path and is never overwritten. The key directory is created owner-only (0700).
- **A key file sealed under a passphrase is refused**, with a message saying tightbeam cannot unlock
  it and to point it at a plain key. tightbeam has no way to ask for a passphrase, and such a file is
  never treated as absent.
- **`identity::write` never replaces a different key.** It leaves a file holding the same key alone and
  refuses one holding another.

### Breaking
- **`Secret` no longer hands its bytes out by value.** `Secret::into_bytes` is replaced by
  `Secret::with_bytes`, which lends the seed to a closure, so the seed never leaves its wiping owner.
- **`IdentityError`** drops `Read`, `Malformed`, `Permissive` and `Write` for `Sealed`, `CreateDir`,
  `Entropy` and `Key` (the keystore's own error).
- Requires bifrost v0.5.0 and nauthy v0.5.0.

### Added
- **`tunnel::Serve`** is re-exported, so an embedder can wrap a typed service without depending on
  tightbeam-handler directly.

### Docs
- **The four public stream slots say what they do not bound:** they are shared across every public
  service, held for a stream's whole life, and a viewer that half-closed before leaving is noticed only
  at the next write. The `+lossy` ring is pinned at its exact byte ceiling by test.

## v0.12.0

A service can be typed, and nothing is forced through a codec.

### Added
- **A typed layer over the handler contract, opt-in and additive.** `Frame` names the obligation every
  engine already hand-rolls: encode into and decode from a length-delimited frame. `Service` carries a
  typed request. `Serve<S>` adapts one to `Handler`, so an engine can hand back a value where it used to
  hand back a reader, and an engine that would rather keep the reader changes nothing at all.

  The two kinds coexist. A typed service and a raw handler sit in one dispatcher side by side, which is
  what makes this an option rather than a migration.

  **The control preamble is framed; the raw halves come back untouched.** A service that splices a
  session or streams a body is never pushed through the codec, because a codec that buffers reads past
  the frame it was asked for: after an eight-byte preamble on a stream carrying thirty-two body bytes,
  a buffering reader holds those thirty-two and the raw phase has to replay them. The exact-read shape
  every engine already uses holds none. A shell session cannot tolerate that at all, since the SSH
  library must own the stream from its first byte.

  The open-safety ceiling forwards through the adapter as a type, so the author's choice stays the
  author's and stays checked at compile time.

## v0.11.0

The wire is a specification, and a neighbouring protocol is no longer answered as a version of this
one.

### Added
- **`PROTOCOL.md`: the TB04 tunnel wire, specified.** Byte widths and endianness, both state
  machines as transition tables, what a receiver does with every value it may not recognise,
  normative caps with their units, refusal semantics stated as dialer responses, and eleven test
  vectors.

  The vectors are what separate a specification from a description. Every octet is generated by this
  crate's own codec rather than typed, the encoder must read its own bytes back before a vector
  exists, and a test parses the document and fails if the octets differ, if the codec writes a
  vector the document lacks, or if the document publishes one the codec no longer writes. A
  stranger can implement a conformant peer from the document alone, which is the whole point of
  saying this is a protocol and we are one implementation of it.

### Fixed
- **A neighbouring wire was answered as a version of this one.** The magic was split at a fixed
  two bytes, so a `TBH1` head, which belongs to a different protocol entirely, was read as identity
  `TB` with version `H1` and answered with a refusal naming this host's version. A peer that speaks
  neither protocol was told what we speak.

  The magic is now split by the rule the identity is actually defined by, the maximal run of
  capitals, so `TBH1` reads as identity `TBH`, is foreign, and receives the silence any foreign wire
  receives. The whole magic is checked at compile time by walking that run rather than by naming
  byte positions, so widening an identity later cannot leave a byte unchecked.

- **An admitted stream that never spoke was held forever.** The pre-gate read clock exists against
  exactly this, a peer that opens a stream and says nothing, and it was dropped the moment the gate
  admitted. Four such streams wedge the entire public path, permanently, because the node has four
  public permits.

  An admitted stream that carries no bytes in either direction within ten seconds is now closed. The
  deadline disarms on the first byte in EITHER direction, so a server-speaks-first endpoint behind a
  forward is untouched: it is a first-traffic bound, never an idle bound. The ten seconds is derived
  from the slowest honest opening in the family at one end and from the cost of holding a permit at
  the other.

## v0.10.0

A peer on another release is told so, and a catalog has one bound.

### Fixed
- **A version-skewed dialer got a bare EOF and nothing else.** The magic was compared for exact
  equality, so a tightbeam peer one release back was indistinguishable from a foreign stream, and
  the host's "not a tightbeam stream" was both false and never sent: it was raised before any
  response could be written. The peer learned nothing and the operator learned a falsehood.

  The window is real and it is days, not months: a locally built dialer runs ahead of the newest
  release, and a node installed from a release cannot speak what an unreleased build speaks.

  `TB04` was already `TB` plus `04`, and nothing parsed it that way. So this reads bytes that
  already exist: a frozen two-byte identity, and a version compared as its own value. **No wire
  change**, no new frame, no bump. Three conditions where there was one: a foreign prefix is still
  refused in silence and the old wording is finally true, a version mismatch is now ANSWERED with
  both versions named and the action implied, and an i/o error stays an i/o error.

  The response frame is documented as frozen from `TB04` forward, on the type itself, because a
  host cannot answer a peer it cannot parse unless some part of the wire is stable across versions.

- **The service catalog had no bound at either end.** A client reading a remote node's menu grew a
  buffer to whatever the peer streamed, so a hostile node could exhaust a client that merely asked
  what it serves, at one-to-one bandwidth cost. The writer had no bound either, so an honest host
  did not even provide an implicit ceiling.

  `MAX_CATALOG_BLOB` is derived from the decoder's own limits rather than chosen, so the reader's
  cap cannot drift away from what the decoder accepts, and a test pins the largest admissible
  catalog to exactly that size. The encoder now enforces the two field bounds `decode` already
  enforced, which is stronger than a total: a catalog can sit far under the blob bound and still be
  refused by the decoder, and an encoder that can emit a frame its own decoder rejects is a defect
  in its own right.

### Changed
- **`Request::read` returns a typed error** naming the three conditions above, rather than a single
  opaque one. **`ServiceCatalog::encode` is fallible**, and `MAX_CATALOG_BLOB` plus
  `CatalogTooLarge` are exported for the reader that must hold the same bound.
- Advances to bifrost v0.4.0.

## v0.9.0

A refusal this build cannot read is reported, never renamed.

### Changed
- **Picks up bifrost v0.3.0, where `Refusal` became `#[non_exhaustive]`.** This is a breaking change
  for anyone matching on `Response::Refused`, which carries a `bifrost::Refusal` through `pub mod
  protocol`: such a match now needs one more arm. It should name the class it cannot read rather
  than fold it onto a known one.

  One match broke inside tightbeam, and it is the one where guessing is worst. `Response::write` now
  asks a `refusal_code` helper for the tag before a byte moves. Every code in the wire table is a
  claim: reusing the not-admitted code for a class this build cannot read would tell a dialer their
  credential was rejected by a host that ruled no such thing, and reusing the unavailable code would
  pile arbitrary future classes behind one word a reader cannot unpick. So the arm is an error
  rather than a substitution, and the write fails. Settling the frame before the first byte also
  means an unencodable refusal leaves the stream untouched instead of a lone frame marker the peer
  blocks behind waiting for a code that never arrives.

  Nothing on the wire moved: three classes, three codes, the same magic.

### Fixed
- **The gate-timeout mapping is no longer labelled an interim.** It has been one since 2026-09-16
  with no end date, and an interim with no arrival is a lie a reader acts on: it reads as
  scaffolding about to be replaced. The mapping itself is correct and is unchanged. A gate that ran
  out of time goes on the refusal that is about THIS HOST because that is what the refusal means,
  not as a stopgap: that variant deliberately lost its narrower "you got past the gate and then we
  failed you" reading upstream, because a dialer who can recover the admission bit out of a refusal
  has been handed an oracle. Whether the outcome eventually earns a code of its own is an open
  question, and a code of its own would narrow this answer rather than correct it.
- **Two stale claims in the same documentation block.** "Every cause maps to the same payload-free
  not-admitted today" had been false since the undecided outcome arrived, and "nauthy is about to
  gain one, and when that pin moves this match will stop compiling" described something that had
  already happened.

## v0.8.2

Names its service, and takes nauthy v0.3.1.

### Fixed
- **`tightbeam connect --service` no longer defaults to `default`.** This crate stopped serving that
  name in `44bc974` (2026-09-08) and the default outlived it. An unnamed service now refuses at the
  argument boundary naming the flag, rather than dialing a name no node can serve and collecting
  the uniform not-admitted refusal, which names nothing and reads identically to a revoked badge or
  a disabled route.

### Changed
- **nauthy v0.3.1.** Takes `Cap::expiry()`, so a holder can answer when its own grant dies, and the
  gate that enforces nauthy's datalog budget funnel. Both manifests move together, because
  `tightbeam-handler` carries its own nauthy pin and advancing only the root resolves the crate
  twice in one graph.

## v0.8.1

Pins bifrost v0.2.3.

### Changed
- **bifrost v0.2.3.** A node no longer publishes or hands out an RFC 8981 temporary IPv6 address. The
  address was scoped `Internet` and so passed the advertisement's own filter, which meant a rotating
  privacy address went onto every network the node joined; a consumer also handed one to a human, and
  it is deprecated within about a day. Both manifests move together, because `tightbeam-handler`
  carries its own `bifrost-core` pin and advancing only the root resolves that crate twice in one
  graph.

## v0.8.0

A gate that ran out of time no longer tells a dialer they lack authority.

### Changed
- **BREAKING for a dialer that matches on the refusal: an undecided gate answer is now `Unavailable`,
  not `NotAdmitted`.** A capability check that exceeds its evaluation budget decided nothing about the
  caller's authority, and the uniform not-admitted refusal is a lie they act on: they stop retrying and
  go looking for a credential nothing rejected, and a download of theirs becomes a permanent 403 rather
  than a retry. The detail is fixed text, never host state, because a detail that varied with load would
  put a channel on a pre-admission refusal. Every other gate cause stays uniform and indistinguishable.
  Interim: the ruling is that this answer deserves its own wire code, which is a format change and not
  this crate's to make.
- **Pinned to nauthy v0.3.0 and bifrost v0.2.2.** The nauthy bump is the point: every capability check
  there ran on a one-millisecond wall-clock budget, so a loaded host refused a VALID capability and
  reported it as a denial. On the previous pin a valid device badge was refused about one run in three on
  the driver's machine.

## v0.7.1

The bifrost pin moves, and both manifests move with it.

### Changed
- **Pinned to bifrost v0.2.1.** Additive upstream: the expansion that turns a bind into the sockets it
  answers on is public there now, and a node reports the sockets it bound. Nothing this crate calls
  changes shape. The handler contract crate pins `bifrost-core` on its own, so both manifests move
  together; bumping only the root left two copies of it in one graph.

## v0.7.0

Every target carries a scheme, so the grammar is total and a near-miss is a refusal.

### Changed
- **Every target carries a scheme: a TCP forward is now `tcp:<host>:<port>`.** The bare `host:port` form is
  gone, not deprecated. It was the one target without a scheme, which made a hostname followed by a colon
  and a number indistinguishable from a scheme carrying an argument, so a near-miss on a zero-argument
  scheme silently became a forward to a host of that name. The grammar is now total: every target is
  `<scheme>:<rest>`, an unknown scheme is refused by name with the legal set (`tcp:`, `unix:`, `file:`,
  `fifo:`, `stdin:`, `echo:`), and a scheme that takes no argument refuses a tail. `unix:<path>` is
  unchanged. Update every `name=host:port` entry and every `Router::forward` addr to `tcp:host:port`.
- **A target is parsed once.** `Forward` held the whole address as a string and re-parsed it at dial, so
  two functions decided `unix:` versus TCP and already disagreed on a reachable input: a forward named with
  a bare `unix:` validated and then dialed the empty path. The parse at the boundary is the only one now,
  which deletes the validator and the prefix re-dispatch both.
- **The legal target forms are public.** A consumer that serves its own schemes on top of this grammar has
  to name both sets in one refusal, and the alternative is retyping the list somewhere it can rot.

## v0.6.0

One concern per file, a router that reads its own gate, and a disabled service that cannot be told from a gated one.

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
