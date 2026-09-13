//! The tunnel library core: store-free, clap-free, banner-free.
//!
//! This is the domain a tunnel is made of, with no CLI around it: an [`Exposer`] that accepts overlay
//! sessions and forwards inbound streams to local services, a [`Connector`] that reaches a peer's exposed
//! service, the [`resolve_gate`] policy, and the offline credential operations on a [`Link`] (mint, narrow,
//! revoke). It prints NOTHING and reads no config path: a caller loads the signet, denylist, and identity,
//! prints its own banner, and drives this core. Everything here already speaks `bifrost` and `nauthy`, never
//! clap or a store.

use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError};

use bifrost::{
    ConnInfo, Discovery, Node, NodeId, PeerProof, PeerProven, Refusal, RefusalDetail, Security,
    SecurityProfile, Session, Transport,
};
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::{Admitted, Cap, FileDenylist, Gate, Link, ProvenPeer, Service};
use tightbeam_handler::bridge::ErasedHandler;
// The handler contract lives in the lean `tightbeam-handler` crate (delib-56 verdict 13), re-exported here
// unchanged so every existing `tightbeam::tunnel::*` path keeps working, and a service implements the
// contract without taking this crate's tree. The erased bridge is imported, not re-exported: `Target` stores
// it privately and it is not part of the author-facing surface.
pub use tightbeam_handler::{
    BoxRead, BoxWrite, Handler, Metering, RootedAdmitted, ServeError, Served,
};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
// Re-exported below: it is part of `Exposer::run`'s contract (the node's teardown authority), so a caller
// reaches it through `tightbeam::tunnel` alongside `Exposer` rather than depending on tokio-util directly.
pub use tokio_util::sync::CancellationToken;

use crate::enabled::{AllEnabled, EnabledServices};
use crate::identity::{AsNodeId as _, AsVerifyKey as _};
use crate::protocol::{Request, Response};
use crate::raw_stream::RawStream;
use crate::security::{peer_proven, proof_label};
use crate::{pipe_stdio_bridge, splice, splice_halves};

/// How long to wait for a `fifo:` WRITER before dropping the stream. The FIFO open itself is NONBLOCKING
/// (`O_NONBLOCK`, so it returns a valid fd at once with no writer and never parks a thread), but a writer-less
/// FIFO reads as instant EOF, which is not a real byte stream. So the raw-stream open awaits readable readiness
/// (a writer connecting/writing) bounded by this timeout; on elapse the fd is dropped (cheap, no parked thread)
/// and the stream is refused, one layer deeper than the pre-gate [`REQUEST_READ_TIMEOUT`] (which has already
/// elapsed by the time a target is dialed). A regular-file open has no writer to wait for and is not bounded by
/// this.
pub(crate) const RAW_STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a connector to send its opening request before dropping the stream. Bounds the
/// pre-gate work an unauthenticated peer can pin (a slow-loris that opens a stream and never speaks).
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The maximum number of peer sessions served concurrently. Past this, `accept` stops being polled so new
/// connections queue at the transport (backpressure), bounding the memory a flood of peers can pin.
const MAX_SESSIONS: usize = 256;

/// The maximum number of in-flight streams per session, bounding what a single connected peer can pin.
const MAX_STREAMS_PER_SESSION: usize = 256;

/// The maximum number of raw-stream opens (`file:`/`fifo:`/`stdin:`) in flight across the whole node. The
/// real invariant that keeps a flood safe is that the open NEVER PARKS: a `fifo:`/`file:` open is nonblocking
/// (`O_NONBLOCK`, guard 2 in [`crate::raw_stream`]), so it returns at once with no writer and a writer-less
/// FIFO is awaited via the reactor (an fd registration, not a blocking-pool thread), not parked in a syscall.
/// So no flood can exhaust the blocking pool the way a blocking open once could (issue #25). This semaphore is
/// kept purely as cheap defense-in-depth: a bound on concurrent in-flight opens is healthy regardless (it
/// caps the fds a peer can hold mid-open), and it costs the common single-stream case nothing (one permit,
/// briefly held). Small because a legitimate node serves a handful of raw streams, never hundreds; a request
/// over the cap is refused cleanly.
const RAW_STREAM_OPEN_PERMITS: usize = 16;

/// The maximum number of concurrent PUBLIC sessions (delib-49 G5): a session that has reached any opened
/// service holds one permit until it closes. This bounds what ADMITTED public dials can occupy: at most 32
/// of [`MAX_SESSIONS`] sessions and [`PUBLIC_STREAM_PERMITS`] streams, so the public path cannot consume
/// the whole table by itself. It reserves nothing: a session that never reaches an opened service (a gated
/// or unknown request, or none) takes no permit, so a stranger can still hold the shared session table up
/// to [`MAX_SESSIONS`] and make member dials queue at accept. That residual is the accepted loss, the same
/// shape the round-3 re-spec accepted one layer up (a redialing occupier keeps the public semaphore full).
/// The cap bounds occupation, not fairness: a dialer that keeps reconnecting can still hold all 32.
const PUBLIC_SESSION_PERMITS: usize = 32;

/// The maximum number of concurrent public streams (delib-49 G5), taken at the public-admit seam. Single
/// digits because one public stream is already a stranger's whole session of work; 4 bounds the aggregate
/// public drain to four in-flight streams while leaving room for a handful of honest dials. Over the cap
/// REFUSES (never queues): queuing would park one stranger's stream behind another's.
const PUBLIC_STREAM_PERMITS: usize = 4;

/// A forwarding target for one exposed service: either a named service handler, bound BY VALUE at
/// registration, or tightbeam's own raw-stream source (a `file:`/`fifo:`/`stdin:` byte source spliced
/// toward the peer).
///
/// There is no scheme-string indirection: the handler value IS the row, so two names bound to one handler
/// type are two independent instances with no synthetic key namespace. The built-in local forward
/// (`host:port` / `unix:<path>`) and the loopback reflector are first-party [`Handler`]s (see
/// [`crate::builtins`]), so everything but the raw-stream family is one access path.
#[derive(Clone)]
enum Target {
    /// A service handler: the value this route serves. Boxed behind the private [`ErasedHandler`] bridge,
    /// the only legal heterogeneous storage (the public [`Handler`] trait is not dyn compatible).
    Handler(Arc<dyn ErasedHandler>),
    /// tightbeam's own primitive, the raw-stream half: source an already-open byte stream and splice it
    /// toward the peer, either an OS object the operator named (`file:<path>` / `fifo:<path>`) or this
    /// process's own standard input (`stdin:`, a single-consumer source taken once). The reverse of piping
    /// a service to the connector's stdout. It stays a native arm because of the second open axis: a raw
    /// stream is unsafe-open only through its own overlay, a policy the one-dimensional `Exposure` marker
    /// cannot express.
    RawStream(RawStream),
}

impl core::fmt::Debug for Target {
    /// Manual, deliberately opaque: never forward `Debug` through the erased handler (a handler may hold a
    /// secret, e.g. a shell's host seed), so this names the arm and nothing inside it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Handler(_) => f.write_str("Handler(<handler>)"),
            Self::RawStream(stream) => f.debug_tuple("RawStream").field(stream).finish(),
        }
    }
}

impl Target {
    /// Whether this target may be OPENED to strangers (added to an [`Exposer`]'s public overlay). A TOTAL
    /// function over [`Target`], resolved THROUGH the target rather than off its served name, so an alias
    /// cannot be opened by naming it: the target's own posture decides, never the name.
    ///
    /// The TYPE guarantee (the sealed, uninhabited [`PublicUse`](crate::open_policy::PublicUse) marker erased to
    /// [`ErasedHandler::open_safe`]) covers [`Handler`](Target::Handler): a `Never` handler (a keyless
    /// shell) reads `false`, an `OptIn` handler `true`. A [`RawStream`](Target::RawStream) has no auth of
    /// its own and is one keystroke from a secret, so it is NOT openable here; it opens only through the
    /// distinct unsafe raw-stream overlay. The exhaustive match is the guarantee: a future `Target`
    /// variant forces a decision rather than defaulting into either answer.
    fn open_safe(&self) -> bool {
        match self {
            Target::Handler(handler) => handler.open_safe(),
            Target::RawStream(_) => false,
        }
    }

    /// Which [`TargetKind`] this target is, so a caller's banner RENDERS what tightbeam resolved (a raw
    /// stream splits into the loudest posture group) instead of re-parsing an address string of its own.
    fn kind(&self) -> TargetKind {
        match self {
            Target::Handler(_) => TargetKind::Handler,
            Target::RawStream(_) => TargetKind::RawStream,
        }
    }
}

/// What KIND of thing a served service forwards to, as a caller's readiness banner needs to reason about it
/// WITHOUT re-parsing an address string in the consumer: a bound handler (a caller-injected service, or a
/// tightbeam built-in such as the local forward or the loopback reflector) or a raw-stream source. Declared
/// by the resolved [`Target`], so a consumer RENDERS what tightbeam resolved (splitting a public raw stream
/// into its own louder posture group) rather than string-matching a `file:` prefix of its own. An enum, not
/// a bool, so a future target kind forces a decision at every match site rather than silently reading as one
/// of these two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// A bound handler: a service the caller wrote, or a tightbeam built-in (the local forward, the
    /// loopback reflector).
    Handler,
    /// A raw-stream source (`file:`/`fifo:`/`stdin:`): bytes with no auth of their own, so an OPEN one is the
    /// loudest reach posture a banner can show (a stranger reading a chosen path or the piped stdin).
    RawStream,
}

/// A route's access class: what the gate must have proven beyond admission. Declared where the route is
/// registered ([`Services::member_only`]), never on the handler: a handler's compile-time marker
/// ([`Handler::Exposure`]) says what the CODE may face, while access is a property of the NAME a caller
/// reaches. Per-route is also the only axis that lets two names bound to one handler carry different
/// floors, and it keeps a handler impl from growing a fourth mandatory item (the cold-author bar).
///
/// [`Family`](Access::Family) is the default and means "the gate alone decides": under a node-wide open
/// gate it admits anyone, so it is no floor beyond the gate, never "this node's family".
/// [`Member`](Access::Member) can only REFUSE: it reads one bit of the witness the gate minted and never
/// mints, clones, or widens one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// The default: the gate's verdict is the whole verdict, byte-identical to a node with no declaration.
    Family,
    /// MEMBER-only: a witness the gate admitted as a whole-node member passes; every other witness (a
    /// delegated slip, a stranger on an open node) is refused with the same payload-free class the gate
    /// gives a miss, BEFORE any `Response::Ok` is written.
    Member,
}

/// One served route: the [`Target`] the name resolves to and the [`Access`] class declared for it. Access
/// travels with the route so the two can never drift apart, and a name a node does not serve cannot carry
/// a declaration.
#[derive(Debug, Clone)]
struct Route {
    target: Target,
    access: Access,
}

impl Route {
    /// A route under the default [`Access::Family`] floor (the gate alone decides).
    fn family(target: Target) -> Self {
        Self {
            target,
            access: Access::Family,
        }
    }
}

/// The local services an exposer publishes: a map of service name to its [`Route`] (a [`Target`] plus the
/// [`Access`] class declared at registration), validated as it is built so the rest of the core receives
/// names, targets, and floors that are already well-formed. Private: the author-facing assembly is the
/// [`Router`], which binds handler values directly.
#[derive(Debug, Clone)]
struct Services(HashMap<String, Route>);

impl Services {
    /// Parse `name=addr` service entries into a fresh table; every entry must name its service. `echo:` is
    /// the built-in loopback reflector, a `host:port` / `unix:<path>` a local forward, and `file:<path>` /
    /// `fifo:<path>` / `stdin:` a raw-stream source. A bare `<scheme>:` no longer resolves: handlers are
    /// bound by value through [`Router::service`], so the scheme namespace is a teaching error.
    #[cfg(test)]
    fn parse(entries: &[String]) -> eyre::Result<Self> {
        let mut services = Self(HashMap::new());
        services.extend_parse(entries)?;
        Ok(services)
    }

    /// Parse `name=addr` entries INTO this table (the [`Router::parse`] path): the same grammar and the same
    /// one duplicate policy as every other bind, refused with a teaching message.
    fn extend_parse(&mut self, entries: &[String]) -> eyre::Result<()> {
        let Self(services) = self;
        for entry in entries {
            let Some((name, addr)) = entry.split_once('=') else {
                eyre::bail!(
                    "`{entry}` names no service. Every serve entry must be `name=addr`, e.g. \
                     `web=127.0.0.1:8080`, `logs=file:/var/log/app.log`"
                );
            };
            // Validate the name through the same domain type the wire uses, so an exposed name and a
            // requested name are compared as the same kind of thing.
            name.parse::<Service>()?;
            // A duplicate name is refused HERE, the same policy every bind verb applies: silently
            // overwriting would drop the first target (and, after `member_only`, could silently move a
            // declared floor off the route the operator thought they marked).
            if services.contains_key(name) {
                eyre::bail!(
                    "service `{name}` is already defined; a name may map to only one target"
                );
            }
            // Resolve (and validate) the addr into a Target: a bogus
            // address fails HERE with a teaching message, not at dial time as an opaque reset.
            services.insert(name.to_owned(), Route::family(parse_target(addr, entry)?));
        }
        Ok(())
    }

    /// Add a handler-target service under `name`, bound to the handler VALUE (constructed directly rather
    /// than through the addr grammar, so a caller holding per-service state, an origin scope, a sink
    /// directory, binds one instance per served name and no scheme namespace is needed). The `name` is
    /// validated through the [`Service`] domain type; a duplicate `name` is refused. The Router wires the
    /// same insert through its typed verbs; this is the test-facing shape.
    #[cfg(test)]
    fn with_handler(mut self, name: &str, handler: impl Handler) -> eyre::Result<Self> {
        let Self(services) = &mut self;
        name.parse::<Service>()?;
        if services.contains_key(name) {
            eyre::bail!("service `{name}` is already defined; a name may map to only one target");
        }
        services.insert(
            name.to_owned(),
            Route::family(Target::Handler(Arc::new(handler))),
        );
        Ok(self)
    }

    /// Declare `name` MEMBER-only: only a witness the gate admitted as a whole-node member may reach it,
    /// and a delegated slip for the same name is refused with the same uniform refusal a gate miss gives,
    /// before any `Response::Ok` (see [`Access::Member`]). The default is [`Access::Family`] (the gate
    /// alone decides), so a declaration can only tighten an already-admitted caller.
    ///
    /// Fallible for the same reason [`with_handler`](Self::with_handler) is: a name the node does not
    /// serve is a caller error, not a silent no-op. The contradicting pairings are refused at the door,
    /// never here: [`Exposer`] refuses a member-only route under a node-wide open gate (an open gate mints
    /// only slips, so the route would refuse every dialer) or in the unsafe raw-stream set (the same dead
    /// route, rendered open); the public proof refuses one named public. The Router's `member_service`
    /// declares the same floor through its typed verb; this is the test-facing shape.
    #[cfg(test)]
    fn member_only(mut self, name: &str) -> eyre::Result<Self> {
        let Self(routes) = &mut self;
        let Some(route) = routes.get_mut(name) else {
            let mut served: Vec<&str> = routes.keys().map(String::as_str).collect();
            served.sort_unstable();
            eyre::bail!(
                "no service named `{name}` to mark member-only; this node serves: {}",
                served.join(", ")
            );
        };
        route.access = Access::Member;
        Ok(self)
    }

    /// The exposed service names, sorted, for a caller's readiness banner.
    fn names(&self) -> impl Iterator<Item = &str> {
        let Self(services) = self;
        let mut names: Vec<&str> = services.keys().map(String::as_str).collect();
        names.sort_unstable();
        names.into_iter()
    }

    /// The served services and their reach posture, for the `control.services` read: a name-sorted
    /// [`ServiceCatalog`] snapshot. The posture is the EFFECTIVE one a dialer faces, PER SERVICE: a service
    /// is [`Open`](Posture::Open) if the node's base `gate` is [`Gate::Open`] (everything is open to anyone)
    /// OR the service is a member of the public overlay `public` (opened per-service); otherwise it is
    /// [`Gated`](Posture::Gated) behind a member badge. Not the handler's compile-time ceiling. A pure read
    /// over the parsed services, no mutable state.
    ///
    /// `public` and `public_unsafe` are the raw operator requests (the display side reads what was ASKED);
    /// the security walls are the public proof ([`Router::public`]) and the unsafe proof
    /// ([`Services::prove_unsafe`]), which prove every requested name before the node serves. So a catalog
    /// naming a service `open` is only ever served once the matching proof passed for the same request. An
    /// unsafe-open raw stream IS open to anyone, so it reads `Open` on the wire too.
    fn catalog(
        &self,
        gate: &Gate,
        public: &PublicRequest,
        public_unsafe: &PublicUnsafeRequest,
    ) -> ServiceCatalog {
        let node_open = matches!(gate, Gate::Open);
        let mut entries: Vec<ServiceEntry> = self
            .names()
            .map(|name| ServiceEntry {
                posture: if node_open || public.contains(name) || public_unsafe.contains(name) {
                    Posture::Open
                } else {
                    Posture::Gated
                },
                name: name.to_owned(),
            })
            .collect();
        // `names()` already sorts, so this is stable; kept explicit so the wire canonical-order invariant is
        // stated where the catalog is built, not left implicit in a helper.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        ServiceCatalog(entries)
    }

    /// The bound handler routes this exposer names, so the construction interlocks can check each: a
    /// handler with no auth of its own may not sit behind an open gate.
    fn handlers(&self) -> impl Iterator<Item = (&str, &Arc<dyn ErasedHandler>)> {
        let Self(routes) = self;
        routes
            .iter()
            .filter_map(|(name, route)| match &route.target {
                Target::Handler(handler) => Some((name.as_str(), handler)),
                Target::RawStream(_) => None,
            })
    }

    /// The served names declared [`Access::Member`], for the construction interlocks: a member-only route
    /// no dialer can reach is a dead route, and when it renders `Open` (the public overlays) that is a
    /// posture lie too.
    fn member_only_names(&self) -> impl Iterator<Item = &str> {
        let Self(routes) = self;
        routes.iter().filter_map(|(name, route)| {
            matches!(route.access, Access::Member).then_some(name.as_str())
        })
    }

    /// The exposed names whose target is a [`Target::RawStream`] (a `file:`/`fifo:` path source, or `stdin:`).
    /// Like a keyless shell, a raw-stream source has no auth of its own: it serves a chosen path's bytes (or
    /// the piped stdin) to whoever the gate admits, so [`Exposer`] refuses it behind an [`Gate::Open`]
    /// gate (a public gate over a `file:` source would exfil a secret, over a `stdin:` source the piped
    /// bytes, to anyone). A local forward (`host:port`/`unix:`) is a service the operator deliberately stood
    /// up, so it may still be a public gate; a bare file path or a piped stdin is one keystroke from a
    /// secret, so it may not.
    fn raw_stream_names(&self) -> impl Iterator<Item = &str> {
        let Self(routes) = self;
        routes
            .iter()
            .filter_map(|(name, route)| match &route.target {
                Target::RawStream(_) => Some(name.as_str()),
                Target::Handler(_) => None,
            })
    }

    /// Prove an UNSAFE raw-stream opt-in set: this is the wall that turns a raw [`PublicUnsafeRequest`] into
    /// the exposer's proven [`PublicServices`] overlay. Every requested name must (1) be an EXACT served name
    /// (a typo or a name the node does not serve bails with the served list) AND (2) resolve to a
    /// [`Target::RawStream`] (a `file:`/`fifo:`/`stdin:` source with no auth of its own).
    ///
    /// A name that resolves to a handler is a TEACHING REDIRECT, never silently opened: the unsafe overlay is
    /// ONLY for raw byte sources, so a legitimate service named here is refused with a message pointing at the
    /// safe public overlay ([`Router::public`]). This is the disjoint-token partition (delib-39): the two
    /// overlays never fold, so crossing them teaches rather than opens. A survivor set freezes into the
    /// overlay [`admit`] consults. The proof reads THROUGH each target, matched by served name, so an alias
    /// can never open a raw stream by naming it.
    fn prove_unsafe(&self, requested: PublicUnsafeRequest) -> eyre::Result<PublicServices> {
        let PublicUnsafeRequest(names) = requested;
        let Self(services) = self;
        let mut proven = HashSet::with_capacity(names.len());
        for name in names {
            match services.get(&name).map(|route| &route.target) {
                None => {
                    let mut served: Vec<&str> = services.keys().map(String::as_str).collect();
                    served.sort_unstable();
                    eyre::bail!(
                        "no service named `{name}` to open; this node serves: {}",
                        served.join(", ")
                    );
                }
                // Crossing the token: the unsafe overlay is ONLY for raw byte sources. A handler named here
                // is redirected to the SAFE public overlay, never silently opened, never leaking a marker
                // type name. The layering gate forbids a library naming a consumer's flags, so this speaks
                // the concept (the public overlay) and a caller's own help names the exact flag.
                Some(Target::Handler(_)) => {
                    eyre::bail!(
                        "`{name}` is not a raw byte source, so the unsafe raw-stream set will not open it; a handler \
                     is opened to anyone through the public set instead"
                    )
                }
                Some(Target::RawStream(stream)) => {
                    // Serve-time source guard: a name proven into the unsafe overlay is advertised in the
                    // readiness banner as "serving the raw bytes of <path> to anyone". The connect-time open
                    // refuses a device, a directory, a socket, or a symlink, so validate the source HERE too and
                    // refuse it loudly at serve, rather than let the banner over-claim bytes a dial will always
                    // reject. A not-yet-created path is still allowed (the dial-time open guards that case). This
                    // aligns the banner with the guard.
                    stream.check_open_source()?;
                    proven.insert(name);
                }
            }
        }
        Ok(PublicServices(proven))
    }

    /// Prove the SAFE public opt-in set: every requested name must be an EXACT served name, must not be
    /// member-only (a public dial carries no membership proof, so the route would refuse every caller while
    /// the catalog rendered it open), must not be a raw stream (a teaching redirect to the unsafe overlay),
    /// and must resolve to an open-safe target (a `Never` handler is a hard no). Resolving through the
    /// target, matched by served name, is what stops an alias from being opened by naming it: the target's
    /// posture decides, never the name. A survivor set freezes into the overlay [`admit`] consults.
    fn prove_public(&self, requested: PublicRequest) -> eyre::Result<PublicServices> {
        let PublicRequest(names) = requested;
        let Self(routes) = self;
        let mut proven = HashSet::with_capacity(names.len());
        for name in names {
            let Some(route) = routes.get(&name) else {
                let mut served: Vec<&str> = routes.keys().map(String::as_str).collect();
                served.sort_unstable();
                eyre::bail!(
                    "no service named `{name}` to open; this node serves: {}",
                    served.join(", ")
                );
            };
            // A member-only route cannot be public: the public overlay admits through `Gate::Open`, whose
            // only witness is an open one, so a public dial could never pass the floor while the catalog
            // renders the name `Open`: a dead route and a posture lie. Refused here, where the overlay is
            // proven, so the contradiction cannot be built however the two declarations were ordered.
            if matches!(route.access, Access::Member) {
                eyre::bail!(
                    "`{name}` is member-only, so it cannot be opened to everyone: a public dial carries no \
                     membership proof, so the route would refuse every caller while the catalog renders it \
                     open. drop it from the public set, or drop the member-only declaration"
                );
            }
            match &route.target {
                // A raw stream named in the SAFE overlay is a teaching REDIRECT, not a flat refusal: the safe
                // overlay never opens a raw byte source (`open_safe` stays `false` for it), but the operator
                // CAN serve its bytes knowingly through the DISTINCT unsafe overlay. Byte-for-byte the SAME
                // string as the whole-node door above: one condition, one string, both callers.
                Target::RawStream(_) => eyre::bail!(
                    "`{name}` is a raw byte source (file:/fifo:/stdin:) with no auth of its own, so a public \
                     gate will not serve it. to serve its raw bytes to anyone, name it in the unsafe raw-stream \
                     set; otherwise gate it or drop it from the public set"
                ),
                // A keyless shell is a HARD no: it has no legitimate public use and no redirect exists
                // (unlike a raw stream). Never leaks a marker type name.
                Target::Handler(_) if !route.target.open_safe() => eyre::bail!(
                    "`{name}` has no legitimate public use: a keyless shell (or an alias of one) would hand a \
                     shell to anyone who reaches this node. keep it family-gated; drop it from the public set"
                ),
                Target::Handler(_) => {
                    proven.insert(name);
                }
            }
        }
        Ok(PublicServices(proven))
    }
}

/// How much a served service costs a stranger to reach: whether the node's gate lets an unauthenticated
/// peer in, or requires a member badge. An enum, not a bool, so a future posture (a per-service gate, a
/// paused service) forces a decision at every match site rather than silently reading as one of these two.
///
/// This is the EFFECTIVE posture a dialer would experience today, read off the node's gate: an [`Gate::Open`]
/// node serves every service to anyone, so each is [`Open`](Posture::Open); any other gate requires a member
/// badge, so each is [`Gated`](Posture::Gated). It is not the handler's compile-time open-safety CEILING
/// (`type Exposure`): a service that COULD be public still reports `Gated` on a gated node, because
/// that is what a caller actually faces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// Reaching this service requires a member badge the node's gate admits.
    Gated,
    /// The node's gate is open: anyone who reaches the node reaches this service, no badge.
    Open,
}

impl Posture {
    /// The one-byte wire tag: `0` gated, `1` open. A closed match, so a new posture must extend the wire
    /// deliberately rather than borrow an existing tag.
    const fn tag(self) -> u8 {
        match self {
            Self::Gated => 0,
            Self::Open => 1,
        }
    }

    /// Parse the wire tag back to a posture; an unknown tag is a decode error, never a silent default.
    fn from_tag(tag: u8) -> eyre::Result<Self> {
        match tag {
            0 => Ok(Self::Gated),
            1 => Ok(Self::Open),
            other => eyre::bail!("unknown service posture tag {other:#04x}"),
        }
    }

    /// The word a table renders for this posture (`gated` / `open`), so a caller's table reads at a glance.
    pub fn label(self) -> &'static str {
        match self {
            Self::Gated => "gated",
            Self::Open => "open",
        }
    }
}

/// One served service in a node's catalog: its name and the [`Posture`] a dialer faces reaching it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEntry {
    /// The service name the exposer published it under (the name a connector requests).
    pub name: String,
    /// The posture a dialer faces reaching this service (gated behind a member badge, or open to anyone).
    pub posture: Posture,
}

/// One served service as a caller's READINESS BANNER needs it: its name, the [`Posture`] a dialer faces, the
/// [`TargetKind`] it forwards to, and the responder-side [`Metering`] its handler declared when open.
///
/// A LOCAL render view an embedder draws its OWN banner from, DISTINCT from the on-wire [`ServiceEntry`] the
/// member-only `control.services` read returns: the banner is printed by a node to its own operator, so it
/// carries the extra render tells (kind, metering) that never cross the wire, and it stays off the
/// anti-oracle surface (delib-18) the wire catalog guards. Built by [`Exposer::manifest`] from the resolved
/// services, so a consumer RENDERS declared facts (posture from the proven overlay, kind from the target,
/// the metering caveat from the handler) rather than re-deriving them from address strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// The service name the exposer published it under (the name a connector requests).
    pub name: String,
    /// The posture a dialer faces reaching it (gated behind a member badge, or open to anyone).
    pub posture: Posture,
    /// What kind of target it forwards to, so the banner can split a public raw stream into its own group.
    pub kind: TargetKind,
    /// The handler's declared responder-side rate limit, for a bound handler route: [`Some`] of what the
    /// handler reports, so a banner narrates "open plus unmetered" where the danger is. [`None`] for a raw
    /// stream (it declares no responder policy of its own; its loudness is the raw-stream group).
    pub metering: Option<Metering>,
    /// For a raw-stream service, the source a banner names in its unsafe warning: the operator's path made
    /// ABSOLUTE (lexically, via [`std::path::absolute`] -- no FS access, no symlink follow, no existence
    /// requirement, so a not-yet-created `fifo:` still renders), or the piped-stdin marker. [`None`] for a
    /// bound handler (no raw source to warn about). Declared by tightbeam so the banner renders a resolved
    /// fact, never re-derives a path from the operator's typed string.
    pub raw_source: Option<RawSource>,
}

/// The resolved source of a raw-stream service, as a caller's banner names it in the loud unsafe warning
/// (which exact bytes reach a stranger when this stream is open). Declared by tightbeam, which OWNS raw-stream
/// resolution, so a consumer renders a resolved fact rather than re-deriving a path from the operator's typed
/// string. An enum, not a bare string, so `stdin:` (no path, the risk is this process's piped input) and a
/// path source are distinct cases a renderer must handle, never conflated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawSource {
    /// A `file:`/`fifo:` source: the operator's path made absolute lexically ([`std::path::absolute`], no FS
    /// access, no symlink follow), so the warning names exactly which path's bytes are at risk.
    Path(String),
    /// A `stdin:` source: no path, so the exfil risk is this process's own piped standard input.
    Stdin,
}

/// The services a node SERVES, each with its reach posture: the answer the gated `control.services` read
/// returns. A pure snapshot read from what the exposer was built with (its [`Services`] + gate), no mutable
/// state. Entries are sorted by name, so the wire is canonical and a rendered table reads in a stable order.
///
/// The wire form (all ints big-endian), self-delimiting so a reader needs no out-of-band length, mirroring
/// the roster blob's count-then-length-prefixed-entries shape:
///
/// ```text
///   count        u32
///   per entry x count, ascending by name:
///     name_len   u16
///     name       [u8; name_len]   (UTF-8)
///     posture    u8               (0 gated, 1 open)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCatalog(Vec<ServiceEntry>);

/// The largest service-name length the catalog wire admits, bounding the buffer a decoder allocates per
/// entry from an untrusted blob. A service name is short; this is far above any real one.
const MAX_SERVICE_NAME_LEN: usize = 256;

/// The largest number of catalog entries the wire admits, bounding the work a decoder does on an untrusted
/// blob. A node serves a handful of services, never thousands.
const MAX_CATALOG_ENTRIES: usize = 1024;

impl ServiceCatalog {
    /// The served services, in name order.
    pub fn entries(&self) -> impl Iterator<Item = &ServiceEntry> {
        let Self(entries) = self;
        entries.iter()
    }

    /// Encode the catalog to its self-delimiting wire form (see the type's layout). The count and each name
    /// are length-prefixed, so a reader delimits every field with no framing around the blob.
    pub fn encode(&self) -> Vec<u8> {
        let Self(entries) = self;
        let mut out = Vec::new();
        // A node's service count never approaches u32::MAX; the cast is deterministic and the decoder bounds
        // it at MAX_CATALOG_ENTRIES.
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for entry in entries {
            let name = entry.name.as_bytes();
            // A service name is short (well under u16::MAX, bounded by MAX_SERVICE_NAME_LEN below), so this
            // cast never truncates.
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(name);
            out.push(entry.posture.tag());
        }
        out
    }

    /// Decode a catalog from the wire form written by [`encode`](Self::encode). Bounds-checked against
    /// untrusted input: an over-long name, an over-large count, an unknown posture tag, or trailing bytes is
    /// a clean error, never a panic. The whole blob must be consumed.
    pub fn decode(bytes: &[u8]) -> eyre::Result<Self> {
        let mut cursor = 0;
        let count = take_u32(bytes, &mut cursor)? as usize;
        if count > MAX_CATALOG_ENTRIES {
            eyre::bail!("service catalog names too many services ({count})");
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let name_len = usize::from(take_u16(bytes, &mut cursor)?);
            if name_len > MAX_SERVICE_NAME_LEN {
                eyre::bail!("service name too long ({name_len} bytes)");
            }
            let name = core::str::from_utf8(take(bytes, &mut cursor, name_len)?)
                .map_err(|_| eyre::eyre!("service name is not valid UTF-8"))?
                .to_owned();
            let posture = Posture::from_tag(take_array::<1>(bytes, &mut cursor)?[0])?;
            entries.push(ServiceEntry { name, posture });
        }
        if cursor != bytes.len() {
            eyre::bail!("service catalog has trailing bytes");
        }
        Ok(Self(entries))
    }
}

/// Read `len` bytes at `cursor`, advancing it, or fail if the blob is too short.
fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> eyre::Result<&'a [u8]> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| eyre::eyre!("length overflow"))?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or_else(|| eyre::eyre!("service catalog is truncated"))?;
    *cursor = end;
    Ok(slice)
}

/// Read a fixed-size array at `cursor`, advancing it.
fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> eyre::Result<[u8; N]> {
    let slice = take(bytes, cursor, N)?;
    let mut array = [0u8; N];
    array.copy_from_slice(slice);
    Ok(array)
}

/// Read a big-endian `u16` at `cursor`, advancing it.
fn take_u16(bytes: &[u8], cursor: &mut usize) -> eyre::Result<u16> {
    Ok(u16::from_be_bytes(take_array::<2>(bytes, cursor)?))
}

/// Read a big-endian `u32` at `cursor`, advancing it.
fn take_u32(bytes: &[u8], cursor: &mut usize) -> eyre::Result<u32> {
    Ok(u32::from_be_bytes(take_array::<4>(bytes, cursor)?))
}

/// Resolve the exposer's node BASE gate, in ONE place so every embedder applies the SAME policy: a family
/// gate on the node's provisioned `signet`; an UNPROVISIONED
/// node fails LOUD rather than ever defaulting to open. The caller loads the denylist and passes it as a
/// value. This exists so the two security-relevant conventions (fail-loud-on-unprovisioned,
/// real-loaded-denylist) are enforced once, not hand-copied into each caller.
///
/// The base gate is the node-wide FAMILY authority; opening individual services is a SEPARATE, per-service
/// overlay ([`Router::public`]), never a node-wide value this function returns. Building a node-wide
/// [`Gate::Open`] base is a caller's own deliberate choice (nauthy's [`Gate::Open`]), not something a
/// gate-resolution policy hands back from a flag: that node-wide-open flag was exactly the whole-node blast
/// radius per-service exposure removes (delib-39).
pub fn resolve_gate(signet: Option<NodeId>, denylist: FileDenylist) -> eyre::Result<Gate> {
    let root = signet.ok_or_else(|| {
        eyre::eyre!(
            "this node has no signet to gate on: provision it (adopt a signet), or open individual services \
             to anyone"
        )
    })?;
    Ok(Gate::rooted(root.verify_key(), denylist))
}

/// The raw, UNVALIDATED set of service names an operator asked to open to strangers (however an embedder
/// surfaces that request), before the [`Router`] proves each one exposed and open-safe. Kept DISTINCT from
/// [`PublicServices`] (the proven set the gate consults) so an unvalidated set can never reach admission:
/// the only way to a [`PublicServices`] is through the proof, so "opened a name the node does not serve / a
/// keyless shell" is a build-time bail, not a silently-open service. Private: the author-facing request is
/// [`Router::public`].
#[derive(Debug, Clone, Default)]
struct PublicRequest(Vec<String>);

impl PublicRequest {
    /// An empty request: no service is opened (every service faces the base gate). The default a node builds
    /// when the operator names nothing public.
    fn none() -> Self {
        Self(Vec::new())
    }

    /// Build a request from the operator's raw public-request names, verbatim (no validation here: this is the
    /// UNPROVEN side of parse-don't-validate; the public proof is the wall).
    fn new(names: impl IntoIterator<Item = String>) -> Self {
        Self(names.into_iter().collect())
    }

    /// Whether `name` was requested public, for a display read (the `control.services` catalog). This reads
    /// the raw request, never the proof, so it is a DISPLAY predicate only, never an admission decision.
    fn contains(&self, name: &str) -> bool {
        let Self(names) = self;
        names.iter().any(|requested| requested == name)
    }
}

/// The raw, UNVALIDATED set of raw-stream service names an operator asked to serve to strangers
/// unauthenticated (however an embedder surfaces that request), before the [`Router`] proves each one an
/// exposed [`Target::RawStream`]. Sibling of [`PublicRequest`], kept DISTINCT from the proven
/// [`PublicServices`] so an unproven name can never reach admission: the only way to a [`PublicServices`] is
/// through [`Services::prove_unsafe`], so "opened a name the node does not serve / a handler as an unsafe raw
/// stream" is a build-time bail, not a silently-open service. Private: the author-facing request is
/// [`Router::public_unsafe`].
///
/// DISJOINT from [`PublicRequest`] on purpose: a safe public overlay opens a legitimate service (a handler
/// the operator stood up), an UNSAFE overlay opens a raw byte source with no auth of its own. The two never
/// fold, so the louder opt-in stays a distinct, deliberate thing the operator cannot type by accident.
#[derive(Debug, Clone, Default)]
struct PublicUnsafeRequest(Vec<String>);

impl PublicUnsafeRequest {
    /// An empty request: no raw stream is served to strangers (every raw stream stays gated).
    fn none() -> Self {
        Self(Vec::new())
    }

    /// Build a request from the operator's raw unsafe-open names, verbatim (no validation here: this is the
    /// UNPROVEN side of parse-don't-validate; [`Services::prove_unsafe`] is the wall).
    fn new(names: impl IntoIterator<Item = String>) -> Self {
        Self(names.into_iter().collect())
    }

    /// Whether `name` was requested unsafe-open, for a display read (the `control.services` catalog). This
    /// reads the raw request, never the proof, so it is a DISPLAY predicate only, never an admission decision.
    fn contains(&self, name: &str) -> bool {
        let Self(names) = self;
        names.iter().any(|requested| requested == name)
    }
}

/// The PROVEN-open set of served service names an [`Exposer`] admits any reaching peer to: every member was
/// validated at [`Exposer::with_public`] against the served set AND its target's [`open_safe`](Target::open_safe)
/// posture, so a member is, by construction, an exposed, open-safe service. Membership is the ONLY fast/open
/// path at admission ([`admit`]); a `Never` handler, a raw stream, or a name the node does not serve can
/// never be a member, so `control.*` and every keyless shell stay member-only by SET NON-MEMBERSHIP, a
/// stronger guarantee than a map entry that merely holds a permissive value.
#[derive(Debug, Clone, Default)]
struct PublicServices(HashSet<String>);

impl PublicServices {
    /// Whether `service` is a proven-open member: the one branch [`admit`] takes on the requested name. A
    /// pure set-membership test with no side branch on member content, so a HIT (open) and a MISS (gated or
    /// absent) differ only in the one bit the model intends, never in timing on the member's identity.
    fn contains(&self, service: &str) -> bool {
        let Self(names) = self;
        names.contains(service)
    }
}

/// The one server-side route table: each served name binds to its handler or raw source in one call, and the
/// terminal [`expose`](Router::expose) proves every route against the gate and hands back the runnable
/// [`Exposer`]. Everything an author assembles is here: typed handlers ([`service`](Router::service),
/// [`member_service`](Router::member_service)), the built-in local forward ([`forward`](Router::forward)),
/// the built-in loopback reflector ([`echo`](Router::echo)), and the native raw-stream arm
/// ([`raw_stream`](Router::raw_stream)).
///
/// The whole table is keyed by the typed [`Service`] name, one duplicate policy (refuse), and the open
/// overlays are proven once, at [`expose`](Router::expose), so prove-before-announce holds: the caller
/// prints its banner only after the exposer exists. A raw-stream route stays a native arm because it has a
/// second open axis (the unsafe overlay) that the one-dimensional [`Handler::Exposure`] marker cannot
/// express; every other route is a handler, the built-ins included.
#[must_use = "a Router is a declaration; call `.expose()` to prove it and get the runnable Exposer"]
pub struct Router {
    services: Services,
    /// The raw safe public request, proven at [`expose`](Router::expose).
    public: PublicRequest,
    /// The raw unsafe raw-stream request, proven at [`expose`](Router::expose).
    public_unsafe: PublicUnsafeRequest,
    /// The base gate every route faces unless opened by an overlay.
    gate: Gate,
}

impl Router {
    /// An empty router over `gate`: the node-wide base gate every route faces, including the
    /// whole-node-open [`Gate::Open`] a caller may deliberately choose.
    pub fn new(gate: Gate) -> Self {
        Self {
            services: Services(HashMap::new()),
            public: PublicRequest::none(),
            public_unsafe: PublicUnsafeRequest::none(),
            gate,
        }
    }

    /// Bind `name` to a handler you wrote. Fallible: a name may map to only one target.
    pub fn service(self, name: Service, handler: impl Handler) -> eyre::Result<Self> {
        self.bind(name, Target::Handler(Arc::new(handler)), Access::Family)
    }

    /// As [`service`](Self::service), with the member floor: only a witness the gate admitted as a
    /// whole-node member may reach it, checked before any `Response::Ok`. A delegated slip for the same
    /// name is refused with the same uniform refusal a gate miss gives.
    pub fn member_service(self, name: Service, handler: impl Handler) -> eyre::Result<Self> {
        self.bind(name, Target::Handler(Arc::new(handler)), Access::Member)
    }

    /// Bind `name` to tightbeam's built-in loopback reflector: it opens no host resource and reflects only
    /// the caller's OWN bytes, so it has a legitimately-safe public form. Sugar over
    /// [`service`](Self::service) with [`Echo`](crate::builtins::Echo).
    pub fn echo(self, name: Service) -> eyre::Result<Self> {
        self.service(name, crate::builtins::Echo)
    }

    /// Bind `name` to tightbeam's built-in local forward: connect `addr` (a `host:port` or a
    /// `unix:<path>`) and splice bytes to it. Sugar over [`service`](Self::service) with
    /// [`Forward`](crate::builtins::Forward). The addr is validated here, so a typo fails at bind with a
    /// teaching message rather than at dial time as an opaque reset.
    pub fn forward(self, name: Service, addr: &str) -> eyre::Result<Self> {
        validate_forward(addr)?;
        self.service(name, crate::builtins::Forward::new(addr))
    }

    /// Bind `name` to a raw byte source (`file:`/`fifo:`/`stdin:`). Native, not a handler: the raw-stream
    /// family carries the second open axis (the unsafe overlay) and its own path guards.
    pub fn raw_stream(self, name: Service, source: RawStream) -> eyre::Result<Self> {
        self.bind(name, Target::RawStream(source), Access::Family)
    }

    /// Absorb the `name=addr` serve grammar: `echo:` is the built-in reflector, a `host:port` /
    /// `unix:<path>` a local forward, and `file:<path>` / `fifo:<path>` / `stdin:` a raw-stream source. A
    /// bare `<scheme>:` is a teaching error: handlers are bound by value through
    /// [`service`](Self::service), so the scheme namespace does not survive the merge.
    pub fn parse(mut self, entries: &[String]) -> eyre::Result<Self> {
        self.services.extend_parse(entries)?;
        Ok(self)
    }

    /// Declare these served names open to anyone, per service. The proof runs at
    /// [`expose`](Router::expose), where a name the node does not serve, a member-only route, a raw stream,
    /// or a `Never` handler is refused with a teaching message.
    pub fn public(mut self, names: impl IntoIterator<Item = Service>) -> Self {
        self.public = PublicRequest::new(names.into_iter().map(|name| name.to_string()));
        self
    }

    /// Declare these served raw-stream names knowingly served to anyone, unauthenticated: the DISTINCT,
    /// louder opt-in for a byte source with no auth of its own. The proof runs at
    /// [`expose`](Router::expose), where a name the node does not serve or a handler route is refused.
    pub fn public_unsafe(mut self, names: impl IntoIterator<Item = Service>) -> Self {
        self.public_unsafe =
            PublicUnsafeRequest::new(names.into_iter().map(|name| name.to_string()));
        self
    }

    /// The declared service names, sorted, for a caller's readiness banner.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.services.names()
    }

    /// The served services and their reach posture, for the `control.services` read: a name-sorted
    /// [`ServiceCatalog`] snapshot. `self_listing` names the one row whose handler VALUE is built from this
    /// catalog (the member-only `control.services` read): it is rendered as a GATED entry and sorted in
    /// tightbeam, so a caller never patches the wire ordering itself. The only legitimate catalog-serving
    /// handler is member-only (a `Never` route can never be open), so Gated is its only possible posture.
    ///
    /// `gate` is the node's base gate (the same one [`new`](Router::new) took): it is a parameter so the
    /// catalog can be rendered during assembly, before every route is bound.
    pub fn catalog(&self, gate: &Gate, self_listing: Option<Service>) -> ServiceCatalog {
        let ServiceCatalog(mut entries) =
            self.services
                .catalog(gate, &self.public, &self.public_unsafe);
        if let Some(name) = self_listing {
            entries.push(ServiceEntry {
                name: name.to_string(),
                posture: Posture::Gated,
            });
            entries.sort_by(|a, b| a.name.cmp(&b.name));
        }
        ServiceCatalog(entries)
    }

    /// The one door: prove every route and interlock against the base gate, prove both open overlays, and
    /// hand back the runnable [`Exposer`]. Fallible: a keyless handler under an open gate, an unproven
    /// public name, a member-only route under an open gate, a raw stream under an open gate not named in
    /// the unsafe set, or a duplicate bind all fail HERE, before any banner.
    pub fn expose(self) -> eyre::Result<Exposer> {
        let Self {
            services,
            public,
            public_unsafe,
            gate,
        } = self;
        Exposer::prove(services, gate, public, public_unsafe)
    }

    /// The one bind: insert a row under its typed name, refusing a duplicate with the one policy every
    /// bind verb shares.
    fn bind(mut self, name: Service, target: Target, access: Access) -> eyre::Result<Self> {
        if self.services.0.contains_key(name.as_str()) {
            eyre::bail!("service `{name}` is already defined; a name may map to only one target");
        }
        self.services
            .0
            .insert(name.to_string(), Route { target, access });
        Ok(self)
    }
}

/// An exposer: the proven services to publish and the gate that decides who may reach them. Accepts overlay
/// sessions and forwards each inbound stream to its service.
///
/// Constructed only by [`Router::expose`], which runs every proof and interlock at one door; the only
/// builder left here is [`with_enabled`](Exposer::with_enabled), which cannot raise posture.
pub struct Exposer {
    services: Services,
    gate: Gate,
    /// The safe public overlay, proven at [`Router::expose`]: legitimate services (a handler or a
    /// built-in) opened to any reaching peer.
    public: PublicServices,
    /// The UNSAFE raw-stream overlay, proven at [`Router::expose`]: raw byte sources (`file:`/`fifo:`/
    /// `stdin:`) with no auth of their own, knowingly served to any reaching peer. Kept DISJOINT from
    /// `public` so the two proof walls write disjoint state (no clobber), the toggle interlock (delib-34) can
    /// read `!public_unsafe.is_empty()` trivially, and the on-thesis reading stays legible: `public` =
    /// "opened a legitimate service", `public_unsafe` = "knowingly serves raw bytes with no auth".
    public_unsafe: PublicServices,
    /// The live enable/disable oracle the per-stream gate consults (delib-47): a stream for a name this
    /// reports disabled is refused at admission, exactly like a revoked capability. Defaults to
    /// [`AllEnabled`] (nothing disabled), so a caller that never toggles pays nothing; a caller that does
    /// wires a file-backed [`FileDisabledList`](crate::enabled::FileDisabledList) with
    /// [`with_enabled`](Exposer::with_enabled). Boxed like the gate's own [`Revocations`](nauthy::Revocations)
    /// store, so a consumer may plug any oracle over its own state.
    enabled: Box<dyn EnabledServices + Send + Sync>,
}

impl Exposer {
    /// Prove an assembled router into the runnable exposer, enforcing the door interlocks:
    /// a handler with no auth of its own (a keyless shell) may not sit behind a node-wide [`Gate::Open`]
    /// base; a raw-stream source under an open base is refused UNLESS the operator knowingly opted it into
    /// the unsafe set (proven here into the disjoint unsafe overlay); a route declared [`Access::Member`]
    /// may not pair with an open base or with that unsafe overlay, both of which admit only open witnesses
    /// and would make the floor a route no dialer can reach (and, opened, a posture lie); and the safe
    /// public overlay proves every requested name exposed and open-safe.
    ///
    /// The two raw-stream interlocks stay DISJOINT (delib-37): the keyless-handler refusal reads a
    /// compile-time marker (`type Exposure`), while the raw-stream-unsafe refusal is a RUNTIME opt-in guard
    /// (the danger depends on a runtime path value no type can see), so the two are never folded onto one
    /// mechanism.
    fn prove(
        services: Services,
        gate: Gate,
        public: PublicRequest,
        public_unsafe: PublicUnsafeRequest,
    ) -> eyre::Result<Self> {
        // Interlock 1: a keyless handler (`type Exposure = Never`) may not sit behind an open BASE. Reads
        // the erased compile-time `OPEN_SAFE` marker.
        if matches!(gate, Gate::Open) {
            for (name, handler) in services.handlers() {
                if !handler.open_safe() {
                    // The `{name}` variant of the keyless-shell refusal: a keyless shell has NO safe way to
                    // be opened, so it hard-refuses with no redirect (unlike a raw stream, which the
                    // raw-stream refusal points at the unsafe raw-stream set).
                    eyre::bail!(
                        "`{name}` has no legitimate public use: a keyless shell (or an alias of one) would hand a \
                         shell to anyone who reaches this node. keep it family-gated; drop it from the public set"
                    );
                }
            }
        }
        // PROVE the unsafe set (parse-don't-validate): every named opt-in must be an EXACT served
        // `Target::RawStream`; a name the node does not serve, or a handler, is a teaching redirect, never a
        // silently-open service. The survivors freeze into the disjoint `public_unsafe` overlay.
        let proven_unsafe = services.prove_unsafe(public_unsafe)?;
        // Interlock 2 (raw-stream door, RELAXED per-name): a raw-stream source (`file:`/`fifo:`/`stdin:`) has
        // no auth of its own, so under a node-wide open BASE it would serve a chosen path's bytes (or the
        // piped stdin) to anyone; a `file:<secret>` or `stdin:` source would exfil it. Refuse it at the same
        // door that refuses a keyless shell, UNLESS the operator knowingly opted this exact name into the
        // unsafe overlay. A local forward (`host:port`/`unix:`) is not refused: it is a service the operator
        // deliberately stood up, not a bare file path one keystroke from a key.
        if matches!(gate, Gate::Open)
            && let Some(name) = services
                .raw_stream_names()
                .find(|name| !proven_unsafe.contains(name))
        {
            // The ONE unified raw-stream-under-a-public-gate refusal, shared byte-for-byte with the
            // per-service public proof (differing only in `{name}`). It REDIRECTS to the unsafe raw-stream
            // set (a raw stream is now deliberately openable), not a flat refusal; a caller's own help names
            // the exact flag (the layering gate forbids a library naming a consumer flag).
            eyre::bail!(
                "`{name}` is a raw byte source (file:/fifo:/stdin:) with no auth of its own, so a public gate \
                 will not serve it. to serve its raw bytes to anyone, name it in the unsafe raw-stream set; \
                 otherwise gate it or drop it from the public set"
            );
        }
        // Interlock 3 (member floor, delib-54): a route declared member-only is reachable only through a
        // witness the gate minted as a whole-node member, so two pairings make it DEAD and both fail here
        // rather than ship a route no dialer can reach:
        //   * a node-wide open gate proves nothing about a peer, so every dial would hit the floor and be
        //     refused: the operator would serve a route that answers no one.
        //   * a raw stream proven into the unsafe overlay is admitted through that same open path, so the
        //     route is dead AND the catalog/manifest render it `Open`: an operator-facing posture lie.
        // The safe public overlay's pairing is refused by the public proof. Read one name at a time so the
        // teaching error can name the route.
        if matches!(gate, Gate::Open)
            && let Some(name) = services.member_only_names().next()
        {
            eyre::bail!(
                "`{name}` is member-only, so an open gate will never serve it: an open gate admits everyone \
                 and proves nothing about who they are, so no dial can count as a member. keep the service on \
                 a gate that admits members, or drop the member-only declaration"
            );
        }
        if let Some(name) = services
            .member_only_names()
            .find(|name| proven_unsafe.contains(name))
        {
            eyre::bail!(
                "`{name}` is member-only, so it cannot be served to everyone as a raw byte source: an opened \
                 stream carries no membership proof, so the route would refuse every caller while the manifest \
                 renders it open. drop it from the unsafe raw-stream set, or drop the member-only declaration"
            );
        }
        // Interlock 4 (toggle mutual-exclusion): a DESIGN-LOCK with no operand today. delib-34's live-toggle
        // set (`ActiveSet`/`--toggleable`) is UNBUILT, so there is no second set to refuse; inventing a toggle
        // field now purely to refuse it would be machinery for a case that cannot occur yet. When the toggle
        // allowlist lands it enters THIS proof beside `public_unsafe` and adds ONE bail here:
        //   `if !proven_unsafe.is_empty() && !toggleable.is_empty() { eyre::bail!(...) }`
        // refusing their co-presence by construction (an unauthenticated toggle must never re-arm a raw-byte
        // exfil remotely). Recorded as a binding acceptance criterion for the delib-34 build; do NOT add a
        // toggle field in this change.
        let proven_public = services.prove_public(public)?;
        Ok(Self {
            services,
            gate,
            public: proven_public,
            public_unsafe: proven_unsafe,
            // Nothing is disabled until a caller wires a real oracle. Live enable/disable is the deliberate
            // `with_enabled` opt-in below.
            enabled: Box::new(AllEnabled),
        })
    }

    /// Wire the live enable/disable oracle the per-stream gate consults (delib-47): a stream requesting a
    /// service this oracle reports disabled is refused at admission, indistinguishably from a gated or
    /// absent service, and a re-enable restores it LIVE with no restart (the oracle re-reads its backing state
    /// when it changes). A separate builder, NOT an assembly parameter, because disabling is orthogonal to
    /// the door interlocks [`Router::expose`] enforces and every existing caller/test builds a fully-gated
    /// exposer without it.
    ///
    /// The oracle never OPENS a service (it can only refuse a declared one), so it grants no authority and
    /// cannot raise posture: a disabled service that is re-enabled returns to its ALREADY-declared baseline,
    /// never more exposed than the launch set. That is why it needs no interlock against the unsafe overlay.
    pub fn with_enabled(mut self, enabled: impl EnabledServices + Send + Sync + 'static) -> Self {
        self.enabled = Box::new(enabled);
        self
    }

    /// The served services as a caller's readiness banner needs them: each name with the [`Posture`] a dialer
    /// faces, its [`TargetKind`], and its handler-declared [`Metering`], name-sorted. A pure read over the
    /// exposer's OWN resolved state (the proven public overlay decides posture, the target decides kind, the
    /// bound handler declares its metering), so an embedder draws its banner from declared facts rather than
    /// by re-parsing an address string. DISTINCT from [`Router::catalog`]: that is the on-wire snapshot the
    /// member-only `control.services` read serves; this is the local banner view (kind + metering never cross
    /// the wire).
    pub fn manifest(&self) -> Vec<ManifestEntry> {
        let node_open = matches!(self.gate, Gate::Open);
        let Services(routes) = &self.services;
        let mut entries: Vec<ManifestEntry> = routes
            .iter()
            .map(|(name, route)| {
                // The PROVEN overlays are the posture source (what a dialer actually faces), the same rule the
                // wire catalog reads off the raw request: a name is open iff the node gate is open OR it was
                // proven into the SAFE public overlay OR into the UNSAFE raw-stream overlay, else it is gated
                // behind a member badge. Unioning `public_unsafe` here is what finally lets an opened raw
                // stream read `Open` and reach a consumer's loudest banner tier.
                let posture =
                    if node_open || self.public.contains(name) || self.public_unsafe.contains(name)
                    {
                        Posture::Open
                    } else {
                        Posture::Gated
                    };
                // Metering is handler-declared, so it is resolved THROUGH the bound handler, never a name
                // match: only a handler route carries a responder policy of its own. A raw stream declares
                // none here (its loudness is its own group).
                let metering = match &route.target {
                    Target::Handler(handler) => Some(handler.metering()),
                    Target::RawStream(_) => None,
                };
                // The raw source a banner names in its unsafe warning is tightbeam's to declare (it owns
                // raw-stream resolution): a raw stream carries its resolved absolute path / stdin marker;
                // a bound handler has no raw source to warn about.
                let raw_source = match &route.target {
                    Target::RawStream(stream) => Some(stream.raw_source()),
                    Target::Handler(_) => None,
                };
                ManifestEntry {
                    name: name.clone(),
                    posture,
                    kind: route.target.kind(),
                    metering,
                    raw_source,
                }
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }

    /// Refuse to arm this exposer over a transport that cannot prove the peer when its gate is rooted.
    ///
    /// The construction half of the transport-security rule: a rooted gate decides on a token BOUND to the
    /// dialer's proven key, so a transport that does not prove the peer (an
    /// [`Announced`](bifrost::Announced) profile) can never root-admit. `T` must be the transport the
    /// exposer will serve: [`run`](Self::run) re-checks with its own `T`, so a mismatch still fails closed,
    /// but at the arming point rather than here. A caller that announces readiness (a banner, a bound
    /// socket) before [`run`](Self::run) should call this at the same point it proves its routes, so the
    /// refusal precedes the announcement. [`run`](Self::run) calls it too, so the invariant holds however
    /// the exposer is driven.
    pub fn prove_security<T: Transport>(&self) -> eyre::Result<()> {
        let security = <T::Security as SecurityProfile>::SECURITY;
        if self.gate.wants_capability() && !peer_proven(security) {
            eyre::bail!(
                "this node gates on a signet, but the bound transport declares {} peer proof, so a gated \
                 dial could never be admitted; bind a transport that proves the peer (the default iroh \
                 transport does), or serve with an open gate (`Gate::Open`), which needs no peer proof",
                proof_label(&security.peer)
            );
        }
        Ok(())
    }

    /// Accept overlay sessions from permitted peers and forward each inbound stream to its service. Runs
    /// until `cancel` fires, then stops accepting and returns gracefully; prints nothing (the caller printed
    /// its own readiness banner before calling).
    ///
    /// `cancel` is the node's ONE teardown authority. The exposer is the single owner of that authority: it
    /// is the only thing that ACTS on the token (stops accepting, drains, returns). A holder of a CLONE of
    /// the token may REQUEST teardown by firing it, but it never holds a node handle and never tears anything
    /// down itself. So "who may stop the node" stays a property of who holds a token clone, while "how the
    /// node stops" lives here, in one place. What may hold a clone, and why, is the caller's policy, not the
    /// tunnel's concern.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        cancel: CancellationToken,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        // Construction refusal, repeated at the arming point so it holds however the exposer is driven;
        // a caller that announces readiness first should have called `prove_security` already.
        self.prove_security::<T>()?;
        let Self {
            services,
            gate,
            public,
            public_unsafe,
            enabled,
        } = self;
        // Cap concurrent raw-stream opens across the whole node (all sessions share this one semaphore) as
        // cheap defense-in-depth: the nonblocking open cannot park a thread, so this bounds the fds held
        // mid-open, not a leak. See `RAW_STREAM_OPEN_PERMITS`.
        //
        // The whole per-node serving context (gate + public overlays + services + the raw-stream open pool
        // + the public capacity pools + the enable/disable oracle) is bundled behind ONE `Arc` so each
        // accepted session carries a single handle rather than a fistful of clones.
        let serving = Arc::new(Serving {
            gate,
            public,
            public_unsafe,
            services,
            raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
            public_pool: PublicPool::new(),
            enabled,
        });
        let mut sessions = FuturesUnordered::new();
        loop {
            tokio::select! {
                // Teardown: the cancel token fired (a holder of a clone requested it). Stop accepting and
                // return gracefully. The in-flight sessions in
                // `sessions` are dropped with this future; the caller closes the node next (`node.close()`),
                // which tears their transport down. One owner of teardown, here.
                () = cancel.cancelled() => return Ok(()),
                // Cap concurrent sessions: past the cap, stop polling `accept` so new connections queue at
                // the transport (backpressure) rather than each pinning a task set, bounding a peer flood.
                accepted = node.accept(), if sessions.len() < MAX_SESSIONS => {
                    // The listener outlives any one peer: a transient accept error must not tear down
                    // the sessions already being served, so log it and keep accepting.
                    let session = match accepted {
                        Ok(session) => session,
                        Err(error) => {
                            tracing::warn!(%error, "accept failed; still listening");
                            continue;
                        }
                    };
                    sessions.push(serve_session(session, Arc::clone(&serving)));
                }
                Some(result) = sessions.next(), if !sessions.is_empty() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "session ended");
                    }
                }
            }
        }
    }
}

/// The per-node shared state every accepted session and inbound stream is served under: the node BASE
/// [`Gate`], the two disjoint [`PublicServices`] overlays it composes with (the SAFE `public` and the UNSAFE
/// raw-stream `public_unsafe`), the bound [`Services`] route table, the raw-stream open permit pool, and the
/// public-path capacity pools. Assembled once in [`Exposer::run`] and shared by one `Arc` across every
/// session/stream, so a serving future carries a single handle.
struct Serving {
    gate: Gate,
    public: PublicServices,
    public_unsafe: PublicServices,
    services: Services,
    raw_stream_opens: Semaphore,
    /// The public-path capacity (delib-49 G5): taken only at the public-admit seam, so a gated route never
    /// consults it and non-public traffic is untouched.
    public_pool: PublicPool,
    /// The live enable/disable oracle (delib-47), consulted per stream at admission, beside the gate: a
    /// disabled service is refused with the same indistinguishable refusal a gate miss gives.
    enabled: Box<dyn EnabledServices + Send + Sync>,
}

/// The node's public-path capacity (delib-49 G5): the two permit pools that bound what strangers can
/// occupy. `sessions` holds one permit per session that has reached an opened service, until that session
/// closes; `streams` holds one per public stream in flight. Both are taken ONLY at the public-admit seam
/// ([`admit`]): a gated route never consults either pool.
struct PublicPool {
    /// One permit per public session (see [`PUBLIC_SESSION_PERMITS`]).
    sessions: Arc<Semaphore>,
    /// One permit per concurrent public stream (see [`PUBLIC_STREAM_PERMITS`]).
    streams: Arc<Semaphore>,
}

impl PublicPool {
    /// The production capacity: [`PUBLIC_SESSION_PERMITS`] public sessions, [`PUBLIC_STREAM_PERMITS`]
    /// concurrent public streams.
    fn new() -> Self {
        Self {
            sessions: Arc::new(Semaphore::new(PUBLIC_SESSION_PERMITS)),
            streams: Arc::new(Semaphore::new(PUBLIC_STREAM_PERMITS)),
        }
    }
}

/// The per-session half of the public cap (delib-49 G5): the ONE public-session permit a session holds
/// once it has been admitted to any opened service, held until the session closes and its last stream
/// drops. A session that only ever dials gated routes never takes one: classification happens at the
/// public-admit seam, so a member's session is invisible to the pool.
#[derive(Default)]
struct PublicSession {
    /// `None` until the first public admit, then this session's permit. The lock is `std` with a
    /// non-blocking `try_acquire` inside and never an await, so it can never park the admit path.
    permit: std::sync::Mutex<Option<OwnedSemaphorePermit>>,
}

impl PublicSession {
    /// Classify this session into the public pool, taking its permit on the first public admit. `Ok` when
    /// the session already holds one or the pool has room; `Err` when the pool is at
    /// [`PUBLIC_SESSION_PERMITS`] sessions.
    fn enter(&self, sessions: &Arc<Semaphore>) -> Result<(), ()> {
        let mut held = self.permit.lock().unwrap_or_else(PoisonError::into_inner);
        if held.is_some() {
            return Ok(());
        }
        let permit = Arc::clone(sessions).try_acquire_owned().map_err(|_| ())?;
        *held = Some(permit);
        Ok(())
    }
}

/// The peer a session attests: the `NodeId` the transport reports, with the security that transport
/// declared for it.
///
/// The two travel together from [`serve_session`] (where both are read off the session) to admission
/// (which rules on them), so a caller can never pair one session's key with another session's declared
/// proof. A rooted gate may only act on this when `security` proves the key; the announced profile
/// reports a key the peer chose, which is exactly why it cannot root-admit.
#[derive(Clone, Copy)]
struct SessionPeer {
    node: NodeId,
    security: Security,
}

impl core::fmt::Display for SessionPeer {
    /// The peer's identity, for the per-stream log lines: the declared security is a transport-wide
    /// fact, named in the admission refusal's own cause when it decides one.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.node)
    }
}

/// Serve one accepted session: handle each inbound stream's service request under the gate.
async fn serve_session<S: Session>(session: S, serving: Arc<Serving>) -> eyre::Result<()>
where
    S::Write: Send + 'static,
    S::Read: Send + 'static,
{
    // Read the peer and its declared security ONCE off the session, and carry both to every stream's
    // admission: a rooted gate may only rule on a peer the transport proves.
    let peer = SessionPeer {
        node: session.peer(),
        security: <S::Security as SecurityProfile>::SECURITY,
    };
    // The per-session half of the public cap (delib-49 G5): created empty, classified by the first stream
    // that reaches an opened service, and dropped with the session (which releases its permit, if any).
    let public_session = Arc::new(PublicSession::default());
    let mut pipes = FuturesUnordered::new();
    // Stop accepting new streams once `accept_bi` errors (the session is closing): drain the in-flight
    // pipes rather than reaping them with `?`, the same courtesy `connect` gives its local listener.
    let mut accepting = true;
    loop {
        tokio::select! {
            // Cap in-flight streams per session: past the cap, stop polling `accept_bi` so the peer's
            // further streams queue at the transport (backpressure) instead of each pinning a task and a
            // buffer. A single peer cannot exhaust the node with unbounded concurrent streams.
            accepted = session.accept_bi(), if accepting && pipes.len() < MAX_STREAMS_PER_SESSION => {
                match accepted {
                    Ok((writer, reader)) => pipes.push(serve_request(
                        peer,
                        writer,
                        reader,
                        Arc::clone(&serving),
                        Arc::clone(&public_session),
                    )),
                    Err(error) => {
                        tracing::warn!(%peer, %error, "accept_bi failed; draining in-flight streams");
                        accepting = false;
                    }
                }
            }
            Some(result) = pipes.next(), if !pipes.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "pipe ended");
                }
            }
            // No more streams to accept and none in flight: the session is done.
            else => break,
        }
    }
    Ok(())
}

/// Serve one inbound stream: read the request, apply the gate, reply, and pipe on success.
///
/// The gate decides per stream, not per session, because the requested service (and any presented
/// capability) is a property of the stream: one session may carry several service requests, each gated on
/// its own merits. `public_session` is this session's half of the public cap (delib-49 G5): a stream that
/// takes the public path classifies the session, and the permit it carries rides this future to the end.
async fn serve_request<W, R>(
    peer: SessionPeer,
    mut writer: W,
    mut reader: R,
    serving: Arc<Serving>,
    public_session: Arc<PublicSession>,
) -> eyre::Result<()>
where
    W: io::AsyncWrite + Unpin + Send + 'static,
    R: io::AsyncRead + Unpin + Send + 'static,
{
    let Serving {
        gate,
        public,
        public_unsafe,
        services,
        raw_stream_opens,
        public_pool,
        enabled,
    } = &*serving;
    let Services(services) = services;
    // Bound the pre-gate read: a peer that opens a stream but never sends its request would otherwise
    // park this task (and its buffer) indefinitely, BEFORE the gate runs, so unauthenticated peers could
    // exhaust the node one slow stream at a time. Time out and drop a silent stream.
    let request = match tokio::time::timeout(REQUEST_READ_TIMEOUT, Request::read(&mut reader)).await
    {
        Ok(result) => result?,
        Err(_elapsed) => {
            tracing::warn!(%peer, "request read timed out before the gate; dropping the stream");
            return Ok(());
        }
    };
    let service = match request.service.parse::<Service>() {
        Ok(service) => service,
        Err(error) => {
            // The request's shape is the peer's own grammar, already public, so the wire names it; the
            // host log carries the parse failure for the operator.
            tracing::warn!(%peer, service = %request.service, %error, "invalid service name");
            return Response::Refused(Refusal::BadRequest {
                detail: RefusalDetail::bounded(format!(
                    "invalid service name {:?}",
                    request.service
                )),
            })
            .write(&mut writer)
            .await
            .map_err(Into::into);
        }
    };
    // A node exposing exactly one service should not require the request to name it: if the request names
    // no exposed service (a connector defaulting to `default`) and there is only one, resolve to it. Done
    // BEFORE the gate so a delegated slip for that service still matches (the gate checks the RESOLVED service).
    let service = resolve_single_service(service, services);

    // Live enable/disable (delib-47), consulted at the SAME point in admission as the gate, on the RESOLVED name: a service
    // the operator has disabled refuses here, before admission, and a re-enable restores it on the next stream
    // with no restart (the oracle re-reads its backing file on change). The wire gets the SAME indistinguishable
    // refusal a gate miss gives, so a disabled service reads exactly like a gated or absent one: no dialer can
    // tell "disabled" from "not a member", and toggling leaks nothing. An already-open stream to a service
    // disabled mid-flight stays open (next-stream semantics, identical to revocation).
    if !enabled.is_enabled(&service) {
        tracing::warn!(%peer, service = %service, "refused: service disabled");
        return Response::Refused(Refusal::NotAdmitted)
            .write(&mut writer)
            .await
            .map_err(Into::into);
    }

    // `admitted` carries the public-stream permit (when this is a public stream) for the WHOLE of this
    // function: the permit field is never moved, so it drops when this stream ends, which is what releases
    // the slot. Its witness is moved on below into `prepare`; the remaining permit field stays bound to the
    // end of this scope.
    let admitted = match admit(
        Admission {
            gate,
            public,
            public_unsafe,
            pool: public_pool,
        },
        public_session.as_ref(),
        peer,
        request.capability.as_deref(),
        request.membership.as_deref(),
        &service,
    ) {
        Ok(admitted) => admitted,
        Err(refusal) => {
            // The full cause (malformed / missing / not-granted / revoked / public capacity, the typed
            // `HostRefusal`) is a LOCAL log line for the node's own operator. The WIRE gets one
            // indistinguishable `Refusal::NotAdmitted`, so a not-admitted dialer cannot tell a stranger's
            // `Missing` from a revoked holder's `Revoked`, nor confirm a service exists at all: no
            // pre-authorization revocation or capability-enumeration oracle. A saturated public pool is
            // wire-identical to a gate miss for the same reason.
            tracing::warn!(%peer, service = %service, %refusal, "refused");
            return Response::Refused(Refusal::NotAdmitted)
                .write(&mut writer)
                .await
                .map_err(Into::into);
        }
    };

    // The member floor (delib-54): a route declared `Access::Member` at registration is checked ONCE here,
    // after `admit` and before every `Response::Ok` below, so the check covers every dispatch arm and can
    // still be a WIRE refusal; a handler-side check would run post-`Ok` and the client would read a stopped
    // "success". The witness is BORROWED for `is_member` (`&self`) and stays owned for the single move into
    // the handler, and the refusal is the SAME payload-free class a gate miss gives: the wire never learns
    // that a route is member-only (no member-vs-slip oracle). The lookup is hoisted so the floor and the
    // dispatch below read the same resolved route.
    let route = services.get(service.as_str());
    if route.is_some_and(|route| route.access == Access::Member) && !admitted.witness.is_member() {
        tracing::warn!(%peer, service = %service, "refused: member-only route");
        return Response::Refused(Refusal::NotAdmitted)
            .write(&mut writer)
            .await
            .map_err(Into::into);
    }

    match route.map(|route| &route.target) {
        // tightbeam's own primitive, the raw-stream half: open the source (a guarded file/FIFO, or take fd 0
        // for `stdin:`) and splice its bytes toward the peer. `Response::Ok` is written only AFTER the open
        // succeeds, so a peer learns "refused" (not a silent hang or a mid-stream reset) when the target is a
        // device, a directory, a symlink, a FIFO whose writer never appears, or a `stdin:` already taken by a
        // concurrent connection (the single-consumer refusal).
        Some(Target::RawStream(stream)) => {
            // Take a raw-stream open permit BEFORE opening, as defense-in-depth (the open is nonblocking and
            // cannot park a thread, so this bounds the fds a peer holds mid-open, not a leak): `try_acquire`
            // refuses immediately over the cap rather than admitting one more concurrent open. The permit is
            // held only across the open (the splice below holds none) and dropped when `_permit` leaves scope.
            // See `RAW_STREAM_OPEN_PERMITS`.
            let opened = match raw_stream_opens.try_acquire() {
                Ok(_permit) => stream.open().await,
                Err(_at_cap) => {
                    tracing::warn!(%peer, service = %service, "raw-stream open cap reached; refusing");
                    Err(eyre::eyre!(
                        "the host is opening too many raw streams right now; try again shortly"
                    ))
                }
            };
            match opened {
                Ok(source) => {
                    Response::Ok.write(&mut writer).await?;
                    // Direction is fixed at parse time: read the source, send its bytes to the peer, and
                    // discard any bytes the peer sends upstream (a read-only source has nowhere to put them).
                    // Using `splice_halves` (never the duplex `splice`) is what makes "write peer bytes back
                    // into the source" unrepresentable.
                    splice_halves(source, io::sink(), writer, reader).await?;
                }
                Err(error) => {
                    tracing::warn!(%peer, service = %service, %error, "raw-stream open refused");
                    Response::Refused(Refusal::Unavailable {
                        detail: RefusalDetail::bounded(error.to_string()),
                    })
                    .write(&mut writer)
                    .await?;
                }
            }
        }
        // A bound handler: prepare the handler-bound proof BEFORE any success, then write `Response::Ok`,
        // then run the frozen serve. The proof mint is monomorphized on the concrete handler, so a `Never`
        // handler refuses an open witness HERE, pre-`Ok`, with the same payload-free `NotAdmitted` class a
        // gate miss gives (no never-public oracle). The witness is moved into the proof by value (single-use),
        // so a handler can never run for an unauthorized peer; the guarantee holds only because the admit
        // (above) and this serve share one stream frame, never hoisted to session scope.
        Some(Target::Handler(handler)) => match handler.prepare(admitted.witness) {
            Ok(prepared) => {
                Response::Ok.write(&mut writer).await?;
                prepared.serve(Box::new(writer), Box::new(reader)).await?;
            }
            Err(refusal) => {
                tracing::warn!(
                    %peer,
                    service = %service,
                    %refusal,
                    "refused: unrooted witness for a never-public handler"
                );
                Response::Refused(Refusal::NotAdmitted)
                    .write(&mut writer)
                    .await?;
            }
        },
        None => {
            // Unknown service. The node's OWN log names what it exposes, so a service-name mismatch (the
            // connector defaulting to `default` while the exposer named `web`) is diagnosable by the
            // operator. It must NOT cross the wire: enumerating the service menu to a dialer is exactly the
            // pre-authorization capability-enumeration oracle deliberation 18 forbids, so the wire gets the
            // same indistinguishable refusal as any not-admitted dial. A dialer learns a service exists only
            // by being admitted to it; the teaching hint returns as the gated `control.services` verb, never
            // as a free menu here. (This arm is reached only past the gate: an Open node, or a whole-node
            // member badge that admits any name -- so uniformity here also stops a member from mapping the
            // menu by probing wrong names, keeping the same rule at every dialer class.)
            let mut available: Vec<&str> = services.keys().map(String::as_str).collect();
            available.sort_unstable();
            tracing::warn!(
                %peer,
                service = %service,
                exposes = %available.join(", "),
                "unknown service requested"
            );
            Response::Refused(Refusal::NotAdmitted)
                .write(&mut writer)
                .await?;
        }
    }
    Ok(())
}

/// Why the host did not admit a stream, in full, for the host's OWN log. It
/// never crosses the wire: the dialer gets one uniform `Refusal::NotAdmitted`,
/// so a stranger cannot tell a missing token from a revoked one, nor confirm an
/// absent name (deliberation 18).
#[derive(Debug, thiserror::Error)]
enum HostRefusal {
    /// A presented capability link did not parse. The parse error is the cause;
    /// the wire still says only "not admitted".
    #[error("malformed capability")]
    MalformedCapability(#[source] nauthy::CapError),
    /// The transport does not prove the peer, so a rooted gate cannot rule on the presented token: its
    /// device binding would rest on a key the peer merely announced.
    #[error(
        "the transport does not prove the peer (declared: {}); a rooted gate cannot admit",
        proof_label(.declared)
    )]
    PeerNotProven {
        /// The peer-identity claim the session's transport declared.
        declared: PeerProof,
    },
    /// The gate ruled: nauthy's typed cause.
    #[error(transparent)]
    Gate(nauthy::Refusal),
    /// The public-path capacity (delib-49 G5) is reached: the node already serves its cap of ADMITTED
    /// public sessions or concurrent public streams. The wire still gets the same payload-free
    /// `Refusal::NotAdmitted` a gate miss gives, so a saturation is indistinguishable from a refusal;
    /// this cause is only the operator's log line. The shared session table is bounded separately by
    /// [`MAX_SESSIONS`] and is outside this pool's claim.
    #[error(
        "public capacity reached ({cap}); refusing rather than queueing the admitted public dial"
    )]
    PublicAtCapacity {
        /// Which pool is at its cap (`public sessions` / `public streams`).
        cap: &'static str,
    },
}

impl From<nauthy::Refusal> for HostRefusal {
    fn from(refusal: nauthy::Refusal) -> Self {
        HostRefusal::Gate(refusal)
    }
}

/// An admitted stream: the nauthy witness the dispatch consumes, plus the public-path permit (if any) this
/// stream holds until it ends. The permit rides the binding through the whole of [`serve_request`], so a
/// public stream keeps its slot for exactly its lifetime; a gated stream carries `None` and touches no
/// public capacity.
#[derive(Debug)]
struct AdmittedStream {
    witness: Admitted,
    /// Held for the stream's lifetime; dropped when the binding leaves scope. Never read.
    _stream_permit: Option<OwnedSemaphorePermit>,
}

/// The policy one stream's admission is ruled under: the node base [`Gate`], the two disjoint open
/// overlays (the SAFE `public` and the UNSAFE raw-stream `public_unsafe`), and the public-path capacity
/// pools. Borrowed from the serving context, so [`admit`] reads one handle and a session's permit can
/// never be taken against another node's pools.
#[derive(Clone, Copy)]
struct Admission<'a> {
    gate: &'a Gate,
    public: &'a PublicServices,
    public_unsafe: &'a PublicServices,
    pool: &'a PublicPool,
}

/// Rule on a request under the node's per-service admission: the two disjoint open overlays (`public`, the
/// safe one, and `public_unsafe`, the unsafe raw-stream one) composed with the base family gate, returning
/// the [`Admitted`] witness plus this stream's public permit (if any) on success, or the typed
/// [`HostRefusal`] for the node's OWN logs. A service the operator opened (a member of EITHER overlay)
/// admits any reaching peer under the public caps; every other service faces the base gate and touches no
/// public capacity. The witness is required to reach a service handler, so "authorize before
/// serve" is a compile-time precondition (see [`nauthy::Admitted`]). The refusal returned here NEVER crosses
/// the wire (the caller sends the payload-free `Refusal::NotAdmitted` to a not-admitted dialer); it exists
/// only so the operator can see WHY on their own `tracing` output. Distinguishing missing/not-granted/revoked
/// to the wire would be a revocation + capability-enumeration oracle for an unauthorized peer (deliberation 18).
fn admit(
    admission: Admission<'_>,
    session: &PublicSession,
    peer: SessionPeer,
    capability: Option<&str>,
    membership: Option<&str>,
    service: &Service,
) -> Result<AdmittedStream, HostRefusal> {
    let Admission {
        gate: base,
        public,
        public_unsafe,
        pool,
    } = admission;
    // The ONLY branch admission takes on the service NAME is this open-set membership test, and it runs
    // BEFORE any dispatch (the `services.get` in `serve_request` is reached only past this admit). A HIT on
    // EITHER overlay is the sole fast/open path: the service was proven open at `with_public` (safe) or at
    // `Exposer::new` (an unsafe raw stream), so this admits with no cap parse and no crypto, minting the
    // witness through nauthy's OWN `Gate::Open` primitive (tightbeam picks WHICH nauthy primitive per
    // service; it never mints authority itself). Both overlays hold, by construction, exposed served names,
    // so the later dispatch always resolves the name. Testing a second already-public set adds no oracle: a
    // hit on either reveals only the already-public fact that the service admits anyone; a miss on both takes
    // the identical family path below.
    if public.contains(service.as_str()) || public_unsafe.contains(service.as_str()) {
        // An open service needs no badge, so the signet-bound membership slot is irrelevant on this path.
        // The witness is `Origin::Open` with `Admission::Slip`: no token is ruled on and nothing about the
        // peer is verified, so the `ProvenPeer` minted here records the key the peer announced and carries
        // no authority. That is what lets an announced transport keep serving a service the operator opened
        // to anyone, while every gated route (below) refuses.
        let witness = Gate::Open
            .admit_witnessed(
                ProvenPeer::from_handshake(peer.node.verify_key()),
                None,
                service,
            )
            .map_err(HostRefusal::from)?;
        // delib-49 G5, the ONE place the public caps are taken. A public stream first takes a
        // public-stream permit (held for the stream's life) and then classifies its session (one
        // public-session permit, held until the session closes). Past either cap the answer is a refusal
        // BEFORE any `Response::Ok`, mapped by the caller to the same payload-free `NotAdmitted` a gate
        // miss gives. Stream permit first: a session is only classified by a stream that actually runs, so
        // a refused stream never burns a session slot. A gated route skips this block entirely.
        let stream_permit = Arc::clone(&pool.streams).try_acquire_owned().map_err(|_| {
            HostRefusal::PublicAtCapacity {
                cap: "public streams",
            }
        })?;
        session
            .enter(&pool.sessions)
            .map_err(|_| HostRefusal::PublicAtCapacity {
                cap: "public sessions",
            })?;
        return Ok(AdmittedStream {
            witness,
            _stream_permit: Some(stream_permit),
        });
    }
    // A rooted gate rules on a token BOUND to the dialer's proven key, so it may only run when the
    // transport's declared profile proves the peer: over an announced session a harvested badge is
    // replayable and the binding would vouch for the impersonator. Refuse before minting a `ProvenPeer`
    // or parsing the token. The wire gets the same uniform `NotAdmitted` a gate miss gives; only the
    // node's own log names the declared profile. A genuinely open service was already admitted above,
    // so public traffic over an announced transport is untouched.
    if base.wants_capability() && !peer_proven(peer.security) {
        return Err(HostRefusal::PeerNotProven {
            declared: peer.security.peer,
        });
    }
    // A MISS is EITHER a gated-present name OR a name the node does not serve at all: both take this
    // identical family path (the same cap parse, the same two ed25519 verifies, the same refusal), so a
    // gated service and an absent one are timing- and response-identical. There is no cheaper path for
    // "absent" than for "gated-present", so hit-vs-miss reveals only what is already public (a public name
    // is reachable by anyone), never the gated menu (delib-18/39 anti-oracle).
    //
    // Parse a presented capability at the edge; a malformed token is a refusal, not a hard error, so the
    // stream ends cleanly rather than being dropped mid-read.
    let cap = match capability.map(Cap::parse).transpose() {
        Ok(cap) => cap,
        Err(error) => return Err(HostRefusal::MalformedCapability(error)),
    };
    // Parse the SECOND slot ONLY when the first is a signet-bound slip: that is the sole path that ANDs a
    // fleet badge, so a plain/bearer/device slip (or none) never triggers the extra `Cap::parse`. The server
    // guards this independently of the dialer (a hostile client ignores the dialer's attach logic), which
    // bounds the second slot's parse work behind the cheap, root-free `is_authority_bound` check. A malformed
    // badge on the signet path is a refusal, not a hard error; both slots inherit `Cap::parse`'s bounds.
    let membership = match cap.as_ref() {
        Some(slip) if slip.is_authority_bound() => match membership.map(Cap::parse).transpose() {
            Ok(membership) => membership,
            Err(error) => return Err(HostRefusal::MalformedCapability(error)),
        },
        _ => None,
    };
    // Mint the peer the transport attested: the declared profile (a completed handshake for `Proven`,
    // exact-by-construction for `InProcess`) is the transport's CLAIM, not a proof this seam re-derives.
    // A rooted gate reaches here only past the predicate above; an open gate needs no peer proof at all.
    let peer = ProvenPeer::from_handshake(peer.node.verify_key());
    // Route the two-cap authority-bound path (a foreign slip AND the membership badge that vouches for the
    // dialer under the slip's foreign authority) through `admit_foreign_witnessed`; every other shape (a
    // membership badge, a plain/bearer/device slip, or no token) is the single-cap path. A `membership` is
    // `Some` only when slot 1 is an authority-bound slip and a badge parsed, so that pairing is the only
    // caller of the foreign twin.
    let witness = match (cap.as_ref(), membership.as_ref()) {
        (Some(slip), Some(badge)) => base
            .admit_foreign_witnessed(peer, slip, badge, service)
            .map_err(HostRefusal::from),
        (presented, _) => base
            .admit_witnessed(peer, presented, service)
            .map_err(HostRefusal::from),
    }?;
    Ok(AdmittedStream {
        witness,
        _stream_permit: None,
    })
}

/// Resolve the requested service against what is exposed: if it names no exposed service but exactly one
/// service is exposed, return that one, so a single-service node needs no named service. Otherwise return
/// the request unchanged (a multi-service node keeps it, to fail later with the "unknown service; this node
/// exposes: …" hint rather than guessing which one was meant).
fn resolve_single_service(requested: Service, services: &HashMap<String, Route>) -> Service {
    if services.contains_key(requested.as_str()) || services.len() != 1 {
        return requested;
    }
    // The sole service's name is already a validated `Service` (parse_services checked it), so this parse
    // cannot fail; fall back to the request if it somehow does rather than unwrap.
    match services.keys().next().map(|only| only.parse::<Service>()) {
        Some(Ok(only)) => only,
        _ => requested,
    }
}

/// Resolve an exposed service's address to a [`Target`]: `file:<path>` / `fifo:<path>` are the raw-stream
/// forward (open an existing OS object, splice its bytes to the peer); `echo:` is the built-in loopback
/// reflector (no argument, no host resource); a bare scheme (a `<name>:` -- a word then a colon with nothing
/// after) names a handler; anything else must be a socket forward (`host:port` or `unix:<path>`). All
/// validated here so a typo fails at parse with a teaching message, not at dial time.
fn parse_target(addr: &str, entry: &str) -> eyre::Result<Target> {
    // A trailing `+lossy` is the operator's opt-in to raw-stream FAN-OUT (delib-20 SYNTHESIS + delib-24): the
    // source may be reached by MANY consumers at once, and a consumer that falls behind has its bytes DROPPED
    // rather than stall the producer or the others. It is a claim only the operator can make ("this stream
    // tolerates loss"), so it is legal ONLY on the live single-writer sources `stdin:`/`fifo:` and REFUSED at
    // parse on anything else: a `file:` (static bytes, already safe fan-out by re-open, loss would be corruption)
    // or a `host:port`/`unix:`/built-in (not a raw-stream source at all). Strip it here, then route the
    // scheme; a source that keeps it (`file:...+lossy`, `web+lossy`) is rejected below.
    let (addr, lossy) = match addr.strip_suffix("+lossy") {
        Some(base) => (base, true),
        None => (addr, false),
    };
    let reject_lossy = |scheme: &str| -> eyre::Result<()> {
        if lossy {
            eyre::bail!(
                "`+lossy` (raw-stream fan-out) is only valid on a `stdin:`/`fifo:` source, not `{scheme}` \
                 (`{entry}`); drop it, or point the service at a live single-writer source"
            );
        }
        Ok(())
    };
    // `stdin:` is a raw-stream source with NO tail (this process's fd 0), so it is a zero-arg target routed
    // FIRST, before any other arm. It shares the raw-stream direction and the public-gate refusal, but
    // inherits none of the path guards (there is no path). Anything after the colon is a typo: `stdin:` takes
    // no argument.
    if addr == "stdin:" {
        return Ok(Target::RawStream(RawStream::stdin(lossy)?));
    }
    // `echo:` is tightbeam's built-in loopback reflector, now a first-party [`Handler`]
    // ([`crate::builtins::Echo`]): a zero-arg target (no path, no host resource). It tolerates no `+lossy`
    // (it is not a raw-stream source) and no tail (`echo:` takes no argument), so both are refused.
    if addr == "echo:" {
        reject_lossy("echo:")?;
        return Ok(Target::Handler(Arc::new(crate::builtins::Echo)));
    }
    // A raw-stream route carries a PATH tail (`file:/tmp/x`, `fifo:/tmp/beam`), so it is native, not a
    // handler. Route it FIRST: the direction (a read-only source toward the peer) is fixed here at parse
    // time, and a bare `file:`/`fifo:` with no path fails loudly.
    if let Some(path) = addr.strip_prefix("file:") {
        reject_lossy("file:")?;
        return Ok(Target::RawStream(RawStream::file(path, entry)?));
    }
    if let Some(path) = addr.strip_prefix("fifo:") {
        return Ok(Target::RawStream(RawStream::fifo(path, entry, lossy)?));
    }
    if let Some(scheme) = addr.strip_suffix(':') {
        // A bare `<scheme>:` (nothing after the colon) used to name a registry handler. The scheme namespace
        // left the public API with the Router, so it is a teaching error, never a silently-dangling target:
        // handlers bind by value. `unix:<path>` and `host:port` carry a tail and fall through to the forward
        // grammar; a bare `unix:` is caught here too and taught.
        if !scheme.is_empty()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            reject_lossy(addr)?;
            eyre::bail!(
                "`{entry}` names a handler scheme (`{addr}`), which is no longer spellable: handlers are bound \
                 by value, e.g. `.service(\"{scheme}\".parse()?, MyHandler)`. use `--` or a bound service"
            );
        }
    }
    reject_lossy(addr)?;
    validate_forward(addr)?;
    Ok(Target::Handler(Arc::new(crate::builtins::Forward::new(
        addr,
    ))))
}

/// Reject a forward addr that is not a real target, so a named service pointed at a bogus addr
/// (`web=nonsense`) fails at parse with a teaching message instead of pointing at an undialable host.
/// Valid forwards: `unix:<path>` or a `host:port` (a bare `<name>:` handler scheme is a teaching error).
fn validate_forward(addr: &str) -> eyre::Result<()> {
    let is_host_port = addr
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
    if addr.starts_with("unix:") || is_host_port {
        return Ok(());
    }
    eyre::bail!(
        "`{addr}` is not a valid forwarding address (host:port, unix:<path>, file:<path>, fifo:<path>, \
         or the built-in `echo:`)"
    )
}

/// Dial a service target (a `unix:<path>` socket or a `host:port`) and pipe it to the bifrost stream. The
/// serve half of [`builtins::Forward`](crate::builtins::Forward), typed [`ServeError`] so a handler body
/// can `?` it directly.
pub(crate) async fn dial_and_splice<W, R>(
    addr: &str,
    writer: W,
    reader: R,
) -> Result<(), ServeError>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    if let Some(path) = addr.strip_prefix("unix:") {
        #[cfg(unix)]
        {
            let local = tokio::net::UnixStream::connect(path).await?;
            splice(local, writer, reader).await?;
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(ServeError::Io(io::Error::other(
                "unix sockets are not supported on this platform",
            )));
        }
    } else {
        let local = TcpStream::connect(addr).await?;
        splice(local, writer, reader).await?;
    }
    Ok(())
}

/// A dial that reached the peer and was refused: the peer plus the typed
/// classification, rendered as one line. Returned by [`Connector::preflight`].
#[derive(Debug, thiserror::Error)]
#[error("reached {dial}, but refused: {refusal}")]
pub struct DialRefused {
    /// The peer that refused the dial.
    pub dial: NodeId,
    /// The peer's classification. Not a `source`: this line is the whole story,
    /// and the refusal has no cause the dialer can see.
    pub refusal: Refusal,
}

/// A resolved connect: the node to dial, the service to ask for, and any token to present.
///
/// The domain half of a `connect`, with target parsing left to the caller. A caller builds one with
/// [`Connector::to_node`] (a raw node id, optionally presenting a [`Link`]) or [`Connector::from_link`]
/// (a `sheer:` link that supplies both the node and the token), then drives it with
/// [`Connector::preflight`] (then [`PortForward::run`]) or [`Connector::pipe_stdio`].
///
/// This type is the path for a transport selected at run time, where no compile-time bound is possible;
/// a caller whose transport type is fixed should prefer [`PresentingConnector`], which enforces the
/// credential rule at compile time.
pub struct Connector {
    dial: NodeId,
    service: Service,
    capability: Option<Link>,
    membership: Option<Link>,
}

impl Connector {
    /// Connect to a raw node id, requesting `service`. A raw-node dial may still present a token via
    /// `present`, for the case where the node id was shared separately from the capability.
    pub fn to_node(dial: NodeId, service: Service, present: Option<Link>) -> Self {
        Self {
            dial,
            service,
            capability: present,
            membership: None,
        }
    }

    /// Connect via a `sheer:` capability link, requesting `service`. The link supplies the node to dial
    /// (the cap's root) and carries the token; the host refuses unless the token actually grants `service`.
    pub fn from_link(link: &Link, service: Service) -> Self {
        Self {
            dial: link.root().node_id(),
            service,
            capability: Some(Link::clone(link)),
            membership: None,
        }
    }

    /// Also present `badge` in the SECOND slot: a membership badge under the foreign fleet a signet-bound
    /// slip in `capability` (slot 1) names. The host ANDs the two (the slip valid at its own root, the badge
    /// valid under the fleet the slip names) before admitting. A no-op for every plain dial, whose slot 1
    /// admits alone and whose host never consults slot 2.
    #[must_use]
    pub fn with_membership(mut self, badge: Link) -> Self {
        self.membership = Some(badge);
        self
    }

    /// The node this connector dials.
    pub fn dial(&self) -> NodeId {
        self.dial
    }

    /// The service this connector requests.
    pub fn service(&self) -> &Service {
        &self.service
    }

    /// The opening request this connector sends on each stream: the service to reach and any token. The
    /// one place the typed slots become the wire's raw text.
    fn request(&self) -> Request {
        Request {
            service: self.service.to_string(),
            capability: self.capability.as_ref().map(ToString::to_string),
            membership: self.membership.as_ref().map(ToString::to_string),
        }
    }

    /// Reach the peer, confirm the gate ADMITS this connector, and bind the local port, returning a live
    /// [`PortForward`] ready to run. Admission is proven here, before any success is announced: a probe
    /// stream sends the request and awaits the host's [`Response`], so a refusal (an unexposed service, a
    /// revoked or non-granting cap, an unauthorized identity) surfaces as an `Err` from THIS call, carrying
    /// the typed [`Refusal`], rather than a silently-reset connection once the caller has already printed
    /// "forwarding …". The caller announces readiness only after this returns `Ok`. Prints nothing.
    pub async fn preflight<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        port: u16,
    ) -> eyre::Result<PortForward<T::Session>> {
        let session = node.connect(self.dial).await?;
        let request = self.request();
        // Probe admission on one throwaway stream before announcing anything: if the gate refuses, fail
        // LOUDLY here with the reason, not mutely mid-forward. On admission the probe stream is dropped
        // (the host tears its serving half down); every later per-connection stream presents the same
        // request to the same gate, so this one admission faithfully predicts theirs.
        let (mut writer, mut reader) = session.open_bi().await?;
        // The checked writer: a request presenting a credential refuses here, before any byte, when the
        // session's declared profile does not prove the peer.
        request.write_checked::<T::Session, _>(&mut writer).await?;
        if let Response::Refused(refusal) = Response::read(&mut reader).await? {
            return Err(DialRefused {
                dial: self.dial,
                refusal,
            }
            .into());
        }
        drop((writer, reader));
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        Ok(PortForward {
            session,
            listener,
            request,
        })
    }

    /// Reach the service over one stream and pipe it against this process's stdin/stdout (a
    /// ProxyCommand-shaped bridge: the peer service is carried to this process's stdout while local stdin is
    /// pumped to the peer). The pump finishes when the peer closes, so a reached command exits when it does.
    pub async fn pipe_stdio<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
    ) -> eyre::Result<()> {
        let session = node.connect(self.dial).await?;
        let (writer, reader) = session.open_bi().await?;
        request_stdio::<T::Session, _, _>(self.request(), writer, reader).await
    }

    /// Reach the peer and return a [`ServiceSession`]: a [`Session`] whose every `open_bi` first speaks
    /// this connector's `Request{service, capability}` / `Response::Ok` handshake, so any caller-injected
    /// protocol generic over `Session` rides the gate transparently, one admitted stream at a
    /// time. This is the client counterpart to a per-stream [`serve_request`]: the exposer gates each
    /// stream, and the wrapper presents the request on each stream so every one of them is admitted on its
    /// own merits. Plain `async fn`, no spawn, so it honors the non-`Send` structured-concurrency rule.
    pub async fn open_service<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
    ) -> eyre::Result<ServiceSession<T::Session>> {
        let session = node.connect(self.dial).await?;
        Ok(ServiceSession {
            session,
            request: self.request(),
        })
    }
}

/// A dial that presents a credential, in its compile-time-checked form.
///
/// Constructed with the credential it always presents: a [`Link`] in slot 1
/// ([`to_node`](Self::to_node) or [`from_link`](Self::from_link)), optionally with a membership badge
/// in slot 2 ([`with_membership`](Self::with_membership)). Every dial method requires the transport's
/// declared profile to prove the peer (`T::Security: PeerProven`), so a credential over a
/// self-announced transport is a compile error, never a runtime hope. The unbounded [`Connector`]
/// carries the same rule at run time, for a transport chosen dynamically.
///
/// Prefer this type when the transport type is fixed; a transport selected at run time stays on
/// [`Connector`], where the checked writer enforces the same rule.
///
/// The announced profile is rejected where a proven peer is required:
///
/// ```compile_fail,E0277
/// # use bifrost::{Addr, Announced, Error, Node, NodeId, NoDiscovery, Session, Transport};
/// # use nauthy::{Link, Service};
/// # use tightbeam::tunnel::PresentingConnector;
/// #
/// # struct AnnouncedTransport;
/// # struct AnnouncedSession;
/// #
/// # impl Transport for AnnouncedTransport {
/// #     type Security = Announced;
/// #     type Session = AnnouncedSession;
/// #     fn node_id(&self) -> NodeId { unimplemented!() }
/// #     fn local_addr(&self) -> Addr { unimplemented!() }
/// #     async fn connect(&self, _: Addr) -> Result<Self::Session, Error> { unimplemented!() }
/// #     async fn accept(&self) -> Result<Self::Session, Error> { unimplemented!() }
/// #     async fn close(&self) {}
/// # }
/// #
/// # impl Session for AnnouncedSession {
/// #     type Security = Announced;
/// #     type Write = Vec<u8>;
/// #     type Read = &'static [u8];
/// #     fn peer(&self) -> NodeId { unimplemented!() }
/// #     async fn open_bi(&self) -> Result<(Self::Write, Self::Read), Error> { unimplemented!() }
/// #     async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), Error> { unimplemented!() }
/// #     async fn wait_closed(&self) {}
/// # }
/// #
/// # fn dial(node: &Node<AnnouncedTransport, NoDiscovery>, link: &Link, service: Service) {
/// // `Announced` does not implement `PeerProven`, so this does not compile:
/// let _ = PresentingConnector::from_link(link, service).preflight(node, 0);
/// # }
/// ```
pub struct PresentingConnector {
    /// The credential-bearing dial this type vouches for; its slots are fixed at construction, so the
    /// type cannot exist without a credential.
    connector: Connector,
}

impl PresentingConnector {
    /// Dial a raw node id, presenting `present` (slot 1). The compile-time twin of
    /// [`Connector::to_node`] with a `Link` in `present`.
    pub fn to_node(dial: NodeId, service: Service, present: Link) -> Self {
        Self {
            connector: Connector::to_node(dial, service, Some(present)),
        }
    }

    /// Dial the node a `sheer:` link names, presenting the link (slot 1). The compile-time twin of
    /// [`Connector::from_link`].
    pub fn from_link(link: &Link, service: Service) -> Self {
        Self {
            connector: Connector::from_link(link, service),
        }
    }

    /// Also present `badge` in slot 2 (the signet-bound AND); see
    /// [`Connector::with_membership`].
    #[must_use]
    pub fn with_membership(mut self, badge: Link) -> Self {
        self.connector = self.connector.with_membership(badge);
        self
    }

    /// The node this connector dials.
    pub fn dial(&self) -> NodeId {
        self.connector.dial()
    }

    /// The service this connector requests.
    pub fn service(&self) -> &Service {
        self.connector.service()
    }

    /// Reach the peer, confirm the gate admits this connector, and bind the local port; see
    /// [`Connector::preflight`].
    pub async fn preflight<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        port: u16,
    ) -> eyre::Result<PortForward<T::Session>>
    where
        T::Security: PeerProven,
    {
        self.connector.preflight(node, port).await
    }

    /// Reach the service over one stream and pipe it against this process's stdin/stdout; see
    /// [`Connector::pipe_stdio`].
    pub async fn pipe_stdio<T: Transport, D: Discovery>(self, node: &Node<T, D>) -> eyre::Result<()>
    where
        T::Security: PeerProven,
    {
        self.connector.pipe_stdio(node).await
    }

    /// Reach the peer and return a [`ServiceSession`]; see [`Connector::open_service`].
    pub async fn open_service<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
    ) -> eyre::Result<ServiceSession<T::Session>>
    where
        T::Security: PeerProven,
    {
        self.connector.open_service(node).await
    }
}

/// A reached, admitted, bound port forward, ready to [`run`](PortForward::run). Returned by
/// [`Connector::preflight`] only AFTER the gate has admitted this connector, so a caller can safely
/// announce readiness before running the loop: readiness is no longer a hopeful guess.
pub struct PortForward<S> {
    session: S,
    listener: TcpListener,
    request: Request,
}

impl<S: Session> PortForward<S> {
    /// Forward each accepted TCP connection over its own stream. Runs until cancelled; prints nothing.
    pub async fn run(self) -> eyre::Result<()> {
        let mut pipes = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    // One local accept or stream-open failing must not drop the pipes already in flight:
                    // log the transient error and keep the local listener up.
                    let (tcp, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            tracing::warn!(%error, "local accept failed; still listening");
                            continue;
                        }
                    };
                    let (writer, reader) = match self.session.open_bi().await {
                        Ok(stream) => stream,
                        Err(error) => {
                            tracing::warn!(%error, "opening a stream to the peer failed; still listening");
                            continue;
                        }
                    };
                    pipes.push(request_service::<S, _, _>(self.request.clone(), tcp, writer, reader));
                }
                Some(result) = pipes.next(), if !pipes.is_empty() => {
                    if let Err(error) = result {
                        // A refused stream (an unexposed service, a revoked or non-granting cap) carries a
                        // user-actionable reason. The core is print-free (a library embedder owns its own
                        // output), so route it through `tracing`; the caller surfaces it to its user.
                        tracing::warn!("connection failed: {error:#}");
                    }
                }
            }
        }
    }
}

/// A [`Session`] view that gates every stream it opens through a fixed service request. Wraps a live
/// bifrost session; on `open_bi` it opens a real stream, sends the request, and yields the admitted halves
/// ONLY on `Response::Ok`, mapping a refusal to [`bifrost::Error::Refused`]. Any caller-injected
/// `Session`-generic protocol runs over it unchanged, every one of its streams admitted by the gate.
///
/// The associated stream halves are the inner session's own (`type Write = S::Write; type Read =
/// S::Read`), so the handshake writes/reads on those exact halves and hands them back untouched: zero
/// boxing, and the wrapped protocol sees the same concrete stream types it would over a raw session.
/// `peer`/`conn_info`/`wait_closed` delegate to the inner session (so a caller still reads the settled
/// path); `accept_bi` is refused, because a service client never accepts peer-opened streams.
pub struct ServiceSession<S> {
    session: S,
    request: Request,
}

impl<S: Session> Session for ServiceSession<S> {
    // The wrapper carries the wrapped transport's declaration, so the security fact survives the
    // wrapping: a caller holding a `ServiceSession` still knows what proved the peer.
    type Security = S::Security;
    type Write = S::Write;
    type Read = S::Read;

    fn peer(&self) -> NodeId {
        self.session.peer()
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        let (mut writer, mut reader) = self.session.open_bi().await?;
        // The checked writer refuses a credential over a session whose declared profile does not prove
        // the peer, before the request's first byte; the inner profile is the transport's own.
        self.request
            .write_checked::<S, _>(&mut writer)
            .await
            .map_err(|error| bifrost::Error::Stream(Box::new(error)))?;
        match Response::read(&mut reader)
            .await
            .map_err(|error| bifrost::Error::Stream(Box::new(error)))?
        {
            Response::Ok => Ok((writer, reader)),
            // The typed refusal travels as its own `Error` variant, so a caller MATCHES it instead of
            // walking the source chain for a formatted reason.
            Response::Refused(refusal) => Err(bifrost::Error::Refused(refusal)),
        }
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        // A service client never accepts peer-opened streams; such service-scoped protocols only ever
        // `open_bi`. Refusing (rather than `unreachable!`) keeps the wrapper total and panic-free.
        Err(bifrost::Error::Stream(
            "a service-scoped session does not accept inbound streams".into(),
        ))
    }

    async fn wait_closed(&self) {
        self.session.wait_closed().await
    }

    fn conn_info(&self) -> ConnInfo {
        self.session.conn_info()
    }
}

/// Open a stream to a service: send the request, and if the host accepts, pipe the connection.
///
/// Generic over the session so the checked writer can read the session's declared security profile; the
/// caller names it, since the profile travels in the type and not in the stream halves.
async fn request_service<S, W, R>(
    request: Request,
    tcp: TcpStream,
    mut writer: W,
    mut reader: R,
) -> eyre::Result<()>
where
    S: Session,
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    request.write_checked::<S, _>(&mut writer).await?;
    match Response::read(&mut reader).await? {
        Response::Ok => splice(tcp, writer, reader).await?,
        Response::Refused(refusal) => return Err(bifrost::Error::Refused(refusal).into()),
    }
    Ok(())
}

/// Open a service and, if the host accepts, pipe it against this process's stdin/stdout (a
/// ProxyCommand-shaped bridge carrying the service to this process's stdout). Same handshake as
/// [`request_service`], but the local ends are the process's own std streams, and the pump
/// ([`pipe_stdio_bridge`]) returns when the PEER closes rather than waiting on a stdin that (at a terminal)
/// never EOFs, so a reached command exits when the command does.
async fn request_stdio<S, W, R>(request: Request, mut writer: W, mut reader: R) -> eyre::Result<()>
where
    S: Session,
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    request.write_checked::<S, _>(&mut writer).await?;
    match Response::read(&mut reader).await? {
        Response::Ok => pipe_stdio_bridge(writer, reader).await?,
        Response::Refused(refusal) => return Err(bifrost::Error::Refused(refusal).into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use bifrost::{Announced, ChannelProtection, NoDiscovery, Node, NodeId, PeerProof, Session};
    use bifrost_mem::MemTransport;
    use nauthy::{Gate, Service};
    use tokio::io::AsyncReadExt as _;

    use super::{
        Access, Admission, AllEnabled, BoxRead, BoxWrite, Exposer, Handler, Metering, Posture,
        PublicPool, PublicRequest, PublicServices, PublicSession, PublicUnsafeRequest,
        RAW_STREAM_OPEN_PERMITS, RawSource, Route, Router, Security, Semaphore, ServeError, Served,
        ServiceCatalog, ServiceEntry, Services, SessionPeer, Target, TargetKind,
        resolve_single_service, serve_request,
    };
    use crate::open_policy::{Never, OptIn};
    use crate::raw_stream::RawStream;

    /// The catalog a gated node serves reports every service as `gated`, name-sorted, and survives a wire
    /// round trip byte for byte: the read `control.services` returns and the client decodes are the same value.
    #[test]
    fn a_gated_catalog_reports_gated_and_round_trips() {
        let services = services(&["c=127.0.0.1:80"])
            .with_handler("a", OpenNoop)
            .expect("`a` binds");
        let services = services.with_handler("b", OpenNoop).expect("`b` binds");
        let signet = nauthy::Identity::from_secret(&[7u8; 32]).expect("valid secret");
        let denylist = nauthy::FileDenylist::empty(std::env::temp_dir().join("tb-catalog-gated"));
        let gate = Gate::rooted(signet.verifying_key(), denylist);
        let catalog = services.catalog(&gate, &PublicRequest::none(), &PublicUnsafeRequest::none());

        let names: Vec<&str> = catalog.entries().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"], "entries are name-sorted");
        assert!(
            catalog
                .entries()
                .all(|entry| entry.posture == Posture::Gated),
            "a gated node reports every service as gated"
        );

        let decoded = ServiceCatalog::decode(&catalog.encode()).expect("catalog decodes");
        assert_eq!(decoded, catalog, "the catalog survives a wire round trip");
    }

    /// An open node reports every service as `open`: the effective posture is read off the node gate, so a
    /// public node's catalog says anyone may reach these.
    #[test]
    fn an_open_catalog_reports_open() {
        let services = services(&["a=127.0.0.1:80"])
            .with_handler("b", OpenNoop)
            .expect("`b` binds");
        let catalog = services.catalog(
            &Gate::Open,
            &PublicRequest::none(),
            &PublicUnsafeRequest::none(),
        );
        assert!(
            catalog
                .entries()
                .all(|entry| entry.posture == Posture::Open),
            "an open node reports every service as open"
        );
        assert_eq!(
            ServiceCatalog::decode(&catalog.encode()).expect("decodes"),
            catalog
        );
    }

    /// An empty catalog encodes to a bare count and decodes back to empty (zero / one / many coverage).
    #[test]
    fn an_empty_catalog_round_trips() {
        let catalog = ServiceCatalog(Vec::new());
        let decoded = ServiceCatalog::decode(&catalog.encode()).expect("empty decodes");
        assert_eq!(decoded, catalog);
        assert_eq!(decoded.entries().count(), 0);
    }

    /// A truncated blob, an unknown posture tag, and trailing bytes are clean decode errors, never a panic:
    /// the wire is bounds-checked against untrusted input.
    #[test]
    fn a_malformed_catalog_is_a_clean_error() {
        // A count of 1 but no entry bytes: truncated.
        assert!(ServiceCatalog::decode(&1u32.to_be_bytes()).is_err());

        // One entry with a posture tag of 9 (neither gated nor open).
        let mut bad_tag = Vec::new();
        bad_tag.extend_from_slice(&1u32.to_be_bytes());
        bad_tag.extend_from_slice(&1u16.to_be_bytes());
        bad_tag.push(b'x');
        bad_tag.push(9);
        assert!(ServiceCatalog::decode(&bad_tag).is_err());

        // A well-formed single entry followed by a stray byte: trailing bytes are rejected.
        let good = ServiceCatalog(vec![ServiceEntry {
            name: "a".to_owned(),
            posture: Posture::Gated,
        }]);
        let mut trailing = good.encode();
        trailing.push(0);
        assert!(ServiceCatalog::decode(&trailing).is_err());
    }

    /// A do-nothing GATED handler (`type Exposure = Never`): a handler with no public use of its own, so an
    /// open gate over it must be refused when the proof is prepared.
    struct GatedNoop;
    impl Handler for GatedNoop {
        type Exposure = Never;
        async fn serve(
            &self,
            _served: Served<Self>,
            _writer: BoxWrite,
            _reader: BoxRead,
        ) -> Result<(), ServeError> {
            Ok(())
        }
    }

    /// A do-nothing OPEN handler (`type Exposure = OptIn`): a legitimately-public responder, exposable under
    /// any gate.
    struct OpenNoop;
    impl Handler for OpenNoop {
        type Exposure = OptIn;
        async fn serve(
            &self,
            _served: Served<Self>,
            _writer: BoxWrite,
            _reader: BoxRead,
        ) -> Result<(), ServeError> {
            Ok(())
        }
    }

    /// A legitimately-public responder that also declares itself [`Metering::Unmetered`]: the shape of
    /// `ping`/`speed`, so a manifest reads the caveat off the handler, not a name list.
    struct AmplifierNoop;
    impl Handler for AmplifierNoop {
        type Exposure = OptIn;
        fn metering(&self) -> Metering {
            Metering::Unmetered
        }
        async fn serve(
            &self,
            _served: Served<Self>,
            _writer: BoxWrite,
            _reader: BoxRead,
        ) -> Result<(), ServeError> {
            Ok(())
        }
    }

    /// A handler that declares itself [`Metering::Metered`]: the manifest must render exactly what the
    /// handler reports, independent of the trait default.
    struct MeteredNoop;
    impl Handler for MeteredNoop {
        type Exposure = OptIn;
        fn metering(&self) -> Metering {
            Metering::Metered
        }
        async fn serve(
            &self,
            _served: Served<Self>,
            _writer: BoxWrite,
            _reader: BoxRead,
        ) -> Result<(), ServeError> {
            Ok(())
        }
    }

    /// A public handler that parks inside `serve` until a permit is added to `release`, so a
    /// public-stream cap test can hold one stream's permit deterministically. `entered` signals the test
    /// that the serve body is running, which is after the stream was admitted and its permit taken.
    struct Parked {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<Semaphore>,
    }
    impl Handler for Parked {
        type Exposure = OptIn;
        async fn serve(
            &self,
            _served: Served<Self>,
            _writer: BoxWrite,
            _reader: BoxRead,
        ) -> Result<(), ServeError> {
            self.entered.notify_one();
            let _permit = self.release.acquire().await;
            Ok(())
        }
    }

    /// Prove a table + gate + raw requests into the runnable exposer, the one-door shape the assembly tests
    /// exercise directly ([`Exposer::prove`]).
    fn prove(
        services: Services,
        gate: Gate,
        public: PublicRequest,
        public_unsafe: PublicUnsafeRequest,
    ) -> eyre::Result<Exposer> {
        Exposer::prove(services, gate, public, public_unsafe)
    }

    /// The readiness manifest reads posture off the PROVEN overlay, kind off the target, and the metering
    /// caveat off the handler's declaration, name-sorted: an opened unmetered responder reads
    /// `Open + Unmetered`, a gated one keeps its declaration (the caveat is the handler's, independent of
    /// posture), and the built-in forward is neither open nor unmetered-warned (its handler IS the default
    /// `Unmetered`, which is the honest read of the built-in). This is what feeds a caller's grouped serve
    /// banner.
    #[test]
    fn the_manifest_declares_posture_kind_and_metering() {
        let services = services(&["web=127.0.0.1:80"])
            .with_handler("fast", AmplifierNoop)
            .expect("`fast` binds");
        let services = services
            .with_handler("quiet", MeteredNoop)
            .expect("`quiet` binds");
        let exposer = prove(
            services,
            family_gate("manifest"),
            PublicRequest::new(["fast".to_owned()]),
            PublicUnsafeRequest::none(),
        )
        .expect("assembles");

        let manifest = exposer.manifest();
        let names: Vec<&str> = manifest.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["fast", "quiet", "web"], "manifest is name-sorted");

        let fast = &manifest[0];
        assert_eq!(fast.posture, Posture::Open, "`fast` was opened per-service");
        assert_eq!(fast.kind, super::TargetKind::Handler);
        assert_eq!(
            fast.metering,
            Some(Metering::Unmetered),
            "the opened unmetered responder declares its caveat"
        );

        let quiet = &manifest[1];
        assert_eq!(quiet.posture, Posture::Gated, "`quiet` stays gated");
        assert_eq!(
            quiet.metering,
            Some(Metering::Metered),
            "the caveat is the handler's, shown independent of posture"
        );

        let web = &manifest[2];
        assert_eq!(web.kind, super::TargetKind::Handler);
        assert_eq!(web.posture, Posture::Gated);
        assert!(
            web.raw_source.is_none(),
            "a forward has no raw source to warn about"
        );
    }

    /// The metering default: a handler that does not override [`Handler::metering`] reports
    /// [`Metering::Unmetered`] through the erased bridge (the fail-loud direction: an open service warns),
    /// and a handler that overrides it reports exactly its own declaration.
    #[test]
    fn metering_defaults_to_unmetered_and_reads_the_override() {
        let services = services(&["web=127.0.0.1:80"])
            .with_handler("plain", OpenNoop)
            .expect("`plain` binds");
        let services = services
            .with_handler("bounded", MeteredNoop)
            .expect("`bounded` binds");
        let exposer = prove(
            services,
            Gate::Open,
            PublicRequest::new(["plain".to_owned(), "bounded".to_owned()]),
            PublicUnsafeRequest::none(),
        )
        .expect("both are OptIn, so an open gate builds");

        let manifest = exposer.manifest();
        let plain = manifest
            .iter()
            .find(|entry| entry.name == "plain")
            .expect("`plain` is in the manifest");
        assert_eq!(
            plain.metering,
            Some(Metering::Unmetered),
            "the trait default is the fail-loud Unmetered"
        );
        let bounded = manifest
            .iter()
            .find(|entry| entry.name == "bounded")
            .expect("`bounded` is in the manifest");
        assert_eq!(bounded.metering, Some(Metering::Metered));
    }

    fn svc(name: &str) -> Service {
        name.parse()
            .unwrap_or_else(|_| panic!("valid service: {name}"))
    }

    fn services(entries: &[&str]) -> Services {
        Services::parse(&entries.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
            .expect("entries parse")
    }

    /// A single-service `Services` whose one target is a `stdin:`-shaped source over `reader`, so the full
    /// served path can be exercised with known bytes instead of the process's real fd 0.
    fn stdin_service(name: &str, reader: BoxRead) -> Services {
        let mut map = HashMap::new();
        map.insert(
            name.to_owned(),
            Route::family(Target::RawStream(RawStream::from_reader(reader))),
        );
        Services(map)
    }

    /// A single-service `Services` whose one target is a `stdin:+lossy`-shaped FAN-OUT source over `reader`, so
    /// the full multi-consumer served path (one shared ring, N cursors) runs without the process's real fd 0.
    fn lossy_service(name: &str, reader: BoxRead) -> Services {
        let mut map = HashMap::new();
        map.insert(
            name.to_owned(),
            Route::family(Target::RawStream(RawStream::lossy_from_reader(reader))),
        );
        Services(map)
    }

    #[test]
    fn a_single_service_node_needs_no_service_name() {
        let Services(one) = services(&["a=127.0.0.1:80"]);
        // A connector defaulting to `default` on a single-service node resolves to that one service.
        assert_eq!(resolve_single_service(svc("default"), &one).as_str(), "a");
        // A request that already names the exposed service is unchanged.
        assert_eq!(resolve_single_service(svc("a"), &one).as_str(), "a");

        let Services(two) = services(&["a=127.0.0.1:80", "b=127.0.0.1:81"]);
        // With two services, an unmatched request is left as-is (fails later with the hint, never guesses).
        assert_eq!(
            resolve_single_service(svc("default"), &two).as_str(),
            "default"
        );
    }

    #[test]
    fn a_bare_service_name_is_rejected_with_a_hint() {
        // Every serve entry must be `name=addr`; a bare entry names no service and fails at parse.
        let Err(err) = Services::parse(&["web".to_owned()]) else {
            panic!("bare `web` should be rejected, not served");
        };
        assert!(
            err.to_string().contains("name=addr"),
            "the error should teach the grammar: {err}"
        );
    }

    #[test]
    fn a_bare_scheme_without_a_name_is_rejected() {
        // Bare `ping:` names no service either: only `ping=ping:` is spelled.
        let Err(err) = Services::parse(&["ping:".to_owned()]) else {
            panic!("bare `ping:` should be rejected, not served");
        };
        assert!(
            err.to_string().contains("name=addr"),
            "the error should teach the grammar: {err}"
        );
    }

    /// A duplicate name is refused by the same policy `with_handler` and `Registry::extend` apply: a silent
    /// overwrite would drop the first target (and could move a member floor off the route it was declared on).
    #[test]
    fn a_duplicate_service_name_is_refused_by_parse() {
        let Err(err) =
            Services::parse(&["web=127.0.0.1:80".to_owned(), "web=127.0.0.1:81".to_owned()])
        else {
            panic!("a duplicate name must be refused, never silently overwritten");
        };
        assert!(
            err.to_string().contains("already defined"),
            "the refusal names the duplicate: {err}"
        );
    }

    #[test]
    fn real_targets_parse() {
        for entry in [
            "web=127.0.0.1:8080",
            "db=unix:/run/db.sock",
            "pipe=file:/tmp/beam",
            "named=fifo:/tmp/beam",
            "demo=echo:",
        ] {
            assert!(
                Services::parse(&[entry.to_owned()]).is_ok(),
                "{entry} should parse"
            );
        }
    }

    /// A bare `<scheme>:` used to name a registry handler. Handlers bind by value on the Router, so the
    /// scheme namespace is a teaching error now, never a silently-dangling target.
    #[test]
    fn a_handler_scheme_entry_is_a_teaching_error() {
        for entry in [
            "a=handler:",
            "status=control.status:",
            "restart=control.restart:",
        ] {
            let Err(err) = Services::parse(&[entry.to_owned()]) else {
                panic!("`{entry}` names a handler scheme and must be refused");
            };
            assert!(
                err.to_string().contains("handler scheme"),
                "the refusal teaches the binding shape: {err}"
            );
        }
    }

    #[test]
    fn raw_stream_schemes_resolve_to_a_raw_stream_target_never_a_bare_forward_or_handler() {
        // `file:`/`fifo:` carry a PATH tail, so they must resolve to the guarded raw-stream forward, NEVER
        // a plain `Target::Forward` (which would splice unguarded) nor a `Target::Handler` (a bare scheme).
        // Pin it so a future refactor cannot regress the routing into an unguarded shape.
        for entry in ["pipe=file:/tmp/beam", "named=fifo:/tmp/beam"] {
            let Services(parsed) = services(&[entry]);
            let route = parsed.values().next().expect("one service parsed");
            assert!(
                matches!(&route.target, super::Target::RawStream(_)),
                "{entry} must resolve to Target::RawStream, got {route:?}"
            );
        }
        // A bare `file:`/`fifo:` with no path is NOT a handler: it fails loudly at parse.
        assert!(
            Services::parse(&["pipe=file:".to_owned()]).is_err(),
            "`file:` with no path must be rejected, never treated as a handler scheme"
        );
        assert!(
            Services::parse(&["pipe=fifo:".to_owned()]).is_err(),
            "`fifo:` with no path must be rejected, never treated as a handler scheme"
        );
    }

    #[test]
    fn a_named_service_pointed_at_a_bogus_addr_is_rejected() {
        assert!(Services::parse(&["web=nonsense".to_owned()]).is_err());
    }

    #[test]
    fn echo_scheme_resolves_to_the_builtin_reflector() {
        // `echo:` is the zero-arg built-in reflector, now a first-party handler value: parsing it must
        // produce the built-in Echo, never a forward. Pin the routing so it stays a first-class built-in.
        let Services(parsed) = services(&["demo=echo:"]);
        let route = parsed.values().next().expect("one service parsed");
        assert!(
            matches!(&route.target, super::Target::Handler(_)),
            "`echo:` must resolve to a bound handler, got {route:?}"
        );
        assert_eq!(route.target.kind(), TargetKind::Handler);
        // `echo:` takes no argument and tolerates no `+lossy` (it is not a raw-stream source): both are refused
        // at parse, loudly at expose.
        assert!(
            Services::parse(&["demo=echo:+lossy".to_owned()]).is_err(),
            "`echo:+lossy` must be rejected: echo is not a fan-out raw-stream source"
        );
        // The typed verb is the sugar the README teaches: `.echo(name)` is `.service(name, Echo)`.
        let exposer = Router::new(Gate::Open)
            .echo(svc("demo"))
            .expect("echo binds")
            .expose()
            .expect("echo is OptIn, so an open gate serves it with no unsafe opt-in");
        let manifest = exposer.manifest();
        let demo = manifest
            .iter()
            .find(|entry| entry.name == "demo")
            .expect("`demo` is in the manifest");
        assert_eq!(demo.posture, Posture::Open);
        assert_eq!(demo.kind, TargetKind::Handler);
        assert!(
            demo.raw_source.is_none(),
            "echo exposes no raw source, so there is nothing to warn about: {demo:?}"
        );
    }

    #[test]
    fn lossy_is_accepted_only_on_stdin_and_fifo_and_rejected_elsewhere() {
        // `+lossy` opts a live single-writer source into fan-out; it is legal ONLY on `stdin:`/`fifo:`.
        for entry in ["cam=stdin:+lossy", "cam=fifo:/tmp/cam+lossy"] {
            let Services(parsed) = services(&[entry]);
            let route = parsed.values().next().expect("one service parsed");
            assert!(
                matches!(&route.target, Target::RawStream(_)),
                "{entry} must resolve to a raw-stream fan-out target, got {route:?}"
            );
        }
        // On any OTHER scheme `+lossy` is refused at PARSE with a teaching message: a `file:` (static bytes,
        // dropping would be corruption), a `host:port` / `unix:` forward, or a handler scheme are not
        // loss-tolerant live sources. Rejected loudly at expose, not silently ignored.
        for entry in [
            "doc=file:/etc/hosts+lossy",
            "web=127.0.0.1:8080+lossy",
            "db=unix:/run/db.sock+lossy",
            "a=handler:+lossy",
        ] {
            let Err(err) = Services::parse(&[entry.to_owned()]) else {
                panic!("`+lossy` on {entry} must be rejected at parse");
            };
            assert!(
                err.to_string().contains("`+lossy`"),
                "the refusal must name the modifier: {err}"
            );
        }
    }

    #[test]
    fn a_public_gate_over_a_lossy_source_is_refused_at_the_same_door() {
        // A `+lossy` fan-out is still a raw-stream source with no auth of its own: a public gate over it would
        // serve the piped bytes to anyone. It must be refused at the SAME door as a non-lossy raw stream, so
        // `+lossy` cannot reopen the delib-05/11 exfil gate.
        let lossy = services(&["cam=stdin:+lossy"]);
        assert!(
            prove(
                lossy,
                Gate::Open,
                PublicRequest::none(),
                PublicUnsafeRequest::none()
            )
            .is_err(),
            "an open gate over a `+lossy` raw-stream source must be refused"
        );
    }

    #[test]
    fn a_dotted_name_binds_a_handler_for_a_method_on_an_interface() {
        // A method on an interface (`control.status`, `control.restart`) is one dotted SERVICE NAME: `.` is
        // in the `Service` alphabet, so a handler binds under the dotted name directly, never through a
        // scheme-string grammar.
        for name in ["control.status", "control.restart"] {
            let services = Services(HashMap::new())
                .with_handler(name, OpenNoop)
                .expect("a dotted name binds");
            assert!(
                services.0.contains_key(name),
                "the dotted name is preserved verbatim as the route key, got {name:?}"
            );
        }
    }

    #[test]
    fn an_exposer_refuses_an_open_gate_over_a_gated_only_handler() {
        // A gated-only handler (`type Exposure = Never`): it has no legitimate public use, so an open gate
        // over it would serve it to anyone. The proof door must reject that pairing, wherever the caller
        // assembles it.
        let gated = Services(HashMap::new())
            .with_handler("a", GatedNoop)
            .expect("`a` binds");
        assert!(
            prove(
                gated,
                Gate::Open,
                PublicRequest::none(),
                PublicUnsafeRequest::none()
            )
            .is_err(),
            "an open gate over a gated-only handler must be refused"
        );
        // The same handler behind a real gate is fine; only the open-gate pairing is refused. A family gate
        // needs a signet and denylist, so prove the inverse with a plain forward under the open gate.
        let web = services(&["web=127.0.0.1:80"]);
        assert!(
            prove(
                web,
                Gate::Open,
                PublicRequest::none(),
                PublicUnsafeRequest::none()
            )
            .is_ok(),
            "an open gate over a plain forward is allowed"
        );
    }

    /// Access is opt-in per route: every parsed route defaults to [`Access::Family`] (the gate alone
    /// decides), and `member_only` flips exactly the named route to [`Access::Member`].
    #[test]
    fn routes_default_to_family_and_member_only_flips_the_named_route() {
        let parsed = services(&["web=127.0.0.1:80", "locked=127.0.0.1:81"]);
        let Services(routes) = &parsed;
        assert!(
            routes.values().all(|route| route.access == Access::Family),
            "parsed routes default to the gate-alone floor"
        );
        let parsed = parsed.member_only("locked").expect("`locked` is served");
        let Services(routes) = &parsed;
        assert_eq!(routes["web"].access, Access::Family);
        assert_eq!(routes["locked"].access, Access::Member);
    }

    /// A member-only route under a node-wide open gate is a DEAD route: an open gate proves nothing about a
    /// peer, so its only witness is a slip and the floor would refuse every dialer. Refused at the door, not
    /// served as a route that answers no one.
    #[test]
    fn a_member_only_route_under_an_open_gate_is_refused_at_construction() {
        let services = services(&["web=127.0.0.1:80"])
            .member_only("web")
            .expect("`web` is served");
        let Err(error) = prove(
            services,
            Gate::Open,
            PublicRequest::none(),
            PublicUnsafeRequest::none(),
        ) else {
            panic!("a member-only route under an open gate must be refused at construction");
        };
        let message = error.to_string();
        assert!(
            message.contains("member-only") && message.contains("web"),
            "the refusal names the route and the contradiction: {message:?}"
        );
    }

    /// A member-only route named public is contradictory: the public overlay admits through `Gate::Open`,
    /// whose only witness is a slip, so the route would refuse every dialer while the catalog renders it
    /// `Open` (a posture lie). Refused where the overlay is proven.
    #[test]
    fn a_member_only_route_named_public_is_refused_at_construction() {
        let services = services(&["web=127.0.0.1:80"])
            .member_only("web")
            .expect("`web` is served");
        let Err(error) = prove(
            services,
            family_gate("member-public"),
            PublicRequest::new(["web".to_owned()]),
            PublicUnsafeRequest::none(),
        ) else {
            panic!("a member-only route must not be opened to everyone");
        };
        let message = error.to_string();
        assert!(
            message.contains("member-only") && message.contains("web"),
            "the refusal names the route and the contradiction: {message:?}"
        );
    }

    /// A member-only raw stream named in the unsafe overlay is the same dead route as the safe public case,
    /// and the same posture lie: the opened stream admits through `Gate::Open` (a slip), so the floor would
    /// refuse every dialer while the manifest renders it `Open`.
    #[test]
    fn a_member_only_raw_stream_named_public_unsafe_is_refused_at_construction() {
        let path = std::env::temp_dir().join("tb-member-unsafe");
        let entry = format!("logs=file:{}", path.display());
        let services = services(&[&entry])
            .member_only("logs")
            .expect("`logs` is served");
        let Err(error) = prove(
            services,
            family_gate("member-unsafe"),
            PublicRequest::none(),
            PublicUnsafeRequest::new(["logs".to_owned()]),
        ) else {
            panic!("a member-only raw stream in the unsafe set must be refused at construction");
        };
        let message = error.to_string();
        assert!(
            message.contains("member-only") && message.contains("logs"),
            "the refusal names the route and the contradiction: {message:?}"
        );
    }

    /// Marking a name the node does not serve is a caller error, exactly like a duplicate in `with_handler`:
    /// a silent no-op would leave the operator believing a floor exists that does not.
    #[test]
    fn member_only_refuses_a_name_the_node_does_not_serve() {
        let Err(error) = services(&["web=127.0.0.1:80"]).member_only("nope") else {
            panic!("marking an unserved name must be refused");
        };
        assert!(
            error.to_string().contains("no service named"),
            "the refusal teaches the served list: {error}"
        );
    }

    #[test]
    fn an_exposer_refuses_a_public_raw_stream() {
        // A raw-stream source (`file:`/`fifo:`) has no auth of its own: under an open gate it would serve a
        // chosen path's bytes to anyone, so a public gate over `file:<secret>` would exfil it. Refused at the
        // same door as a public shell UNLESS the operator knowingly names it unsafe (that path is covered by
        // `an_exposer_admits_a_public_raw_stream_named_in_public_unsafe`). With an EMPTY unsafe set it bails.
        let secret = services(&["leak=file:/etc/hosts"]);
        assert!(
            prove(
                secret,
                Gate::Open,
                PublicRequest::none(),
                PublicUnsafeRequest::none()
            )
            .is_err(),
            "an open gate over a file:/fifo: source with no unsafe opt-in must be refused"
        );
        // A raw forward the operator deliberately stood up (host:port) stays open-able; only the no-auth
        // raw-stream source is refused under the open gate.
        let web = services(&["web=127.0.0.1:80"]);
        assert!(
            prove(
                web,
                Gate::Open,
                PublicRequest::none(),
                PublicUnsafeRequest::none()
            )
            .is_ok(),
            "an open gate over a host:port forward is still allowed"
        );
    }

    #[test]
    fn an_exposer_admits_a_public_raw_stream_named_in_public_unsafe() {
        // The escape hatch: an open BASE gate over a `file:` source that the operator KNOWINGLY named in the
        // unsafe opt-in set BUILDS (the door is relaxed per-name), and the manifest reports that name Open, a
        // RawStream, carrying its resolved absolute source for the banner warning.
        let path = std::env::temp_dir().join("tb-public-unsafe-admits");
        let entry = format!("logs=file:{}", path.display());
        let services = services(&[&entry]);
        let exposer = prove(
            services,
            Gate::Open,
            PublicRequest::none(),
            PublicUnsafeRequest::new(["logs".to_owned()]),
        )
        .expect("a raw stream named in the unsafe set builds under an open gate");

        let manifest = exposer.manifest();
        let logs = manifest
            .iter()
            .find(|entry| entry.name == "logs")
            .expect("`logs` is in the manifest");
        assert_eq!(
            logs.posture,
            Posture::Open,
            "the unsafe-open raw stream reads Open"
        );
        assert_eq!(logs.kind, TargetKind::RawStream, "it is a raw stream");
        let Some(RawSource::Path(absolute)) = &logs.raw_source else {
            panic!("a file: raw stream declares a resolved absolute Path source: {logs:?}");
        };
        assert!(
            std::path::Path::new(absolute).is_absolute(),
            "the banner source is an absolute path (std::path::absolute), got {absolute:?}"
        );
    }

    #[test]
    fn echo_is_admitted_under_plain_public_with_no_unsafe_opt_in() {
        // The whole point of the built-in reflector: it is the ONE thing a newcomer can open to strangers
        // under a PLAIN public gate, with no louder raw-stream opt-in. Prove both public doors admit it:
        // (1) the per-service SAFE overlay opens it, and it reads Open + Handler in the manifest with no
        //     raw-source warning; and
        // (2) a node-wide open BASE gate over `Gate::Open` with an EMPTY unsafe set BUILDS, where a raw
        //     stream would have been refused and redirected to the unsafe raw-stream set.
        let per_service = prove(
            services(&["demo=echo:"]),
            family_gate("echo-public"),
            PublicRequest::new(["demo".to_owned()]),
            PublicUnsafeRequest::none(),
        )
        .expect("echo is safe public, so a plain public gate opens it with no unsafe opt-in");

        let manifest = per_service.manifest();
        let demo = manifest
            .iter()
            .find(|entry| entry.name == "demo")
            .expect("`demo` is in the manifest");
        assert_eq!(demo.posture, Posture::Open, "the opened echo reads Open");
        assert_eq!(demo.kind, TargetKind::Handler, "it is a bound handler");
        assert!(
            demo.raw_source.is_none(),
            "echo exposes no raw source, so there is nothing to warn about: {demo:?}"
        );
        assert_eq!(
            demo.metering,
            Some(Metering::Metered),
            "echo reflects the caller's own bytes (symmetric), so it does not carry the unmetered caveat"
        );

        assert!(
            prove(
                services(&["demo=echo:"]),
                Gate::Open,
                PublicRequest::none(),
                PublicUnsafeRequest::none(),
            )
            .is_ok(),
            "a node-wide open gate over an echo reflector builds with no unsafe opt-in (unlike a raw stream)"
        );
    }

    #[test]
    fn public_unsafe_over_a_device_or_directory_is_refused_at_serve() {
        // The banner must never advertise bytes the dial will refuse: a `file:` source that is a DEVICE or a
        // DIRECTORY is refused at connect, so naming it in the unsafe set is refused loudly at SERVE (in
        // `Exposer::new`, before any banner), rather than printed as "serving the raw bytes of ..." and then
        // refused mid-dial. Both `/dev/null` (a char device) and the temp dir (a directory) EXIST, so the
        // serve-time `lstat` sees the always-refused type.
        let device = services(&["drain=file:/dev/null"]);
        let Err(via_device) = prove(
            device,
            Gate::Open,
            PublicRequest::none(),
            PublicUnsafeRequest::new(["drain".to_owned()]),
        ) else {
            panic!(
                "a device named in the unsafe set must be refused at serve, not advertised then refused"
            );
        };
        assert!(
            via_device.to_string().contains("character device"),
            "the serve-time refusal names the device type: {via_device}"
        );

        let dir_entry = format!("logs=file:{}", std::env::temp_dir().display());
        let directory = services(&[&dir_entry]);
        let Err(via_dir) = prove(
            directory,
            Gate::Open,
            PublicRequest::none(),
            PublicUnsafeRequest::new(["logs".to_owned()]),
        ) else {
            panic!("a directory named in the unsafe set must be refused at serve");
        };
        assert!(
            via_dir.to_string().contains("directory"),
            "the serve-time refusal names the directory type: {via_dir}"
        );
    }

    #[test]
    fn public_unsafe_naming_a_handler_or_forward_is_redirected() {
        // The disjoint-token partition: the unsafe overlay is ONLY for raw streams. A handler or a forward
        // named in it is a teaching redirect to the public overlay, never silently
        // opened.
        let handler = Services(HashMap::new())
            .with_handler("ping", OpenNoop)
            .expect("`ping` binds");
        let Err(via_handler) = prove(
            handler,
            family_gate("unsafe-handler"),
            PublicRequest::none(),
            PublicUnsafeRequest::new(["ping".to_owned()]),
        ) else {
            panic!("a handler named unsafe must be redirected, not opened");
        };
        assert!(
            via_handler.to_string().contains("not a raw byte source")
                && via_handler.to_string().contains("public set"),
            "a handler named unsafe is redirected to the public overlay: {via_handler}"
        );

        let forward = services(&["web=127.0.0.1:80"]);
        let Err(via_forward) = prove(
            forward,
            family_gate("unsafe-forward"),
            PublicRequest::none(),
            PublicUnsafeRequest::new(["web".to_owned()]),
        ) else {
            panic!("a forward named unsafe must be redirected, not opened");
        };
        assert!(
            via_forward.to_string().contains("not a raw byte source")
                && via_forward.to_string().contains("public set"),
            "a forward named unsafe is redirected to the public overlay: {via_forward}"
        );
    }

    #[test]
    fn public_unsafe_naming_an_unserved_name_is_a_parse_error() {
        // A name the node does not serve, named unsafe, bails with the served list (parse-don't-validate at
        // the door), never silently opening nothing.
        let services = services(&["cam=stdin:"]);
        let Err(error) = prove(
            services,
            family_gate("unsafe-unserved"),
            PublicRequest::none(),
            PublicUnsafeRequest::new(["nope".to_owned()]),
        ) else {
            panic!("an unserved name in the unsafe set must bail");
        };
        assert!(
            error.to_string().contains("no service named"),
            "an unserved unsafe name is refused with the served list: {error}"
        );
    }

    /// DESIGN-LOCK marker (delib-34, no operand today): the toggle mutual-exclusion interlock is OWED but not
    /// yet buildable. delib-34's live-toggle set (`ActiveSet`/`--toggleable`) is unbuilt, so there is no
    /// second set for `Exposer::new` to refuse against a `public_unsafe` set; inventing a toggle field now
    /// purely to refuse it would be machinery for a case that cannot occur yet. This test records the
    /// acceptance criterion for the delib-34 build: when the toggle allowlist lands it enters `Exposer::new`
    /// beside `public_unsafe` and adds ONE bail refusing their co-presence
    /// (`!proven_unsafe.is_empty() && !toggleable.is_empty()`), so an unauthenticated toggle can never re-arm
    /// a raw-byte exfil remotely. TODO(delib-34): replace this marker with the live construction-fail test
    /// once the toggle set exists. Today, an unsafe set alone builds (no toggle operand to conflict with).
    #[test]
    fn public_unsafe_alone_builds_and_the_toggle_interlock_is_a_design_lock_owed_to_delib_34() {
        let path = std::env::temp_dir().join("tb-public-unsafe-designlock");
        let entry = format!("logs=file:{}", path.display());
        let services = services(&[&entry]);
        // No toggle operand exists today, so an unsafe set on its own is fully legal.
        assert!(
            prove(
                services,
                Gate::Open,
                PublicRequest::none(),
                PublicUnsafeRequest::new(["logs".to_owned()]),
            )
            .is_ok(),
            "an unsafe raw-stream set alone builds; the toggle mutual-exclusion is owed to the delib-34 build"
        );
    }

    #[test]
    fn stdin_resolves_to_a_raw_stream_target_routed_before_the_bare_scheme_arm() {
        // `stdin:` is a zero-arg raw-stream source: it must resolve to `Target::RawStream`, NOT a
        // `Target::Handler("stdin")` (which the bare-scheme arm would produce and no registry would hold).
        // (Under `cargo test` fd 0 is not a tty, so the parse-time TTY refusal does not fire.)
        let Services(parsed) = services(&["cam=stdin:"]);
        let route = parsed.values().next().expect("one service parsed");
        assert!(
            matches!(&route.target, Target::RawStream(_)),
            "`stdin:` must resolve to Target::RawStream, got {route:?}"
        );
    }

    #[test]
    fn an_exposer_refuses_a_public_stdin() {
        // `stdin:` has no auth of its own: under an open gate it would pipe the producer's bytes to anyone, so
        // a public gate over `stdin:` would exfil them. Refused at the same door as a public shell or a public file:.
        let piped = services(&["cam=stdin:"]);
        assert!(
            prove(
                piped,
                Gate::Open,
                PublicRequest::none(),
                PublicUnsafeRequest::none()
            )
            .is_err(),
            "an open gate over a stdin: source with no unsafe opt-in must be refused"
        );
    }

    /// The full served path: an exposer over a `stdin:`-shaped source, a connector reaching it over the
    /// in-process transport, and the peer receiving the source's EXACT bytes. Drives the same take-once +
    /// `Target::RawStream` splice the served path uses, with an injected reader in place of the real fd 0. A second
    /// concurrent connection finds the source taken and is refused cleanly (not a corrupted second read).
    #[tokio::test]
    async fn a_stdin_source_is_served_to_the_peer_and_a_second_reader_is_refused() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let body: &'static [u8] = b"live bytes piped into the exposer";
                let services = stdin_service("cam", Box::new(body));

                let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
                let exposer_id = exposer_node.node_id();
                let consumer = Node::new(MemTransport::bind(), NoDiscovery);

                // Drive the SERVE path directly. `Exposer::new`'s public-gate refusal for a raw-stream source
                // is covered separately (`an_exposer_refuses_a_public_stdin`); here we construct the exposer
                // past that door so the open gate keeps the peer admitted with no token, and the test isolates
                // the take-once + splice path a `stdin:` source runs.
                let exposer = Exposer {
                    services,
                    gate: Gate::Open,
                    public: PublicServices::default(),
                    public_unsafe: PublicServices::default(),
                    enabled: Box::new(AllEnabled),
                };
                tokio::task::spawn_local(async move {
                    exposer
                        .run(&exposer_node, super::CancellationToken::new())
                        .await
                        .expect("exposer runs");
                });

                // First consumer: opens a service stream, gets Ok, and reads the source's exact bytes.
                let session = consumer.connect(exposer_id).await.expect("connect");
                let service = ServiceStream::open(&session, "cam")
                    .await
                    .expect("first stream admitted");
                let got = service.read_all().await.expect("read the piped bytes");
                assert_eq!(got, body, "the reaching peer gets the source's exact bytes");

                // Second CONCURRENT connection: the source is taken, so the host refuses cleanly with the
                // single-consumer reason, never a racing (corrupting) second read.
                let session2 = consumer.connect(exposer_id).await.expect("second connect");
                let Err(refusal) = ServiceStream::open(&session2, "cam").await else {
                    panic!("the second reader must be refused, not a racing second read");
                };
                let bifrost::Refusal::Unavailable { detail } = &refusal else {
                    panic!("the second reader must be refused as unavailable, got: {refusal:?}");
                };
                assert!(
                    detail
                        .as_str()
                        .contains("single-consumer source, already in use"),
                    "the refusal must name the single-consumer contract: {detail}"
                );
            })
            .await;
    }

    /// The full served path for the built-in reflector: an exposer over an `echo:` target, a connector
    /// reaching it over the in-process transport, and the peer receiving its OWN bytes back verbatim. Drives
    /// the exact `builtins::Echo` loopback the exposer serves. The open BASE gate keeps the peer admitted with
    /// no token, isolating the reflect path (the safe-public admission is covered by
    /// `echo_is_admitted_under_plain_public_with_no_unsafe_opt_in`).
    #[tokio::test]
    async fn an_echo_service_reflects_the_clients_own_bytes() {
        use tokio::io::AsyncWriteExt as _;

        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
                let exposer_id = exposer_node.node_id();
                let consumer = Node::new(MemTransport::bind(), NoDiscovery);

                let exposer = prove(
                    services(&["demo=echo:"]),
                    Gate::Open,
                    PublicRequest::none(),
                    PublicUnsafeRequest::none(),
                )
                .expect("echo builds under an open gate with no unsafe opt-in (it is safe public)");
                tokio::task::spawn_local(async move {
                    exposer
                        .run(&exposer_node, super::CancellationToken::new())
                        .await
                        .expect("exposer runs");
                });

                let session = consumer.connect(exposer_id).await.expect("connect");
                let mut stream = ServiceStream::open(&session, "demo")
                    .await
                    .expect("echo admits the reaching peer under the open gate");

                // Send our bytes, then half-close so the reflector's copy hits EOF, closes, and we can read to
                // EOF. The peer gets back EXACTLY what it sent: a loopback of its own input, no host resource.
                let body = b"reflect these bytes back to me";
                stream.writer.write_all(body).await.expect("write the body");
                stream
                    .writer
                    .shutdown()
                    .await
                    .expect("half-close toward the host");
                let mut got = Vec::new();
                stream
                    .reader
                    .read_to_end(&mut got)
                    .await
                    .expect("read the echo");
                assert_eq!(got, body, "echo returns the client's own bytes verbatim");
            })
            .await;
    }

    /// The cancel path (delib-18/S18): `Exposer::run` returns gracefully when its cancel token fires, so any
    /// holder of a CLONE of this token can stop the node. Here the token is cancelled from OUTSIDE the run
    /// (the shape any such holder uses); the run must finish with `Ok(())` rather than accept forever. Uses
    /// the mem transport so no real socket is bound.
    #[tokio::test]
    async fn run_returns_gracefully_when_its_cancel_token_fires() {
        let node = Node::new(MemTransport::bind(), NoDiscovery);
        let exposer = Exposer {
            services: services(&["web=127.0.0.1:80"]),
            gate: Gate::Open,
            public: PublicServices::default(),
            public_unsafe: PublicServices::default(),
            enabled: Box::new(AllEnabled),
        };
        let cancel = super::CancellationToken::new();

        // Run the exposer, then cancel it: the run is idle (no peer connects), so its accept loop is parked
        // on `accept`. Cancelling must wake it and return `Ok(())`, bounded so a regression (a run that
        // ignores the token and accepts forever) fails as a timeout rather than hanging the suite.
        let handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { exposer.run(&node, cancel).await }
        });
        cancel.cancel();
        let ended = tokio::time::timeout(core::time::Duration::from_secs(5), handle)
            .await
            .expect("a cancelled run must return promptly, not accept forever")
            .expect("the run task joins");
        assert!(
            ended.is_ok(),
            "a cancelled run returns Ok(()), not an error: {ended:?}"
        );
    }

    /// FAN-OUT (delib-20 ship-blocker): a `+lossy` source served to N consumers over the in-process transport,
    /// each receiving the source's bytes from ONE shared ring. The source is a duplex whose write half the test
    /// holds, so all N consumers attach BEFORE any bytes flow (a live session, not a replay); then the body is
    /// written once and every consumer reads it. This drives the exact `Target::RawStream(RawStream::lossy)`
    /// serve path, proving one source fans out to many independent cursors.
    #[tokio::test]
    async fn a_lossy_source_fans_out_to_many_consumers() {
        use tokio::io::AsyncWriteExt as _;

        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let body: &'static [u8] = b"one live source, fanned out to every consumer";
                // A duplex source: the exposer reads one end, the test writes the other AFTER all consumers
                // have attached (a live session), so no consumer misses the start.
                let (mut source_writer, source_reader) = tokio::io::duplex(4096);
                let services = lossy_service("cam", Box::new(source_reader));

                let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
                let exposer_id = exposer_node.node_id();
                let consumer = Node::new(MemTransport::bind(), NoDiscovery);

                // Past the public-gate door (covered by `a_public_gate_over_a_lossy_source_is_refused...`): an
                // open gate keeps every peer admitted so the test isolates the fan-out splice path.
                let exposer = Exposer {
                    services,
                            gate: Gate::Open,
                    public: PublicServices::default(),
                    public_unsafe: PublicServices::default(),
                    enabled: Box::new(AllEnabled),
                };
                tokio::task::spawn_local(async move {
                    exposer.run(&exposer_node, super::CancellationToken::new()).await.expect("exposer runs");
                });

                // Attach N consumers: each opens a stream and is admitted (Response::Ok), the first lazy-opening
                // the source and arming the ring, the rest attaching to it. Hold them all before writing.
                const N: usize = 4;
                let mut streams = Vec::new();
                for _ in 0..N {
                    let session = consumer.connect(exposer_id).await.expect("connect");
                    streams.push(
                        ServiceStream::open(&session, "cam")
                            .await
                            .expect("consumer admitted to the fan-out"),
                    );
                }

                // Now write the body once and close the source: the pump copies it into the one ring, and every
                // cursor drains the same bytes. The body fits the ring, so no consumer lags -> each gets it all.
                source_writer.write_all(body).await.expect("write source");
                drop(source_writer);

                for stream in streams {
                    let got = stream.read_all().await.expect("read the fan-out");
                    assert_eq!(
                        got, body,
                        "each of the N consumers receives the source's exact bytes from the one ring"
                    );
                }
            })
            .await;
    }

    /// Make a named FIFO with no writer, so opening it for read BLOCKS (the parking a flood exploits). The
    /// path is unique per process + a counter so parallel tests never collide; the caller removes it.
    fn never_written_fifo(tag: &str) -> std::path::PathBuf {
        use core::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "tightbeam-fifo-cap-{}-{tag}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_file(&path);
        let mut c_path = path.clone().into_os_string().into_encoded_bytes();
        c_path.push(0);
        // SAFETY: `c_path` is a NUL-terminated C string that outlives the call; a failed mkfifo returns -1
        // and the test fails on it. Mode 0600: the FIFO is scratch, readable/writable by this process only.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr().cast::<libc::c_char>(), 0o600) };
        assert_eq!(rc, 0, "mkfifo {} failed", path.display());
        path
    }

    /// A `Serving` context over `services` sharing one `permits` pool, on a `Gate::Open` base with empty
    /// public overlays and an empty registry: the shared node state the raw-stream cap tests drive many
    /// `serve_request`s against.
    fn open_serving(services: Services, permits: Semaphore) -> std::sync::Arc<super::Serving> {
        std::sync::Arc::new(super::Serving {
            gate: Gate::Open,
            public: PublicServices::default(),
            public_unsafe: PublicServices::default(),
            services,
            raw_stream_opens: permits,
            public_pool: PublicPool::new(),
            enabled: Box::new(AllEnabled),
        })
    }

    /// The declared security the admission-core tests present by default: proven and sealed, what a real
    /// handshake-backed transport declares. The announced-refusal test passes its own.
    const PROVEN: Security = Security {
        peer: PeerProof::Proven,
        channel: ChannelProtection::Aead,
    };

    /// Drive one `serve_request` for `service` against the shared `serving` context, with a fresh public
    /// session and no token: the common shape, for tests that do not need to hold the session open or
    /// present a capability. See [`drive_open_in`] for that.
    fn drive_open(
        service: &str,
        serving: std::sync::Arc<super::Serving>,
    ) -> (
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        impl core::future::Future<Output = eyre::Result<()>>,
    ) {
        drive_open_in(
            service,
            serving,
            std::sync::Arc::new(PublicSession::default()),
            None,
        )
    }

    /// Drive one `serve_request` for `service` against the shared `serving` context under `session`, and
    /// return the client's stream end plus the serving future. The serving future is returned un-awaited so
    /// a caller can let it park (a never-written FIFO, a parked handler) or poll it for the refusal, and the
    /// returned reader carries the host's `Response`. Uses `tokio::io::duplex` so no transport is needed.
    /// The session is passed by `Arc` because the caller may hold it open (the public-session cap test) and
    /// a spawned future must stay `'static`; `capability` lets a test dial as a member.
    fn drive_open_in(
        service: &str,
        serving: std::sync::Arc<super::Serving>,
        session: std::sync::Arc<PublicSession>,
        capability: Option<String>,
    ) -> (
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        impl core::future::Future<Output = eyre::Result<()>>,
    ) {
        let (client, server) = tokio::io::duplex(1024);
        let (server_read, server_write) = tokio::io::split(server);
        let (client_read, mut client_write) = tokio::io::split(client);
        let service = service.to_owned();
        // The peer id is only for the host's log line here; any valid NodeId does.
        let peer = SessionPeer {
            node: bifrost::NodeId::from_ed25519_secret(&[9u8; 32]),
            security: PROVEN,
        };
        let serve = async move {
            crate::protocol::Request {
                service: service.clone(),
                capability,
                membership: None,
            }
            .write(&mut client_write)
            .await
            .expect("write request");
            // Close the client's write half now the request is sent: the served splice's downstream copy
            // (peer -> `io::sink()`) ends on this EOF, so a served stream can actually finish (otherwise the
            // splice's `try_join!` would wait forever for the client to hang up).
            drop(client_write);
            serve_request(peer, server_write, server_read, serving, session).await
        };
        (client_read, serve)
    }

    /// The admission core with an unconstrained public pool and a fresh session: the predicate tests care
    /// about the ruling, not the caps (the cap tests build their own [`Admission`]).
    fn admit(
        gate: &Gate,
        public: &PublicServices,
        public_unsafe: &PublicServices,
        peer: SessionPeer,
        capability: Option<&str>,
        membership: Option<&str>,
        service: &Service,
    ) -> Result<super::AdmittedStream, super::HostRefusal> {
        super::admit(
            Admission {
                gate,
                public,
                public_unsafe,
                pool: &PublicPool::new(),
            },
            &PublicSession::default(),
            peer,
            capability,
            membership,
            service,
        )
    }

    /// The exposure ceiling refuses PRE-`Ok`: an open witness cannot mint a `Never` handler's proof, so the
    /// wire sees the uniform `Refused(NotAdmitted)` and never a success. This is the wire-level ordering pin
    /// for the `serve_request` split: a refactor that hoists `Response::Ok` above `handler.prepare` fails here.
    #[tokio::test]
    async fn an_open_witness_is_refused_before_ok_for_a_never_handler() {
        // Hand-build the serving context, bypassing the assembly interlock (which would refuse an open gate
        // over a Never handler outright): this isolates the bridge's prepare-time refusal on the serve path.
        let serving = Arc::new(super::Serving {
            gate: Gate::Open,
            public: PublicServices::default(),
            public_unsafe: PublicServices::default(),
            services: Services(HashMap::new())
                .with_handler("locked", GatedNoop)
                .expect("`locked` binds"),
            raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
            public_pool: PublicPool::new(),
            enabled: Box::new(AllEnabled),
        });
        let (mut client, serve) = drive_open("locked", serving);
        let (served, response) = tokio::join!(serve, crate::protocol::Response::read(&mut client));
        served.expect("serve_request returns Ok after writing a refusal");
        assert_eq!(
            response.expect("the refusal frame reads"),
            crate::protocol::Response::Refused(bifrost::Refusal::NotAdmitted),
            "the ceiling refusal is the uniform payload-free class, written with no success"
        );
    }

    /// delib-49 G5, the anti-starvation property: with the public-session pool FULL, a gated member dial
    /// on its own session is still admitted and served, because only the public-admit seam touches the
    /// pool. The public dial over the cap gets the same payload-free `NotAdmitted` a gate miss gives, and
    /// dropping the public session releases its slot for the next public dial.
    #[tokio::test]
    async fn a_saturated_public_pool_never_starves_a_gated_member() {
        use crate::identity::AsVerifyKey as _;

        let signet = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
        let gate = Gate::rooted(
            signet.verifying_key(),
            nauthy::FileDenylist::empty(std::env::temp_dir().join("tb-public-starvation")),
        );
        // The badge is bound to the peer `drive_open_in` dials as, so the rooted gate admits it.
        let peer = bifrost::NodeId::from_ed25519_secret(&[9u8; 32]);
        let badge = signet
            .mint_member(
                peer.verify_key(),
                nauthy::Request::expires_in(core::time::Duration::from_secs(300)),
            )
            .expect("mint member badge")
            .link()
            .expect("link");

        let services = Services(HashMap::new())
            .with_handler("open", OpenNoop)
            .expect("`open` binds")
            .with_handler("web", OpenNoop)
            .expect("`web` binds");
        let serving = Arc::new(super::Serving {
            gate,
            public: PublicServices(["open".to_owned()].into_iter().collect()),
            public_unsafe: PublicServices::default(),
            services,
            raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
            public_pool: PublicPool {
                sessions: Arc::new(Semaphore::new(1)),
                streams: Arc::new(Semaphore::new(4)),
            },
            enabled: Box::new(AllEnabled),
        });

        // One public session reaches `open` and stays alive, holding the single public-session permit.
        let holder = Arc::new(PublicSession::default());
        let (mut holder_reader, holder_serve) =
            drive_open_in("open", Arc::clone(&serving), Arc::clone(&holder), None);
        let (served, response) = tokio::join!(
            holder_serve,
            crate::protocol::Response::read(&mut holder_reader)
        );
        served.expect("the serving future returns after the stream");
        assert_eq!(
            response.expect("the response reads"),
            crate::protocol::Response::Ok,
            "the first public dial is admitted"
        );

        // The pool is full: a second public session is refused at the seam, with the uniform wire class.
        let stranger = Arc::new(PublicSession::default());
        let (mut stranger_reader, stranger_serve) =
            drive_open_in("open", Arc::clone(&serving), Arc::clone(&stranger), None);
        let (served, response) = tokio::join!(
            stranger_serve,
            crate::protocol::Response::read(&mut stranger_reader)
        );
        served.expect("the serving future returns after the refusal");
        assert_eq!(
            response.expect("the response reads"),
            crate::protocol::Response::Refused(bifrost::Refusal::NotAdmitted),
            "a public dial over the session cap is refused with the uniform gate refusal"
        );

        // The anti-starvation property: a gated member dials its own session and is served while the
        // public pool is full. Its session presents a real badge, so it never touches the public pool.
        let member = Arc::new(PublicSession::default());
        let (mut member_reader, member_serve) = drive_open_in(
            "web",
            Arc::clone(&serving),
            Arc::clone(&member),
            Some(badge.to_string()),
        );
        let (served, response) = tokio::join!(
            member_serve,
            crate::protocol::Response::read(&mut member_reader)
        );
        served.expect("the serving future returns after the member stream");
        assert_eq!(
            response.expect("the response reads"),
            crate::protocol::Response::Ok,
            "a gated member dial is served while the public pool is saturated"
        );

        // Close the public session: its permit returns to the pool, so the next public dial is admitted.
        drop(holder);
        let (mut fresh_reader, fresh_serve) = drive_open_in(
            "open",
            Arc::clone(&serving),
            Arc::new(PublicSession::default()),
            None,
        );
        let (served, response) = tokio::join!(
            fresh_serve,
            crate::protocol::Response::read(&mut fresh_reader)
        );
        served.expect("the serving future returns after the stream");
        assert_eq!(
            response.expect("the response reads"),
            crate::protocol::Response::Ok,
            "a closed public session releases its permit for the next public dial"
        );
    }

    /// delib-49 G5, the public-stream cap: one parked public stream holds the single stream permit, so a
    /// second public stream on the same (already classified) session is refused at the seam; releasing the
    /// parked handler lets its stream end, drops the permit, and the next stream is admitted. Over-cap
    /// refusal is the uniform wire class, written before any `Response::Ok`.
    #[tokio::test]
    async fn a_public_stream_over_the_cap_is_refused_and_released_when_it_ends() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(Semaphore::new(0));
        let services = Services(HashMap::new())
            .with_handler(
                "park",
                Parked {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                },
            )
            .expect("`park` binds");
        let serving = Arc::new(super::Serving {
            gate: Gate::Open,
            public: PublicServices(["park".to_owned()].into_iter().collect()),
            public_unsafe: PublicServices::default(),
            services,
            raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
            public_pool: PublicPool {
                sessions: Arc::new(Semaphore::new(4)),
                streams: Arc::new(Semaphore::new(1)),
            },
            enabled: Box::new(AllEnabled),
        });

        // The first stream is admitted and parks in the handler, holding the one stream permit.
        let session = Arc::new(PublicSession::default());
        let (mut first_reader, first_serve) =
            drive_open_in("park", Arc::clone(&serving), Arc::clone(&session), None);
        let first = tokio::spawn(first_serve);
        assert_eq!(
            crate::protocol::Response::read(&mut first_reader)
                .await
                .expect("the response reads"),
            crate::protocol::Response::Ok,
            "the first public stream is admitted"
        );
        entered.notified().await;

        // The cap is taken: a second public stream on the same session is refused, uniformly.
        let (mut second_reader, second_serve) =
            drive_open_in("park", Arc::clone(&serving), Arc::clone(&session), None);
        let (served, response) = tokio::join!(
            second_serve,
            crate::protocol::Response::read(&mut second_reader)
        );
        served.expect("the serving future returns after the refusal");
        assert_eq!(
            response.expect("the response reads"),
            crate::protocol::Response::Refused(bifrost::Refusal::NotAdmitted),
            "a public stream over the cap is refused with the uniform gate refusal"
        );

        // Release the parked handler: the stream ends, its permit drops, and the next stream is admitted.
        release.add_permits(1);
        first
            .await
            .expect("the parked stream ends after its release")
            .expect("the serve future returns Ok");
        let (mut third_reader, third_serve) =
            drive_open_in("park", Arc::clone(&serving), Arc::clone(&session), None);
        let third = tokio::spawn(third_serve);
        assert_eq!(
            crate::protocol::Response::read(&mut third_reader)
                .await
                .expect("the response reads"),
            crate::protocol::Response::Ok,
            "a stream permit released by a finished stream admits the next public stream"
        );
        entered.notified().await;
        release.add_permits(1);
        third
            .await
            .expect("the second parked stream ends")
            .expect("the serve future returns Ok");
    }

    /// AVAILABILITY (Adversary A-1, delib 05, issue #25): a flood of never-written `fifo:` opens is bounded
    /// by `RAW_STREAM_OPEN_PERMITS` and, crucially, parks NO threads (the open is nonblocking; a writer-less
    /// FIFO is awaited via the reactor, not a blocking-pool thread). With a cap of N, launch N+K concurrent
    /// opens of a writer-less FIFO: exactly N acquire a permit and wait for a writer (no `Response` yet, no
    /// parked thread), while every over-cap open is refused CLEANLY and FAST with the cap message. Proven with
    /// a small explicit permit count so the test does not wait the full writer-wait timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_flood_of_fifo_opens_cannot_exceed_the_cap() {
        use tokio::io::AsyncReadExt as _;

        // Hold the writer-wait lock so the no-leak test (which SHRINKS the writer-wait) cannot run concurrently
        // and make these parked opens time out early; here the wait must stay long so they genuinely park.
        let _lock = crate::raw_stream::WRITER_WAIT_TEST_LOCK.lock().await;

        let fifo = never_written_fifo("flood");
        let services = services(&[&format!("pipe=fifo:{}", fifo.display())]);

        const CAP: usize = 3;
        const OVER: usize = 4;
        // One shared serving context (so all opens draw on the SAME `CAP`-sized permit pool).
        let serving = open_serving(services, Semaphore::new(CAP));

        // CAP opens grab a permit and park in the blocking FIFO open; hold their serving futures so the
        // permits stay taken. They MUST NOT respond (they are blocked waiting for a writer that never comes).
        let mut parked = Vec::new();
        for _ in 0..CAP {
            let (mut client_read, serve) = drive_open("pipe", std::sync::Arc::clone(&serving));
            let handle = tokio::spawn(serve);
            // Give the open a moment to acquire its permit and enter the blocking syscall.
            let mut byte = [0u8; 1];
            let responded = tokio::time::timeout(
                core::time::Duration::from_millis(200),
                client_read.read(&mut byte),
            )
            .await;
            assert!(
                responded.is_err(),
                "a permit-holding FIFO open must PARK (no response), not answer before a writer appears"
            );
            parked.push((handle, client_read));
        }

        // With every permit taken, the OVER-cap opens must be refused immediately with the cap message, never
        // parking another thread. Each returns a `Response::Refused` a client can read at once.
        for _ in 0..OVER {
            let (mut client_read, serve) = drive_open("pipe", std::sync::Arc::clone(&serving));
            tokio::spawn(serve);
            let response = tokio::time::timeout(
                core::time::Duration::from_secs(2),
                crate::protocol::Response::read(&mut client_read),
            )
            .await
            .expect("an over-cap open must answer promptly, not park")
            .expect("read response");
            match response {
                crate::protocol::Response::Refused(bifrost::Refusal::Unavailable { detail }) => {
                    assert!(
                        detail.as_str().contains("too many raw streams"),
                        "the over-cap refusal must name the cap: {detail}"
                    );
                }
                other => panic!("an over-cap open must be refused with a detail, got: {other:?}"),
            }
        }

        // Release the parked opens so the test's runtime can shut down: open the FIFO's write end, which is the
        // writer they were awaiting. Their reactor readiness fires, the served splice runs, and the futures
        // finish. Nothing was leaked to clean up (the open is nonblocking and the wait is a reactor
        // registration, not a parked thread); this write end just unblocks the writer-wait so the tasks end
        // cleanly rather than being aborted mid-wait. Opening the FIFO `O_RDWR` never blocks.
        let writer_path = fifo.clone();
        tokio::task::spawn_blocking(move || {
            use std::os::unix::fs::OpenOptionsExt as _;
            let _rdwr = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_RDWR)
                .open(&writer_path);
        })
        .await
        .expect("open the FIFO read-write end");
        for (handle, _client) in parked {
            handle.abort();
        }
        let _ = std::fs::remove_file(&fifo);
    }

    /// A single raw-stream open under the cap still works: one `file:` open (the common case) acquires a
    /// permit, opens fast, and serves its bytes. The cap never penalizes normal single-stream serving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_single_raw_stream_open_is_unaffected_by_the_cap() {
        use std::io::Write as _;

        use tokio::io::AsyncReadExt as _;

        let path = std::env::temp_dir().join(format!("tightbeam-cap-ok-{}", std::process::id()));
        let body = b"one open, under the cap";
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(body))
            .expect("write scratch file");

        let services = services(&[&format!("doc=file:{}", path.display())]);
        let serving = open_serving(services, Semaphore::new(RAW_STREAM_OPEN_PERMITS));

        let (mut client_read, serve) = drive_open("doc", serving);
        tokio::spawn(serve);
        // First the Ok, then the source's exact bytes.
        match crate::protocol::Response::read(&mut client_read)
            .await
            .expect("read response")
        {
            crate::protocol::Response::Ok => {}
            other => panic!("a single open under the cap must succeed, got: {other:?}"),
        }
        let mut got = Vec::new();
        client_read.read_to_end(&mut got).await.expect("read bytes");
        assert_eq!(got, body, "the single open serves the file's exact bytes");

        let _ = std::fs::remove_file(&path);
    }

    /// delib-47 live toggle, END TO END through the gate: a service named in the `<home>/disabled` file is
    /// refused at `serve_request` with the SAME indistinguishable refusal a gate miss gives, and after the file
    /// is rewritten to RE-ENABLE it, the very next stream against the SAME running serving context serves it,
    /// with no restart (the mtime-watched [`FileDisabledList`] re-read the change). This is the property the
    /// whole feature turns on: disable refuses live, enable restores live.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_disabled_service_is_refused_at_the_gate_then_restored_live_on_re_enable() {
        use std::io::Write as _;

        use tokio::io::AsyncReadExt as _;

        // A `file:` service so the served (enabled) path returns deterministic bytes with no external socket.
        let path = std::env::temp_dir().join(format!("tb-toggle-served-{}", std::process::id()));
        let body = b"served once re-enabled";
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(body))
            .expect("write scratch file");

        // The disabled-list file starts with `doc` disabled.
        let disabled = std::env::temp_dir().join(format!("tb-toggle-list-{}", std::process::id()));
        std::fs::write(&disabled, "doc\n").expect("write disabled list");

        let services = services(&[&format!("doc=file:{}", path.display())]);
        let enabled = crate::enabled::FileDisabledList::load(disabled.clone())
            .await
            .expect("load disabled list");
        // One serving context, held across the toggle: the same `Arc` serves both drives, so a pass proves the
        // LIVE re-read, not a rebuild.
        let serving = std::sync::Arc::new(super::Serving {
            gate: Gate::Open,
            public: PublicServices::default(),
            public_unsafe: PublicServices::default(),
            services,
            raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
            public_pool: PublicPool::new(),
            enabled: Box::new(enabled),
        });

        // Disabled: the gate refuses with the uniform typed refusal, before any dispatch.
        let (mut client_read, serve) = drive_open("doc", std::sync::Arc::clone(&serving));
        tokio::spawn(serve);
        match crate::protocol::Response::read(&mut client_read)
            .await
            .expect("read response")
        {
            crate::protocol::Response::Refused(bifrost::Refusal::NotAdmitted) => {}
            other => panic!("a disabled service must be refused at the gate, got: {other:?}"),
        }

        // Re-enable: rewrite the file without `doc` and wait past the mtime-watch debounce (100ms).
        std::fs::write(&disabled, "\n").expect("re-enable doc");
        tokio::time::sleep(core::time::Duration::from_millis(250)).await;

        // The SAME serving context now serves it: Ok, then the file's exact bytes. No restart.
        let (mut client_read, serve) = drive_open("doc", std::sync::Arc::clone(&serving));
        tokio::spawn(serve);
        match crate::protocol::Response::read(&mut client_read)
            .await
            .expect("read response")
        {
            crate::protocol::Response::Ok => {}
            other => panic!("a re-enabled service must serve, got: {other:?}"),
        }
        let mut got = Vec::new();
        client_read.read_to_end(&mut got).await.expect("read bytes");
        assert_eq!(
            got, body,
            "the re-enabled service serves the file's exact bytes"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&disabled);
    }

    /// A tiny test client that speaks tightbeam's `Request`/`Response` handshake on one stream, so the unit
    /// tests can reach a service without the `Connector`'s port/stdio machinery.
    struct ServiceStream<W, R> {
        writer: W,
        reader: R,
    }

    impl<W, R> ServiceStream<W, R>
    where
        W: tokio::io::AsyncWrite + Unpin,
        R: tokio::io::AsyncRead + Unpin,
    {
        /// Open a stream, request `service`, and return it on `Ok` or the host's typed refusal.
        async fn open<S>(session: &S, service: &str) -> Result<Self, bifrost::Refusal>
        where
            S: bifrost::Session<Write = W, Read = R>,
        {
            Self::open_with(session, service, None).await
        }

        /// Like [`open`](Self::open) but presents `capability`, so a test can dial as a stranger (`None`) or
        /// as a token-holder (a revoked slip). Returns the host's typed refusal verbatim, which is what lets
        /// a test assert two dialers got the SAME refusal value.
        async fn open_with<S>(
            session: &S,
            service: &str,
            capability: Option<String>,
        ) -> Result<Self, bifrost::Refusal>
        where
            S: bifrost::Session<Write = W, Read = R>,
        {
            Self::open_with_slots(session, service, capability, None).await
        }

        /// Like [`open_with`](Self::open_with) but also presents a second `membership` slot: a badge under
        /// the foreign fleet a signet-bound slip names, so a test can drive the two-token AND at the gate.
        async fn open_with_slots<S>(
            session: &S,
            service: &str,
            capability: Option<String>,
            membership: Option<String>,
        ) -> Result<Self, bifrost::Refusal>
        where
            S: bifrost::Session<Write = W, Read = R>,
        {
            let (mut writer, mut reader) = session.open_bi().await.expect("open a stream");
            crate::protocol::Request {
                service: service.to_owned(),
                capability,
                membership,
            }
            .write(&mut writer)
            .await
            .expect("write request");
            match crate::protocol::Response::read(&mut reader)
                .await
                .expect("read response")
            {
                crate::protocol::Response::Ok => Ok(Self { writer, reader }),
                crate::protocol::Response::Refused(refusal) => Err(refusal),
            }
        }

        /// Read the piped payload to EOF. The exposer half-closes its write when the source hits EOF.
        async fn read_all(mut self) -> std::io::Result<Vec<u8>> {
            // Hold the writer open for the stream's lifetime (dropping it early would half-close our side
            // before the peer finishes sending); read the piped payload to EOF.
            let mut got = Vec::new();
            self.reader.read_to_end(&mut got).await?;
            drop(self.writer);
            Ok(got)
        }
    }

    #[test]
    fn a_router_refuses_a_duplicate_across_bind_verbs() {
        // The Router is one add-only table with one duplicate policy: a name bound by `service`, then named
        // again by `parse`, a built-in verb, or a second `service`, is refused at bind. The base case: two
        // `service` binds collide.
        let dup = Router::new(Gate::Open)
            .service(svc("web"), OpenNoop)
            .expect("first bind")
            .service(svc("web"), OpenNoop);
        assert!(
            dup.is_err(),
            "a second bind under one name must be refused, never silently overwrite"
        );
        // A parsed `name=addr` entry colliding with a bound handler is the same policy at the same door.
        let through_parse = Router::new(Gate::Open)
            .service(svc("web"), OpenNoop)
            .expect("first bind")
            .parse(&["web=127.0.0.1:80".to_owned()]);
        assert!(
            through_parse.is_err(),
            "the parse entry must refuse the duplicate too"
        );
        // And within one `parse`, the duplicate is refused by the same message.
        let Err(error) = Router::new(Gate::Open)
            .parse(&["web=127.0.0.1:80".to_owned(), "web=127.0.0.1:81".to_owned()])
        else {
            panic!("a duplicate `name=addr` entry must be refused");
        };
        assert!(
            error.to_string().contains("already defined"),
            "the refusal names the duplicate: {error}"
        );
    }

    /// SECURITY (deliberation 18, the discovery oracle): a dialer the gate does NOT admit must get ONE
    /// indistinguishable refusal on the wire. No reason separates a stranger (no token) from a revoked
    /// holder from a not-granting token, and no response enumerates or confirms a service. This test dials a
    /// Family-gated node four ways -- a stranger, a revoked-slip holder, an unknown-service probe, and a
    /// slip-for-the-wrong-service holder -- and asserts every refusal is the same payload-free
    /// `NotAdmitted` (one wire code, nothing after it), so the wire is not a revocation oracle and not a
    /// capability-enumeration oracle. The gate is the discovery boundary: existence, shape, and verdict are
    /// revealed only AFTER admission.
    #[tokio::test]
    async fn an_unadmitted_dialer_gets_one_uniform_refusal_no_reason_no_menu() {
        use nauthy::{FileDenylist, Identity};

        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                // The signet that roots the family, and a real exposed service (`ssh`) plus a second name
                // (`web`) so the node has a genuine menu that MUST NOT leak. The bodies are irrelevant: every
                // dial here is refused at the gate or at the unknown-service arm, never served.
                let signet = Identity::from_secret(&[7u8; 32]).expect("valid secret");
                let hour = nauthy::Request::expires_in(core::time::Duration::from_secs(3600));

                let mut map = HashMap::new();
                map.insert(
                    "ssh".to_owned(),
                    Route::family(Target::RawStream(RawStream::from_reader(Box::new(
                        &b"secret"[..],
                    )))),
                );
                map.insert(
                    "web".to_owned(),
                    Route::family(Target::RawStream(RawStream::from_reader(Box::new(
                        &b"secret"[..],
                    )))),
                );
                let services = Services(map);

                // A slip the family once honored for `ssh`, now REVOKED: the revoked-but-persistent holder.
                let revoked_slip = signet.mint(&svc("ssh"), hour).expect("mint ssh slip");
                let path = std::env::temp_dir()
                    .join(format!("tb-uniform-refusal-{}", std::process::id()));
                let _ = std::fs::remove_file(&path);
                let mut denylist = FileDenylist::load(path.clone()).await.expect("load denylist");
                denylist.revoke(&revoked_slip).await.expect("revoke the slip");

                let exposer = Exposer {
                    services,
                            gate: Gate::rooted(signet.verifying_key(), denylist),
                    public: PublicServices::default(),
                    public_unsafe: PublicServices::default(),
                    enabled: Box::new(AllEnabled),
                };

                let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
                let exposer_id = exposer_node.node_id();
                let consumer = Node::new(MemTransport::bind(), NoDiscovery);
                tokio::task::spawn_local(async move {
                    exposer.run(&exposer_node, super::CancellationToken::new()).await.expect("exposer runs");
                });

                // Every dial opens a fresh session/stream (each stream is gated on its own merits).
                let dial = |service: &'static str, cap: Option<String>| {
                    let consumer = &consumer;
                    async move {
                        let session = consumer.connect(exposer_id).await.expect("connect");
                        match ServiceStream::open_with(&session, service, cap).await {
                            Ok(_) => panic!("dial for {service:?} must be refused, not served"),
                            Err(refusal) => refusal,
                        }
                    }
                };

                // (a) a STRANGER: no token at all -> gate refuses (Missing) -> `NotAdmitted`.
                let stranger = dial("ssh", None).await;
                // (b) a REVOKED holder: presents the now-denylisted `ssh` slip -> gate refuses (Revoked).
                let revoked = dial("ssh", Some(revoked_slip.link().expect("link").to_string())).await;
                // (c) an UNKNOWN-SERVICE probe by a stranger: gate refuses the unknown name -> NotAdmitted.
                let unknown = dial("admin", None).await;
                // (d) a WRONG-SERVICE slip: a valid, UNREVOKED slip for `web` presented for `ssh` -> gate
                //     refuses (NotGranted). Distinct internal reason, must still be the same wire class.
                let wrong_slip = signet.mint(&svc("web"), hour).expect("mint web slip");
                let not_granted =
                    dial("ssh", Some(wrong_slip.link().expect("link").to_string())).await;

                // The whole point: all four are the SAME payload-free `NotAdmitted`, so no consumer can
                // tell revoked from stranger from not-granted, and none can confirm `ssh` exists or that
                // `admin` does not.
                assert_eq!(
                    stranger, revoked,
                    "a revoked holder and a stranger must get the same refusal (no revocation oracle)"
                );
                assert_eq!(
                    stranger, unknown,
                    "an unknown-service probe must be indistinguishable from a refused known service"
                );
                assert_eq!(
                    stranger, not_granted,
                    "a not-granting slip must get the same refusal as a stranger (no capability oracle)"
                );

                // And the refusal renders NOTHING distinguishing: no cause word, no service name, no menu.
                // The ratified `NotAdmitted` phrase names both credential kinds by policy ("no member badge
                // or capability ... was accepted"), the same bytes for every cause, so it is not a leak.
                let rendered = stranger.to_string();
                for leaked in [
                    "revoked",
                    "requires",
                    "grant",
                    "exposes",
                    "unknown",
                    "ssh",
                    "web",
                    "admin",
                ] {
                    assert!(
                        !rendered.contains(leaked),
                        "the uniform refusal must not leak {leaked:?}: {rendered:?}"
                    );
                }

                let _ = std::fs::remove_file(&path);
            })
            .await;
    }

    /// The unknown-service menu must not cross the wire even to an ADMITTED caller: under an open gate every
    /// dialer is admitted, yet a probe for a name the node does not expose still gets the uniform refusal,
    /// never the sorted "this node exposes: ..." menu that used to enumerate the surface. (The teaching hint
    /// returns as the gated `control.services` verb, not as a free menu on the wrong-name path.)
    #[tokio::test]
    async fn an_unknown_service_probe_never_gets_the_menu_even_when_admitted() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let mut map = HashMap::new();
                map.insert(
                    "cam".to_owned(),
                    Route::family(Target::RawStream(RawStream::from_reader(Box::new(
                        &b"x"[..],
                    )))),
                );
                map.insert(
                    "mic".to_owned(),
                    Route::family(Target::RawStream(RawStream::from_reader(Box::new(
                        &b"x"[..],
                    )))),
                );
                let exposer = Exposer {
                    services: Services(map),
                            gate: Gate::Open,
                    public: PublicServices::default(),
                    public_unsafe: PublicServices::default(),
                    enabled: Box::new(AllEnabled),
                };

                let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
                let exposer_id = exposer_node.node_id();
                let consumer = Node::new(MemTransport::bind(), NoDiscovery);
                tokio::task::spawn_local(async move {
                    exposer.run(&exposer_node, super::CancellationToken::new()).await.expect("exposer runs");
                });

                let session = consumer.connect(exposer_id).await.expect("connect");
                let Err(refusal) = ServiceStream::open(&session, "nope").await else {
                    panic!("an unknown service must be refused, not served");
                };
                let rendered = refusal.to_string();
                for leaked in ["cam", "mic", "exposes", "unknown"] {
                    assert!(
                        !rendered.contains(leaked),
                        "an admitted unknown-service probe must not learn the menu; leaked {leaked:?}: {rendered:?}"
                    );
                }
            })
            .await;
    }

    /// A family gate + a `speed` service; a helper to build the two postures the per-service tests need.
    fn family_gate(tag: &str) -> Gate {
        let signet = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
        Gate::rooted(
            signet.verifying_key(),
            nauthy::FileDenylist::empty(std::env::temp_dir().join(format!("tb-per-service-{tag}"))),
        )
    }

    /// The per-service admission core (BLOCKER-1): a HIT on EITHER open overlay (the safe `public` or the
    /// unsafe raw-stream `public_unsafe`) admits any peer with no token (minting a `Slip`, never a member),
    /// while EVERY miss -- a gated-present name AND a name the node does not serve at all -- takes the
    /// identical family path and is refused. The one branch on the service name is the set-membership test;
    /// there is no cheaper path for "absent" than for "gated-present", and a hit on either open set reveals
    /// only the already-public fact that the service admits anyone.
    #[test]
    fn a_public_member_admits_a_stranger_and_every_miss_takes_the_family_path() {
        let gate = family_gate("admit");
        let public = super::PublicServices(["speed".to_owned()].into_iter().collect());
        // The unsafe overlay is disjoint from the safe one: `logs` is an unsafe-open raw stream, `speed` a
        // safe-open handler. Both admit a stranger; neither leaks into the other's set.
        let public_unsafe = super::PublicServices(["logs".to_owned()].into_iter().collect());
        let stranger = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]);

        // HIT (safe overlay): the opened `speed` admits a tokenless stranger, and the witness is a Slip (an
        // opened service proves nothing about the peer), never a whole-node member.
        let admitted = admit(
            &gate,
            &public,
            &public_unsafe,
            SessionPeer {
                node: stranger,
                security: PROVEN,
            },
            None,
            None,
            &svc("speed"),
        )
        .expect("an opened service admits a stranger");
        assert!(
            !admitted.witness.is_member(),
            "an opened service admits as a Slip, never a whole-node member"
        );

        // HIT (unsafe overlay): a stranger reaching the unsafe-open raw stream is admitted the same way, also
        // as a Slip (§9 `an_unsafe_raw_stream_member_admits_a_stranger`).
        let unsafe_admitted = admit(
            &gate,
            &public,
            &public_unsafe,
            SessionPeer {
                node: stranger,
                security: PROVEN,
            },
            None,
            None,
            &svc("logs"),
        )
        .expect("an unsafe-open raw stream admits a stranger");
        assert!(
            !unsafe_admitted.witness.is_member(),
            "an unsafe-open raw stream admits as a Slip, never a whole-node member"
        );

        // MISS (gated-present): `control.stop` is served but NOT open on either overlay, so a stranger takes
        // the family path and is refused. MISS (absent): a name the node does not serve takes the SAME path.
        assert!(
            admit(
                &gate,
                &public,
                &public_unsafe,
                SessionPeer {
                    node: stranger,
                    security: PROVEN,
                },
                None,
                None,
                &svc("control.stop")
            )
            .is_err(),
            "a served-but-gated service is refused for a stranger (family path)"
        );
        assert!(
            admit(
                &gate,
                &public,
                &public_unsafe,
                SessionPeer {
                    node: stranger,
                    security: PROVEN,
                },
                None,
                None,
                &svc("nope")
            )
            .is_err(),
            "an absent service is refused for a stranger, on the same family path"
        );
    }

    /// Server-side slot-2 guard (Adversary): the second slot is parsed ONLY when slot 1 is a signet-bound
    /// slip. A plain member badge admits on slot 1 alone, so a hostile client's garbage in slot 2 is never
    /// parsed and cannot turn a valid member dial into a refusal. The server guards this itself, never
    /// trusting the dialer's attach logic.
    #[test]
    fn a_member_dial_ignores_a_second_slot_when_slot_one_is_not_signet_bound() {
        use crate::identity::AsVerifyKey as _;

        let signet = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
        let gate = family_gate("guard");
        let public = super::PublicServices::default();
        let peer = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]);
        let badge = signet
            .mint_member(
                peer.verify_key(),
                nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("mint member badge")
            .link()
            .expect("link");
        let admitted = admit(
            &gate,
            &public,
            &super::PublicServices::default(),
            SessionPeer {
                node: peer,
                security: PROVEN,
            },
            Some(badge.as_str()),
            Some("not a sheer link"),
            &svc("web"),
        )
        .expect("a member badge admits on slot 1 alone; garbage in slot 2 is ignored");
        assert!(
            admitted.witness.is_member(),
            "a whole-node member badge admits as Member regardless of slot 2"
        );
    }

    /// The peer-proof predicate at the admission seam: an announced session cannot root-admit, even
    /// with a genuine member badge bound to the announced key. The badge verifies (it is the signet's
    /// own signature); that is exactly the replay an announced transport enables, so the predicate
    /// refuses before the ruling and the node's own log names the declared profile.
    #[test]
    fn an_announced_session_cannot_root_admit_a_valid_badge() {
        use crate::identity::AsVerifyKey as _;

        let announced = Security {
            peer: PeerProof::Announced,
            channel: ChannelProtection::Plain,
        };
        let signet = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
        let gate = family_gate("announced");
        let peer = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]);
        let badge = signet
            .mint_member(
                peer.verify_key(),
                nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("mint member badge")
            .link()
            .expect("link");

        // The same badge over a proven session IS admitted (the control): the refusal below is the
        // profile, not the token.
        assert!(
            admit(
                &gate,
                &super::PublicServices::default(),
                &super::PublicServices::default(),
                SessionPeer {
                    node: peer,
                    security: PROVEN,
                },
                Some(badge.as_str()),
                None,
                &svc("web"),
            )
            .is_ok(),
            "a valid member badge is admitted over a proven session"
        );
        let refused = admit(
            &gate,
            &super::PublicServices::default(),
            &super::PublicServices::default(),
            SessionPeer {
                node: peer,
                security: announced,
            },
            Some(badge.as_str()),
            None,
            &svc("web"),
        )
        .expect_err("an announced session cannot root-admit, even with a valid badge");
        assert!(
            matches!(
                refused,
                super::HostRefusal::PeerNotProven {
                    declared: PeerProof::Announced
                }
            ),
            "the local cause names the declared profile: {refused:?}"
        );
    }

    /// An announced session that hands `serve_session` one pre-built stream: the session-level fixture
    /// for the admission predicate, so the test drives the production path that reads the profile off
    /// the session type, not the predicate in isolation.
    struct AnnouncedSession {
        peer: NodeId,
        stream: tokio::sync::Mutex<
            Option<(
                tokio::io::WriteHalf<tokio::io::DuplexStream>,
                tokio::io::ReadHalf<tokio::io::DuplexStream>,
            )>,
        >,
    }

    impl Session for AnnouncedSession {
        type Security = Announced;
        type Write = tokio::io::WriteHalf<tokio::io::DuplexStream>;
        type Read = tokio::io::ReadHalf<tokio::io::DuplexStream>;

        fn peer(&self) -> NodeId {
            self.peer
        }

        async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            Err(bifrost::Error::Closed)
        }

        async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            self.stream
                .lock()
                .await
                .take()
                .ok_or(bifrost::Error::Closed)
        }

        async fn wait_closed(&self) {}
    }

    /// The admission seam refuses an announced session even when the presented badge is genuine and
    /// bound to the announced key: `serve_session` reads the session's declared profile, the predicate
    /// refuses before any `ProvenPeer` is minted, and the wire gets the uniform `NotAdmitted` a gate
    /// miss gives. The client writes the request with the RAW `Request::write` on purpose (a hostile or
    /// legacy client bypasses the checked writer).
    #[tokio::test]
    async fn an_announced_session_is_refused_at_admission_with_the_uniform_answer() {
        use crate::identity::AsVerifyKey as _;
        use crate::protocol::{Request, Response};

        let signet = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
        let peer = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]);
        let badge = signet
            .mint_member(
                peer.verify_key(),
                nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("mint member badge")
            .link()
            .expect("link");
        let serving = std::sync::Arc::new(super::Serving {
            gate: family_gate("announced-seam"),
            public: PublicServices::default(),
            public_unsafe: PublicServices::default(),
            services: services(&["web=127.0.0.1:80"]),
            raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
            public_pool: PublicPool::new(),
            enabled: Box::new(AllEnabled),
        });

        let (client, server) = tokio::io::duplex(1024);
        let (server_read, server_write) = tokio::io::split(server);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let session = AnnouncedSession {
            peer,
            stream: tokio::sync::Mutex::new(Some((server_write, server_read))),
        };

        let serve = super::serve_session(session, std::sync::Arc::clone(&serving));
        let (response, served) = tokio::join!(
            async {
                Request {
                    service: "web".to_owned(),
                    capability: Some(badge.to_string()),
                    membership: None,
                }
                .write(&mut client_write)
                .await
                .expect("write request");
                Response::read(&mut client_read)
                    .await
                    .expect("read response")
            },
            serve
        );
        served.expect("the session drains after the refused stream");
        assert_eq!(
            response,
            Response::Refused(bifrost::Refusal::NotAdmitted),
            "an announced session gets the same payload-free refusal a gate miss gives"
        );
    }

    /// The flagship, at the tunnel level (delib-39): a family-gated node opens ONE service per-service; a
    /// stranger with no token is ADMITTED to that service but still REFUSED, uniformly, for a gated service
    /// and for the always-on `control.stop`, which can never be opened. Proves the anti-oracle survives the
    /// overlay: the gated refusals are the same payload-free class.
    #[tokio::test]
    async fn a_stranger_is_admitted_to_an_opened_service_and_uniformly_refused_for_the_rest() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                // `open` is an OptIn responder (openable); `locked` is a Never handler (never openable);
                // `control.stop` stands in for the always-on gated control surface (also a Never handler).
                let services = Services(HashMap::new())
                    .with_handler("open", OpenNoop)
                    .expect("`open` binds")
                    .with_handler("locked", GatedNoop)
                    .expect("`locked` binds")
                    .with_handler("control.stop", GatedNoop)
                    .expect("`control.stop` binds");
                let exposer = prove(
                    services,
                    family_gate("flagship"),
                    PublicRequest::new(["open".to_owned()]),
                    PublicUnsafeRequest::none(),
                )
                .expect("`open` is OptIn, so it opens");

                let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
                let exposer_id = exposer_node.node_id();
                let consumer = Node::new(MemTransport::bind(), NoDiscovery);
                tokio::task::spawn_local(async move {
                    exposer
                        .run(&exposer_node, super::CancellationToken::new())
                        .await
                        .expect("runs");
                });

                // A stranger (no token) is ADMITTED to the opened service and reads it to a clean EOF.
                let session = consumer.connect(exposer_id).await.expect("connect");
                let opened = ServiceStream::open(&session, "open")
                    .await
                    .expect("a stranger is admitted to the opened service");
                opened
                    .read_all()
                    .await
                    .expect("the opened service serves the stranger");

                // The same stranger is REFUSED for a gated service AND for control.stop, with the same
                // typed refusal: opening one service leaks nothing about the gated ones.
                let session = consumer.connect(exposer_id).await.expect("connect");
                let Err(gated) = ServiceStream::open(&session, "locked").await else {
                    panic!("a gated service must refuse the stranger");
                };
                let session = consumer.connect(exposer_id).await.expect("connect");
                let Err(control) = ServiceStream::open(&session, "control.stop").await else {
                    panic!("the always-on control surface must refuse the stranger");
                };
                assert_eq!(
                    gated, control,
                    "a gated service and the control surface refuse identically (no oracle)"
                );
                assert_eq!(
                    gated,
                    bifrost::Refusal::NotAdmitted,
                    "the refusal is the payload-free uniform class"
                );
            })
            .await;
    }

    /// The member floor (delib-54), end to end at the tunnel level: a route declared member-only serves a
    /// whole-node member (the witness is borrowed for the check and then moved once into the handler, so the
    /// single-use guarantee survives), and refuses a delegated slip for the SAME route and a tokenless
    /// stranger with the SAME uniform class a gate miss gives. The echo route proves the floor covers a
    /// non-handler dispatch arm too: the check precedes the whole dispatch match.
    #[tokio::test]
    async fn a_member_only_route_serves_a_member_and_uniformly_refuses_a_slip_and_a_stranger() {
        use crate::identity::AsVerifyKey as _;

        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let signet = nauthy::Identity::from_secret(&[7u8; 32]).expect("valid secret");
                let gate = Gate::rooted(
                    signet.verifying_key(),
                    nauthy::FileDenylist::empty(std::env::temp_dir().join("tb-member-floor")),
                );
                let services = services(&["reflect=echo:"])
                    .with_handler("locked", GatedNoop)
                    .expect("`locked` binds");
                let services = services
                    .member_only("locked")
                    .expect("`locked` is served")
                    .member_only("reflect")
                    .expect("`reflect` is served");
                let exposer = prove(
                    services,
                    gate,
                    PublicRequest::none(),
                    PublicUnsafeRequest::none(),
                )
                .expect("a member-only route under a rooted gate assembles");

                let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
                let exposer_id = exposer_node.node_id();
                tokio::task::spawn_local(async move {
                    exposer
                        .run(&exposer_node, super::CancellationToken::new())
                        .await
                        .expect("runs");
                });

                // A whole-node member: a badge the signet signed, bound to the member's proven mem id.
                let member = Node::new(MemTransport::bind(), NoDiscovery);
                let badge = signet
                    .mint_member(
                        member.node_id().verify_key(),
                        nauthy::Request::expires_in(core::time::Duration::from_secs(300)),
                    )
                    .expect("mint a member badge")
                    .link()
                    .expect("link");
                let session = member.connect(exposer_id).await.expect("connect");
                for name in ["locked", "reflect"] {
                    ServiceStream::open_with(&session, name, Some(badge.to_string()))
                        .await
                        .expect("a member badge passes the member floor");
                }

                // A delegated slip for `locked`: the gate's OWN ruling admits it (the slip grants the
                // service to this device), and the route floor turns that admission into the uniform refusal
                // a gate miss gives. A tokenless stranger gets the same refusal.
                let delegate = Node::new(MemTransport::bind(), NoDiscovery);
                let slip = signet
                    .mint_bound(
                        &svc("locked"),
                        delegate.node_id().verify_key(),
                        nauthy::Request::expires_in(core::time::Duration::from_secs(300)),
                    )
                    .expect("mint a bound slip")
                    .link()
                    .expect("link");
                let session = delegate.connect(exposer_id).await.expect("connect");
                let Err(slip_refused) =
                    ServiceStream::open_with(&session, "locked", Some(slip.to_string())).await
                else {
                    panic!("a slip must not pass a member-only route");
                };
                assert_eq!(
                    slip_refused,
                    bifrost::Refusal::NotAdmitted,
                    "the floor refuses with the uniform payload-free class"
                );
                let session = delegate.connect(exposer_id).await.expect("connect");
                let Err(stranger_refused) = ServiceStream::open(&session, "locked").await else {
                    panic!("a tokenless stranger must not pass the gate");
                };
                assert_eq!(
                    stranger_refused, slip_refused,
                    "a slip refusal is wire-identical to a gate miss (no member-only oracle)"
                );
            })
            .await;
    }

    /// The public proof is the wall (BLOCKER-2): it refuses a `Never` handler named public with a teaching
    /// error (leading with the fix, never leaking the marker names), refuses a name the node does not serve,
    /// and REDIRECTS a raw stream named in the SAFE overlay toward the unsafe overlay (a distinct message
    /// from the `Never`-handler hard refusal). The three walls are disjoint.
    #[test]
    fn the_public_proof_refuses_a_never_handler_a_raw_stream_and_an_unexposed_name() {
        let table = || {
            Services::parse(&["logs=file:/etc/hosts".to_owned()])
                .expect("the raw stream parses")
                .with_handler("ssh", GatedNoop)
                .expect("`ssh` binds")
                .with_handler("speed", OpenNoop)
                .expect("`speed` binds")
        };

        // A Never handler named public is refused: the teaching error names the SERVICE and the fix, never a
        // marker type. (A stranger never sees it; it is a build-time bail to the operator's own terminal.)
        let Err(never) = prove(
            table(),
            family_gate("never"),
            PublicRequest::new(["ssh".to_owned()]),
            PublicUnsafeRequest::none(),
        ) else {
            panic!("a Never handler cannot be opened");
        };
        let message = never.to_string();
        assert!(
            message.contains("ssh") && message.contains("gated"),
            "the refusal names the service and leads with the fix: {message:?}"
        );
        for marker in ["Never", "OptIn"] {
            assert!(
                !message.contains(marker),
                "the refusal must not leak the marker name {marker:?}: {message:?}"
            );
        }

        // A raw stream named in the SAFE overlay is REDIRECTED to the unsafe overlay, with a message DISTINCT
        // from the `Never`-handler refusal.
        let Err(raw) = prove(
            table(),
            family_gate("rawredirect"),
            PublicRequest::new(["logs".to_owned()]),
            PublicUnsafeRequest::none(),
        ) else {
            panic!("a raw stream cannot be opened by the safe overlay; it is redirected");
        };
        let raw_message = raw.to_string();
        assert!(
            raw_message.contains("raw byte source")
                && raw_message.contains("unsafe raw-stream set"),
            "a raw stream in the safe overlay is redirected to the unsafe raw-stream set: {raw_message:?}"
        );
        assert_ne!(
            raw_message, message,
            "the raw-stream redirect is a distinct message from the Never-handler hard refusal"
        );

        // A name the node does not serve is refused, and the error names what it DOES serve.
        let Err(unknown) = prove(
            table(),
            family_gate("unknown"),
            PublicRequest::new(["nope".to_owned()]),
            PublicUnsafeRequest::none(),
        ) else {
            panic!("an unexposed name cannot be opened");
        };
        assert!(
            unknown.to_string().contains("no service named"),
            "an unexposed public name is refused with the served list: {unknown}"
        );
    }

    /// `open_safe` is TOTAL over [`Target`]: a bound handler reads its erased `Exposure` ceiling (an OptIn
    /// handler yes, a Never handler never), and a raw stream never (it opens only through the distinct unsafe
    /// overlay). The built-ins are OptIn handlers: a deliberately stood-up forward is openable, and the
    /// symmetric echo reflector is safe public.
    #[test]
    fn open_safe_is_total_over_target() {
        let optin: Target = Target::Handler(Arc::new(OpenNoop));
        let never: Target = Target::Handler(Arc::new(GatedNoop));
        let forward: Target =
            Target::Handler(Arc::new(crate::builtins::Forward::new("127.0.0.1:80")));
        let echo: Target = Target::Handler(Arc::new(crate::builtins::Echo));
        let raw = Target::RawStream(RawStream::from_reader(Box::new(&b"x"[..])));

        assert!(
            forward.open_safe(),
            "a deliberately stood-up forward is openable"
        );
        assert!(
            echo.open_safe(),
            "an echo reflector exposes no host resource, so it is safe public"
        );
        assert!(optin.open_safe(), "an OptIn handler is openable");
        assert!(!never.open_safe(), "a Never handler is never openable");
        assert!(
            !raw.open_safe(),
            "a raw stream has no auth of its own and opens only through the unsafe overlay"
        );
    }

    /// The scheme namespace is gone: a `fetch_0:`-shaped entry is a handler-scheme teaching error at parse,
    /// while the NAME `fetch_0` binds through the typed Router call like any other service name. Nothing is
    /// special about an underscore anymore; per-service instances are structural (one `service` call each).
    #[test]
    fn a_synthetic_shaped_name_is_just_a_bound_name() {
        assert!(
            Services::parse(&["x=fetch_0:".to_owned()]).is_err(),
            "`fetch_0:` is a handler scheme and must be a teaching error"
        );
        let exposer = Router::new(Gate::Open)
            .service(svc("pub"), OpenNoop)
            .expect("a bound name")
            .expose()
            .expect("an OptIn handler under an open gate");
        assert!(
            exposer.manifest().iter().any(|entry| entry.name == "pub"),
            "the bound name is served"
        );
    }

    /// The catalog reports each service's PER-SERVICE posture: a service in the public request reads `open`,
    /// the rest `gated`, under a family base gate. This is what the `control.services` read serves.
    #[test]
    fn a_catalog_reports_public_services_open_and_the_rest_gated() {
        let services = services(&["web=127.0.0.1:80"])
            .with_handler("speed", OpenNoop)
            .expect("`speed` binds")
            .with_handler("ssh", GatedNoop)
            .expect("`ssh` binds");
        let catalog = services.catalog(
            &family_gate("catalog"),
            &PublicRequest::new(["speed".to_owned()]),
            &PublicUnsafeRequest::none(),
        );
        for entry in catalog.entries() {
            let expected = if entry.name == "speed" {
                Posture::Open
            } else {
                Posture::Gated
            };
            assert_eq!(
                entry.posture,
                expected,
                "`{}` should read {:?} with speed in the public set",
                entry.name,
                expected.label()
            );
        }
    }

    /// The catalog's self-listing contract (delib-54): `self_listing` renders the one row whose handler value
    /// is being built from the catalog (the member-only `control.services` read) as a GATED entry, sorted in
    /// tightbeam with the rest, so a consumer never patches the wire ordering itself.
    #[test]
    fn a_catalog_self_lists_the_row_being_built_gated() {
        let gate = family_gate("self-listing");
        let router = Router::new(gate)
            .parse(&["aaa=127.0.0.1:81".to_owned()])
            .expect("parses");
        let catalog = router.catalog(&family_gate("self-listing"), Some(svc("control.services")));
        let names: Vec<&str> = catalog.entries().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["aaa", "control.services"], "sorted, row included");
        let self_row = catalog
            .entries()
            .find(|entry| entry.name == "control.services")
            .expect("the self-listing row is present");
        assert_eq!(
            self_row.posture,
            Posture::Gated,
            "the row being built is gated by construction"
        );
        assert_eq!(
            ServiceCatalog::decode(&catalog.encode()).expect("round-trips"),
            catalog
        );
    }

    /// B3: the uniform refusal renders descriptively (a reason a person can act on), never as the bare
    /// wire word, so a `refused (…)` wrapper can never double it into `refused (refused)`.
    #[test]
    fn a_not_admitted_refusal_renders_descriptively_never_doubled() {
        let rendered = bifrost::Refusal::NotAdmitted.to_string();
        assert!(
            rendered.contains("not admitted"),
            "the uniform refusal renders as a reason a person can act on: {rendered:?}"
        );
        assert!(
            !rendered.contains("refused: refused"),
            "the refusal render must never double the bare word: {rendered:?}"
        );
    }

    /// The Router's typed verbs bind one table and the one terminal proof: a bound handler, the built-in
    /// forward, and the built-in reflector all serve from one catalog after `.expose()`, and `parse` absorbs
    /// the `name=addr` addresses alongside them.
    #[test]
    fn a_router_binds_every_verb_and_proves_at_expose() {
        let exposer = Router::new(Gate::Open)
            .service(svc("ping"), OpenNoop)
            .expect("service binds")
            .forward(svc("web"), "127.0.0.1:80")
            .expect("forward binds")
            .echo(svc("demo"))
            .expect("echo binds")
            .parse(&["db=unix:/run/db.sock".to_owned()])
            .expect("parse absorbs the addr grammar")
            .expose()
            .expect("an open gate over OptIn handlers and forwards proves");
        let manifest = exposer.manifest();
        let names: Vec<&str> = manifest.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            ["db", "demo", "ping", "web"],
            "one table, name-sorted"
        );
        assert!(
            manifest
                .iter()
                .all(|entry| entry.posture == Posture::Open && entry.kind == TargetKind::Handler),
            "under the open base every bound route reads Open and Handler"
        );
    }

    /// A raw stream stays a native target arm: bound through `.raw_stream`, it proves only into the distinct
    /// unsafe overlay, and the manifest renders it the loudest group with its resolved source.
    #[test]
    fn a_raw_stream_stays_a_native_arm_proven_unsafe() {
        let path = std::env::temp_dir().join("tb-native-raw-stream");
        let exposer = Router::new(family_gate("native-raw"))
            .raw_stream(
                svc("logs"),
                RawStream::file(&path.display().to_string(), "logs=file:...")
                    .expect("the path shapes a raw stream"),
            )
            .expect("raw stream binds")
            .public_unsafe([svc("logs")])
            .expose()
            .expect("a named unsafe raw stream proves");
        let logs = exposer
            .manifest()
            .into_iter()
            .find(|entry| entry.name == "logs")
            .expect("`logs` is in the manifest");
        assert_eq!(logs.posture, Posture::Open);
        assert_eq!(logs.kind, TargetKind::RawStream);
        assert!(
            logs.raw_source.is_some(),
            "a raw stream declares its resolved source for the banner"
        );
    }
}
