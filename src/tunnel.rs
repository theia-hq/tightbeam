//! The tunnel library core: store-free, clap-free, banner-free.
//!
//! This is the domain a tunnel is made of, with no CLI around it: an [`Exposer`] that accepts overlay
//! sessions and forwards inbound streams to local services, a [`Connector`] that reaches a peer's exposed
//! service, the [`resolve_gate`] policy, and the offline capability operations ([`mint_link`],
//! [`narrow_link`], [`revoke_into`]). It prints NOTHING and reads no config path: a caller (tightbeam's
//! own CLI, or any other consumer) loads the signet, denylist, and identity, prints its own banner, and drives
//! this core. Everything here already speaks `bifrost` and `nauthy`, never clap or a store.

use core::future::Future;
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bifrost::{ConnInfo, Discovery, Node, NodeId, Session, Transport};
use futures::StreamExt as _;
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use nauthy::{Admitted, Cap, Denylist, Gate, Identity, Refusal, Service};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
// Re-exported below: it is part of `Exposer::run`'s contract (the node's teardown authority), so a caller
// reaches it through `tightbeam::tunnel` alongside `Exposer` rather than depending on tokio-util directly.
pub use tokio_util::sync::CancellationToken;

use crate::identity::{AsNodeId as _, AsVerifyKey as _};
use crate::open_policy::PublicUse;
use crate::protocol::{Request, Response};
use crate::raw_stream::RawStream;
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

/// The single, indistinguishable refusal a not-admitted dialer receives on the wire. A dialer the gate does
/// not admit gets THIS and nothing else: no reason that separates a stranger (missing token) from a
/// not-granting token from a revoked one, and no hint that names or enumerates a service. Existence, shape,
/// and verdict of a service are revealed ONLY AFTER the gate admits the caller for that service, so the
/// refusal path is not a pre-authorization capability-enumeration or revocation oracle (deliberation 18).
/// The real reason still reaches the SERVER'S OWN logs (`tracing`); it is only the WIRE that is uniform.
///
/// Public so a dialer-side renderer can RECOGNIZE this exact token and phrase it descriptively ("reached,
/// but refused at the gate") rather than echoing the bare word doubled (`refused (refused)`). Recognizing
/// the token leaks nothing new: it is what every not-admitted dialer already receives; the descriptive
/// phrasing is client-side rendering of an outcome the dialer already holds, not a new on-wire signal.
pub const UNIFORM_REFUSAL: &str = "refused";

/// A forwarding target for one exposed service, resolved once at parse time so `serve_request` matches an
/// enum rather than a string prefix: either tightbeam's own raw forward (a local socket it splices to) or a
/// named handler the caller injected into the [`Registry`].
#[derive(Debug, Clone)]
enum Target {
    /// tightbeam's own primitive: connect a local `host:port` / `unix:<path>` and splice bytes to it.
    Forward(String),
    /// tightbeam's own primitive, the raw-stream half: source an already-open byte stream and splice it
    /// toward the peer, either an OS object the operator named (`file:<path>` / `fifo:<path>`) or this
    /// process's own standard input (`stdin:`, a single-consumer source taken once). The reverse of
    /// piping a service to the connector's stdout. Carries a [`RawStream`] whose direction is fixed at parse
    /// time (a read-only
    /// source), so "write peer bytes back into the source" is unrepresentable rather than a runtime error.
    RawStream(RawStream),
    /// A named service handler (a bare `<name>:` scheme) dispatched through the injected registry.
    Handler(String),
}

impl Target {
    /// Whether this target may be OPENED to strangers (added to an [`Exposer`]'s public overlay). A TOTAL
    /// function over [`Target`], resolved THROUGH the target rather than off its served name, so an alias
    /// (`foo=sshd:`) or a raw stream cannot be opened by naming it: the target's own posture decides, never
    /// the name.
    ///
    /// The exhaustive match is the guarantee, split by which mechanism proves each arm safe. The TYPE
    /// guarantee (the sealed, uninhabited `Public` marker erased to [`ErasedHandler::open_safe`]) covers
    /// [`Handler`](Target::Handler) only: a `Never` handler (a keyless shell) reads `false`, an `OptIn`
    /// handler `true`, and an unregistered scheme fails closed (`false`). The EXHAUSTIVE-MATCH guarantee
    /// covers the other two arms: a [`Forward`](Target::Forward) is a socket the operator deliberately stood
    /// up, so it is openable (`true`, today's rule); a [`RawStream`](Target::RawStream) (`file:`/`fifo:`/
    /// `stdin:`) has no auth of its own and is one keystroke from a secret, so it is NOT (`false`). A future
    /// `Target` variant forces a decision here rather than defaulting into either answer.
    fn open_safe(&self, registry: &Registry) -> bool {
        match self {
            Target::Handler(scheme) => registry
                .get(scheme)
                .is_some_and(|handler| handler.open_safe()),
            Target::Forward(_) => true,
            Target::RawStream(_) => false,
        }
    }

    /// Which [`TargetKind`] this target is, so a caller's banner RENDERS what tightbeam resolved (a raw
    /// stream splits into the loudest posture group) instead of re-parsing an address string of its own.
    fn kind(&self) -> TargetKind {
        match self {
            Target::Handler(_) => TargetKind::Handler,
            Target::Forward(_) => TargetKind::Forward,
            Target::RawStream(_) => TargetKind::RawStream,
        }
    }
}

/// What KIND of thing a served service forwards to, as a caller's readiness banner needs to reason about it
/// WITHOUT re-parsing an address string in the consumer: a caller-injected handler, a raw socket forward, or
/// a raw-stream source. Declared by the resolved [`Target`], so a consumer RENDERS what tightbeam resolved
/// (splitting a public raw stream into its own louder posture group) rather than string-matching a `file:`
/// prefix of its own. An enum, not a bool, so a future target kind forces a decision at every match site
/// rather than silently reading as one of these three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// A caller-injected handler (a bare `<scheme>:`): a diagnostic responder, a shell, a fetch, ...
    Handler,
    /// A raw socket forward (`host:port` / `unix:<path>`) the operator deliberately stood up.
    Forward,
    /// A raw-stream source (`file:`/`fifo:`/`stdin:`): bytes with no auth of their own, so an OPEN one is the
    /// loudest reach posture a banner can show (a stranger reading a chosen path or the piped stdin).
    RawStream,
}

/// The local services an exposer publishes: a map of service name to its [`Target`], validated once at
/// parse time so the rest of the core receives names and targets that are already well-formed.
#[derive(Debug, Clone)]
pub struct Services(HashMap<String, Target>);

impl Services {
    /// Parse `name=addr` service entries; a bare `addr` becomes the `default` service. A bare `<name>:`
    /// scheme resolves to a handler; a `host:port` / `unix:<path>` to a raw
    /// forward. A scheme may be dotted (`<iface>.<method>:`) for a method on an interface.
    pub fn parse(entries: &[String]) -> eyre::Result<Self> {
        let mut services = HashMap::new();
        for entry in entries {
            let (name, addr) = match entry.split_once('=') {
                Some((name, addr)) => (name.to_owned(), addr.to_owned()),
                None => ("default".to_owned(), String::clone(entry)),
            };
            // Validate the name through the same domain type the wire uses, so an exposed name and a
            // requested name are compared as the same kind of thing.
            name.parse::<Service>()?;
            // Resolve (and validate) the addr into a Target: a bare service name (`expose web`) or a bogus
            // address fails HERE with a teaching message, not at dial time as an opaque reset.
            services.insert(name, parse_target(&addr, entry)?);
        }
        Ok(Self(services))
    }

    /// Add a handler-target service under `name`, dispatched to registry `scheme`, constructed DIRECTLY
    /// rather than through the addr grammar ([`parse`](Self::parse) -> `parse_target`). Because it bypasses
    /// that grammar, `scheme` may be one an operator's own service entry could NEVER spell: a caller that
    /// needs per-service handler isolation (one handler instance per served name) registers each instance
    /// under a synthetic scheme carrying a byte the handler-scheme grammar rejects (e.g. `fetch_0`, whose
    /// `_` `parse_target` refuses), so no `x=fetch_0:` entry can ever resolve onto a synthetic instance. The
    /// `name` is validated through the [`Service`] domain type; a duplicate `name` is refused.
    ///
    /// The `scheme` is deliberately NOT validated against the addr grammar (that is the whole point: it is a
    /// registry key, not a spellable address), so a caller is responsible for pairing it with a matching
    /// [`Registry`] entry, which [`Exposer::new`] then checks is present like any other named handler.
    pub fn with_handler(mut self, name: &str, scheme: &str) -> eyre::Result<Self> {
        let Self(services) = &mut self;
        name.parse::<Service>()?;
        if services.contains_key(name) {
            eyre::bail!("service `{name}` is already defined; a name may map to only one target");
        }
        services.insert(name.to_owned(), Target::Handler(scheme.to_owned()));
        Ok(self)
    }

    /// The exposed service names, sorted, for a caller's readiness banner.
    pub fn names(&self) -> impl Iterator<Item = &str> {
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
    /// the security walls are [`Exposer::with_public`] (safe) and [`Exposer::new`]/[`Services::prove_unsafe`]
    /// (unsafe raw streams), which prove every requested name before the node serves. So a catalog naming a
    /// service `open` is only ever served once the matching proof passed for the same request. An unsafe-open
    /// raw stream IS open to anyone, so it reads `Open` on the wire too.
    pub fn catalog(
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

    /// The handler schemes this exposer names (each a bare `<name>:`), so [`Exposer::new`] can check each
    /// against the injected registry: every named handler must be registered, and a handler with no auth of
    /// its own may not sit behind an open gate.
    fn handler_schemes(&self) -> impl Iterator<Item = &str> {
        let Self(services) = self;
        services.values().filter_map(|target| match target {
            Target::Handler(scheme) => Some(scheme.as_str()),
            Target::Forward(_) | Target::RawStream(_) => None,
        })
    }

    /// The exposed names whose target is a [`Target::RawStream`] (a `file:`/`fifo:` path source, or `stdin:`).
    /// Like a keyless shell, a raw-stream source has no auth of its own: it serves a chosen path's bytes (or
    /// the piped stdin) to whoever the gate admits, so [`Exposer::new`] refuses it behind an [`Gate::Open`]
    /// gate (a public gate over a `file:` source would exfil a secret, over a `stdin:` source the piped
    /// bytes, to anyone). A raw forward (`host:port`/`unix:`) is a service the operator deliberately stood
    /// up, so it may still be a public gate; a bare file path or a piped stdin is one keystroke from a
    /// secret, so it may not.
    fn raw_stream_names(&self) -> impl Iterator<Item = &str> {
        let Self(services) = self;
        services.iter().filter_map(|(name, target)| match target {
            Target::RawStream(_) => Some(name.as_str()),
            Target::Handler(_) | Target::Forward(_) => None,
        })
    }

    /// Prove an UNSAFE raw-stream opt-in set: this is the wall that turns a raw [`PublicUnsafeRequest`] into
    /// the exposer's proven [`PublicServices`] overlay for [`Exposer::new`]. Every requested name must (1) be
    /// an EXACT served name (a typo or a name the node does not serve bails with the served list) AND (2)
    /// resolve to a [`Target::RawStream`] (a `file:`/`fifo:`/`stdin:` source with no auth of its own).
    ///
    /// A name that resolves to a handler or a forward is a TEACHING REDIRECT, never silently opened: the
    /// unsafe overlay is ONLY for raw byte sources, so a legitimate service named here is refused with a
    /// message pointing at the safe public overlay ([`with_public`](Exposer::with_public)). This is the
    /// disjoint-token partition (delib-39): the two overlays never fold, so crossing them teaches rather than
    /// opens. A survivor set freezes into the overlay [`admit`] consults. The proof reads THROUGH each
    /// target, matched by served name, so an alias can never open a raw stream by naming it.
    fn prove_unsafe(&self, requested: PublicUnsafeRequest) -> eyre::Result<PublicServices> {
        let PublicUnsafeRequest(names) = requested;
        let Self(services) = self;
        let mut proven = HashSet::with_capacity(names.len());
        for name in names {
            match services.get(&name) {
                None => {
                    let mut served: Vec<&str> = services.keys().map(String::as_str).collect();
                    served.sort_unstable();
                    eyre::bail!(
                        "no service named `{name}` to open; this node serves: {}",
                        served.join(", ")
                    );
                }
                // Crossing the token: the unsafe overlay is ONLY for raw byte sources. A handler or a forward
                // named here is redirected to the SAFE public overlay, never silently opened, never leaking a
                // marker type name. STRING B, CLI-Architect round-3, in its library-PURE form: the layering
                // gate forbids a library naming a consumer flag, so this speaks the concept (the public
                // overlay) and each consumer bin's --help names the exact flag. See the report FLAG to
                // CLI-Architect/Style-Warden on the flag-named-vs-conceptual branch.
                Some(Target::Handler(_)) | Some(Target::Forward(_)) => eyre::bail!(
                    "`{name}` is not a raw byte source, so the unsafe raw-stream set will not open it; a handler \
                     or a forward is opened to anyone through the public set instead"
                ),
                Some(Target::RawStream(_)) => {
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
/// (`type Public`): a service that COULD be public still reports `Gated` on a gated node, because
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

    /// The word a table renders for this posture (`gated` / `open`), so the CLI reads at a glance.
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
/// [`TargetKind`] it forwards to, and whether it is an unmetered [`amplifier`](Handler::AMPLIFIER) when open.
///
/// A LOCAL render view an embedder draws its OWN banner from, DISTINCT from the on-wire [`ServiceEntry`] the
/// member-only `control.services` read returns: the banner is printed by a node to its own operator, so it
/// carries the extra render tells (kind, amplifier) that never cross the wire, and it stays off the
/// anti-oracle surface (delib-18) the wire catalog guards. Built by [`Exposer::manifest`] from the resolved
/// services + injected registry, so a consumer RENDERS declared facts (posture from the proven overlay, kind
/// from the target, the amplifier caveat from the handler) rather than re-deriving them from address strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// The service name the exposer published it under (the name a connector requests).
    pub name: String,
    /// The posture a dialer faces reaching it (gated behind a member badge, or open to anyone).
    pub posture: Posture,
    /// What kind of target it forwards to, so the banner can split a public raw stream into its own group.
    pub kind: TargetKind,
    /// Whether its handler declared itself an unmetered amplifier (a caveat the banner narrates when open).
    pub amplifier: bool,
    /// For a raw-stream service, the source a banner names in its unsafe warning: the operator's path made
    /// ABSOLUTE (lexically, via [`std::path::absolute`] -- no FS access, no symlink follow, no existence
    /// requirement, so a not-yet-created `fifo:` still renders), or the piped-stdin marker. [`None`] for a
    /// handler or a forward (no raw source to warn about). Declared by tightbeam so the banner renders a
    /// resolved fact, never re-derives a path from the operator's typed string.
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

/// A boxed writer half handed to a handler (the accepted stream is already `Send + 'static`, so boxing it
/// as a trait object is a small per-stream allocation, invisible next to the splice it feeds).
pub type BoxWrite = Box<dyn io::AsyncWrite + Unpin + Send>;
/// A boxed reader half handed to a handler.
pub type BoxRead = Box<dyn io::AsyncRead + Unpin + Send>;

/// A service handler: what to DO with one admitted stream. The tunnel knows only this CONTRACT (a name maps
/// to a thing that consumes an admitted stream), never what a handler does; a caller that depends on the
/// service crates injects them. The handler receives the gate's [`Admitted`] witness by value (single-use,
/// so "authorize before serve" is a compile-time precondition) and the raw stream halves for ONE stream.
///
/// Whether the handler may EVER face an unauthenticated stranger is a COMPILE-TIME property, stated once as
/// the associated [`type Public`](Handler::Public): a keyless shell names [`Never`](crate::open_policy::Never)
/// (an open gate over it is refused at [`Exposer::new`]), a legitimately-public responder names
/// [`OptIn`](crate::open_policy::OptIn). There is no default and no runtime bool: omitting the choice does not
/// compile, and the marker is sealed + uninhabited, so "a keyless service mislabeled open" is unrepresentable
/// rather than a guarded default (delib-37).
///
/// The `serve` future is `+ Send`: the exposer is `tokio::spawn`ed on a multi-thread runtime and holds the
/// boxed serve future across `.await`, so it must be `Send` (delib-32 r2, compiler-forced). Authors may still
/// write a plain `async fn serve` whose body is `Send`; on the pinned toolchain that coerces to the `+ Send`
/// RPITIT bound at the impl site with no `trait_variant` needed.
pub trait Handler: Send + Sync + 'static {
    /// This handler's open-safety CEILING, stated as a type (no default, so the author MUST pick one of
    /// [`Never`](crate::open_policy::Never) / [`OptIn`](crate::open_policy::OptIn)). Erased to a frozen
    /// `const bool` at the [`ErasedHandler`] bridge, read once at [`Exposer::new`] to refuse an open gate over
    /// a [`Never`](crate::open_policy::Never) handler.
    type Public: PublicUse;

    /// Whether serving this handler answers any caller with NO responder-side rate limit, so an OPEN (public)
    /// one lets an anonymous stranger drain the node's uplink: an unmetered AMPLIFIER. A property the handler
    /// DECLARES so a caller's banner RENDERS the caveat where the danger is (delib-40/41), instead of the
    /// consumer hardcoding a scheme list of its own. This is a caveat a UI narrates, NOT a security gate (the
    /// gate is [`type Public`](Handler::Public)), so it is a plain `const bool` with a safe `false` default: a
    /// handler that IS an amplifier (a reach-diagnostic responder) overrides it to `true`, and every other
    /// handler inherits `false` with no annotation. Erased to [`ErasedHandler::amplifier`] and read when the
    /// exposer builds its readiness [`manifest`](Exposer::manifest).
    const AMPLIFIER: bool = false;

    /// Serve ONE admitted stream: the gate's single-use [`Admitted`] witness by value, and the stream halves.
    fn serve(
        &self,
        admitted: Admitted,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> impl Future<Output = eyre::Result<()>> + Send;
}

/// The object-safe, stored-in-the-`HashMap` view of a [`Handler`]: the associated `Public` marker is erased
/// here to a `const bool` ([`open_safe`](ErasedHandler::open_safe)) and the RPITIT `serve` future is boxed
/// ([`BoxFuture`], `Send`-bearing), so heterogeneous handlers (a [`Never`](crate::open_policy::Never) and an
/// [`OptIn`](crate::open_policy::OptIn) handler) share ONE `Arc<dyn ErasedHandler>` storage type. The marker
/// never enters these signatures, so it does its job at the impl-site type-check and then vanishes into the
/// object's frozen `open_safe()` answer (delib-37: this is why the associated type, not a generic, survives
/// erasure).
trait ErasedHandler: Send + Sync {
    /// The erased open-safety ceiling: `<H::Public as PublicUse>::OPEN_SAFE`, read once at [`Exposer::new`].
    fn open_safe(&self) -> bool;
    /// The erased amplifier caveat: `H::AMPLIFIER`, read when the exposer builds its readiness manifest.
    fn amplifier(&self) -> bool;
    /// The boxed serve future, tied to `&'a self` (`'a`, not `'static`: it borrows the handler's fields).
    fn serve_erased<'a>(
        &'a self,
        admitted: Admitted,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> BoxFuture<'a, eyre::Result<()>>;
}

impl<H: Handler> ErasedHandler for H {
    fn open_safe(&self) -> bool {
        <H::Public as PublicUse>::OPEN_SAFE
    }

    fn amplifier(&self) -> bool {
        H::AMPLIFIER
    }

    fn serve_erased<'a>(
        &'a self,
        admitted: Admitted,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> BoxFuture<'a, eyre::Result<()>> {
        Box::pin(Handler::serve(self, admitted, writer, reader))
    }
}

/// The scheme -> handler map the [`Exposer`] takes at construction. The caller builds it; the tunnel core
/// depends on no service crate and ships no handler of its own. Keyed by the `<scheme>:` an exposed service
/// resolves to (a bare `<name>:`).
#[derive(Default)]
pub struct Registry(HashMap<String, Arc<dyn ErasedHandler>>);

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `scheme` -> `handler`, returning self for chaining. The handler's open-safety marker
    /// (`type Public`) is erased to a `const bool` as it is boxed into the shared `Arc<dyn ErasedHandler>`
    /// storage, so heterogeneous handlers live in one map.
    #[must_use]
    pub fn with(mut self, scheme: impl Into<String>, handler: impl Handler) -> Self {
        let Self(handlers) = &mut self;
        handlers.insert(scheme.into(), Arc::new(handler));
        self
    }

    /// Merge another registry's handlers into this one. The merge is ADD-ONLY: a collision with a scheme
    /// already present is refused HERE at merge intent, never silently overwritten. tightbeam ships no
    /// handler of its own, so the caller assembles the whole registry; this guard keeps that
    /// assembly honest, so a second `extend` cannot shadow (and silently downgrade the gate of) a handler
    /// the caller already registered, rather than repairing the collision after the fact.
    pub fn extend(mut self, other: Registry) -> eyre::Result<Self> {
        let Self(handlers) = &mut self;
        let Registry(others) = other;
        for (scheme, handler) in others {
            if handlers.contains_key(&scheme) {
                eyre::bail!(
                    "cannot inject a handler for `{scheme}:`: a handler for that scheme is already \
                     registered and may not be replaced"
                );
            }
            handlers.insert(scheme, handler);
        }
        Ok(self)
    }

    /// Look up a handler by scheme.
    fn get(&self, scheme: &str) -> Option<&Arc<dyn ErasedHandler>> {
        let Self(handlers) = self;
        handlers.get(scheme)
    }
}

/// Resolve the exposer's node BASE gate, in ONE place so every embedder (tightbeam's own CLI and any other
/// consumer) applies the SAME policy: a family gate on the node's provisioned `signet`; an UNPROVISIONED
/// node fails LOUD rather than ever defaulting to open. The caller loads the denylist and passes it as a
/// value. This exists so the two security-relevant conventions (fail-loud-on-unprovisioned,
/// real-loaded-denylist) are enforced once, not hand-copied into each caller.
///
/// The base gate is the node-wide FAMILY authority; opening individual services is a SEPARATE, per-service
/// overlay ([`Exposer::with_public`]), never a node-wide value this function returns. Building a node-wide
/// [`Gate::Open`] base is a caller's own deliberate choice (nauthy's [`Gate::Open`]), not something a
/// gate-resolution policy hands back from a flag: that node-wide-open flag was exactly the whole-node blast
/// radius per-service exposure removes (delib-39).
pub fn resolve_gate(signet: Option<NodeId>, denylist: Denylist) -> eyre::Result<Gate> {
    let root = signet.ok_or_else(|| {
        eyre::eyre!(
            "this node has no signet to gate on: provision it (adopt a signet), or open individual services \
             to anyone"
        )
    })?;
    Ok(Gate::family(root.verify_key(), denylist))
}

/// The raw, UNVALIDATED set of service names an operator asked to open to strangers (however an embedder
/// surfaces that request), before [`Exposer::with_public`] proves each one exposed and
/// open-safe. Kept DISTINCT from [`PublicServices`] (the proven set the gate consults) so an unvalidated set
/// can never reach admission: the only way to a [`PublicServices`] is through the proof, so "opened a name
/// the node does not serve / a keyless shell" is a build-time bail, not a silently-open service.
#[derive(Debug, Clone, Default)]
pub struct PublicRequest(Vec<String>);

impl PublicRequest {
    /// An empty request: no service is opened (every service faces the base gate). The default a node builds
    /// when the operator names nothing public.
    pub fn none() -> Self {
        Self(Vec::new())
    }

    /// Build a request from the operator's raw public-request names, verbatim (no validation here: this is the
    /// UNPROVEN side of parse-don't-validate; [`Exposer::with_public`] is the wall).
    pub fn new(names: impl IntoIterator<Item = String>) -> Self {
        Self(names.into_iter().collect())
    }

    /// Whether `name` was requested public, for a display read (the `control.services` catalog). This reads
    /// the raw request, never the proof, so it is a DISPLAY predicate only, never an admission decision.
    pub fn contains(&self, name: &str) -> bool {
        let Self(names) = self;
        names.iter().any(|requested| requested == name)
    }

    /// Whether the operator requested nothing public.
    pub fn is_empty(&self) -> bool {
        let Self(names) = self;
        names.is_empty()
    }
}

/// The raw, UNVALIDATED set of raw-stream service names an operator asked to serve to strangers
/// unauthenticated (however an embedder surfaces that request), before [`Exposer::new`] proves each one an
/// exposed [`Target::RawStream`]. Sibling of [`PublicRequest`], kept DISTINCT from the proven
/// [`PublicServices`] so an unproven name can never reach admission: the only way to a [`PublicServices`] is
/// through [`Services::prove_unsafe`], so "opened a name the node does not serve / a handler / a forward as an
/// unsafe raw stream" is a build-time bail, not a silently-open service.
///
/// DISJOINT from [`PublicRequest`] on purpose: a safe public overlay opens a legitimate service (a handler or
/// a forward the operator stood up), an UNSAFE overlay opens a raw byte source with no auth of its own. The
/// two never fold, so the louder opt-in stays a distinct, deliberate thing the operator cannot type by
/// accident.
#[derive(Debug, Clone, Default)]
pub struct PublicUnsafeRequest(Vec<String>);

impl PublicUnsafeRequest {
    /// An empty request: no raw stream is served to strangers (every raw stream stays gated).
    pub fn none() -> Self {
        Self(Vec::new())
    }

    /// Build a request from the operator's raw unsafe-open names, verbatim (no validation here: this is the
    /// UNPROVEN side of parse-don't-validate; [`Services::prove_unsafe`], run by [`Exposer::new`], is the wall).
    pub fn new(names: impl IntoIterator<Item = String>) -> Self {
        Self(names.into_iter().collect())
    }

    /// Whether the operator requested no raw stream served to strangers.
    pub fn is_empty(&self) -> bool {
        let Self(names) = self;
        names.is_empty()
    }

    /// Whether `name` was requested unsafe-open, for a display read (the `control.services` catalog). This
    /// reads the raw request, never the proof, so it is a DISPLAY predicate only, never an admission decision.
    pub fn contains(&self, name: &str) -> bool {
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

/// An exposer: the services to publish, the caller-injected handler registry that serves the named ones,
/// and the gate that decides who may reach them. Accepts overlay sessions and forwards each inbound stream
/// to its service.
pub struct Exposer {
    services: Services,
    registry: Arc<Registry>,
    gate: Gate,
    /// The safe public overlay, proven by [`with_public`](Exposer::with_public): legitimate services (a
    /// handler or a forward) opened to any reaching peer.
    public: PublicServices,
    /// The UNSAFE raw-stream overlay, proven by [`new`](Exposer::new): raw byte sources (`file:`/`fifo:`/
    /// `stdin:`) with no auth of their own, knowingly served to any reaching peer. Kept DISJOINT from
    /// `public` so the two proof walls write disjoint state (no clobber), the toggle interlock (delib-34) can
    /// read `!public_unsafe.is_empty()` trivially, and the on-thesis reading stays legible: `public` =
    /// "opened a legitimate service", `public_unsafe` = "knowingly serves raw bytes with no auth".
    public_unsafe: PublicServices,
}

impl Exposer {
    /// Assemble an exposer from the parsed services, the caller-injected handler registry, the node BASE
    /// gate, and the operator's UNSAFE raw-stream opt-in set, enforcing the door interlocks: every named
    /// handler is actually registered (a typo or an unbuilt feature fails HERE, not at dial time); a handler
    /// with no auth of its own (a keyless shell) may not sit behind a node-wide [`Gate::Open`] BASE; and a
    /// raw-stream source under an open BASE is refused UNLESS the operator knowingly opted it into
    /// `public_unsafe` (proven here into the disjoint unsafe overlay).
    ///
    /// The two raw-stream interlocks stay DISJOINT (delib-37): the keyless-handler refusal reads a compile-time
    /// marker (`type Public`), while the raw-stream-unsafe refusal is a RUNTIME opt-in guard (the danger
    /// depends on a runtime path value no type can see), so the two are never folded onto one mechanism. The
    /// unsafe set enters HERE, at [`new`](Self::new), rather than a `with_public`-style builder, because the
    /// whole-node-open door lives here and a builder chained after `new` could not un-fire a bail `new` already
    /// raised; co-locating the interlocks at one door is what keeps them legible.
    ///
    /// No SAFE service is opened per-service by this constructor: the exposer starts with an EMPTY safe
    /// overlay (every handler/forward faces the base gate). A caller opens individual legitimate services with
    /// [`with_public`](Self::with_public), which proves each requested name exposed and open-safe. So
    /// `Exposer::new(services, registry, gate, PublicUnsafeRequest::none())` alone is a fully-gated node (or,
    /// over a [`Gate::Open`] base, a fully-open one), and the safe per-service overlay is a deliberate second
    /// step.
    pub fn new(
        services: Services,
        registry: Registry,
        gate: Gate,
        public_unsafe: PublicUnsafeRequest,
    ) -> eyre::Result<Self> {
        // Interlock 1: every named handler is registered, and a keyless handler (`type Public = Never`) may
        // not sit behind an open BASE. Reads the erased compile-time `OPEN_SAFE` marker.
        for scheme in services.handler_schemes() {
            let Some(handler) = registry.get(scheme) else {
                eyre::bail!(
                    "register a handler for `{scheme}:` before exposing it (or drop the service): \
                     no handler is registered for it (is the feature that provides it built in?)"
                );
            };
            if matches!(gate, Gate::Open) && !handler.open_safe() {
                // STRING C (CLI-Architect round-3), `{scheme}` variant: a keyless shell has NO safe way to be
                // opened, so it hard-refuses with no redirect (unlike a raw stream, which STRING A points at
                // the unsafe raw-stream set).
                eyre::bail!(
                    "`{scheme}` has no legitimate public use: a keyless shell (or an alias of one) would hand a \
                     shell to anyone who reaches this node. keep it family-gated; drop it from the public set"
                );
            }
        }
        // PROVE the unsafe set (parse-don't-validate): every named opt-in must be an EXACT served
        // `Target::RawStream`; a name the node does not serve, or a handler/forward, is a teaching redirect,
        // never a silently-open service. The survivors freeze into the disjoint `public_unsafe` overlay.
        let proven_unsafe = services.prove_unsafe(public_unsafe)?;
        // Interlock 2 (raw-stream door, RELAXED per-name): a raw-stream source (`file:`/`fifo:`/`stdin:`) has
        // no auth of its own, so under a node-wide open BASE it would serve a chosen path's bytes (or the
        // piped stdin) to anyone; a `file:<secret>` or `stdin:` source would exfil it. Refuse it at the same
        // door that refuses a keyless shell, UNLESS the operator knowingly opted this exact name into the
        // unsafe overlay. A raw forward (`host:port`/`unix:`) is not refused: it is a service the operator
        // deliberately stood up, not a bare file path one keystroke from a key. This guards the node-wide-open
        // BASE gate; the per-service SAFE overlay takes its own wall in [`with_public`].
        if matches!(gate, Gate::Open)
            && let Some(name) = services
                .raw_stream_names()
                .find(|name| !proven_unsafe.contains(name))
        {
            // STRING A (CLI-Architect round-3), library-PURE form: the ONE unified raw-stream-under-a-public-
            // gate refusal, shared byte-for-byte with the per-service `with_public` door below (differing only
            // in `{name}`). It REDIRECTS to the unsafe raw-stream set (a raw stream is now deliberately
            // openable), not a flat refusal; the exact flag token is named by each consumer bin's --help
            // (the layering gate forbids a library naming a consumer flag).
            eyre::bail!(
                "`{name}` is a raw byte source (file:/fifo:/stdin:) with no auth of its own, so a public gate \
                 will not serve it. to serve its raw bytes to anyone, name it in the unsafe raw-stream set; \
                 otherwise gate it or drop it from the public set"
            );
        }
        // Interlock 3 (toggle mutual-exclusion): a DESIGN-LOCK with no operand today. delib-34's live-toggle
        // set (`ActiveSet`/`--toggleable`) is UNBUILT, so there is no second set to refuse; inventing a toggle
        // field now purely to refuse it would be machinery for a case that cannot occur yet. When the toggle
        // allowlist lands it enters THIS constructor beside `public_unsafe` and adds ONE bail here:
        //   `if !proven_unsafe.is_empty() && !toggleable.is_empty() { eyre::bail!(...) }`
        // refusing their co-presence by construction (an unauthenticated toggle must never re-arm a raw-byte
        // exfil remotely). Recorded as a binding acceptance criterion for the delib-34 build; do NOT add a
        // toggle field in this change.
        Ok(Self {
            services,
            registry: Arc::new(registry),
            gate,
            public: PublicServices::default(),
            public_unsafe: proven_unsafe,
        })
    }

    /// Open the requested services to any reaching peer, per-service, PROVING each one first: this is the
    /// wall that turns a raw [`PublicRequest`] into the exposer's proven [`PublicServices`] overlay. Every
    /// requested name must (1) be an EXACT served name (a typo, a casing miss, or a name the node does not
    /// serve bails, never silently opening nothing), and (2) resolve THROUGH its [`Target`] to an
    /// [`open_safe`](Target::open_safe) posture (a `Never` handler, an aliased shell, or a raw stream bails
    /// with a teaching message). Resolving through the target, matched by served name, is what stops an alias
    /// (`foo=sshd:` named in the public set) or a raw stream from being opened by naming it: the target's posture
    /// decides, never the name. A survivor set freezes into the overlay [`admit`] consults.
    ///
    /// This REPLACES a node-wide open value with a per-service one: a caller opens `speed` and `fetch` by
    /// name while `control.*` and every keyless shell stay member-only by set non-membership. The teaching
    /// bails fire at BUILD time to the operator's own terminal (no remote party observes them), so there is
    /// no dial-time oracle. It never names a marker type (`Never`/`OptIn`), only the constraint.
    pub fn with_public(mut self, requested: PublicRequest) -> eyre::Result<Self> {
        let PublicRequest(names) = requested;
        let Services(services) = &self.services;
        let mut proven = HashSet::with_capacity(names.len());
        for name in names {
            let Some(target) = services.get(&name) else {
                let mut served: Vec<&str> = services.keys().map(String::as_str).collect();
                served.sort_unstable();
                eyre::bail!(
                    "no service named `{name}` to open; this node serves: {}",
                    served.join(", ")
                );
            };
            match target {
                // A raw stream named in the SAFE overlay is a teaching REDIRECT, not a flat refusal: the safe
                // overlay never opens a raw byte source (`open_safe` stays `false` for it), but the operator
                // CAN serve its bytes knowingly through the DISTINCT unsafe overlay. STRING A (CLI-Architect
                // round-3), byte-for-byte the SAME string as the whole-node door above: one condition, one
                // string, both bins.
                Target::RawStream(_) => eyre::bail!(
                    "`{name}` is a raw byte source (file:/fifo:/stdin:) with no auth of its own, so a public \
                     gate will not serve it. to serve its raw bytes to anyone, name it in the unsafe raw-stream \
                     set; otherwise gate it or drop it from the public set"
                ),
                // A keyless shell or an aliased shell is a HARD no: it has no legitimate public use and no
                // redirect exists (unlike a raw stream). STRING C (CLI-Architect round-3), `{name}` variant.
                // Never leaks a marker type name.
                _ if !target.open_safe(&self.registry) => eyre::bail!(
                    "`{name}` has no legitimate public use: a keyless shell (or an alias of one) would hand a \
                     shell to anyone who reaches this node. keep it family-gated; drop it from the public set"
                ),
                _ => {
                    proven.insert(name);
                }
            }
        }
        self.public = PublicServices(proven);
        Ok(self)
    }

    /// The served services as a caller's readiness banner needs them: each name with the [`Posture`] a dialer
    /// faces, its [`TargetKind`], and its handler-declared [`amplifier`](Handler::AMPLIFIER) caveat,
    /// name-sorted. A pure read over the exposer's OWN resolved state (the proven public overlay decides
    /// posture, the target decides kind, the injected handler declares the amplifier), so an embedder draws
    /// its banner from declared facts rather than by re-parsing an address string. DISTINCT from
    /// [`Services::catalog`]: that is the on-wire snapshot the member-only `control.services` read serves;
    /// this is the local banner view (kind + amplifier never cross the wire).
    pub fn manifest(&self) -> Vec<ManifestEntry> {
        let node_open = matches!(self.gate, Gate::Open);
        let Services(services) = &self.services;
        let mut entries: Vec<ManifestEntry> = services
            .iter()
            .map(|(name, target)| {
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
                // The amplifier caveat is handler-declared, so it is resolved THROUGH the target's handler,
                // never a name match: only a registered handler can be an amplifier; a forward or a raw
                // stream never is (they carry no responder the handler owns).
                let amplifier = match target {
                    Target::Handler(scheme) => self
                        .registry
                        .get(scheme)
                        .is_some_and(|handler| handler.amplifier()),
                    Target::Forward(_) | Target::RawStream(_) => false,
                };
                // The raw source a banner names in its unsafe warning is tightbeam's to declare (it owns
                // raw-stream resolution): a raw stream carries its resolved absolute path / stdin marker, a
                // handler or a forward has no raw source to warn about.
                let raw_source = match target {
                    Target::RawStream(stream) => Some(stream.raw_source()),
                    Target::Handler(_) | Target::Forward(_) => None,
                };
                ManifestEntry {
                    name: name.clone(),
                    posture,
                    kind: target.kind(),
                    amplifier,
                    raw_source,
                }
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
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
        let Self {
            services,
            registry,
            gate,
            public,
            public_unsafe,
        } = self;
        // Cap concurrent raw-stream opens across the whole node (all sessions share this one semaphore) as
        // cheap defense-in-depth: the nonblocking open cannot park a thread, so this bounds the fds held
        // mid-open, not a leak. See `RAW_STREAM_OPEN_PERMITS`.
        //
        // The whole per-node serving context (gate + public overlay + services + registry + the open pool)
        // is bundled behind ONE `Arc` so each accepted session carries a single handle rather than a fistful
        // of clones.
        let serving = Arc::new(Serving {
            gate,
            public,
            public_unsafe,
            services,
            registry,
            raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
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
/// raw-stream `public_unsafe`), the parsed [`Services`], the injected handler [`Registry`], and the raw-stream
/// open permit pool. Assembled once in [`Exposer::run`] and shared by one `Arc` across every session/stream,
/// so a serving future carries a single handle.
struct Serving {
    gate: Gate,
    public: PublicServices,
    public_unsafe: PublicServices,
    services: Services,
    registry: Arc<Registry>,
    raw_stream_opens: Semaphore,
}

/// Serve one accepted session: handle each inbound stream's service request under the gate.
async fn serve_session<S: Session>(session: S, serving: Arc<Serving>) -> eyre::Result<()>
where
    S::Write: Send + 'static,
    S::Read: Send + 'static,
{
    let peer = session.peer();
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
                    Ok((writer, reader)) => {
                        pipes.push(serve_request(peer, writer, reader, Arc::clone(&serving)))
                    }
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
/// its own merits.
async fn serve_request<W, R>(
    peer: NodeId,
    mut writer: W,
    mut reader: R,
    serving: Arc<Serving>,
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
        registry,
        raw_stream_opens,
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
    let Ok(service) = request.service.parse::<Service>() else {
        let message = format!("invalid service name {:?}", request.service);
        return Response::Error(message)
            .write(&mut writer)
            .await
            .map_err(Into::into);
    };
    // A node exposing exactly one service should not require the request to name it: if the request names
    // no exposed service (a connector defaulting to `default`) and there is only one, resolve to it. Done
    // BEFORE the gate so a delegated slip for that service still matches (the gate checks the RESOLVED service).
    let service = resolve_single_service(service, services);

    let admitted = match admit(
        gate,
        public,
        public_unsafe,
        peer,
        request.capability.as_deref(),
        request.membership.as_deref(),
        &service,
    ) {
        Ok(admitted) => admitted,
        Err(refusal) => {
            // The real reason (missing / not-granted / revoked / malformed) is a LOCAL log line for the
            // node's own operator. The WIRE gets one indistinguishable refusal, so a not-admitted dialer
            // cannot tell a stranger's `Missing` from a revoked holder's `Revoked`, nor confirm a service
            // exists at all: no pre-authorization revocation or capability-enumeration oracle.
            tracing::warn!(%peer, service = %service, %refusal, "refused");
            return Response::Error(UNIFORM_REFUSAL.to_owned())
                .write(&mut writer)
                .await
                .map_err(Into::into);
        }
    };

    match services.get(service.as_str()) {
        // tightbeam's own primitive: connect the local socket and splice raw bytes to it.
        Some(Target::Forward(addr)) => {
            Response::Ok.write(&mut writer).await?;
            dial_and_splice(addr, writer, reader).await?;
        }
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
                    Response::Error(error.to_string())
                        .write(&mut writer)
                        .await?;
                }
            }
        }
        // A named service: hand the admitted stream to the caller-injected handler. The `Admitted` witness
        // proves the gate ruled on THIS stream and is moved into the handler by value (single-use), so a
        // handler can never run for an unauthorized peer; the guarantee holds only because the admit
        // (above) and this serve share one stream frame, never hoisted to session scope.
        Some(Target::Handler(scheme)) => match registry.get(scheme) {
            Some(handler) => {
                Response::Ok.write(&mut writer).await?;
                handler
                    .serve_erased(admitted, Box::new(writer), Box::new(reader))
                    .await?;
            }
            // `Exposer::new` proved every exposed handler is registered, so this is unreachable in practice;
            // answer defensively rather than panic if an exposer was hand-built around that invariant.
            None => {
                let message = format!("no handler for service {:?}", service.as_str());
                Response::Error(message).write(&mut writer).await?;
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
            Response::Error(UNIFORM_REFUSAL.to_owned())
                .write(&mut writer)
                .await?;
        }
    }
    Ok(())
}

/// Rule on a request under the node's per-service admission: the two disjoint open overlays (`public`, the
/// safe one, and `public_unsafe`, the unsafe raw-stream one) composed with the `base` family gate, returning
/// the [`Admitted`] witness on success or a DISTINGUISHING refusal string for the node's OWN logs. A service
/// the operator opened (a member of EITHER overlay) admits any reaching peer; every other service faces the
/// `base` gate. The witness is required to reach a service handler, so "authorize before
/// serve" is a compile-time precondition (see [`nauthy::Admitted`]). The reason returned here NEVER crosses
/// the wire (the caller sends [`UNIFORM_REFUSAL`] to a not-admitted dialer); it exists only so the operator
/// can see WHY on their own `tracing` output. Distinguishing missing/not-granted/revoked to the wire would
/// be a revocation + capability-enumeration oracle for an unauthorized peer (deliberation 18).
fn admit(
    base: &Gate,
    public: &PublicServices,
    public_unsafe: &PublicServices,
    peer: NodeId,
    capability: Option<&str>,
    membership: Option<&str>,
    service: &Service,
) -> Result<Admitted, String> {
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
        return mint(Gate::Open.admit_witnessed(peer.verify_key(), None, None, service));
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
        Err(_) => return Err("malformed capability".to_owned()),
    };
    // Parse the SECOND slot ONLY when the first is a signet-bound slip: that is the sole path that ANDs a
    // fleet badge, so a plain/bearer/device slip (or none) never triggers the extra `Cap::parse`. The server
    // guards this independently of the dialer (a hostile client ignores the dialer's attach logic), which
    // bounds the second slot's parse work behind the cheap, root-free `is_signet_bound` check. A malformed
    // badge on the signet path is a refusal, not a hard error; both slots inherit `Cap::parse`'s bounds.
    let membership = match cap.as_ref() {
        Some(slip) if slip.is_signet_bound() => match membership.map(Cap::parse).transpose() {
            Ok(membership) => membership,
            Err(_) => return Err("malformed capability".to_owned()),
        },
        _ => None,
    };
    mint(base.admit_witnessed(
        peer.verify_key(),
        cap.as_ref(),
        membership.as_ref(),
        service,
    ))
}

/// Map a nauthy admission result to the [`admit`] contract: the witness on success, or a DISTINGUISHING
/// reason for the node's OWN logs on refusal (never the wire). Shared by the public-HIT path (whose
/// [`Gate::Open`] admission never actually refuses) and the family MISS path, so both surface a refusal the
/// same way.
fn mint(result: Result<Admitted, Refusal>) -> Result<Admitted, String> {
    result.map_err(|refusal| match refusal {
        Refusal::Missing => "this service requires a capability".to_owned(),
        Refusal::NotGranted => "capability does not grant this service".to_owned(),
        Refusal::Revoked => "capability has been revoked".to_owned(),
    })
}

/// Render, for a DIALER, the reason a host returned on the wire, descriptively. The dialer REACHED the host
/// and was refused (an unreachable peer never receives a [`Response`]), so this is the "reached but refused"
/// outcome, distinct from "could not reach". It recognizes the [`UNIFORM_REFUSAL`] token a not-admitted
/// dialer gets and phrases it as a reason a person can act on, rather than echoing the bare word (which a
/// caller wrapping it in "refused (…)" would double into `refused (refused)`). A host that returned a MORE
/// specific reason (a service that admitted the stream, then declined the requested method) keeps it
/// verbatim. This is purely client-side rendering of the outcome the dialer already holds: it reveals
/// nothing the wire did not, so the anti-oracle stands (a true stranger still cannot tell WHICH gated
/// service exists, only that this dial was refused).
pub fn refusal_reason(message: &str) -> String {
    if message == UNIFORM_REFUSAL {
        "not admitted: not a member of this node's family, and no capability for this service"
            .to_owned()
    } else {
        message.to_owned()
    }
}

/// A one-line dialer-side refusal for a REACHED host: `reached <node>, but refused: <reason>`. Used where a
/// probe reached the peer and its gate refused (e.g. [`Connector::preflight`]); it names the peer, states it
/// was reached (not unreachable), and renders the reason through [`refusal_reason`] so a bare gate refusal
/// is descriptive and never doubled.
fn refusal_reached(dial: NodeId, message: &str) -> String {
    format!("reached {dial}, but refused: {}", refusal_reason(message))
}

/// Resolve the requested service against what is exposed: if it names no exposed service but exactly one
/// service is exposed, return that one, so a single-service node needs no named service. Otherwise return
/// the request unchanged (a multi-service node keeps it, to fail later with the "unknown service; this node
/// exposes: …" hint rather than guessing which one was meant).
fn resolve_single_service(requested: Service, services: &HashMap<String, Target>) -> Service {
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
/// forward (open an existing OS object, splice its bytes to the peer); a bare scheme (a `<name>:` -- a word
/// then a colon with nothing after) names a handler; anything else must be a socket forward
/// (`host:port` or `unix:<path>`). All validated here so a typo fails at parse with a teaching message, not
/// at dial time.
fn parse_target(addr: &str, entry: &str) -> eyre::Result<Target> {
    // A trailing `+lossy` is the operator's opt-in to raw-stream FAN-OUT (delib-20 SYNTHESIS + delib-24): the
    // source may be reached by MANY consumers at once, and a consumer that falls behind has its bytes DROPPED
    // rather than stall the producer or the others. It is a claim only the operator can make ("this stream
    // tolerates loss"), so it is legal ONLY on the live single-writer sources `stdin:`/`fifo:` and REFUSED at
    // parse on anything else: a `file:` (static bytes, already safe fan-out by re-open, loss would be corruption)
    // or a `host:port`/`unix:`/handler scheme (not a raw-stream source at all). Strip it here, then route the
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
    // FIRST, before the bare-scheme handler arm would read `stdin` as a handler no registry holds. It shares
    // the raw-stream direction and the public-gate refusal, but inherits none of the path guards (there is no
    // path). Anything after the colon is a typo: `stdin:` takes no argument.
    if addr == "stdin:" {
        return Ok(Target::RawStream(RawStream::stdin(lossy)?));
    }
    // A raw-stream forward carries a PATH tail (`file:/tmp/x`, `fifo:/tmp/beam`), so it is a Forward, not a
    // bare-scheme Handler. Route it FIRST: the direction (a read-only source toward the peer) is fixed here
    // at parse time, and a bare `file:`/`fifo:` with no path fails loudly rather than resolving to a
    // handler no registry holds.
    if let Some(path) = addr.strip_prefix("file:") {
        reject_lossy("file:")?;
        return Ok(Target::RawStream(RawStream::file(path, entry)?));
    }
    if let Some(path) = addr.strip_prefix("fifo:") {
        return Ok(Target::RawStream(RawStream::fifo(path, entry, lossy)?));
    }
    if let Some(scheme) = addr.strip_suffix(':') {
        // A bare `<scheme>:` (nothing after the colon) is a handler selector. `unix:<path>` and `host:port`
        // carry a tail and so fall through to the forward grammar; a bare `unix:` (no path) resolves to a
        // handler named `unix` that no registry holds, failing loudly at `Exposer::new`. A `.` is allowed
        // so a dotted method on an interface (`control.status:`, `control.restart:`) is typeable as one
        // handler: `.` is in the `Service` alphabet, so a real interface's methods are addressable by name.
        if !scheme.is_empty()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            reject_lossy(addr)?;
            return Ok(Target::Handler(scheme.to_owned()));
        }
    }
    reject_lossy(addr)?;
    validate_forward(addr, entry)?;
    Ok(Target::Forward(addr.to_owned()))
}

/// Reject a forward addr that is not a real target, so a bare service name (`expose web`) fails at parse
/// with a teaching message instead of silently pointing the `default` service at an undialable host. Valid
/// forwards: `unix:<path>` or a `host:port` (a bare `<name>:` handler scheme is resolved earlier).
fn validate_forward(addr: &str, entry: &str) -> eyre::Result<()> {
    let is_host_port = addr
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
    if addr.starts_with("unix:") || is_host_port {
        return Ok(());
    }
    // A bare token with no `=` was almost certainly meant as a service NAME, not an address.
    if !entry.contains('=') {
        eyre::bail!(
            "`{entry}` is not an address to forward to. Did you mean a service pointing at one, e.g. \
             `{entry}=127.0.0.1:8080`? (an address is host:port, unix:<path>, file:<path>, fifo:<path>, \
             or a bare `<name>:` handler scheme)"
        );
    }
    eyre::bail!(
        "`{addr}` is not a valid forwarding address (host:port, unix:<path>, file:<path>, fifo:<path>, \
         or a bare `<name>:` handler scheme)"
    )
}

/// Dial a service target (a `unix:<path>` socket or a `host:port`) and pipe it to the bifrost stream.
async fn dial_and_splice<W, R>(addr: &str, writer: W, reader: R) -> eyre::Result<()>
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
            eyre::bail!("unix sockets are not supported on this platform");
        }
    } else {
        let local = TcpStream::connect(addr).await?;
        splice(local, writer, reader).await?;
    }
    Ok(())
}

/// A resolved connect: the node to dial, the service to ask for, and any token to present.
///
/// The domain half of a `connect`, with the CLI's target-parsing (`Target`/`FromStr`) left in the CLI
/// layer. A caller builds one with [`Connector::to_node`] (a raw node id, optionally presenting a link) or
/// [`Connector::from_link`] (a `sheer:` link that supplies both the node and the token), then drives it
/// with [`Connector::preflight`] (then [`PortForward::run`]) or [`Connector::pipe_stdio`].
pub struct Connector {
    dial: NodeId,
    service: String,
    capability: Option<String>,
    membership: Option<String>,
}

impl Connector {
    /// Connect to a raw node id, requesting `service`. A raw-node dial may still present a token via
    /// `present`, for the case where the node id was shared separately from the capability.
    pub fn to_node(dial: NodeId, service: String, present: Option<String>) -> Self {
        Self {
            dial,
            service,
            capability: present,
            membership: None,
        }
    }

    /// Connect via a `sheer:` capability link, requesting `service`. The link supplies the node to dial
    /// (the cap's root) and carries the token; the host refuses unless the token actually grants `service`.
    pub fn from_link(link: &str, service: String) -> eyre::Result<Self> {
        Ok(Self {
            dial: Cap::parse(link)?.root().node_id(),
            service,
            capability: Some(link.to_owned()),
            membership: None,
        })
    }

    /// Also present `badge` in the SECOND slot: a membership badge under the foreign fleet a signet-bound
    /// slip in `capability` (slot 1) names. The host ANDs the two (the slip valid at its own root, the badge
    /// valid under the fleet the slip names) before admitting. A no-op for every plain dial, whose slot 1
    /// admits alone and whose host never consults slot 2.
    #[must_use]
    pub fn with_membership(mut self, badge: String) -> Self {
        self.membership = Some(badge);
        self
    }

    /// The node this connector dials.
    pub fn dial(&self) -> NodeId {
        self.dial
    }

    /// The service this connector requests.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The opening request this connector sends on each stream: the service to reach and any token.
    fn request(&self) -> Request {
        Request {
            service: String::clone(&self.service),
            capability: self.capability.clone(),
            membership: self.membership.clone(),
        }
    }

    /// Reach the peer, confirm the gate ADMITS this connector, and bind the local port, returning a live
    /// [`PortForward`] ready to run. Admission is proven here, before any success is announced: a probe
    /// stream sends the request and awaits the host's [`Response`], so a refusal (an unexposed service, a
    /// revoked or non-granting cap, an unauthorized identity) surfaces as an `Err` from THIS call, carrying
    /// the host's reason, rather than a silently-reset connection once the caller has already printed
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
        request.write(&mut writer).await?;
        if let Response::Error(message) = Response::read(&mut reader).await? {
            eyre::bail!("{}", refusal_reached(self.dial, &message));
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
        request_stdio(self.request(), writer, reader).await
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
                    pipes.push(request_service(self.request.clone(), tcp, writer, reader));
                }
                Some(result) = pipes.next(), if !pipes.is_empty() => {
                    if let Err(error) = result {
                        // A refused stream (an unexposed service, a revoked or non-granting cap) carries a
                        // user-actionable reason. The core is print-free (a library embedder owns its own
                        // output), so route it through `tracing`; the CLI adapter surfaces it to the user.
                        tracing::warn!("connection failed: {error:#}");
                    }
                }
            }
        }
    }
}

/// A [`Session`] view that gates every stream it opens through a fixed service request. Wraps a live
/// bifrost session; on `open_bi` it opens a real stream, sends the request, and yields the admitted halves
/// ONLY on `Response::Ok`, mapping a refusal to [`bifrost::Error::Stream`]. Any caller-injected
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
    type Write = S::Write;
    type Read = S::Read;

    fn peer(&self) -> NodeId {
        self.session.peer()
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        let (mut writer, mut reader) = self.session.open_bi().await?;
        self.request
            .write(&mut writer)
            .await
            .map_err(|error| bifrost::Error::Stream(Box::new(error)))?;
        match Response::read(&mut reader)
            .await
            .map_err(|error| bifrost::Error::Stream(Box::new(error)))?
        {
            Response::Ok => Ok((writer, reader)),
            // Surface the host's refusal reason through the stream error, using the same phrasing
            // `request_service` gives the forward path, so a caller's error chain reads one way.
            Response::Error(message) => Err(bifrost::Error::Stream(
                format!("service refused: {message}").into(),
            )),
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
async fn request_service<W, R>(
    request: Request,
    tcp: TcpStream,
    mut writer: W,
    mut reader: R,
) -> eyre::Result<()>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    request.write(&mut writer).await?;
    match Response::read(&mut reader).await? {
        Response::Ok => splice(tcp, writer, reader).await?,
        Response::Error(message) => eyre::bail!("service refused: {message}"),
    }
    Ok(())
}

/// Open a service and, if the host accepts, pipe it against this process's stdin/stdout (a
/// ProxyCommand-shaped bridge carrying the service to this process's stdout). Same handshake as
/// [`request_service`], but the local ends are the process's own std streams, and the pump
/// ([`pipe_stdio_bridge`]) returns when the PEER closes rather than waiting on a stdin that (at a terminal)
/// never EOFs, so a reached command exits when the command does.
async fn request_stdio<W, R>(request: Request, mut writer: W, mut reader: R) -> eyre::Result<()>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    request.write(&mut writer).await?;
    match Response::read(&mut reader).await? {
        Response::Ok => pipe_stdio_bridge(writer, reader).await?,
        Response::Error(message) => eyre::bail!("service refused: {message}"),
    }
    Ok(())
}

/// Mint a `sheer:` capability link granting `service`, valid for `lifetime`.
///
/// A non-delegable link is sealed so no holder can append a narrower block; a delegable one is left open.
/// Verification is unaffected either way. Offline: needs the signing `identity` but no network.
pub fn mint_link(
    identity: &Identity,
    service: &Service,
    lifetime: Duration,
    delegable: bool,
) -> eyre::Result<String> {
    let cap = identity.mint(service, nauthy::expires_in(lifetime))?;
    let cap = if delegable { cap } else { cap.seal()? };
    Ok(cap.link()?)
}

/// Mint a device-bound `sheer:` capability link granting `service` to the proven device `bound_to`, valid
/// for `lifetime`.
///
/// The standing per-service grant for one device (see [`nauthy::Identity::mint_bound`]): the link is inert
/// unless presented by `bound_to`, so a copy observed in flight or at rest grants no one. Always sealed:
/// a bound slip is non-delegable by construction (it cannot be narrowed and handed onward, which is the
/// point of binding it), so unlike [`mint_link`] there is no `delegable` option. Offline: needs the signing
/// `identity` but no network.
pub fn mint_bound_link(
    identity: &Identity,
    service: &Service,
    bound_to: nauthy::VerifyKey,
    lifetime: Duration,
) -> eyre::Result<String> {
    let cap = identity.mint_bound(service, bound_to, nauthy::expires_in(lifetime))?;
    Ok(cap.seal()?.link()?)
}

/// Mint a signet-bound `sheer:` link granting `service` to any device of the fleet `foreign_root`, valid
/// for `lifetime`.
///
/// The work-sim primitive: issue ONCE to a person's signet `foreign_root`, and every device that signet
/// vouches for may use it (see [`nauthy::Identity::mint_signet_slip`]). Inert alone: the far gate admits it
/// only when the presenter ALSO proves membership under `foreign_root`. Always sealed: a fleet-bound slip is
/// theft-resistant and non-delegable by construction (like [`mint_bound_link`]). Offline: needs the signing
/// `identity` but no network.
pub fn mint_signet_link(
    identity: &Identity,
    service: &Service,
    foreign_root: nauthy::VerifyKey,
    lifetime: Duration,
) -> eyre::Result<String> {
    let cap = identity.mint_signet_slip(service, foreign_root, nauthy::expires_in(lifetime))?;
    Ok(cap.seal()?.link()?)
}

/// Narrow a `sheer:` link offline: tighten its service and/or shorten its expiry, returning the tighter
/// link. Only ever adds constraints, so the result is never broader than the input. At least one of
/// `service` or `shorten` must be given.
pub fn narrow_link(
    link: &str,
    service: Option<&Service>,
    shorten: Option<Duration>,
) -> eyre::Result<String> {
    if service.is_none() && shorten.is_none() {
        eyre::bail!("narrow it by service and/or a shorter expiry");
    }
    let cap = Cap::parse(link)?;
    let shorten = shorten.map(nauthy::expires_in);
    let narrowed = cap.attenuate(service, shorten)?;
    Ok(narrowed.link()?)
}

/// Revoke a `sheer:` link into an open denylist, so the gate refuses it and everything attenuated from it.
///
/// The caller opens the denylist (from wherever it persists revocations) and passes it BY REF; the core
/// never reads a config path. It records EXACTLY the link's id and every narrower cap delegated from it,
/// NOT the wider grant it was attenuated from.
pub async fn revoke_into(denylist: &mut Denylist, link: &str) -> eyre::Result<()> {
    let cap = Cap::parse(link)?;
    denylist.revoke(&cap).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bifrost::{NoDiscovery, Node};
    use bifrost_mem::MemTransport;
    use nauthy::{Gate, Service};
    use tokio::io::AsyncReadExt as _;

    use super::{
        BoxRead, BoxWrite, Exposer, Handler, Posture, PublicRequest, PublicServices,
        PublicUnsafeRequest, RAW_STREAM_OPEN_PERMITS, RawSource, Registry, Semaphore,
        ServiceCatalog, ServiceEntry, Services, Target, TargetKind, resolve_single_service,
        serve_request,
    };
    use crate::open_policy::{Never, OptIn};
    use crate::raw_stream::RawStream;

    /// The catalog a gated node serves reports every service as `gated`, name-sorted, and survives a wire
    /// round trip byte for byte: the read `control.services` returns and the client decodes are the same value.
    #[test]
    fn a_gated_catalog_reports_gated_and_round_trips() {
        let services = services(&["c=127.0.0.1:80", "a=handler:", "b=handler:"]);
        let signet = nauthy::Identity::from_secret(&[7u8; 32]).expect("valid secret");
        let denylist = nauthy::Denylist::empty(std::env::temp_dir().join("tb-catalog-gated"));
        let gate = Gate::family(signet.node_id(), denylist);
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
        let services = services(&["a=127.0.0.1:80", "b=handler:"]);
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

    /// A do-nothing GATED handler (`type Public = Never`): a handler with no public use of its own, so an
    /// open gate over it must be refused at `Exposer::new`.
    struct GatedNoop;
    impl Handler for GatedNoop {
        type Public = Never;
        async fn serve(
            &self,
            _admitted: nauthy::Admitted,
            _writer: BoxWrite,
            _reader: BoxRead,
        ) -> eyre::Result<()> {
            Ok(())
        }
    }

    /// A do-nothing OPEN handler (`type Public = OptIn`): a legitimately-public responder, exposable under any
    /// gate.
    struct OpenNoop;
    impl Handler for OpenNoop {
        type Public = OptIn;
        async fn serve(
            &self,
            _admitted: nauthy::Admitted,
            _writer: BoxWrite,
            _reader: BoxRead,
        ) -> eyre::Result<()> {
            Ok(())
        }
    }

    /// A legitimately-public responder that also DECLARES itself an unmetered amplifier (`const AMPLIFIER =
    /// true`): the shape of `ping`/`speed`, so a manifest reads the caveat off the handler, not a name list.
    struct AmplifierNoop;
    impl Handler for AmplifierNoop {
        type Public = OptIn;
        const AMPLIFIER: bool = true;
        async fn serve(
            &self,
            _admitted: nauthy::Admitted,
            _writer: BoxWrite,
            _reader: BoxRead,
        ) -> eyre::Result<()> {
            Ok(())
        }
    }

    /// The readiness manifest reads posture off the PROVEN overlay, kind off the target, and the amplifier
    /// caveat off the handler's declaration, name-sorted: an opened amplifier reads `Open + amplifier`, a
    /// gated one `Gated + amplifier` (the caveat is the handler's, independent of posture), and a plain
    /// forward is neither open nor an amplifier. This is what feeds a caller's grouped serve banner.
    #[test]
    fn the_manifest_declares_posture_kind_and_amplifier() {
        let services = services(&["fast=amp:", "quiet=amp:", "web=127.0.0.1:80"]);
        let registry = Registry::new().with("amp", AmplifierNoop);
        let exposer = Exposer::new(
            services,
            registry,
            family_gate("manifest"),
            PublicUnsafeRequest::none(),
        )
        .expect("assembles")
        .with_public(PublicRequest::new(["fast".to_owned()]))
        .expect("`fast` is an OptIn amplifier, so it opens");

        let manifest = exposer.manifest();
        let names: Vec<&str> = manifest.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["fast", "quiet", "web"], "manifest is name-sorted");

        let fast = &manifest[0];
        assert_eq!(fast.posture, Posture::Open, "`fast` was opened per-service");
        assert_eq!(fast.kind, super::TargetKind::Handler);
        assert!(fast.amplifier, "the opened amplifier declares its caveat");

        let quiet = &manifest[1];
        assert_eq!(quiet.posture, Posture::Gated, "`quiet` stays gated");
        assert!(
            quiet.amplifier,
            "the caveat is the handler's, shown independent of posture"
        );

        let web = &manifest[2];
        assert_eq!(web.kind, super::TargetKind::Forward);
        assert!(!web.amplifier, "a plain forward is not an amplifier");
        assert_eq!(web.posture, Posture::Gated);
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
            Target::RawStream(RawStream::from_reader(reader)),
        );
        Services(map)
    }

    /// A single-service `Services` whose one target is a `stdin:+lossy`-shaped FAN-OUT source over `reader`, so
    /// the full multi-consumer served path (one shared ring, N cursors) runs without the process's real fd 0.
    fn lossy_service(name: &str, reader: BoxRead) -> Services {
        let mut map = HashMap::new();
        map.insert(
            name.to_owned(),
            Target::RawStream(RawStream::lossy_from_reader(reader)),
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

        let Services(two) = services(&["a=127.0.0.1:80", "b=handler:"]);
        // With two services, an unmatched request is left as-is (fails later with the hint, never guesses).
        assert_eq!(
            resolve_single_service(svc("default"), &two).as_str(),
            "default"
        );
    }

    #[test]
    fn a_bare_service_name_is_rejected_with_a_hint() {
        // `expose web` was silently mapped to the `default` service at addr "web"; now it fails at parse.
        let Err(err) = Services::parse(&["web".to_owned()]) else {
            panic!("bare `web` should be rejected, not treated as addr \"web\"");
        };
        assert!(
            err.to_string().contains("web=127.0.0.1:8080"),
            "the error should teach the grammar: {err}"
        );
    }

    #[test]
    fn real_targets_parse() {
        for entry in [
            "web=127.0.0.1:8080",
            "a=handler:",
            "b=handler:",
            "db=unix:/run/db.sock",
            "pipe=file:/tmp/beam",
            "named=fifo:/tmp/beam",
            "127.0.0.1:5000",
        ] {
            assert!(
                Services::parse(&[entry.to_owned()]).is_ok(),
                "{entry} should parse"
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
            let target = parsed.values().next().expect("one service parsed");
            assert!(
                matches!(target, super::Target::RawStream(_)),
                "{entry} must resolve to Target::RawStream, got {target:?}"
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
    fn lossy_is_accepted_only_on_stdin_and_fifo_and_rejected_elsewhere() {
        // `+lossy` opts a live single-writer source into fan-out; it is legal ONLY on `stdin:`/`fifo:`.
        for entry in ["cam=stdin:+lossy", "cam=fifo:/tmp/cam+lossy"] {
            let Services(parsed) = services(&[entry]);
            let target = parsed.values().next().expect("one service parsed");
            assert!(
                matches!(target, Target::RawStream(_)),
                "{entry} must resolve to a raw-stream fan-out target, got {target:?}"
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
            super::Exposer::new(
                lossy,
                super::Registry::new(),
                Gate::Open,
                PublicUnsafeRequest::none()
            )
            .is_err(),
            "an open gate over a `+lossy` raw-stream source must be refused"
        );
    }

    #[test]
    fn a_dotted_scheme_resolves_to_a_handler_for_a_method_on_an_interface() {
        // A method on an interface (`control.status`, `control.restart`) is one dotted handler scheme: `.`
        // is in the `Service` alphabet and the bare-scheme arm admits it, so `serve status=control.status:`
        // names one handler the registry holds, not a `host.port`-shaped forward.
        for entry in ["status=control.status:", "restart=control.restart:"] {
            let Services(parsed) = services(&[entry]);
            let target = parsed.values().next().expect("one service parsed");
            let super::Target::Handler(scheme) = target else {
                panic!("{entry} must resolve to Target::Handler, got {target:?}");
            };
            assert!(
                scheme.contains('.'),
                "the dotted scheme is preserved verbatim as the registry key, got {scheme:?}"
            );
        }
    }

    #[test]
    fn an_exposer_refuses_an_open_gate_over_a_gated_only_handler() {
        // A gated-only handler (`type Public = Never`): it has no legitimate public use, so an open gate over
        // it would serve it to anyone. `Exposer::new` must reject that pairing, wherever the caller assembles
        // it.
        let gated = services(&["a=handler:"]);
        let registry = super::Registry::new().with("handler", GatedNoop);
        assert!(
            super::Exposer::new(gated, registry, Gate::Open, PublicUnsafeRequest::none()).is_err(),
            "an open gate over a gated-only handler must be refused"
        );
        // The same handler behind a real gate is fine; only the open-gate pairing is refused. A family gate
        // needs a signet and denylist, so prove the inverse with a plain forward (an empty registry
        // suffices, since a raw forward needs no handler) under the open gate.
        let web = services(&["web=127.0.0.1:80"]);
        assert!(
            super::Exposer::new(
                web,
                super::Registry::new(),
                Gate::Open,
                PublicUnsafeRequest::none()
            )
            .is_ok(),
            "an open gate over a plain forward is allowed"
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
            super::Exposer::new(
                secret,
                super::Registry::new(),
                Gate::Open,
                PublicUnsafeRequest::none()
            )
            .is_err(),
            "an open gate over a file:/fifo: source with no unsafe opt-in must be refused"
        );
        // A raw forward the operator deliberately stood up (host:port) stays open-able; only the no-auth
        // raw-stream source is refused under the open gate.
        let web = services(&["web=127.0.0.1:80"]);
        assert!(
            super::Exposer::new(
                web,
                super::Registry::new(),
                Gate::Open,
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
        let exposer = super::Exposer::new(
            services,
            super::Registry::new(),
            Gate::Open,
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
    fn public_unsafe_naming_a_handler_or_forward_is_redirected() {
        // The disjoint-token partition: the unsafe overlay is ONLY for raw streams. A handler or a forward
        // named in it is a teaching redirect to the public overlay (STRING B, CLI-Architect round-3), never silently
        // opened.
        let handler = services(&["ping=ping:"]);
        let registry = super::Registry::new().with("ping", OpenNoop);
        let Err(via_handler) = super::Exposer::new(
            handler,
            registry,
            family_gate("unsafe-handler"),
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
        let Err(via_forward) = super::Exposer::new(
            forward,
            super::Registry::new(),
            family_gate("unsafe-forward"),
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
        let Err(error) = super::Exposer::new(
            services,
            super::Registry::new(),
            family_gate("unsafe-unserved"),
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
            super::Exposer::new(
                services,
                super::Registry::new(),
                Gate::Open,
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
        let target = parsed.values().next().expect("one service parsed");
        assert!(
            matches!(target, Target::RawStream(_)),
            "`stdin:` must resolve to Target::RawStream, got {target:?}"
        );
    }

    #[test]
    fn an_exposer_refuses_a_public_stdin() {
        // `stdin:` has no auth of its own: under an open gate it would pipe the producer's bytes to anyone, so
        // a public gate over `stdin:` would exfil them. Refused at the same door as a public shell or a public file:.
        let piped = services(&["cam=stdin:"]);
        assert!(
            super::Exposer::new(
                piped,
                super::Registry::new(),
                Gate::Open,
                PublicUnsafeRequest::none()
            )
            .is_err(),
            "an open gate over a stdin: source with no unsafe opt-in must be refused"
        );
    }

    /// The full served path: an exposer over a `stdin:`-shaped source, a connector reaching it over the
    /// in-process transport, and the peer receiving the source's EXACT bytes. Drives the same take-once +
    /// `Target::RawStream` splice the binary uses, with an injected reader in place of the real fd 0. A second
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
                    registry: std::sync::Arc::new(Registry::new()),
                    gate: Gate::Open,
                    public: PublicServices::default(),
                    public_unsafe: PublicServices::default(),
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
                let Err(err) = ServiceStream::open(&session2, "cam").await else {
                    panic!("the second reader must be refused, not a racing second read");
                };
                assert!(
                    err.contains("single-consumer source, already in use"),
                    "the refusal must name the single-consumer contract: {err}"
                );
            })
            .await;
    }

    /// The cancel seam (delib-18/S18): `Exposer::run` returns gracefully when its cancel token fires, so any
    /// holder of a CLONE of this token can stop the node. Here the token is cancelled from OUTSIDE the run
    /// (the shape any such holder uses); the run must finish with `Ok(())` rather than accept forever. Uses
    /// the mem transport so no real socket is bound.
    #[tokio::test]
    async fn run_returns_gracefully_when_its_cancel_token_fires() {
        let node = Node::new(MemTransport::bind(), NoDiscovery);
        let exposer = Exposer {
            services: services(&["web=127.0.0.1:80"]),
            registry: std::sync::Arc::new(Registry::new()),
            gate: Gate::Open,
            public: PublicServices::default(),
            public_unsafe: PublicServices::default(),
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
    /// serve path the binary uses, proving one source fans out to many independent cursors.
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
                    registry: std::sync::Arc::new(Registry::new()),
                    gate: Gate::Open,
                    public: PublicServices::default(),
                    public_unsafe: PublicServices::default(),
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
            registry: std::sync::Arc::new(Registry::new()),
            raw_stream_opens: permits,
        })
    }

    /// Drive one `serve_request` for `service` against the shared `serving` context, and return the client's
    /// stream end plus the serving future. The serving future is returned UN-awaited so a caller can let it
    /// park (a never-written FIFO) or poll it for the refusal, and the returned reader carries the host's
    /// `Response`. Uses `tokio::io::duplex` so no transport is needed.
    fn drive_open(
        service: &str,
        serving: std::sync::Arc<super::Serving>,
    ) -> (
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        impl core::future::Future<Output = eyre::Result<()>>,
    ) {
        let (client, server) = tokio::io::duplex(1024);
        let (server_read, server_write) = tokio::io::split(server);
        let (client_read, mut client_write) = tokio::io::split(client);
        let service = service.to_owned();
        // The peer id is only for the host's log line here; any valid NodeId does.
        let peer = bifrost::NodeId::from_ed25519_secret(&[9u8; 32]);
        let serve = async move {
            crate::protocol::Request {
                service: service.clone(),
                capability: None,
                membership: None,
            }
            .write(&mut client_write)
            .await
            .expect("write request");
            // Close the client's write half now the request is sent: the served splice's downstream copy
            // (peer -> `io::sink()`) ends on this EOF, so a served stream can actually finish (otherwise the
            // splice's `try_join!` would wait forever for the client to hang up).
            drop(client_write);
            serve_request(peer, server_write, server_read, serving).await
        };
        (client_read, serve)
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
        // parking another thread. Each returns a `Response::Error` a client can read at once.
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
                crate::protocol::Response::Error(message) => assert!(
                    message.contains("too many raw streams"),
                    "the over-cap refusal must name the cap: {message}"
                ),
                crate::protocol::Response::Ok => {
                    panic!("an over-cap open must be refused, not served")
                }
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
            crate::protocol::Response::Error(message) => {
                panic!("a single open under the cap must succeed, got: {message}")
            }
        }
        let mut got = Vec::new();
        client_read.read_to_end(&mut got).await.expect("read bytes");
        assert_eq!(got, body, "the single open serves the file's exact bytes");

        let _ = std::fs::remove_file(&path);
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
        /// Open a stream, request `service`, and return it on `Ok` or the host's reason on refusal.
        async fn open<S>(session: &S, service: &str) -> Result<Self, String>
        where
            S: bifrost::Session<Write = W, Read = R>,
        {
            Self::open_with(session, service, None).await
        }

        /// Like [`open`](Self::open) but presents `capability`, so a test can dial as a stranger (`None`) or
        /// as a token-holder (a revoked slip). Returns the host's refusal string verbatim on `Error`, which
        /// is what lets a test assert two dialers got BYTE-IDENTICAL refusals.
        async fn open_with<S>(
            session: &S,
            service: &str,
            capability: Option<String>,
        ) -> Result<Self, String>
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
        ) -> Result<Self, String>
        where
            S: bifrost::Session<Write = W, Read = R>,
        {
            let (mut writer, mut reader) = session.open_bi().await.map_err(|e| e.to_string())?;
            crate::protocol::Request {
                service: service.to_owned(),
                capability,
                membership,
            }
            .write(&mut writer)
            .await
            .map_err(|e| e.to_string())?;
            match crate::protocol::Response::read(&mut reader)
                .await
                .map_err(|e| e.to_string())?
            {
                crate::protocol::Response::Ok => Ok(Self { writer, reader }),
                crate::protocol::Response::Error(message) => Err(message),
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
    fn an_exposer_refuses_a_handler_with_no_registration() {
        // A named service with no handler in the registry is a config error caught at construction, not a
        // dial-time mystery reset. (Here a `handler:` scheme is exposed but nothing registered it.)
        let unregistered = services(&["a=handler:"]);
        assert!(
            super::Exposer::new(
                unregistered,
                super::Registry::new(),
                Gate::Open,
                PublicUnsafeRequest::none()
            )
            .is_err(),
            "exposing a handler scheme with no registered handler must be refused at construction"
        );
    }

    #[test]
    fn extend_is_add_only_and_refuses_a_collision() {
        // Adding a NEW scheme (an embedder injecting its own scheme beside another) is allowed.
        let base = super::Registry::new().with("a", OpenNoop);
        let added = base.extend(super::Registry::new().with("b", OpenNoop));
        assert!(added.is_ok(), "injecting a new scheme must be allowed");
        // Re-injecting a scheme already registered is refused at merge intent, so a second `extend` can
        // never shadow (and silently downgrade the gate of) a handler the caller already registered.
        let base = super::Registry::new().with("c", GatedNoop);
        let shadowed = base.extend(super::Registry::new().with("c", OpenNoop));
        assert!(
            shadowed.is_err(),
            "re-injecting an already-registered scheme must be refused so it cannot shadow a handler"
        );
    }

    /// SECURITY (deliberation 18, the discovery oracle): a dialer the gate does NOT admit must get ONE
    /// indistinguishable refusal on the wire. No reason separates a stranger (no token) from a revoked
    /// holder from a not-granting token, and no response enumerates or confirms a service. This test dials a
    /// Family-gated node four ways -- a stranger, a revoked-slip holder, an unknown-service probe, and a
    /// slip-for-the-wrong-service holder -- and asserts every refusal is BYTE-IDENTICAL, so the wire is not a
    /// revocation oracle and not a capability-enumeration oracle. The gate is the discovery boundary:
    /// existence, shape, and verdict are revealed only AFTER admission.
    #[tokio::test]
    async fn an_unadmitted_dialer_gets_one_uniform_refusal_no_reason_no_menu() {
        use nauthy::{Denylist, Identity};

        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                // The signet that roots the family, and a real exposed service (`ssh`) plus a second name
                // (`web`) so the node has a genuine menu that MUST NOT leak. The bodies are irrelevant: every
                // dial here is refused at the gate or at the unknown-service arm, never served.
                let signet = Identity::from_secret(&[7u8; 32]).expect("valid secret");
                let hour = nauthy::expires_in(core::time::Duration::from_secs(3600));

                let mut map = HashMap::new();
                map.insert(
                    "ssh".to_owned(),
                    Target::RawStream(RawStream::from_reader(Box::new(&b"secret"[..]))),
                );
                map.insert(
                    "web".to_owned(),
                    Target::RawStream(RawStream::from_reader(Box::new(&b"secret"[..]))),
                );
                let services = Services(map);

                // A slip the family once honored for `ssh`, now REVOKED: the revoked-but-persistent holder.
                let revoked_slip = signet.mint(&svc("ssh"), hour).expect("mint ssh slip");
                let path = std::env::temp_dir()
                    .join(format!("tb-uniform-refusal-{}", std::process::id()));
                let _ = std::fs::remove_file(&path);
                let mut denylist = Denylist::load(path.clone()).await.expect("load denylist");
                denylist.revoke(&revoked_slip).await.expect("revoke the slip");

                let exposer = Exposer {
                    services,
                    registry: std::sync::Arc::new(Registry::new()),
                    gate: Gate::family(signet.node_id(), denylist),
                    public: PublicServices::default(),
                    public_unsafe: PublicServices::default(),
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
                            Err(message) => message,
                        }
                    }
                };

                // (a) a STRANGER: no token at all -> gate refuses (Missing) -> uniform "refused".
                let stranger = dial("ssh", None).await;
                // (b) a REVOKED holder: presents the now-denylisted `ssh` slip -> gate refuses (Revoked).
                let revoked = dial("ssh", Some(revoked_slip.link().expect("link"))).await;
                // (c) an UNKNOWN-SERVICE probe by a stranger: gate refuses the unknown name -> uniform.
                let unknown = dial("admin", None).await;
                // (d) a WRONG-SERVICE slip: a valid, UNREVOKED slip for `web` presented for `ssh` -> gate
                //     refuses (NotGranted). Distinct internal reason, must still be the same wire string.
                let wrong_slip = signet.mint(&svc("web"), hour).expect("mint web slip");
                let not_granted = dial("ssh", Some(wrong_slip.link().expect("link"))).await;

                // The whole point: all four are BYTE-IDENTICAL. A walker cannot tell revoked from stranger
                // from not-granted, and cannot confirm `ssh` exists or that `admin` does not.
                assert_eq!(
                    stranger, revoked,
                    "a revoked holder and a stranger must get byte-identical refusals (no revocation oracle)"
                );
                assert_eq!(
                    stranger, unknown,
                    "an unknown-service probe must be indistinguishable from a refused known service"
                );
                assert_eq!(
                    stranger, not_granted,
                    "a not-granting slip must get the same refusal as a stranger (no capability oracle)"
                );

                // And the refusal reveals NOTHING: no reason word, no service name, no menu.
                for leaked in [
                    "capability",
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
                        !stranger.contains(leaked),
                        "the uniform refusal must not leak {leaked:?}: {stranger:?}"
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
                    Target::RawStream(RawStream::from_reader(Box::new(&b"x"[..]))),
                );
                map.insert(
                    "mic".to_owned(),
                    Target::RawStream(RawStream::from_reader(Box::new(&b"x"[..]))),
                );
                let exposer = Exposer {
                    services: Services(map),
                    registry: std::sync::Arc::new(Registry::new()),
                    gate: Gate::Open,
                    public: PublicServices::default(),
                    public_unsafe: PublicServices::default(),
                };

                let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
                let exposer_id = exposer_node.node_id();
                let consumer = Node::new(MemTransport::bind(), NoDiscovery);
                tokio::task::spawn_local(async move {
                    exposer.run(&exposer_node, super::CancellationToken::new()).await.expect("exposer runs");
                });

                let session = consumer.connect(exposer_id).await.expect("connect");
                let Err(message) = ServiceStream::open(&session, "nope").await else {
                    panic!("an unknown service must be refused, not served");
                };
                for leaked in ["cam", "mic", "exposes", "unknown"] {
                    assert!(
                        !message.contains(leaked),
                        "an admitted unknown-service probe must not learn the menu; leaked {leaked:?}: {message:?}"
                    );
                }
            })
            .await;
    }

    /// A family gate + a `speed` service; a helper to build the two postures the per-service tests need.
    fn family_gate(tag: &str) -> Gate {
        let signet = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
        Gate::family(
            signet.node_id(),
            nauthy::Denylist::empty(std::env::temp_dir().join(format!("tb-per-service-{tag}"))),
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
        let admitted = super::admit(
            &gate,
            &public,
            &public_unsafe,
            stranger,
            None,
            None,
            &svc("speed"),
        )
        .expect("an opened service admits a stranger");
        assert!(
            !admitted.is_member(),
            "an opened service admits as a Slip, never a whole-node member"
        );

        // HIT (unsafe overlay): a stranger reaching the unsafe-open raw stream is admitted the same way, also
        // as a Slip (§9 `an_unsafe_raw_stream_member_admits_a_stranger`).
        let unsafe_admitted = super::admit(
            &gate,
            &public,
            &public_unsafe,
            stranger,
            None,
            None,
            &svc("logs"),
        )
        .expect("an unsafe-open raw stream admits a stranger");
        assert!(
            !unsafe_admitted.is_member(),
            "an unsafe-open raw stream admits as a Slip, never a whole-node member"
        );

        // MISS (gated-present): `control.stop` is served but NOT open on either overlay, so a stranger takes
        // the family path and is refused. MISS (absent): a name the node does not serve takes the SAME path.
        assert!(
            super::admit(
                &gate,
                &public,
                &public_unsafe,
                stranger,
                None,
                None,
                &svc("control.stop")
            )
            .is_err(),
            "a served-but-gated service is refused for a stranger (family path)"
        );
        assert!(
            super::admit(
                &gate,
                &public,
                &public_unsafe,
                stranger,
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
                nauthy::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("mint member badge")
            .link()
            .expect("link");
        let admitted = super::admit(
            &gate,
            &public,
            &super::PublicServices::default(),
            peer,
            Some(badge.as_str()),
            Some("not a sheer link"),
            &svc("web"),
        )
        .expect("a member badge admits on slot 1 alone; garbage in slot 2 is ignored");
        assert!(
            admitted.is_member(),
            "a whole-node member badge admits as Member regardless of slot 2"
        );
    }

    /// The flagship, at the tunnel level (delib-39): a family-gated node opens ONE service per-service via
    /// `with_public`; a stranger with no token is ADMITTED to that service but still REFUSED, uniformly, for
    /// a gated service and for the always-on `control.stop`, which can never be opened. Proves the anti-oracle
    /// survives the overlay: the gated refusals are byte-identical.
    #[tokio::test]
    async fn a_stranger_is_admitted_to_an_opened_service_and_uniformly_refused_for_the_rest() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                // `open` is an OptIn responder (openable); `locked` is a Never handler (never openable);
                // `control.stop` stands in for the always-on gated control surface (also a Never handler).
                let services = services(&["open=open:", "locked=locked:", "control.stop=locked:"]);
                let registry = Registry::new()
                    .with("open", OpenNoop)
                    .with("locked", GatedNoop);
                let exposer = Exposer::new(
                    services,
                    registry,
                    family_gate("flagship"),
                    PublicUnsafeRequest::none(),
                )
                .expect("assembles")
                .with_public(PublicRequest::new(["open".to_owned()]))
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

                // The same stranger is REFUSED for a gated service AND for control.stop, byte-identically:
                // opening one service leaks nothing about the gated ones.
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
                    "a gated service and the control surface refuse byte-identically (no oracle)"
                );
                assert_eq!(
                    gated,
                    super::UNIFORM_REFUSAL,
                    "the refusal is the uniform token"
                );
            })
            .await;
    }

    /// `with_public` is the wall (BLOCKER-2): it refuses a `Never` handler named public with a teaching error
    /// (leading with the fix, never leaking the marker names), refuses a name the node does not serve, and
    /// REDIRECTS a raw stream named in the SAFE overlay toward the unsafe overlay (a distinct message from the
    /// `Never`-handler hard refusal). The three walls are disjoint.
    #[test]
    fn with_public_refuses_a_never_handler_and_an_unexposed_name() {
        let services = services(&["ssh=locked:", "speed=open:", "logs=file:/etc/hosts"]);
        let registry = || {
            Registry::new()
                .with("locked", GatedNoop)
                .with("open", OpenNoop)
        };

        // A Never handler named public is refused: the teaching error names the SERVICE and the fix, never a
        // marker type. (A stranger never sees it; it is a build-time bail to the operator's own terminal.)
        let assembled = Exposer::new(
            services.clone(),
            registry(),
            family_gate("never"),
            PublicUnsafeRequest::none(),
        )
        .expect("assembles");
        let Err(never) = assembled.with_public(PublicRequest::new(["ssh".to_owned()])) else {
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
        // from the `Never`-handler refusal (§9 `with_public_naming_a_raw_stream_redirects_to_public_unsafe`).
        let assembled = Exposer::new(
            services.clone(),
            registry(),
            family_gate("rawredirect"),
            PublicUnsafeRequest::none(),
        )
        .expect("assembles");
        let Err(raw) = assembled.with_public(PublicRequest::new(["logs".to_owned()])) else {
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
        let assembled = Exposer::new(
            services,
            registry(),
            family_gate("unknown"),
            PublicUnsafeRequest::none(),
        )
        .expect("assembles");
        let Err(unknown) = assembled.with_public(PublicRequest::new(["nope".to_owned()])) else {
            panic!("an unexposed name cannot be opened");
        };
        assert!(
            unknown.to_string().contains("no service named"),
            "an unexposed public name is refused with the served list: {unknown}"
        );
    }

    /// `open_safe` is TOTAL over `Target` (BLOCKER-2): a forward is openable, a raw stream never, a Never
    /// handler never, an OptIn handler yes, and an unregistered scheme fails closed.
    #[test]
    fn open_safe_is_total_over_target() {
        let registry = Registry::new()
            .with("open", OpenNoop)
            .with("locked", GatedNoop);
        let forward = Target::Forward("127.0.0.1:80".to_owned());
        let raw = Target::RawStream(RawStream::from_reader(Box::new(&b"x"[..])));
        let opt_in = Target::Handler("open".to_owned());
        let never = Target::Handler("locked".to_owned());
        let missing = Target::Handler("unregistered".to_owned());

        assert!(
            forward.open_safe(&registry),
            "a deliberately stood-up forward is openable"
        );
        assert!(
            !raw.open_safe(&registry),
            "a raw stream has no auth of its own"
        );
        assert!(opt_in.open_safe(&registry), "an OptIn handler is openable");
        assert!(
            !never.open_safe(&registry),
            "a Never handler is never openable"
        );
        assert!(
            !missing.open_safe(&registry),
            "an unregistered scheme fails closed"
        );
    }

    /// B1 (BLOCKER-3): a synthetic per-service scheme carries a byte the handler-scheme grammar rejects
    /// (`_`), so an operator entry `x=fetch_0:` can NEVER resolve onto a synthetic instance -- it is a parse
    /// error. The same mapping is reachable ONLY through `with_handler`, which constructs it directly.
    #[test]
    fn a_synthetic_underscore_scheme_is_unspellable_but_constructible_directly() {
        // Spelled as an operator entry, `fetch_0:` is not a handler scheme (the grammar rejects `_`), so it
        // falls through to the forward grammar and is refused. The pivot `x=fetch_0:` named public cannot open.
        assert!(
            Services::parse(&["x=fetch_0:".to_owned()]).is_err(),
            "`fetch_0:` must not be a spellable handler scheme"
        );
        // Built directly, the same served name maps to the synthetic handler, verbatim as the registry key.
        let Services(map) = Services::parse(&["ping=ping:".to_owned()])
            .expect("base parses")
            .with_handler("pub", "fetch_0")
            .expect("a direct synthetic handler is constructible");
        let Some(Target::Handler(scheme)) = map.get("pub") else {
            panic!("`pub` must map to the synthetic handler target");
        };
        assert_eq!(
            scheme, "fetch_0",
            "the synthetic scheme is the verbatim registry key"
        );
    }

    /// The catalog reports each service's PER-SERVICE posture: a service in the public request reads `open`,
    /// the rest `gated`, under a family base gate. This is what the `control.services` read serves.
    #[test]
    fn a_catalog_reports_public_services_open_and_the_rest_gated() {
        let services = services(&["speed=open:", "ssh=locked:", "web=127.0.0.1:80"]);
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

    /// B3: a dialer-side render recognizes the uniform refusal token and phrases it descriptively (not the
    /// bare word, which a `refused (…)` wrapper would double), while a more specific host reason is kept.
    #[test]
    fn a_dialer_refusal_reason_is_descriptive_for_the_uniform_token() {
        let uniform = super::refusal_reason(super::UNIFORM_REFUSAL);
        assert_ne!(
            uniform,
            super::UNIFORM_REFUSAL,
            "the bare token is not echoed back"
        );
        assert!(
            uniform.contains("not admitted"),
            "the uniform refusal renders as a reason a person can act on: {uniform:?}"
        );
        assert_eq!(
            super::refusal_reason("this service does not serve that method"),
            "this service does not serve that method",
            "a specific host reason is preserved verbatim"
        );
    }
}
