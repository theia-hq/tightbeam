//! The exposer: a proven route table armed behind its gate, accepting overlay sessions and handing each
//! inbound stream to the service it names.
//!
//! [`Exposer`] is built only by [`Router::expose`](super::router::Router::expose), which runs every door
//! interlock; [`run`](Exposer::run) then owns the node's accept loop, its session and stream limits, and
//! the one teardown authority a [`CancellationToken`] clone can request.

use std::sync::{Arc, PoisonError};

use bifrost::{Discovery, Node, NodeId, Security, SecurityProfile, Session, Transport};
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::Gate;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
// Re-exported below: it is part of `Exposer::run`'s contract (the node's teardown authority), so a caller
// reaches it through `tightbeam::tunnel` alongside `Exposer` rather than depending on tokio-util directly.
pub use tokio_util::sync::CancellationToken;

use super::admit::serve_request;
use super::catalog::Posture;
use super::cut::{self, Cuts, LiveCuts};
use super::router::{
    ManifestEntry, PublicRequest, PublicServices, PublicUnsafeRequest, Services, Target,
};
use crate::enabled::{AllEnabled, EnabledServices};
use crate::security::{peer_proven, proof_label};

/// The maximum number of peer sessions served concurrently. Past this, `accept` stops being polled so new
/// connections queue at the transport (backpressure), bounding the memory a flood of peers can pin.
pub(super) const MAX_SESSIONS: usize = 256;

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
pub(super) const RAW_STREAM_OPEN_PERMITS: usize = 16;

/// The maximum number of concurrent PUBLIC sessions: a session that has reached any opened
/// service holds one permit until it closes. This bounds what ADMITTED public dials can occupy: at most 32
/// of [`MAX_SESSIONS`] sessions and [`PUBLIC_STREAM_PERMITS`] streams, so the public path cannot consume
/// the whole table by itself. It reserves nothing: a session that never reaches an opened service (a gated
/// or unknown request, or none) takes no permit, so a stranger can still hold the shared session table up
/// to [`MAX_SESSIONS`] and make member dials queue at accept. That residual is accepted rather than
/// overlooked: the shared table is bounded on its own by [`MAX_SESSIONS`], and this pool's claim is only
/// over ADMITTED public work. The cap bounds occupation, not fairness: the slots are
/// activity-independent, so a dialer that keeps its sessions open can hold all 32 and wedge new public
/// dialers until it closes them.
const PUBLIC_SESSION_PERMITS: usize = 32;

/// The maximum number of concurrent public streams, taken at the public-admit seam. Single
/// digits because one public stream is already a stranger's whole session of work; 4 bounds the aggregate
/// public drain to four in-flight streams. Over the cap REFUSES (never queues: queuing would park one
/// stranger's stream behind another's), before any `Response::Ok` and with the same answer a gate miss
/// gets, so a full pool reads exactly like a service that is not there.
///
/// What four slots do NOT bound, written here because this is the whole of what the public path can be
/// made to do:
///
/// - The slots are node-wide and service-blind. One public broadcast with four viewers holds all of them
///   and every other public service refuses until one ends: the room for honest dials is room across
///   time, never across services.
/// - A slot is held for its stream's whole life, busy or idle. A handler stream silent both ways is
///   dropped by the first-traffic deadline, but a raw stream has none, so four idle raw streams on any
///   public service hold the pool for as long as they stay connected.
/// - A raw stream's slot returns when its splice ends, and the splice ends when a write to the viewer
///   fails or a read from it errors (a reset or a lost connection), so a viewer that simply goes away is
///   noticed at once. A viewer that closed its own send half BEFORE it left reads as a clean EOF, which
///   the splice waits past: that one is noticed only at the next write, so on an idle source it keeps
///   its slot until the source speaks again or ends. (The in-process tests reach only the second case;
///   their pipes report a vanished peer as EOF, never as the error a real transport returns.)
/// - Raw streams served through the unsafe overlay and every public `+lossy` viewer draw these same four
///   slots.
///   [`RAW_STREAM_OPEN_PERMITS`] is no second bound on them: it covers an open in flight, never a splice.
/// - The session slots beside this pool are activity-independent (see [`PUBLIC_SESSION_PERMITS`]).
///
/// Not per peer (a stranger mints identities for free, so a per-peer cap bounds nobody) and not a
/// lifetime (that would cut every long-lived public handler to catch the idle ones).
pub(super) const PUBLIC_STREAM_PERMITS: usize = 4;

/// An exposer: the proven services to publish and the gate that decides who may reach them. Accepts overlay
/// sessions and forwards each inbound stream to its service.
///
/// Constructed only by [`Router::expose`](super::Router::expose), which runs every proof and interlock at
/// one door; the only builder left here is [`with_enabled`](Exposer::with_enabled), which cannot raise
/// posture.
pub struct Exposer {
    services: Services,
    gate: Gate,
    /// The safe public overlay, proven at [`Router::expose`](super::Router::expose): legitimate services
    /// (a handler or a built-in) opened to any reaching peer.
    public: PublicServices,
    /// The UNSAFE raw-stream overlay, proven at [`Router::expose`](super::Router::expose): raw byte
    /// sources (`file:`/`fifo:`/`stdin:`) with no auth of their own, knowingly served to any reaching
    /// peer. Kept DISJOINT from
    /// `public` so the two proof walls write disjoint state (no clobber), the toggle interlock can read
    /// `!public_unsafe.is_empty()` trivially, and the on-thesis reading stays legible: `public` =
    /// "opened a legitimate service", `public_unsafe` = "knowingly serves raw bytes with no auth".
    public_unsafe: PublicServices,
    /// The live enable/disable oracle the per-stream gate consults: a stream for a name this
    /// reports disabled is refused at admission, exactly like a revoked capability. Defaults to
    /// [`AllEnabled`] (nothing disabled), so a caller that never toggles pays nothing; a caller that does
    /// wires a file-backed [`FileDisabledList`](crate::enabled::FileDisabledList) with
    /// [`with_enabled`](Exposer::with_enabled). Boxed like the gate's own [`Revocations`](nauthy::Revocations)
    /// store, so a consumer may plug any oracle over its own state.
    enabled: Box<dyn EnabledServices + Send + Sync>,
    /// The live cut oracle, or `None` until a caller wires one with
    /// [`with_live_cuts`](Exposer::with_live_cuts). `None` arms nothing: no sweep timer, no subscription, and
    /// every session ends exactly as it always has.
    cuts: Option<Box<dyn LiveCuts>>,
}

impl Exposer {
    /// Prove an assembled router into the runnable exposer, enforcing the door interlocks:
    /// a handler with no auth of its own (a keyless shell) may not sit behind a node-wide [`Gate::Open`]
    /// base; a raw-stream source under an open base is refused UNLESS the operator knowingly opted it into
    /// the unsafe set (proven here into the disjoint unsafe overlay); a route declared [`Access::Member`](super::router::Access::Member)
    /// may not pair with an open base or with that unsafe overlay, both of which admit only open witnesses
    /// and would make the floor a route no dialer can reach (and, opened, a posture lie); and the safe
    /// public overlay proves every requested name exposed and open-safe.
    ///
    /// The two raw-stream interlocks stay DISJOINT: the keyless-handler refusal reads a
    /// compile-time marker (`type Exposure`), while the raw-stream-unsafe refusal is a RUNTIME opt-in guard
    /// (the danger depends on a runtime path value no type can see), so the two are never folded onto one
    /// mechanism.
    pub(super) fn prove(
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
        // unsafe overlay. A local forward (`tcp:`/`unix:`) is not refused: it is a service the operator
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
        // Interlock 3 (member floor): a route declared member-only is reachable only through a
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
        // Interlock 4 (toggle mutual-exclusion): a DESIGN-LOCK with no operand today. A live-toggle
        // allowlist (the set of services a peer may re-enable at runtime) is UNBUILT, so there is no second
        // set to refuse; inventing a toggle field now purely to refuse it would be machinery for a case that
        // cannot occur yet. When that allowlist lands it enters THIS proof beside `public_unsafe` and adds
        // ONE bail here:
        //   `if !proven_unsafe.is_empty() && !toggleable.is_empty() { eyre::bail!(...) }`
        // refusing their co-presence by construction, because a remotely flippable toggle over an open raw
        // byte source is a re-armable exfil: the operator closes the hole and a stranger reopens it. Do NOT
        // add a toggle field before that set exists.
        let proven_public = services.prove_public(public)?;
        Ok(Self {
            services,
            gate,
            public: proven_public,
            public_unsafe: proven_unsafe,
            // Nothing is disabled until a caller wires a real oracle. Live enable/disable is the deliberate
            // `with_enabled` opt-in below.
            enabled: Box::new(AllEnabled),
            cuts: None,
        })
    }

    /// Wire the live enable/disable oracle the per-stream gate consults: a stream requesting a
    /// service this oracle reports disabled is refused at admission, indistinguishably from a gated or
    /// absent service, and a re-enable restores it LIVE with no restart (the oracle re-reads its backing state
    /// when it changes). A separate builder, NOT an assembly parameter, because disabling is orthogonal to
    /// the door interlocks [`Router::expose`](super::Router::expose) enforces and every existing
    /// caller/test builds a fully-gated exposer without it.
    ///
    /// The oracle never OPENS a service (it can only refuse a declared one), so it grants no authority and
    /// cannot raise posture: a disabled service that is re-enabled returns to its ALREADY-declared baseline,
    /// never more exposed than the launch set. That is why it needs no interlock against the unsafe overlay.
    pub fn with_enabled(mut self, enabled: impl EnabledServices + Send + Sync + 'static) -> Self {
        self.enabled = Box::new(enabled);
        self
    }

    /// Wire the live cut: every live session is re-checked against `cuts` once per sweep, and one admitted
    /// on a capability since revoked, or rooted at a key since disabled, ends itself. Without it a recall
    /// refuses only the next stream, and a session already open runs on until its peer leaves.
    ///
    /// Pass the same instance the gate was resolved over (an `Arc` of it serves both), so admission and
    /// the cut read one store and cannot disagree. Nothing here checks that: an oracle over a different
    /// store cuts on that store's answers, not the gate's. Like [`with_enabled`](Exposer::with_enabled) it can only
    /// take service away, never grant it, so it needs no interlock.
    pub fn with_live_cuts(mut self, cuts: impl LiveCuts + 'static) -> Self {
        self.cuts = Some(Box::new(cuts));
        self
    }

    /// The served services as a caller's readiness banner needs them: each name with the [`Posture`] a dialer
    /// faces, its [`TargetKind`](super::TargetKind), and its handler-declared
    /// [`Metering`](super::Metering), name-sorted. A pure read over the exposer's OWN resolved state (the
    /// proven public overlay decides posture, the target decides kind, the
    /// bound handler declares its metering), so an embedder draws its banner from declared facts rather than
    /// by re-parsing an address string. DISTINCT from [`Router::catalog`](super::Router::catalog): that
    /// is the on-wire snapshot the member-only `control.services` read serves; this is the local banner
    /// view (kind + metering never cross
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
            cuts,
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
            cuts: cuts.map(Cuts::new),
        });
        // The one sweep timer, only when a cut is wired: an exposer without one arms nothing.
        let mut sweep = serving.cuts.as_ref().map(|_| Cuts::interval());
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
                // Wake every live session to re-check itself. The run loop decides nothing here; each
                // session asks about its own chains and ends itself, so this arm is one O(1) signal.
                () = cut::tick(&mut sweep) => {
                    if let Some(cuts) = &serving.cuts {
                        cuts.sweep();
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
pub(super) struct Serving {
    pub(super) gate: Gate,
    pub(super) public: PublicServices,
    pub(super) public_unsafe: PublicServices,
    pub(super) services: Services,
    pub(super) raw_stream_opens: Semaphore,
    /// The public-path capacity: taken only at the public-admit seam, so a gated route never
    /// consults it and non-public traffic is untouched.
    pub(super) public_pool: PublicPool,
    /// The live enable/disable oracle, consulted per stream at admission, beside the gate: a
    /// disabled service is refused with the same indistinguishable refusal a gate miss gives.
    pub(super) enabled: Box<dyn EnabledServices + Send + Sync>,
    /// The live cut, `None` when no caller wired one, and then no session subscribes or re-checks.
    pub(super) cuts: Option<Cuts>,
}

/// The node's public-path capacity: the two permit pools that bound what strangers can
/// occupy. `sessions` holds one permit per session that has reached an opened service, until that session
/// closes; `streams` holds one per public stream in flight. Both are taken ONLY at the public-admit seam
/// ([`admit`](super::admit)): a gated route never consults either pool.
pub(super) struct PublicPool {
    /// One permit per public session (see [`PUBLIC_SESSION_PERMITS`]).
    pub(super) sessions: Arc<Semaphore>,
    /// One permit per concurrent public stream (see [`PUBLIC_STREAM_PERMITS`]).
    pub(super) streams: Arc<Semaphore>,
}

impl PublicPool {
    /// The production capacity: [`PUBLIC_SESSION_PERMITS`] public sessions, [`PUBLIC_STREAM_PERMITS`]
    /// concurrent public streams.
    pub(super) fn new() -> Self {
        Self {
            sessions: Arc::new(Semaphore::new(PUBLIC_SESSION_PERMITS)),
            streams: Arc::new(Semaphore::new(PUBLIC_STREAM_PERMITS)),
        }
    }
}

/// The per-session half of the public cap: the ONE public-session permit a session holds
/// once it has been admitted to any opened service, held until the session closes and its last stream
/// drops. A session that only ever dials gated routes never takes one: classification happens at the
/// public-admit seam, so a member's session is invisible to the pool.
#[derive(Default)]
pub(super) struct PublicSession {
    /// `None` until the first public admit, then this session's permit. The lock is `std` with a
    /// non-blocking `try_acquire` inside and never an await, so it can never park the admit path.
    permit: std::sync::Mutex<Option<OwnedSemaphorePermit>>,
}

impl PublicSession {
    /// Classify this session into the public pool, taking its permit on the first public admit. `Ok` when
    /// the session already holds one or the pool has room; `Err` when the pool is at
    /// [`PUBLIC_SESSION_PERMITS`] sessions.
    pub(super) fn enter(&self, sessions: &Arc<Semaphore>) -> Result<(), ()> {
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
pub(super) struct SessionPeer {
    pub(super) node: NodeId,
    pub(super) security: Security,
}

impl core::fmt::Display for SessionPeer {
    /// The peer's identity, for the per-stream log lines: the declared security is a transport-wide
    /// fact, named in the admission refusal's own cause when it decides one.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.node)
    }
}

/// Serve one accepted session: handle each inbound stream's service request under the gate.
pub(super) async fn serve_session<S: Session>(session: S, serving: Arc<Serving>) -> eyre::Result<()>
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
    // The per-session half of the public cap: created empty, classified by the first stream
    // that reaches an opened service, and dropped with the session (which releases its permit, if any).
    let public_session = Arc::new(PublicSession::default());
    // This session's half of the live cut, owned by this frame alone: `None` when no cut is wired.
    let mut cut = serving.cuts.as_ref().map(Cuts::watch);
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
                        cut.as_ref().map(cut::SessionCut::chains),
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
            // The live cut: on a sweep, re-ask about the chains this session was admitted on, and end it
            // if any was recalled. Returning drops the session and every stream on it.
            //
            // Guarded by the same liveness the two arms above share. A sweep arm left enabled would keep
            // this select from ever reaching `else`, so a session whose peer left and whose streams drained
            // would park until the next tick, and the next, forever, holding its `MAX_SESSIONS` slot; enough
            // connect-and-close cycles would stop the node accepting at all.
            true = cut::swept(&mut cut), if accepting || !pipes.is_empty() => {
                if let (Some(cuts), Some(cut)) = (&serving.cuts, &cut)
                    && cuts.cuts(cut)
                {
                    // Close, not just drop: a stream a handler handed to a detached task can hold a
                    // connection open past the session value, and a cut must end the peer's reach.
                    session.close();
                    tracing::warn!(
                        %peer,
                        "session cut: a capability it was admitted on is revoked or its root disabled"
                    );
                    return Ok(());
                }
            }
            // No more streams to accept and none in flight: the session is done.
            else => break,
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "exposer_tests.rs"]
mod exposer_tests;
