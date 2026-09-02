//! The tunnel library core: store-free, clap-free, banner-free.
//!
//! This is the domain a tunnel is made of, with no CLI around it: an [`Exposer`] that accepts overlay
//! sessions and forwards inbound streams to local services, a [`Connector`] that reaches a peer's exposed
//! service, the [`resolve_gate`] policy, and the offline capability operations ([`mint_link`],
//! [`narrow_link`], [`revoke_into`]). It prints NOTHING and reads no config path: a caller (tightbeam's
//! own CLI, or a future swoosh) loads the signet, denylist, and identity, prints its own banner, and drives
//! this core. Everything here already speaks `bifrost` and `nauthy`, never clap or a store.

use core::future::Future;
use core::time::Duration;
use std::collections::HashMap;
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
const UNIFORM_REFUSAL: &str = "refused";

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
    /// A named service handler (`sshd`, `fetch`, `diag`, ...) dispatched through the injected registry.
    Handler(String),
}

/// The local services an exposer publishes: a map of service name to its [`Target`], validated once at
/// parse time so the rest of the core receives names and targets that are already well-formed.
#[derive(Debug, Clone)]
pub struct Services(HashMap<String, Target>);

impl Services {
    /// Parse `name=addr` service entries; a bare `addr` becomes the `default` service. A bare scheme
    /// (`sshd:`, `fetch:`, `ping:`) resolves to a handler; a `host:port` / `unix:<path>` to a raw
    /// forward. A scheme may be dotted (`control.status`, `control.restart`) for a method on an interface.
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

    /// The exposed service names, sorted, for a caller's readiness banner.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        let Self(services) = self;
        let mut names: Vec<&str> = services.keys().map(String::as_str).collect();
        names.sort_unstable();
        names.into_iter()
    }

    /// The handler schemes this exposer names (e.g. `sshd`, `fetch`), so [`Exposer::new`] can check each
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
/// ([`BoxFuture`], `Send`-bearing), so heterogeneous handlers (a [`Never`](crate::open_policy::Never) sshd and
/// an [`OptIn`](crate::open_policy::OptIn) ping) share ONE `Arc<dyn ErasedHandler>` storage type. The marker
/// never enters these signatures, so it does its job at the impl-site type-check and then vanishes into the
/// object's frozen `open_safe()` answer (delib-37: this is why the associated type, not a generic, survives
/// erasure).
trait ErasedHandler: Send + Sync {
    /// The erased open-safety ceiling: `<H::Public as PublicUse>::OPEN_SAFE`, read once at [`Exposer::new`].
    fn open_safe(&self) -> bool;
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
/// resolves to (`sshd`, `fetch`, `diag`).
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
    /// handler of its own, so the caller (swoosh) assembles the whole registry; this guard keeps that
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

/// Resolve the exposer's gate from the operator's choices, in ONE place so every embedder (tightbeam's own
/// CLI and swoosh) applies the SAME policy: an explicit `public` request (and ONLY that) opens the gate;
/// otherwise a family gate on the node's provisioned `signet`; an UNPROVISIONED node fails LOUD rather than
/// ever defaulting to open. The caller loads the denylist and passes it as a value. This exists so the
/// three security-relevant conventions (open-only-when-`public`, fail-loud-on-unprovisioned,
/// real-loaded-denylist) are enforced once, not hand-copied into each caller.
pub fn resolve_gate(
    public: bool,
    signet: Option<NodeId>,
    denylist: Denylist,
) -> eyre::Result<Gate> {
    if public {
        return Ok(Gate::Open);
    }
    let root = signet.ok_or_else(|| {
        eyre::eyre!(
            "this node has no signet to gate on: provision it (adopt a signet), or open it as a public \
             gate to serve anyone"
        )
    })?;
    Ok(Gate::family(root.verify_key(), denylist))
}

/// An exposer: the services to publish, the caller-injected handler registry that serves the named ones,
/// and the gate that decides who may reach them. Accepts overlay sessions and forwards each inbound stream
/// to its service.
pub struct Exposer {
    services: Services,
    registry: Arc<Registry>,
    gate: Gate,
}

impl Exposer {
    /// Assemble an exposer from the parsed services, the caller-injected handler registry, and the gate,
    /// enforcing two invariants at the door: every named handler is actually registered (a typo or an
    /// unbuilt feature fails HERE, not at dial time), and a handler with no auth of its own (a keyless
    /// shell) may not sit behind an [`Gate::Open`] gate, which would hand it to anyone who reaches the node.
    pub fn new(services: Services, registry: Registry, gate: Gate) -> eyre::Result<Self> {
        for scheme in services.handler_schemes() {
            let Some(handler) = registry.get(scheme) else {
                eyre::bail!(
                    "register a handler for `{scheme}:` before exposing it (or drop the service): \
                     no handler is registered for it (is the feature that provides it built in?)"
                );
            };
            if matches!(gate, Gate::Open) && !handler.open_safe() {
                eyre::bail!(
                    "gate the `{scheme}:` service instead of opening it: it has no legitimate public use, \
                     so a public gate would hand it to anyone who reaches this node"
                );
            }
        }
        // A raw-stream source (`file:`/`fifo:`/`stdin:`) also has no auth of its own: under an open gate it
        // would serve a chosen path's bytes (or the piped stdin) to anyone, so a public gate over a
        // `file:<secret>` or a `stdin:` source would exfil it. Refuse it at the same door that refuses a
        // public shell. A raw forward (`host:port`/`unix:`) stays open-able: it is a service the operator
        // deliberately stood up, not a bare file path or a piped stream one keystroke from a key.
        if matches!(gate, Gate::Open)
            && let Some(name) = services.raw_stream_names().next()
        {
            eyre::bail!(
                "a raw-stream service (`{name}`, a file:/fifo:/stdin: source) has no auth of its own and \
                 must be gated; a public gate would serve its bytes to anyone who reaches this node"
            );
        }
        Ok(Self {
            services,
            registry: Arc::new(registry),
            gate,
        })
    }

    /// Accept overlay sessions from permitted peers and forward each inbound stream to its service. Runs
    /// until `cancel` fires, then stops accepting and returns gracefully; prints nothing (the caller printed
    /// its own readiness banner before calling).
    ///
    /// `cancel` is the node's ONE teardown authority. The exposer is the single owner of that authority: it
    /// is the only thing that ACTS on the token (stops accepting, drains, returns). A local timer
    /// (`serve --for`) or an admitted `control.stop` handler holds a CLONE of the same token as a
    /// node-control CAPABILITY -- they may REQUEST teardown by cancelling it, but they never hold a node
    /// handle and never tear anything down themselves. So "who may stop the node" stays a property of who
    /// holds a token clone (a cap-gated question), while "how the node stops" lives here, in one place.
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
        } = self;
        let services = Arc::new(services);
        let gate = Arc::new(gate);
        // Cap concurrent raw-stream opens across the whole node (all sessions share this one semaphore) as
        // cheap defense-in-depth: the nonblocking open cannot park a thread, so this bounds the fds held
        // mid-open, not a leak. See `RAW_STREAM_OPEN_PERMITS`.
        let raw_stream_opens = Arc::new(Semaphore::new(RAW_STREAM_OPEN_PERMITS));
        let mut sessions = FuturesUnordered::new();
        loop {
            tokio::select! {
                // Teardown: the cancel token fired (a local `--for` deadline, or an admitted `control.stop`
                // caller holding a clone). Stop accepting and return gracefully. The in-flight sessions in
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
                    sessions.push(serve_session(
                        session,
                        Arc::clone(&gate),
                        Arc::clone(&services),
                        Arc::clone(&registry),
                        Arc::clone(&raw_stream_opens),
                    ));
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

/// Serve one accepted session: handle each inbound stream's service request under the gate.
async fn serve_session<S: Session>(
    session: S,
    gate: Arc<Gate>,
    services: Arc<Services>,
    registry: Arc<Registry>,
    raw_stream_opens: Arc<Semaphore>,
) -> eyre::Result<()>
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
                    Ok((writer, reader)) => pipes.push(serve_request(
                        peer,
                        writer,
                        reader,
                        Arc::clone(&gate),
                        Arc::clone(&services),
                        Arc::clone(&registry),
                        Arc::clone(&raw_stream_opens),
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
/// its own merits.
async fn serve_request<W, R>(
    peer: NodeId,
    mut writer: W,
    mut reader: R,
    gate: Arc<Gate>,
    services: Arc<Services>,
    registry: Arc<Registry>,
    raw_stream_opens: Arc<Semaphore>,
) -> eyre::Result<()>
where
    W: io::AsyncWrite + Unpin + Send + 'static,
    R: io::AsyncRead + Unpin + Send + 'static,
{
    let Services(services) = &*services;
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

    let admitted = match admit(&gate, peer, request.capability.as_deref(), &service) {
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

/// Apply the gate to a request, returning the [`Admitted`] witness on success or a DISTINGUISHING refusal
/// string for the node's OWN logs. The witness is required to reach a service handler, so "authorize before
/// serve" is a compile-time precondition (see [`nauthy::Admitted`]). The reason returned here NEVER crosses
/// the wire (the caller sends [`UNIFORM_REFUSAL`] to a not-admitted dialer); it exists only so the operator
/// can see WHY on their own `tracing` output. Distinguishing missing/not-granted/revoked to the wire would
/// be a revocation + capability-enumeration oracle for an unauthorized peer (deliberation 18).
fn admit(
    gate: &Gate,
    peer: NodeId,
    capability: Option<&str>,
    service: &Service,
) -> Result<Admitted, String> {
    // Parse a presented capability at the edge; a malformed token is a refusal, not a hard error, so the
    // stream ends cleanly rather than being dropped mid-read.
    let cap = match capability.map(Cap::parse).transpose() {
        Ok(cap) => cap,
        Err(_) => return Err("malformed capability".to_owned()),
    };
    gate.admit_witnessed(peer.verify_key(), cap.as_ref(), service)
        .map_err(|refusal| match refusal {
            Refusal::Missing => "this service requires a capability".to_owned(),
            Refusal::NotGranted => "capability does not grant this service".to_owned(),
            Refusal::Revoked => "capability has been revoked".to_owned(),
        })
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
/// forward (open an existing OS object, splice its bytes to the peer); a bare scheme (`sshd:`, `fetch:`,
/// `ping:` -- a word then a colon with nothing after) names a handler; anything else must be a socket forward
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
/// forwards: `unix:<path>` or a `host:port` (a handler scheme like `sshd:`/`fetch:` is resolved earlier).
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
             or a handler like sshd:/fetch:)"
        );
    }
    eyre::bail!(
        "`{addr}` is not a valid forwarding address (host:port, unix:<path>, file:<path>, fifo:<path>, \
         or a handler like sshd:/fetch:)"
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
}

impl Connector {
    /// Connect to a raw node id, requesting `service`. A raw-node dial may still present a token via
    /// `present`, for the case where the node id was shared separately from the capability.
    pub fn to_node(dial: NodeId, service: String, present: Option<String>) -> Self {
        Self {
            dial,
            service,
            capability: present,
        }
    }

    /// Connect via a `sheer:` capability link, requesting `service`. The link supplies the node to dial
    /// (the cap's root) and carries the token; the host refuses unless the token actually grants `service`.
    pub fn from_link(link: &str, service: String) -> eyre::Result<Self> {
        Ok(Self {
            dial: Cap::parse(link)?.root().node_id(),
            service,
            capability: Some(link.to_owned()),
        })
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
            eyre::bail!("refused by {}: {message}", self.dial);
        }
        drop((writer, reader));
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        Ok(PortForward {
            session,
            listener,
            request,
        })
    }

    /// Reach the service over one stream and pipe it against this process's stdin/stdout (piping the service
    /// to this process's stdout, the ssh `ProxyCommand` shape): ssh speaks its protocol over our stdio and we carry it to the
    /// peer. The pump finishes when the peer closes, so a `-- <cmd>` invocation exits when its command does.
    pub async fn pipe_stdio<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
    ) -> eyre::Result<()> {
        let session = node.connect(self.dial).await?;
        let (writer, reader) = session.open_bi().await?;
        request_stdio(self.request(), writer, reader).await
    }

    /// Reach the peer and return a [`ServiceSession`]: a [`Session`] whose every `open_bi` first speaks
    /// this connector's `Request{service, capability}` / `Response::Ok` handshake, so a protocol that is
    /// generic over `Session` (diag's ping/speed) rides the gate transparently, one admitted stream at a
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
/// ONLY on `Response::Ok`, mapping a refusal to [`bifrost::Error::Stream`]. Any `Session`-generic protocol
/// (diag's `Speedtest`/`Ping`) runs over it unchanged, every one of its streams admitted by the gate.
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
        // A service client never accepts peer-opened streams; the diag protocols only ever `open_bi`.
        // Refusing (rather than `unreachable!`) keeps the wrapper total and panic-free.
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

/// Open a service and, if the host accepts, pipe it against this process's stdin/stdout (piping the service
/// to this process's stdout, the ssh-`ProxyCommand` path). Same handshake as [`request_service`], but the local ends are the
/// process's own std streams, and the pump ([`pipe_stdio_bridge`]) returns when the PEER closes rather than
/// waiting on a stdin that (at a terminal) never EOFs, so `ssh <peer> -- <cmd>` exits when the command does.
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
        BoxRead, BoxWrite, Exposer, Handler, RAW_STREAM_OPEN_PERMITS, Registry, Semaphore, Services,
        Target, resolve_single_service, serve_request,
    };
    use crate::open_policy::{Never, OptIn};
    use crate::raw_stream::RawStream;

    /// A do-nothing GATED handler (`type Public = Never`): stands in for a keyless shell, so an open gate over
    /// it must be refused at `Exposer::new`.
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
        let Services(one) = services(&["web=127.0.0.1:80"]);
        // A connector defaulting to `default` on a single-service node resolves to that one service.
        assert_eq!(resolve_single_service(svc("default"), &one).as_str(), "web");
        // A request that already names the exposed service is unchanged.
        assert_eq!(resolve_single_service(svc("web"), &one).as_str(), "web");

        let Services(two) = services(&["web=127.0.0.1:80", "ssh=sshd:"]);
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
            "ssh=sshd:",
            "proxy=fetch:",
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
            "ssh=sshd:+lossy",
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
            super::Exposer::new(lossy, super::Registry::new(), Gate::Open).is_err(),
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
    fn an_exposer_refuses_a_public_shell() {
        // A gated handler standing in for the keyless shell (`type Public = Never`): a shell has no
        // legitimate public use, so an open gate over it would hand anyone a shell. `Exposer::new` must reject
        // that pairing, wherever the caller assembles it.
        let shell = services(&["ssh=sshd:"]);
        let registry = super::Registry::new().with("sshd", GatedNoop);
        assert!(
            super::Exposer::new(shell, registry, Gate::Open).is_err(),
            "an open gate over a shell service must be refused"
        );
        // The same shell behind a real gate is fine; only the open-gate pairing is refused. A family gate
        // needs a signet and denylist, so prove the inverse with a non-shell service (an empty registry
        // suffices, since a raw forward needs no handler) under the open gate.
        let web = services(&["web=127.0.0.1:80"]);
        assert!(
            super::Exposer::new(web, super::Registry::new(), Gate::Open).is_ok(),
            "an open gate over a non-shell service is allowed"
        );
    }

    #[test]
    fn an_exposer_refuses_a_public_raw_stream() {
        // A raw-stream source (`file:`/`fifo:`) has no auth of its own: under an open gate it would serve a
        // chosen path's bytes to anyone, so a public gate over `file:<secret>` would exfil it. Refused at the same door
        // as a public shell.
        let secret = services(&["leak=file:/etc/hosts"]);
        assert!(
            super::Exposer::new(secret, super::Registry::new(), Gate::Open).is_err(),
            "an open gate over a file:/fifo: source must be refused"
        );
        // A raw forward the operator deliberately stood up (host:port) stays open-able; only the no-auth
        // raw-stream source is refused under the open gate.
        let web = services(&["web=127.0.0.1:80"]);
        assert!(
            super::Exposer::new(web, super::Registry::new(), Gate::Open).is_ok(),
            "an open gate over a host:port forward is still allowed"
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
            super::Exposer::new(piped, super::Registry::new(), Gate::Open).is_err(),
            "an open gate over a stdin: source must be refused"
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

    /// The cancel seam (delib-18/S18): `Exposer::run` returns gracefully when its cancel token fires, so a
    /// local `serve --for` timer or an admitted `control.stop` caller (each holding a CLONE of this token as
    /// the node-control capability) can stop the node. Here the token is cancelled from OUTSIDE the run (the
    /// shape both the timer and the handler use); the run must finish with `Ok(())` rather than accept
    /// forever. Uses the mem transport so no real socket is bound.
    #[tokio::test]
    async fn run_returns_gracefully_when_its_cancel_token_fires() {
        let node = Node::new(MemTransport::bind(), NoDiscovery);
        let exposer = Exposer {
            services: services(&["web=127.0.0.1:80"]),
            registry: std::sync::Arc::new(Registry::new()),
            gate: Gate::Open,
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

    /// Drive one `serve_request` for `service` against a `Gate::Open` node sharing `permits`, and return the
    /// client's stream end plus the serving future. The serving future is returned UN-awaited so a caller can
    /// let it park (a never-written FIFO) or poll it for the refusal, and the returned reader carries the
    /// host's `Response`. Uses `tokio::io::duplex` so no transport is needed.
    fn drive_open(
        service: &str,
        services: std::sync::Arc<Services>,
        permits: std::sync::Arc<Semaphore>,
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
            }
            .write(&mut client_write)
            .await
            .expect("write request");
            // Close the client's write half now the request is sent: the served splice's downstream copy
            // (peer -> `io::sink()`) ends on this EOF, so a served stream can actually finish (otherwise the
            // splice's `try_join!` would wait forever for the client to hang up).
            drop(client_write);
            serve_request(
                peer,
                server_write,
                server_read,
                std::sync::Arc::new(Gate::Open),
                services,
                std::sync::Arc::new(Registry::new()),
                permits,
            )
            .await
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
        let services = std::sync::Arc::new(services(&[&format!("pipe=fifo:{}", fifo.display())]));

        const CAP: usize = 3;
        const OVER: usize = 4;
        let permits = std::sync::Arc::new(Semaphore::new(CAP));

        // CAP opens grab a permit and park in the blocking FIFO open; hold their serving futures so the
        // permits stay taken. They MUST NOT respond (they are blocked waiting for a writer that never comes).
        let mut parked = Vec::new();
        for _ in 0..CAP {
            let (mut client_read, serve) = drive_open(
                "pipe",
                std::sync::Arc::clone(&services),
                std::sync::Arc::clone(&permits),
            );
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
            let (mut client_read, serve) = drive_open(
                "pipe",
                std::sync::Arc::clone(&services),
                std::sync::Arc::clone(&permits),
            );
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

        let services = std::sync::Arc::new(services(&[&format!("doc=file:{}", path.display())]));
        let permits = std::sync::Arc::new(Semaphore::new(RAW_STREAM_OPEN_PERMITS));

        let (mut client_read, serve) = drive_open("doc", services, permits);
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
            let (mut writer, mut reader) = session.open_bi().await.map_err(|e| e.to_string())?;
            crate::protocol::Request {
                service: service.to_owned(),
                capability,
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
        // dial-time mystery reset. (Here `sshd:` is exposed but nothing registered it.)
        let shell = services(&["ssh=sshd:"]);
        assert!(
            super::Exposer::new(shell, super::Registry::new(), Gate::Open).is_err(),
            "exposing a handler scheme with no registered handler must be refused at construction"
        );
    }

    #[test]
    fn extend_is_add_only_and_refuses_a_collision() {
        // Adding a NEW scheme (an embedder injecting its own `ping:` beside `fetch:`) is allowed.
        let base = super::Registry::new().with("fetch", OpenNoop);
        let added = base.extend(super::Registry::new().with("ping", OpenNoop));
        assert!(added.is_ok(), "injecting a new scheme must be allowed");
        // Re-injecting a scheme already registered is refused at merge intent, so a second `extend` can
        // never shadow (and silently downgrade the gate of) a handler the caller already registered.
        let base = super::Registry::new().with("sshd", GatedNoop);
        let shadowed = base.extend(super::Registry::new().with("sshd", OpenNoop));
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
}
