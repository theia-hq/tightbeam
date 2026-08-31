//! The tunnel library core: store-free, clap-free, banner-free.
//!
//! This is the domain a tunnel is made of, with no CLI around it: an [`Exposer`] that accepts overlay
//! sessions and forwards inbound streams to local services, a [`Connector`] that reaches a peer's exposed
//! service, the [`resolve_gate`] policy, and the offline capability operations ([`mint_link`],
//! [`narrow_link`], [`revoke_into`]). It prints NOTHING and reads no config path: a caller (tightbeam's
//! own CLI, or a future swoosh) loads the signet, denylist, and identity, prints its own banner, and drives
//! this core. Everything here already speaks `bifrost` and `nauthy`, never clap or a store.

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

use crate::identity::{AsNodeId as _, AsVerifyKey as _};
use crate::protocol::{Request, Response};
use crate::raw_stream::RawStream;
use crate::{pipe_stdio_bridge, splice, splice_halves};

/// How long to wait for a raw-stream open to complete before dropping the stream. A `fifo:` `open()`
/// blocks until a peer opens the other end (POSIX), so an admitted peer that requests a FIFO whose writer
/// never appears would park the serving task indefinitely, one layer deeper than the pre-gate
/// [`REQUEST_READ_TIMEOUT`] (which has already elapsed by the time a target is dialed). Mirror that
/// timeout on the open so a never-opened FIFO cannot pin a stream slot forever.
pub(crate) const RAW_STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a connector to send its opening request before dropping the stream. Bounds the
/// pre-gate work an unauthenticated peer can pin (a slow-loris that opens a stream and never speaks).
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The maximum number of peer sessions served concurrently. Past this, `accept` stops being polled so new
/// connections queue at the transport (backpressure), bounding the memory a flood of peers can pin.
const MAX_SESSIONS: usize = 256;

/// The maximum number of in-flight streams per session, bounding what a single connected peer can pin.
const MAX_STREAMS_PER_SESSION: usize = 256;

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
    /// `connect --to -`. Carries a [`RawStream`] whose direction is fixed at parse time (a read-only
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
    /// (`sshd:`, `fetch:`, `diag.ping:`) resolves to a handler; a `host:port` / `unix:<path>` to a raw
    /// forward. A scheme may be dotted (`diag.ping`, `diag.speed`) for a method-service split.
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
    /// gate (a `--public file:` would exfil a secret, a `--public stdin:` the piped bytes, to anyone). A raw
    /// forward (`host:port`/`unix:`) is a service the operator deliberately stood up, so it stays
    /// `--public`-able; a bare file path or a piped stdin is one keystroke from a secret, so it does not.
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
pub type ServeFn =
    Arc<dyn Fn(Admitted, BoxWrite, BoxRead) -> BoxFuture<'static, eyre::Result<()>> + Send + Sync>;

/// One registered service: how to serve it, and whether it MUST be gated. A handler with no auth of its own
/// (a keyless shell) declares `requires_gate`, so an open gate over it is refused at [`Exposer::new`].
pub struct Handler {
    serve: ServeFn,
    requires_gate: bool,
}

impl Handler {
    /// A handler that may be exposed under any gate (it has auth of its own, or is safe to open).
    pub fn open(serve: ServeFn) -> Self {
        Self {
            serve,
            requires_gate: false,
        }
    }

    /// A handler with no auth of its own: the gate IS its authentication, so an open gate over it is refused.
    pub fn gated(serve: ServeFn) -> Self {
        Self {
            serve,
            requires_gate: true,
        }
    }
}

/// The scheme -> handler map the [`Exposer`] takes at construction. The caller builds it; the tunnel core
/// depends on no service crate and ships no handler of its own. Keyed by the `<scheme>:` an exposed service
/// resolves to (`sshd`, `fetch`, `diag`).
#[derive(Default)]
pub struct Registry(HashMap<String, Handler>);

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `scheme` -> `handler`, returning self for chaining.
    #[must_use]
    pub fn with(mut self, scheme: impl Into<String>, handler: Handler) -> Self {
        let Self(handlers) = &mut self;
        handlers.insert(scheme.into(), handler);
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
    fn get(&self, scheme: &str) -> Option<&Handler> {
        let Self(handlers) = self;
        handlers.get(scheme)
    }
}

/// Resolve the exposer's gate from the operator's choices, in ONE place so every embedder (tightbeam's own
/// CLI and swoosh) applies the SAME policy: an explicit `--public` (and ONLY that) opens the gate; otherwise
/// a family gate on the node's provisioned `signet`; an UNPROVISIONED node fails LOUD rather than ever
/// defaulting to open. The caller loads the denylist and passes it as a value. This exists so the three
/// security-relevant conventions (open-only-on-`--public`, fail-loud-on-unprovisioned, real-loaded-denylist)
/// are enforced once, not hand-copied into each caller.
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
            "this node has no signet to gate on: provision it with `adopt`, or pass --public to expose \
             to anyone"
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
                    "no handler is registered for `{scheme}:` \
                     (is the feature that provides it built in?)"
                );
            };
            if matches!(gate, Gate::Open) && handler.requires_gate {
                eyre::bail!(
                    "a `{scheme}:` service has no auth of its own and must be gated; \
                     drop --public, which would expose it to anyone who reaches this node"
                );
            }
        }
        // A raw-stream source (`file:`/`fifo:`/`stdin:`) also has no auth of its own: under an open gate it
        // would serve a chosen path's bytes (or the piped stdin) to anyone, so `--public file:<secret>` or
        // `--public stdin:` would exfil it. Refuse it at the same door that refuses a public shell. A raw
        // forward (`host:port`/`unix:`) stays open-able: it is a service the operator deliberately stood up,
        // not a bare file path or a piped stream one keystroke from a key.
        if matches!(gate, Gate::Open)
            && let Some(name) = services.raw_stream_names().next()
        {
            eyre::bail!(
                "a raw-stream service (`{name}`, a file:/fifo:/stdin: source) has no auth of its own and \
                 must be gated; drop --public, which would serve its bytes to anyone who reaches this node"
            );
        }
        Ok(Self {
            services,
            registry: Arc::new(registry),
            gate,
        })
    }

    /// Accept overlay sessions from permitted peers and forward each inbound stream to its service. Runs
    /// until cancelled; prints nothing (the caller printed its own readiness banner before calling).
    pub async fn run<T: Transport, D: Discovery>(self, node: &Node<T, D>) -> eyre::Result<()>
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
        let mut sessions = FuturesUnordered::new();
        loop {
            tokio::select! {
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
    // A node exposing exactly one service should not require `--service`: if the request names no exposed
    // service (a connector defaulting to `default`) and there is only one, resolve to it. Done BEFORE the
    // gate so a delegated slip for that service still matches (the gate checks the RESOLVED service).
    let service = resolve_single_service(service, services);

    let admitted = match admit(&gate, peer, request.capability.as_deref(), &service) {
        Ok(admitted) => admitted,
        Err(refusal) => {
            tracing::warn!(%peer, service = %service, %refusal, "refused");
            return Response::Error(refusal)
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
        Some(Target::RawStream(stream)) => match stream.open().await {
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
        },
        // A named service: hand the admitted stream to the caller-injected handler. The `Admitted` witness
        // proves the gate ruled on THIS stream and is moved into the handler by value (single-use), so a
        // handler can never run for an unauthorized peer; the guarantee holds only because the admit
        // (above) and this serve share one stream frame, never hoisted to session scope.
        Some(Target::Handler(scheme)) => match registry.get(scheme) {
            Some(handler) => {
                Response::Ok.write(&mut writer).await?;
                (handler.serve)(admitted, Box::new(writer), Box::new(reader)).await?;
            }
            // `Exposer::new` proved every exposed handler is registered, so this is unreachable in practice;
            // answer defensively rather than panic if an exposer was hand-built around that invariant.
            None => {
                let message = format!("no handler for service {:?}", service.as_str());
                Response::Error(message).write(&mut writer).await?;
            }
        },
        None => {
            // Name what this node DOES expose, so a service-name mismatch (the connector defaulting to
            // `default` while the exposer named `web`) reads as a fixable error, not an opaque reset.
            let mut available: Vec<&str> = services.keys().map(String::as_str).collect();
            available.sort_unstable();
            let message = format!(
                "unknown service {:?}; this node exposes: {}",
                service.as_str(),
                available.join(", ")
            );
            Response::Error(message).write(&mut writer).await?;
        }
    }
    Ok(())
}

/// Apply the gate to a request, returning the [`Admitted`] witness on success or a peer-facing refusal
/// string. The witness is required to reach a service handler, so "authorize before serve" is a
/// compile-time precondition (see [`nauthy::Admitted`]).
fn admit(
    gate: &Gate,
    peer: NodeId,
    capability: Option<&str>,
    service: &Service,
) -> Result<Admitted, String> {
    // Parse a presented capability at the edge; a malformed token is a refusal, not a hard error, so the
    // connector gets a clean "not permitted" rather than a dropped stream.
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
/// service is exposed, return that one, so a single-service node needs no `--service`. Otherwise return
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
/// `diag:` — a word then a colon with nothing after) names a handler; anything else must be a socket forward
/// (`host:port` or `unix:<path>`). All validated here so a typo fails at parse with a teaching message, not
/// at dial time.
fn parse_target(addr: &str, entry: &str) -> eyre::Result<Target> {
    // `stdin:` is a raw-stream source with NO tail (this process's fd 0), so it is a zero-arg target routed
    // FIRST, before the bare-scheme handler arm would read `stdin` as a handler no registry holds. It shares
    // the raw-stream direction and the `--public` refusal, but inherits none of the path guards (there is no
    // path). Anything after the colon is a typo: `stdin:` takes no argument.
    if addr == "stdin:" {
        return Ok(Target::RawStream(RawStream::stdin()?));
    }
    // A raw-stream forward carries a PATH tail (`file:/tmp/x`, `fifo:/tmp/beam`), so it is a Forward, not a
    // bare-scheme Handler. Route it FIRST: the direction (a read-only source toward the peer) is fixed here
    // at parse time, and a bare `file:`/`fifo:` with no path fails loudly rather than resolving to a
    // handler no registry holds.
    if let Some(path) = addr.strip_prefix("file:") {
        return Ok(Target::RawStream(RawStream::file(path, entry)?));
    }
    if let Some(path) = addr.strip_prefix("fifo:") {
        return Ok(Target::RawStream(RawStream::fifo(path, entry)?));
    }
    if let Some(scheme) = addr.strip_suffix(':') {
        // A bare `<scheme>:` (nothing after the colon) is a handler selector. `unix:<path>` and `host:port`
        // carry a tail and so fall through to the forward grammar; a bare `unix:` (no path) resolves to a
        // handler named `unix` that no registry holds, failing loudly at `Exposer::new`. A `.` is allowed
        // so a dotted method-service (`diag.ping:`, `diag.speed:`) is typeable as one handler: `.` is in
        // the `Service` alphabet, and these are the shipped instance of the methods-as-services split.
        if !scheme.is_empty()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            return Ok(Target::Handler(scheme.to_owned()));
        }
    }
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
    /// stream sends the request and awaits the host's [`Response`], so a refusal (wrong `--service`, a
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

    /// Reach the service over one stream and pipe it against this process's stdin/stdout (the `--to -`
    /// stdout / ssh `ProxyCommand` shape): ssh speaks its protocol over our stdio and we carry it to the
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
                        // A refused stream (wrong `--service`, a revoked or non-granting cap) carries a
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

/// Open a service and, if the host accepts, pipe it against this process's stdin/stdout (the `--to -`
/// stdout/ssh-`ProxyCommand` path). Same handshake as [`request_service`], but the local ends are the
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
        eyre::bail!("give --service and/or --expires to narrow the link");
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

    use super::{BoxRead, Exposer, Registry, Services, Target, resolve_single_service};
    use crate::raw_stream::RawStream;

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
    fn a_dotted_scheme_resolves_to_a_handler_for_the_method_service_split() {
        // A method-service split (`diag.ping`, `diag.speed`) is one dotted handler scheme: `.` is in the
        // `Service` alphabet and the bare-scheme arm admits it, so `serve diag.ping=diag.ping:` names one
        // handler the registry holds, not a `host.port`-shaped forward.
        for entry in ["ping=diag.ping:", "speed=diag.speed:"] {
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
        use futures::FutureExt as _;
        // A gated handler standing in for the keyless shell (it declares `requires_gate`): a shell has no
        // auth of its own, so an open gate over it would hand anyone a shell. `Exposer::new` must reject
        // that pairing, wherever the caller assembles it.
        let noop: super::ServeFn =
            std::sync::Arc::new(|_admitted, _writer, _reader| async { Ok(()) }.boxed());
        let shell = services(&["ssh=sshd:"]);
        let registry = super::Registry::new().with("sshd", super::Handler::gated(noop));
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
        // chosen path's bytes to anyone, so `--public file:<secret>` would exfil it. Refused at the same door
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
        // `--public stdin:` would exfil them. Refused at the same door as a public shell or a public file:.
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

                // Drive the SERVE path directly. `Exposer::new`'s `--public` refusal for a raw-stream source
                // is covered separately (`an_exposer_refuses_a_public_stdin`); here we construct the exposer
                // past that door so the open gate keeps the peer admitted with no token, and the test isolates
                // the take-once + splice path a `stdin:` source runs.
                let exposer = Exposer {
                    services,
                    registry: std::sync::Arc::new(Registry::new()),
                    gate: Gate::Open,
                };
                tokio::task::spawn_local(async move {
                    exposer.run(&exposer_node).await.expect("exposer runs");
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
            let (mut writer, mut reader) = session.open_bi().await.map_err(|e| e.to_string())?;
            crate::protocol::Request {
                service: service.to_owned(),
                capability: None,
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
        use futures::FutureExt as _;
        let noop: super::ServeFn =
            std::sync::Arc::new(|_admitted, _writer, _reader| async { Ok(()) }.boxed());
        // Adding a NEW scheme (an embedder injecting its own `diag:` beside `fetch:`) is allowed.
        let base = super::Registry::new().with("fetch", super::Handler::open(noop.clone()));
        let added =
            base.extend(super::Registry::new().with("diag", super::Handler::open(noop.clone())));
        assert!(added.is_ok(), "injecting a new scheme must be allowed");
        // Re-injecting a scheme already registered is refused at merge intent, so a second `extend` can
        // never shadow (and silently downgrade the gate of) a handler the caller already registered.
        let base = super::Registry::new().with("sshd", super::Handler::gated(noop.clone()));
        let shadowed = base.extend(super::Registry::new().with("sshd", super::Handler::open(noop)));
        assert!(
            shadowed.is_err(),
            "re-injecting an already-registered scheme must be refused so it cannot shadow a handler"
        );
    }
}
