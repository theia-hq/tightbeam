//! The tunnel library core: store-free, clap-free, banner-free.
//!
//! This is the domain a tunnel is made of, with no CLI around it: an [`Exposer`] that accepts overlay
//! sessions and forwards inbound streams to local services, a [`Connector`] that reaches a peer's exposed
//! service, the [`family_gate`] builder, and the offline capability operations ([`mint_link`],
//! [`narrow_link`], [`revoke_into`]). It prints NOTHING and reads no config path: a caller (tightbeam's
//! own CLI, or a future swoosh) loads the signet, denylist, and identity, prints its own banner, and drives
//! this core. Everything here already speaks `bifrost` and `nauthy`, never clap or a store.

use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::{Admitted, Cap, Denylist, Gate, Identity, Refusal, Service};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};

use crate::identity::{AsNodeId as _, AsVerifyKey as _};
use crate::protocol::{Request, Response};
use crate::{splice, splice_halves};

/// How long to wait for a connector to send its opening request before dropping the stream. Bounds the
/// pre-gate work an unauthenticated peer can pin (a slow-loris that opens a stream and never speaks).
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The maximum number of peer sessions served concurrently. Past this, `accept` stops being polled so new
/// connections queue at the transport (backpressure), bounding the memory a flood of peers can pin.
const MAX_SESSIONS: usize = 256;

/// The maximum number of in-flight streams per session, bounding what a single connected peer can pin.
const MAX_STREAMS_PER_SESSION: usize = 256;

/// The local services an exposer publishes: a map of service name to forwarding target (`host:port`,
/// `unix:<path>`, `sshd:`, or `fetch:`), validated once at parse time so the rest of the core receives
/// names and addresses that are already well-formed.
#[derive(Debug, Clone)]
pub struct Services(HashMap<String, String>);

impl Services {
    /// Parse `name=addr` service entries; a bare `addr` becomes the `default` service.
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
            // Validate the ADDR too: without this, `expose web` silently maps the `default` service to the
            // literal address "web", which only fails at dial time as an opaque reset. Fail HERE instead.
            validate_addr(&addr, entry)?;
            services.insert(name, addr);
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

    /// Whether any exposed service is a keyless shell (`sshd:`), which has no auth of its own and so may
    /// never be opened to the world. The [`Exposer::new`] invariant checks this.
    pub fn contains_shell(&self) -> bool {
        let Self(services) = self;
        services.values().any(|addr| addr == "sshd:")
    }
}

/// Build a family authorization gate: admit a peer that presents a signed token rooted at `signet`
/// (a membership badge or a delegated slip), unless the token is on `denylist`.
///
/// A pure builder. The CALLER loads the denylist (from wherever it keeps revocations) and passes it in;
/// the core never reads a config path. `--public` is the caller's own choice, so the open gate
/// ([`Gate::Open`]) is built at the call site, not here.
pub fn family_gate(signet: NodeId, denylist: Denylist) -> Gate {
    Gate::Family(signet.verify_key(), Box::new(denylist))
}

/// An exposer: the services to publish, the gate that decides who may reach them, and the ssh host seed a
/// `sshd:` service needs. Accepts overlay sessions and forwards each inbound stream to its service.
pub struct Exposer {
    services: Services,
    gate: Gate,
    host_seed: [u8; 32],
}

impl Exposer {
    /// Assemble an exposer, enforcing the one domain invariant a tunnel has: a keyless shell (`sshd:`) has
    /// no auth of its own, so the gate IS its authentication. An [`Gate::Open`] gate over a shell would hand
    /// a keyless shell to anyone who reaches this node, so that pairing is refused HERE, where the domain
    /// lives, rather than trusted to each caller to re-check.
    pub fn new(services: Services, gate: Gate, host_seed: [u8; 32]) -> eyre::Result<Self> {
        if matches!(gate, Gate::Open) && services.contains_shell() {
            eyre::bail!(
                "a shell service (sshd:) has no auth of its own and must be gated; \
                 drop --public, which would expose an unauthenticated shell to anyone"
            );
        }
        Ok(Self {
            services,
            gate,
            host_seed,
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
            gate,
            host_seed,
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
                        host_seed,
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
    host_seed: [u8; 32],
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
                        host_seed,
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
#[cfg_attr(not(feature = "ssh"), allow(unused_variables))]
async fn serve_request<W, R>(
    peer: NodeId,
    mut writer: W,
    mut reader: R,
    gate: Arc<Gate>,
    services: Arc<Services>,
    host_seed: [u8; 32],
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
        // `fetch:` is the HTTP egress target: rather than splice to a fixed local socket, the node acts
        // as an HTTP client and streams an origin response back (see `crate::fetch`).
        Some(addr) if addr == "fetch:" => {
            Response::Ok.write(&mut writer).await?;
            crate::fetch::serve_fetch(&mut writer, &mut reader).await?;
        }
        // `sshd:` is a keyless SSH server (the `sshh` crate): the cap gate already authorized the peer, so
        // the ssh server accepts auth `none`. A standard `ssh`/`scp` client reaches a shell with no ssh
        // keys, the way Tailscale SSH is keyless behind WireGuard. Built only with `--features ssh`, so the
        // heavy russh/pty dependency tree stays out of the default tunnel binary.
        Some(addr) if addr == "sshd:" => {
            #[cfg(feature = "ssh")]
            {
                Response::Ok.write(&mut writer).await?;
                // The gate admitted this peer; the `Admitted` witness proves it at the type level, so a
                // keyless shell can never be reached un-gated. The witness binds no peer itself, so this
                // guarantee holds only because the admit (above) and this serve share one stream frame:
                // never hoist the admit to session scope, or one witness would cover streams the gate
                // never ruled on.
                sshh::serve(admitted, host_seed, writer, reader).await?;
            }
            #[cfg(not(feature = "ssh"))]
            Response::Error(
                "ssh support not built in; rebuild tightbeam with --features ssh".to_owned(),
            )
            .write(&mut writer)
            .await?;
        }
        Some(addr) => {
            Response::Ok.write(&mut writer).await?;
            dial_and_splice(addr, writer, reader).await?;
        }
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
fn resolve_single_service(requested: Service, services: &HashMap<String, String>) -> Service {
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

/// Reject an addr that is not a real forwarding target, so a bare service name (`expose web`) fails at
/// parse with a teaching message instead of silently pointing the `default` service at an undialable
/// host. Valid targets: `sshd:` (keyless shell), `fetch:` (HTTP egress), `unix:<path>`, or a `host:port`.
fn validate_addr(addr: &str, entry: &str) -> eyre::Result<()> {
    let is_host_port = addr
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
    if addr == "sshd:" || addr == "fetch:" || addr.starts_with("unix:") || is_host_port {
        return Ok(());
    }
    // A bare token with no `=` was almost certainly meant as a service NAME, not an address.
    if !entry.contains('=') {
        eyre::bail!(
            "`{entry}` is not an address to forward to. Did you mean a service pointing at one, e.g. \
             `{entry}=127.0.0.1:8080`? (an address is host:port, unix:<path>, sshd:, or fetch:)"
        );
    }
    eyre::bail!(
        "`{addr}` is not a valid forwarding address (host:port, unix:<path>, sshd:, or fetch:)"
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
/// with [`Connector::forward_port`] or [`Connector::pipe_stdio`].
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

    /// Reach the peer, bind a local port, and forward each accepted TCP connection over its own stream.
    /// Runs until cancelled; prints nothing.
    pub async fn forward_port<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        port: u16,
    ) -> eyre::Result<()> {
        let session = node.connect(self.dial).await?;
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        let mut pipes = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    // One local accept or stream-open failing must not drop the pipes already in flight:
                    // log the transient error and keep the local listener up.
                    let (tcp, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            tracing::warn!(%error, "local accept failed; still listening");
                            continue;
                        }
                    };
                    let (writer, reader) = match session.open_bi().await {
                        Ok(stream) => stream,
                        Err(error) => {
                            tracing::warn!(%error, "opening a stream to the peer failed; still listening");
                            continue;
                        }
                    };
                    pipes.push(request_service(self.request(), tcp, writer, reader));
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

    /// Reach the service over one stream and pipe it against this process's stdin/stdout: the ssh
    /// `ProxyCommand` shape, where ssh speaks its protocol over our stdio and we carry it to the peer.
    pub async fn pipe_stdio<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
    ) -> eyre::Result<()> {
        let session = node.connect(self.dial).await?;
        let (writer, reader) = session.open_bi().await?;
        request_stdio(self.request(), writer, reader).await
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

/// Open a service and, if the host accepts, pipe it against this process's stdin/stdout (the stdio path).
/// Same handshake as [`request_service`], but the local ends are the process's own std streams.
async fn request_stdio<W, R>(request: Request, mut writer: W, mut reader: R) -> eyre::Result<()>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    request.write(&mut writer).await?;
    match Response::read(&mut reader).await? {
        Response::Ok => splice_halves(io::stdin(), io::stdout(), writer, reader).await?,
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
    use nauthy::{Gate, Service};

    use super::{Services, resolve_single_service};

    fn svc(name: &str) -> Service {
        name.parse()
            .unwrap_or_else(|_| panic!("valid service: {name}"))
    }

    fn services(entries: &[&str]) -> Services {
        Services::parse(&entries.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
            .expect("entries parse")
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
            "127.0.0.1:5000",
        ] {
            assert!(
                Services::parse(&[entry.to_owned()]).is_ok(),
                "{entry} should parse"
            );
        }
    }

    #[test]
    fn a_named_service_pointed_at_a_bogus_addr_is_rejected() {
        assert!(Services::parse(&["web=nonsense".to_owned()]).is_err());
    }

    #[test]
    fn an_exposer_refuses_a_public_shell() {
        // A keyless shell has no auth of its own, so an open gate over it would hand anyone a shell.
        // `Exposer::new` must reject that pairing, wherever the caller assembles it.
        let shell = services(&["ssh=sshd:"]);
        assert!(
            super::Exposer::new(shell, Gate::Open, [0u8; 32]).is_err(),
            "an open gate over a shell service must be refused"
        );
        // The same shell behind a real gate is fine; only the open-gate pairing is refused. A family gate
        // needs a signet and denylist, so prove the inverse with a non-shell service under the open gate.
        let web = services(&["web=127.0.0.1:80"]);
        assert!(
            super::Exposer::new(web, Gate::Open, [0u8; 32]).is_ok(),
            "an open gate over a non-shell service is allowed"
        );
    }
}
