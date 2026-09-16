//! The connector: reaching a service another node exposes, and the admitted stream that comes back.
//!
//! [`Connector`] resolves what to dial, what to ask for, and what credential to present, then drives it
//! one of three ways: a preflighted [`PortForward`], a stdio bridge, or a [`ServiceSession`] whose every
//! stream repeats the handshake. [`PresentingConnector`] is the same dial with the credential rule moved
//! into the type system.

use bifrost::{ConnInfo, Discovery, Node, NodeId, PeerProven, Refusal, Session, Transport};
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::{Link, Service};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};

use crate::identity::AsNodeId as _;
use crate::protocol::{Request, Response};
use crate::{pipe_stdio_bridge, splice};

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
    /// time. This is the client counterpart to a per-stream
    /// [`serve_request`](super::admit::serve_request): the exposer gates each stream, and the wrapper
    /// presents the request on each stream so every one of them is admitted on its
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
