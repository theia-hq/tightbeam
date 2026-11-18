//! Tests for the port forward: every local connection rides its own stream, and a connection waiting for
//! a stream the peer has not yet granted never holds up the ones already flowing.

use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;

use bifrost::{ConnInfo, NoDiscovery, Node, NodeId, Path, PathChanges, Relay, Session, WriteEnd};
use bifrost_mem::{MemRead, MemSession, MemTransport, MemWrite};
use nauthy::Gate;
use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::{ConnectionLost, Connector, MAX_PIPES, PortForward, ServiceSession};
use crate::protocol::{Request, Response};
use crate::tunnel::CancellationToken;
use crate::tunnel::fixtures::{prove, services, svc};
use crate::tunnel::router::{PublicRequest, PublicUnsafeRequest};

/// The peer's cap on concurrently open streams in these tests: small, so the forward reaches it quickly.
const STREAM_LIMIT: usize = 4;

/// Long enough for a loaded CI box to move a few bytes, short enough that a stalled forward fails the
/// suite rather than hanging it.
const WITHIN: Duration = Duration::from_secs(5);

/// A session whose peer grants at most a fixed number of concurrently open streams, the way a QUIC peer
/// does: `open_bi` waits for a free slot, and a stream's slot returns when its write half is dropped.
struct Capped<S> {
    session: S,
    slots: Arc<Semaphore>,
    /// How many opens are waiting for a slot right now.
    waiting: Arc<AtomicUsize>,
}

/// Counts one open as waiting for a slot for as long as it lives.
struct Waiting(Arc<AtomicUsize>);

impl Waiting {
    fn new(waiting: &Arc<AtomicUsize>) -> Self {
        waiting.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(waiting))
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let Self(waiting) = self;
        waiting.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A write half holding its stream's slot for as long as it lives.
struct SlotWrite<W> {
    inner: W,
    _slot: OwnedSemaphorePermit,
}

impl<W: io::AsyncWrite + Unpin> io::AsyncWrite for SlotWrite<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Ends the stream it wraps: holding a slot changes nothing about how the stream ends.
impl<W: WriteEnd> WriteEnd for SlotWrite<W> {
    fn abort(&mut self) {
        self.inner.abort();
    }

    /// The slot rides the future, not the call: the stream stays open until the peer holds its end, so
    /// returning the slot any earlier would let the forward open past the peer's cap.
    fn delivered(self) -> impl Future<Output = io::Result<()>> + Send + 'static {
        let Self { inner, _slot: slot } = self;
        let delivered = inner.delivered();
        async move {
            let outcome = delivered.await;
            drop(slot);
            outcome
        }
    }
}

impl<S: Session> Session for Capped<S> {
    type Write = SlotWrite<S::Write>;
    type Read = S::Read;

    fn peer(&self) -> NodeId {
        self.session.peer()
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        let waiting = Waiting::new(&self.waiting);
        let slot = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(|error| bifrost::Error::Stream(Box::new(error)))?;
        drop(waiting);
        let (inner, reader) = self.session.open_bi().await?;
        Ok((SlotWrite { inner, _slot: slot }, reader))
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        Err(bifrost::Error::Stream("the forward never accepts".into()))
    }

    async fn wait_closed(&self) {
        self.session.wait_closed().await;
    }

    fn close(&self) {
        self.session.close();
    }

    fn conn_info(&self) -> ConnInfo {
        self.session.conn_info()
    }

    fn path_changes(&self) -> PathChanges {
        self.session.path_changes()
    }
}

/// Round-trip `bytes` through the echo behind the forward, within [`WITHIN`].
async fn echoes(client: &mut TcpStream, bytes: &[u8]) -> bool {
    if client.write_all(bytes).await.is_err() {
        return false;
    }
    let mut echoed = vec![0u8; bytes.len()];
    matches!(
        tokio::time::timeout(WITHIN, client.read_exact(&mut echoed)).await,
        Ok(Ok(_))
    ) && echoed == bytes
}

/// Expose an echo, preflight a forward to it with the peer capped at [`STREAM_LIMIT`] streams and the
/// forward holding at most `max_pipes` connections, and run it. Returns the local port and the count of
/// opens waiting for a stream. Call inside a `LocalSet`.
async fn capped_forward(max_pipes: usize) -> (u16, Arc<AtomicUsize>) {
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let exposer = prove(
        services(&["demo=echo:"]),
        Gate::Open,
        PublicRequest::none(),
        PublicUnsafeRequest::none(),
    )
    .expect("an open echo builds");
    tokio::task::spawn_local(async move {
        exposer.run(&host, CancellationToken::new()).await;
    });

    let consumer = Node::new(MemTransport::bind(), NoDiscovery);
    let forward = Connector::to_node(host_id, svc("demo"), None)
        .preflight(&consumer, 0)
        .await
        .expect("the open echo admits the forward");
    let port = forward.listener.local_addr().expect("bound").port();
    let waiting = Arc::new(AtomicUsize::new(0));
    let forward = PortForward {
        session: Capped {
            session: forward.session,
            slots: Arc::new(Semaphore::new(STREAM_LIMIT)),
            waiting: Arc::clone(&waiting),
        },
        listener: forward.listener,
        request: forward.request,
        max_pipes,
    };
    tokio::task::spawn_local(forward.run());
    (port, waiting)
}

/// Take every stream the peer grants through the forward on `port`, each one proven live.
async fn hold_every_stream(port: u16) -> Vec<TcpStream> {
    let mut held = Vec::new();
    for _ in 0..STREAM_LIMIT {
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert!(
            echoes(&mut client, b"up").await,
            "a forward within the limit echoes"
        );
        held.push(client);
    }
    held
}

#[tokio::test]
async fn a_local_connection_past_the_stream_limit_does_not_stall_the_forward() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (port, _) = capped_forward(MAX_PIPES).await;
            let mut held = hold_every_stream(port).await;

            // One more local connection: it has no stream yet, and must wait for one.
            let mut extra = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            extra.write_all(b"late").await.unwrap();
            let mut early = [0u8; 4];
            assert!(
                tokio::time::timeout(Duration::from_millis(200), extra.read_exact(&mut early))
                    .await
                    .is_err(),
                "the extra connection is carried before any stream frees: the limit was never reached"
            );

            // The forwards already flowing keep moving bytes while it waits.
            for client in &mut held {
                assert!(
                    echoes(client, b"still").await,
                    "a held forward stalled behind a connection waiting for a stream"
                );
            }

            // Ending one forward frees its stream, and the waiting connection is carried on it.
            drop(held.remove(0));
            let mut late = [0u8; 4];
            assert!(
                matches!(
                    tokio::time::timeout(WITHIN, extra.read_exact(&mut late)).await,
                    Ok(Ok(_))
                ),
                "the waiting connection never got the freed stream"
            );
            assert_eq!(&late, b"late");
        })
        .await;
}

#[tokio::test]
async fn connections_waiting_for_a_stream_stay_within_the_cap() {
    // Room for two connections to wait for a stream beyond the ones carried.
    const CAP: usize = STREAM_LIMIT + 2;
    const EXTRA: usize = 10;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (port, waiting) = capped_forward(CAP).await;
            let mut held = hold_every_stream(port).await;

            // Far more connections than the cap leaves room for. Each one completes in the kernel's
            // backlog whether or not the forward accepts it.
            let mut extras = Vec::new();
            for _ in 0..EXTRA {
                extras.push(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(
                waiting.load(Ordering::SeqCst),
                CAP - STREAM_LIMIT,
                "the forward took in more waiting connections than its cap allows"
            );

            // The carried forwards keep moving bytes at the cap.
            for client in &mut held {
                assert!(
                    echoes(client, b"still").await,
                    "a held forward stalled at the cap"
                );
            }

            // As streams free, the connections left in the backlog are taken in and carried, each
            // ending once it has echoed so the next one gets its stream.
            drop(held);
            for mut client in extras {
                assert!(
                    echoes(&mut client, b"late").await,
                    "a connection left in the backlog was never carried"
                );
            }
        })
        .await;
}

#[tokio::test]
async fn a_forward_ends_with_an_error_when_the_host_ends_its_session() {
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let consumer = Node::new(MemTransport::bind(), NoDiscovery);
    // The host admits the forward's probe and holds the session open until the forward is ready.
    let admits = async {
        let session = host.accept().await.unwrap();
        let (mut writer, mut reader) = session.accept_bi().await.unwrap();
        Request::read(&mut reader).await.unwrap();
        Response::Ok.write(&mut writer).await.unwrap();
        session
    };
    let preflight = Connector::to_node(host.node_id(), svc("demo"), None).preflight(&consumer, 0);
    let (session, forward) = tokio::join!(admits, preflight);
    let forward = forward.expect("the host admits the forward");

    // The host ends the session with no local connection in flight: the forward must end with it, not
    // keep listening on a port whose every stream would fail to open.
    session.close();
    let error = tokio::time::timeout(WITHIN, forward.run())
        .await
        .expect("the forward ended when its session did")
        .expect_err("a forward whose session ended is an error");
    assert!(
        error.downcast_ref::<ConnectionLost>().is_some(),
        "the forward names the lost connection: {error:#}"
    );
    assert_eq!(
        format!("{error:#}"),
        "connection lost: transport closed",
        "the transport's cause follows the line"
    );
}

/// The write half of a session that opens no stream: uninhabited, since no stream ever exists to write to.
enum NoStream {}

impl io::AsyncWrite for NoStream {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        match *self.get_mut() {}
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        match *self.get_mut() {}
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        match *self.get_mut() {}
    }
}

impl WriteEnd for NoStream {
    fn abort(&mut self) {
        match *self {}
    }

    fn delivered(self) -> impl Future<Output = io::Result<()>> + Send + 'static {
        core::future::ready(Err(io::ErrorKind::Unsupported.into()))
    }
}

/// A session whose path moves from a relay to direct, the change a hole punch makes. It answers with two
/// items, which no `PathChanges::fixed` can, so a wrapper that answers for itself is told apart from one
/// that forwards. It carries no streams.
struct Moving {
    peer: NodeId,
}

impl Session for Moving {
    type Write = NoStream;
    type Read = &'static [u8];

    fn peer(&self) -> NodeId {
        self.peer
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        Err(bifrost::Error::Closed)
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        Err(bifrost::Error::Closed)
    }

    async fn wait_closed(&self) {}

    /// A double that carries nothing has nothing to end.
    fn close(&self) {}

    fn path_changes(&self) -> PathChanges {
        PathChanges::new(futures::stream::iter([relayed(), Path::Direct]))
    }
}

/// A relayed path through a fixed relay.
fn relayed() -> Path {
    let url = url::Url::parse("https://relay.example/").expect("a valid url");
    Path::Relayed(Relay::from(url))
}

#[tokio::test]
async fn a_service_session_reports_its_sessions_path_changes() {
    use futures::StreamExt as _;

    let peer = NodeId::from_ed25519_secret(&[7u8; 32]);
    let session = ServiceSession {
        session: Moving { peer },
        connector: Connector::to_node(peer, svc("demo"), None),
    };
    let heard: Vec<Path> = session.path_changes().collect().await;
    assert_eq!(heard, [relayed(), Path::Direct]);
}

/// A forward to a host the test plays by hand, carrying one local client on one admitted stream. The host's
/// halves of that stream and its session are held here, so nothing ends until a row ends it.
struct Carried {
    _nodes: [Node<MemTransport, NoDiscovery>; 2],
    session: MemSession,
    writer: MemWrite,
    reader: MemRead,
    client: TcpStream,
    forward: tokio::task::JoinHandle<eyre::Result<()>>,
}

/// Run a forward to a hand-played host and connect `client` through it, returning once the host has
/// admitted the client's stream. Call inside a `LocalSet`.
async fn carried(client: TcpSocket) -> Carried {
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let consumer = Node::new(MemTransport::bind(), NoDiscovery);
    let admits = async {
        let session = host.accept().await.expect("the forward reaches the host");
        let (mut writer, mut reader) = session.accept_bi().await.expect("the probe stream");
        Request::read(&mut reader)
            .await
            .expect("the probe's request");
        Response::Ok
            .write(&mut writer)
            .await
            .expect("admit the probe");
        session
    };
    let preflight = Connector::to_node(host.node_id(), svc("demo"), None).preflight(&consumer, 0);
    let (session, forward) = tokio::join!(admits, preflight);
    let forward = forward.expect("the host admits the forward");
    // A large send buffer, inherited by the accepted socket, so a reply's tail is still queued in the
    // forward when it closes rather than already held by the client.
    let listener = TcpSocket::new_v4().expect("a forward socket");
    listener
        .set_send_buffer_size(256 * 1024)
        .expect("grow the forward's send buffer");
    listener
        .bind("127.0.0.1:0".parse().expect("a loopback address"))
        .expect("bind the forward");
    let listener = listener.listen(1).expect("listen");
    let addr = listener.local_addr().expect("bound");
    let forward = PortForward {
        listener,
        ..forward
    };
    let forward = tokio::task::spawn_local(forward.run());
    let client = client.connect(addr).await.expect("the forward accepts");
    let (mut writer, mut reader) = session.accept_bi().await.expect("the client's stream");
    Request::read(&mut reader)
        .await
        .expect("the client's request");
    Response::Ok
        .write(&mut writer)
        .await
        .expect("admit the client");
    Carried {
        _nodes: [host, consumer],
        session,
        writer,
        reader,
        client,
        forward,
    }
}

/// A plain loopback client socket.
fn client_socket() -> TcpSocket {
    TcpSocket::new_v4().expect("a client socket")
}

/// Whether `ended` is the read of a stream that was cut off.
fn reset(ended: &io::Result<usize>) -> bool {
    matches!(ended, Err(error) if error.kind() == io::ErrorKind::ConnectionReset)
}

/// Read `stream` to its end within [`WITHIN`], failing the row rather than hanging it.
async fn read_rest(stream: &mut (impl io::AsyncRead + Unpin)) -> io::Result<usize> {
    let mut rest = Vec::new();
    tokio::time::timeout(WITHIN, stream.read_to_end(&mut rest))
        .await
        .expect("the stream ends")
}

/// A local client that resets mid-upload reaches the host as a cut-off stream, never as an upload that
/// ended there: a clean end would hand the far service a truncated upload as a finished one.
#[tokio::test]
async fn a_local_client_reset_mid_upload_resets_the_hosts_stream() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut carried = carried(client_socket()).await;
            let part = b"the first part of an upload";
            carried.client.write_all(part).await.expect("upload");
            let mut got = vec![0_u8; part.len()];
            carried
                .reader
                .read_exact(&mut got)
                .await
                .expect("the host reads the part");

            carried
                .client
                .set_zero_linger()
                .expect("arm the client's reset");
            drop(carried.client);
            let ended = read_rest(&mut carried.reader).await;
            assert!(reset(&ended), "a client reset reaches the host: {ended:?}");
        })
        .await;
}

/// A host that cuts its stream off mid-download reaches the local client as a reset, never as a reply that
/// ended there.
#[tokio::test]
async fn a_host_cut_off_mid_download_resets_the_local_client() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut carried = carried(client_socket()).await;
            let part = b"the first part of a reply";
            carried.writer.write_all(part).await.expect("reply");
            let mut got = vec![0_u8; part.len()];
            carried
                .client
                .read_exact(&mut got)
                .await
                .expect("the client reads the part");

            carried.writer.abort();
            let ended = read_rest(&mut carried.client).await;
            assert!(reset(&ended), "a host cut-off resets the client: {ended:?}");
        })
        .await;
}

/// A session lost under a running forward drops every connection it carries where it stands, and each local
/// client reads that as a reset: nothing runs on that way out, so only a socket armed when it was accepted
/// can say it.
#[tokio::test]
async fn a_lost_session_resets_the_local_client() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut carried = carried(client_socket()).await;
            let part = b"the first part of a reply";
            carried.writer.write_all(part).await.expect("reply");
            let mut got = vec![0_u8; part.len()];
            carried
                .client
                .read_exact(&mut got)
                .await
                .expect("the client reads the part");

            carried.session.close();
            let ended = read_rest(&mut carried.client).await;
            assert!(reset(&ended), "a lost session resets the client: {ended:?}");
            let forwarded = tokio::time::timeout(WITHIN, carried.forward)
                .await
                .expect("the forward ends with its session")
                .expect("the forward ran");
            assert!(
                forwarded.is_err_and(|error| error.downcast_ref::<ConnectionLost>().is_some()),
                "the forward names the lost connection"
            );
        })
        .await;
}

/// A forward whose client and host both end cleanly passes each side every byte and a clean end. The client
/// reads slowly through a small receive buffer, so the reply's tail still waits in the forward's socket when
/// the forward closes it, and a reset left armed there would drop it.
#[tokio::test]
async fn a_forward_that_ends_cleanly_both_ways_delivers_every_byte() {
    const REPLY: usize = 1024 * 1024;

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let socket = client_socket();
            socket
                .set_recv_buffer_size(16 * 1024)
                .expect("shrink the client's receive buffer");
            let Carried {
                _nodes,
                session: _session,
                mut writer,
                mut reader,
                mut client,
                forward: _forward,
            } = carried(socket).await;
            let upload = b"a whole request";
            let reply: Vec<u8> = (0..REPLY).map(|at| (at % 251) as u8).collect();
            let host = async {
                let mut got = Vec::new();
                tokio::time::timeout(WITHIN, reader.read_to_end(&mut got))
                    .await
                    .expect("the upload ends")
                    .expect("the host reads a clean end");
                assert_eq!(got, upload, "the host reads every byte of the upload");
                writer.write_all(&reply).await.expect("reply");
                writer.shutdown().await.expect("end the reply");
            };
            let client = async {
                client.write_all(upload).await.expect("upload");
                client.shutdown().await.expect("end the upload");
                let mut got = Vec::new();
                let mut chunk = vec![0_u8; 16 * 1024];
                loop {
                    let read = client
                        .read(&mut chunk)
                        .await
                        .expect("the client reads a clean end");
                    if read == 0 {
                        return got;
                    }
                    got.extend_from_slice(&chunk[..read]);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            };
            let ((), got) = tokio::time::timeout(WITHIN, async { tokio::join!(host, client) })
                .await
                .expect("the forward ends");
            assert!(got == reply, "the client reads every byte the host sent");
        })
        .await;
}
