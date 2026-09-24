//! Tests for the port forward: every local connection rides its own stream, and a connection waiting for
//! a stream the peer has not yet granted never holds up the ones already flowing.

use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;

use bifrost::{ConnInfo, NoDiscovery, Node, NodeId, Session};
use bifrost_mem::MemTransport;
use nauthy::Gate;
use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::{Connector, MAX_PIPES, PortForward};
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

impl<S: Session> Session for Capped<S> {
    type Security = S::Security;
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
        exposer
            .run(&host, CancellationToken::new())
            .await
            .expect("exposer runs");
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
