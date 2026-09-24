//! Tests for the port forward: every local connection rides its own stream, and a connection waiting for
//! a stream the peer has not yet granted never holds up the ones already flowing.

use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;

use bifrost::{ConnInfo, NoDiscovery, Node, NodeId, Session};
use bifrost_mem::MemTransport;
use nauthy::Gate;
use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::{Connector, PortForward};
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
        let slot = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(|error| bifrost::Error::Stream(Box::new(error)))?;
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

#[tokio::test]
async fn a_local_connection_past_the_stream_limit_does_not_stall_the_forward() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
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
            let forward = PortForward {
                session: Capped {
                    session: forward.session,
                    slots: Arc::new(Semaphore::new(STREAM_LIMIT)),
                },
                listener: forward.listener,
                request: forward.request,
            };
            tokio::task::spawn_local(forward.run());

            // Take every stream the peer grants, each one proven live.
            let mut held = Vec::new();
            for _ in 0..STREAM_LIMIT {
                let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                assert!(echoes(&mut client, b"up").await, "a forward within the limit echoes");
                held.push(client);
            }

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
