//! tightbeam: private peer-to-peer tunnels over the bifrost overlay.
//!
//! `expose` forwards inbound overlay streams to a local TCP service; `connect` binds a peer's exposed
//! service to a local port. Each proxied TCP connection rides one bifrost bidirectional stream.
//!
//! Concurrency uses `FuturesUnordered` + `select!` (structured concurrency on one task) rather than
//! `tokio::spawn`, because the bifrost seam's futures are not `Send`-bounded. This keeps the tool
//! generic over any transport; see DECISIONS.md for the trade-off.

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use tokio::io::{self, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// Expose a local service to peers who hold this node's key.
#[derive(Debug, Args)]
pub struct ExposeCmd {
    /// The local address inbound streams are forwarded to, e.g. `127.0.0.1:22`.
    pub local_addr: String,
}

impl ExposeCmd {
    /// Accept overlay sessions and forward every inbound stream to the local service.
    pub async fn run<T: Transport, D: Discovery>(&self, node: &Node<T, D>) -> eyre::Result<()> {
        println!("exposing {} as {}", self.local_addr, node.node_id());
        let mut sessions = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = node.accept() => {
                    sessions.push(serve_session(accepted?, self.local_addr.clone()));
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

/// Reach a peer's exposed service and bind it to a local port.
#[derive(Debug, Args)]
pub struct ConnectCmd {
    /// The node id to dial.
    pub node: String,
    /// The local port to listen on and forward to the peer.
    #[arg(long)]
    pub to: u16,
}

impl ConnectCmd {
    /// Listen locally and forward each accepted connection to the peer over one stream.
    pub async fn run<T: Transport, D: Discovery>(&self, node: &Node<T, D>) -> eyre::Result<()> {
        let peer: NodeId = self.node.parse()?;
        let session = node.connect(peer).await?;
        let listener = TcpListener::bind(("127.0.0.1", self.to)).await?;
        println!("forwarding 127.0.0.1:{} to {peer}", self.to);
        let mut pipes = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (tcp, _) = accepted?;
                    let (writer, reader) = session.open_bi().await?;
                    pipes.push(splice(tcp, writer, reader));
                }
                Some(result) = pipes.next(), if !pipes.is_empty() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "pipe ended");
                    }
                }
            }
        }
    }
}

/// Serve one accepted session: forward each inbound stream to a fresh local connection.
async fn serve_session<S: Session>(session: S, local_addr: String) -> eyre::Result<()> {
    let mut pipes = FuturesUnordered::new();
    loop {
        tokio::select! {
            accepted = session.accept_bi() => {
                let (writer, reader) = accepted?;
                let tcp = TcpStream::connect(&local_addr).await?;
                pipes.push(splice(tcp, writer, reader));
            }
            Some(result) = pipes.next(), if !pipes.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "pipe ended");
                }
            }
        }
    }
}

/// Copy bytes both ways between a TCP connection and a bifrost stream until both sides close.
async fn splice<W, R>(tcp: TcpStream, mut writer: W, mut reader: R) -> io::Result<()>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    let (mut tcp_reader, mut tcp_writer) = tcp.into_split();
    let upstream = async {
        io::copy(&mut tcp_reader, &mut writer).await?;
        writer.shutdown().await
    };
    let downstream = async {
        io::copy(&mut reader, &mut tcp_writer).await?;
        tcp_writer.shutdown().await
    };
    tokio::try_join!(upstream, downstream)?;
    Ok(())
}
