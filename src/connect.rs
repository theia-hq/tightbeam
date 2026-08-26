//! `tightbeam connect`: bind a peer's exposed service to a local port.

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};

use crate::protocol::{Request, Response};
use crate::splice;

/// Reach a peer's exposed service and bind it to a local port.
#[derive(Debug, Args)]
pub struct ConnectCmd {
    /// The node id to dial.
    pub node: NodeId,
    /// The local port to listen on and forward to the peer.
    #[arg(long)]
    pub to: u16,
    /// Which exposed service to reach.
    #[arg(long, default_value = "default")]
    pub service: String,
}

impl ConnectCmd {
    /// Listen locally and forward each accepted connection to the peer over one stream.
    pub async fn run<T: Transport, D: Discovery>(self, node: &Node<T, D>) -> eyre::Result<()> {
        let session = node.connect(self.node).await?;
        let listener = TcpListener::bind(("127.0.0.1", self.to)).await?;
        println!("forwarding 127.0.0.1:{} to {}", self.to, self.node);
        let mut pipes = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (tcp, _) = accepted?;
                    let (writer, reader) = session.open_bi().await?;
                    pipes.push(request_service(self.service.clone(), tcp, writer, reader));
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

/// Open a stream to a service: send the request, and if the host accepts, pipe the connection.
async fn request_service<W, R>(
    service: String,
    tcp: TcpStream,
    mut writer: W,
    mut reader: R,
) -> eyre::Result<()>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    Request { service }.write(&mut writer).await?;
    match Response::read(&mut reader).await? {
        Response::Ok => splice(tcp, writer, reader).await?,
        Response::Error(message) => eyre::bail!("service refused: {message}"),
    }
    Ok(())
}
