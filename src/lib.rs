//! tightbeam: private peer-to-peer tunnels over the bifrost overlay.
//!
//! `expose` forwards inbound overlay streams to a local TCP service; `connect` binds a peer's exposed
//! service to a local port. Each proxied TCP connection rides one bifrost bidirectional stream. Who
//! may connect is decided by [`nauthy`], the authorization gate.
//!
//! Concurrency uses `FuturesUnordered` + `select!` (structured concurrency on one task) rather than
//! `tokio::spawn`, because the bifrost interface's futures are not `Send`-bounded. This keeps the tool
//! generic over any transport; see DECISIONS.md for the trade-off.

pub mod nauthy;

mod protocol;

use std::collections::HashMap;
use std::sync::Arc;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use tokio::io::{self, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::nauthy::{Approvals, Gate, parse_allowed};
use crate::protocol::{Request, Response};

/// Expose a local service to peers who hold this node's key.
#[derive(Debug, Args)]
pub struct ExposeCmd {
    /// Services to expose as `name=addr` (e.g. `ssh=127.0.0.1:22`), or a bare `addr` for `default`.
    #[arg(required = true)]
    pub services: Vec<String>,
    /// Only allow these node ids to connect (repeatable). Overrides `--pair`.
    #[arg(long = "allow")]
    pub allow: Vec<String>,
    /// Pairing mode: permit only approved peers, and print unknown attempts to approve later.
    #[arg(long)]
    pub pair: bool,
}

impl ExposeCmd {
    /// Accept overlay sessions from permitted peers and forward each inbound stream to the service.
    pub async fn run<T: Transport, D: Discovery>(&self, node: &Node<T, D>) -> eyre::Result<()> {
        let gate = self.gate().await?;
        let services = Arc::new(parse_services(&self.services)?);
        println!(
            "exposing {} service(s) as {}",
            services.len(),
            node.node_id()
        );
        let mut sessions = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = node.accept() => {
                    let session = accepted?;
                    let peer = session.peer();
                    if !gate.permits(peer) {
                        self.reject(peer);
                        continue;
                    }
                    sessions.push(serve_session(session, services.clone()));
                }
                Some(result) = sessions.next(), if !sessions.is_empty() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "session ended");
                    }
                }
            }
        }
    }

    /// Build the authorization gate from the flags: `--allow` (strict) wins, then `--pair`, else open.
    async fn gate(&self) -> eyre::Result<Gate> {
        if !self.allow.is_empty() {
            Ok(Gate::Strict(parse_allowed(&self.allow)?))
        } else if self.pair {
            Ok(Gate::Paired(Approvals::load().await?))
        } else {
            Ok(Gate::Open)
        }
    }

    /// Report a rejected peer: a reviewable pending line in pairing mode, otherwise a warning.
    fn reject(&self, peer: NodeId) {
        if self.pair {
            println!("pending: {peer} tried to connect (approve: tightbeam approve {peer})");
        } else {
            tracing::warn!(%peer, "rejected: not permitted");
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
    /// Which exposed service to reach.
    #[arg(long, default_value = "default")]
    pub service: String,
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

/// Approve a peer key so it may connect in pairing mode.
#[derive(Debug, Args)]
pub struct ApproveCmd {
    /// The node id to approve.
    pub node: String,
}

impl ApproveCmd {
    /// Add a peer to the persisted approved set.
    pub async fn run(&self) -> eyre::Result<()> {
        let peer: NodeId = self.node.parse()?;
        let mut approvals = Approvals::load().await?;
        approvals.approve(peer).await?;
        println!("approved {peer} ({})", approvals.path().display());
        Ok(())
    }
}

/// Serve one accepted session: handle each inbound stream's service request.
async fn serve_session<S: Session>(
    session: S,
    services: Arc<HashMap<String, String>>,
) -> eyre::Result<()> {
    let mut pipes = FuturesUnordered::new();
    loop {
        tokio::select! {
            accepted = session.accept_bi() => {
                let (writer, reader) = accepted?;
                pipes.push(serve_request(writer, reader, services.clone()));
            }
            Some(result) = pipes.next(), if !pipes.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "pipe ended");
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

/// Serve one inbound stream: read the requested service, reply, and pipe on success.
async fn serve_request<W, R>(
    mut writer: W,
    mut reader: R,
    services: Arc<HashMap<String, String>>,
) -> eyre::Result<()>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    let request = Request::read(&mut reader).await?;
    match services.get(&request.service) {
        Some(addr) => {
            Response::Ok.write(&mut writer).await?;
            dial_and_splice(addr, writer, reader).await?;
        }
        None => {
            let message = format!("unknown service {:?}", request.service);
            Response::Error(message).write(&mut writer).await?;
        }
    }
    Ok(())
}

/// Parse `name=addr` service entries; a bare `addr` becomes the `default` service.
fn parse_services(entries: &[String]) -> eyre::Result<HashMap<String, String>> {
    let mut services = HashMap::new();
    for entry in entries {
        let (name, addr) = match entry.split_once('=') {
            Some((name, addr)) => (name.to_owned(), addr.to_owned()),
            None => ("default".to_owned(), entry.clone()),
        };
        services.insert(name, addr);
    }
    Ok(services)
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

/// Copy bytes both ways between a local stream and a bifrost stream until both sides close.
async fn splice<S, W, R>(local: S, mut writer: W, mut reader: R) -> io::Result<()>
where
    S: io::AsyncRead + io::AsyncWrite + Unpin,
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    let (mut local_reader, mut local_writer) = io::split(local);
    let upstream = async {
        io::copy(&mut local_reader, &mut writer).await?;
        writer.shutdown().await
    };
    let downstream = async {
        io::copy(&mut reader, &mut local_writer).await?;
        local_writer.shutdown().await
    };
    tokio::try_join!(upstream, downstream)?;
    Ok(())
}
