//! `tightbeam connect`: bind a peer's exposed service to a local port, by node id or by capability link.

use core::str::FromStr;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::{ArgGroup, Args};
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::{Cap, SCHEME};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};

use crate::protocol::{Request, Response};
use crate::{splice, splice_halves};

/// Reach a peer's exposed service and bind it to a local port, or pipe it over stdin/stdout.
#[derive(Debug, Args)]
#[command(group = ArgGroup::new("dest").required(true).args(["to", "stdio"]))]
pub struct ConnectCmd {
    /// who to reach: a raw node id, or a `sheer:` capability link
    #[arg(value_name = "peer")]
    pub target: Target,
    /// local port to forward to the peer
    #[arg(long, value_name = "port")]
    pub to: Option<u16>,
    /// pipe the peer's service over stdin/stdout instead of a local port (for ssh ProxyCommand)
    #[arg(long)]
    pub stdio: bool,
    /// which exposed service to reach
    #[arg(long, default_value = "default")]
    pub service: String,
    /// present a capability link alongside a raw node id
    #[arg(long, value_name = "link")]
    pub present: Option<String>,
}

/// What `connect` was pointed at: a bare identity, or a capability link.
///
/// A capability link supersedes the identity path entirely: it names the node to dial (the cap's root)
/// and the service it grants, and it presents the token. A bare node id is the pre-capability path, gated
/// on the proven identity alone.
#[derive(Debug, Clone)]
pub enum Target {
    /// A raw node id to dial; the host gates on the proven identity (open/strict/paired).
    Node(NodeId),
    /// A capability link (`sheer:…`) to present to a `cap`-gated host.
    Capability(String),
}

impl FromStr for Target {
    type Err = eyre::Error;

    fn from_str(text: &str) -> eyre::Result<Self> {
        if text.starts_with(SCHEME) {
            // Parse it now so a malformed link fails fast at the CLI boundary, not mid-connect. The
            // owned string is re-parsed at use so the token travels whole to the host.
            Cap::parse(text)?;
            Ok(Target::Capability(text.to_owned()))
        } else {
            Ok(Target::Node(text.parse::<NodeId>()?))
        }
    }
}

impl ConnectCmd {
    /// Reach the peer, then either bind a local port and forward each accepted connection, or (`--stdio`)
    /// pipe the single service stream against this process's stdin/stdout, the ssh `ProxyCommand` shape.
    pub async fn run<T: Transport, D: Discovery>(self, node: &Node<T, D>) -> eyre::Result<()> {
        let plan = self.plan()?;
        let session = node.connect(plan.dial).await?;
        // The arg group makes exactly one of `--to`/`--stdio` present, so a missing port means stdio.
        match self.to {
            Some(port) => serve_port(&session, &plan, port).await,
            None => stdio_pipe(&session, &plan).await,
        }
    }

    /// Resolve the target into a node to dial, a service to request, and an optional token to present.
    ///
    /// A capability link supplies the node to dial (the cap's root) and carries the token; the service
    /// requested is still `--service`, and the host refuses unless the token actually grants that service.
    /// A bare node id uses `--service` and presents nothing.
    fn plan(&self) -> eyre::Result<Plan> {
        let service = String::clone(&self.service);
        match &self.target {
            Target::Node(node) => Ok(Plan {
                dial: *node,
                service,
                // A raw-node dial may still present a token via `--present`, for the case where the node
                // id was shared separately from the capability.
                capability: self.present.clone(),
            }),
            Target::Capability(link) => Ok(Plan {
                dial: Cap::parse(link)?.root(),
                service,
                capability: Some(String::clone(link)),
            }),
        }
    }
}

/// A resolved connect: the node to dial, the service to ask for, and any token to present.
struct Plan {
    dial: NodeId,
    service: String,
    capability: Option<String>,
}

impl Plan {
    /// The opening request this plan sends on each stream: the service to reach and any token.
    fn request(&self) -> Request {
        Request {
            service: String::clone(&self.service),
            capability: self.capability.clone(),
        }
    }
}

/// Bind a local port and forward each accepted TCP connection to the peer over its own stream.
async fn serve_port<S: Session>(session: &S, plan: &Plan, port: u16) -> eyre::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    println!(
        "forwarding 127.0.0.1:{port} to {} ({})",
        plan.dial, plan.service
    );
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
                pipes.push(request_service(plan.request(), tcp, writer, reader));
            }
            Some(result) = pipes.next(), if !pipes.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "pipe ended");
                }
            }
        }
    }
}

/// Reach the service over one stream and pipe it against this process's stdin/stdout: the ssh
/// `ProxyCommand` shape, where ssh speaks its protocol over our stdio and we carry it to the peer. No
/// stdout prints here, since stdout IS the data channel.
async fn stdio_pipe<S: Session>(session: &S, plan: &Plan) -> eyre::Result<()> {
    let (writer, reader) = session.open_bi().await?;
    request_stdio(plan.request(), writer, reader).await
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

/// Open a service and, if the host accepts, pipe it against this process's stdin/stdout (the `--stdio`
/// path). Same handshake as [`request_service`], but the local ends are the process's own std streams.
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
