//! `tightbeam connect`: bind a peer's exposed service to a local port, by node id or by capability link.

use core::str::FromStr;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::{Cap, SCHEME};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};

use crate::protocol::{Request, Response};
use crate::splice;

/// Reach a peer's exposed service and bind it to a local port.
#[derive(Debug, Args)]
pub struct ConnectCmd {
    /// Who to reach: a raw node id, or a `sheer:` capability link (which carries the node to dial and the
    /// token to present).
    pub target: Target,
    /// The local port to listen on and forward to the peer.
    #[arg(long)]
    pub to: u16,
    /// Which exposed service to reach. With a capability link, the host verifies the token grants this
    /// exact service, so it must match what the link was minted or narrowed for.
    #[arg(long, default_value = "default")]
    pub service: String,
    /// Present this capability link while dialing a raw node id. Rarely needed: a `sheer:` target already
    /// carries its token. Use it when you hold a token but were also given the node id directly.
    #[arg(long)]
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
    /// Listen locally and forward each accepted connection to the peer over one stream.
    pub async fn run<T: Transport, D: Discovery>(self, node: &Node<T, D>) -> eyre::Result<()> {
        let plan = self.plan()?;
        let session = node.connect(plan.dial).await?;
        let listener = TcpListener::bind(("127.0.0.1", self.to)).await?;
        println!(
            "forwarding 127.0.0.1:{} to {} ({})",
            self.to, plan.dial, plan.service
        );
        let mut pipes = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    // One local accept or stream-open failing must not drop the pipes already in
                    // flight: log the transient error and keep the local listener up.
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
                    let request = Request {
                        service: String::clone(&plan.service),
                        capability: plan.capability.clone(),
                    };
                    pipes.push(request_service(request, tcp, writer, reader));
                }
                Some(result) = pipes.next(), if !pipes.is_empty() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "pipe ended");
                    }
                }
            }
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
