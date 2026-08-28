//! `tightbeam expose`: publish local services under this node's key and forward inbound streams.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::{Args, ValueEnum};
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::{Approvals, Cap, Decision, Denylist, Gate, Identity, Refusal, Service};
use tokio::io;
use tokio::net::TcpStream;

use crate::protocol::{Request, Response};
use crate::splice;

/// Expose a local service to peers who hold this node's key.
#[derive(Debug, Args)]
pub struct ExposeCmd {
    /// expose local services as `name=addr` (bare `addr` = `default`)
    #[arg(required = true, value_name = "name=addr")]
    pub services: Vec<String>,
    /// How to authorize connectors. `open` (any peer), `strict` (the `--allow` list), `paired`
    /// (approved peers), or `cap` (a presented capability that verifies against this node's identity).
    #[arg(long, value_enum, default_value_t = GateMode::Open)]
    pub gate: GateMode,
    /// Only allow these node ids to connect (repeatable). Used by `--gate strict`.
    #[arg(long = "allow")]
    pub allow: Vec<String>,
    /// Suppress the readiness banner (the node id and service list). For unattended/CI use where the key
    /// must never land in a log; the tunnel still runs.
    #[arg(long)]
    pub quiet: bool,
}

/// How `expose` authorizes an inbound connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum GateMode {
    /// Permit any peer that reached the key.
    Open,
    /// Permit only the node ids passed with `--allow`.
    Strict,
    /// Permit only peers in the persisted approved set (approve with `tightbeam approve`).
    Paired,
    /// Permit only peers that present a capability rooted at this node's identity.
    Cap,
}

impl ExposeCmd {
    /// Accept overlay sessions from permitted peers and forward each inbound stream to the service.
    ///
    /// `identity` is the exposer's cap-signing identity, rooted at the same secret bifrost bound the node
    /// under, so a `cap` gate verifies presented tokens against the key peers dial.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        identity: Identity,
        host_seed: [u8; 32],
        approved_path: PathBuf,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let gate = Arc::new(self.gate(identity, approved_path).await?);
        let services = Arc::new(parse_services(&self.services)?);
        // A shell service has no auth of its own, so the gate IS its authentication: refuse to expose one
        // with an open gate, which would hand a keyless shell to anyone who reaches this node.
        if matches!(self.gate, GateMode::Open) && services.values().any(|addr| addr == "sshd:") {
            eyre::bail!(
                "a shell service (sshd:) has no auth of its own and must be gated; \
                 use --gate cap or --gate strict, not open"
            );
        }
        // The readiness banner names the node id; `--quiet` withholds it so a key never lands in an
        // unattended log. The tunnel is unaffected either way.
        if !self.quiet {
            println!("tightbeam ready. peers can reach these services at:\n");
            println!(
                "    {}                     (share this key, or mint a link with `tightbeam share`)\n",
                node.node_id()
            );
            let mut names: Vec<&str> = services.keys().map(String::as_str).collect();
            names.sort_unstable();
            println!("exposing {}. press ctrl-c to stop.", names.join(", "));
        }
        let mut sessions = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = node.accept() => {
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

    /// Build the authorization gate from the flags.
    async fn gate(&self, identity: Identity, approved_path: PathBuf) -> eyre::Result<Gate> {
        match self.gate {
            GateMode::Open => Ok(Gate::Open),
            GateMode::Strict => Ok(Gate::Strict(parse_allowed(&self.allow)?)),
            GateMode::Paired => Ok(Gate::Paired(Approvals::load(approved_path).await?)),
            GateMode::Cap => {
                // The revocation denylist is loaded once at expose; a `tightbeam revoke` adds to the file,
                // which the next exposer run reads. Offline recall, node-local, no server.
                let denylist = Denylist::load(crate::config::revoked_path()?).await?;
                Ok(Gate::Cap(identity, Box::new(denylist)))
            }
        }
    }
}

/// Serve one accepted session: handle each inbound stream's service request under the gate.
async fn serve_session<S: Session>(
    session: S,
    gate: Arc<Gate>,
    services: Arc<HashMap<String, String>>,
    host_seed: [u8; 32],
) -> eyre::Result<()>
where
    S::Write: Send + 'static,
    S::Read: Send + 'static,
{
    let peer = session.peer();
    let mut pipes = FuturesUnordered::new();
    loop {
        tokio::select! {
            accepted = session.accept_bi() => {
                let (writer, reader) = accepted?;
                pipes.push(serve_request(
                    peer,
                    writer,
                    reader,
                    Arc::clone(&gate),
                    Arc::clone(&services),
                    host_seed,
                ));
            }
            Some(result) = pipes.next(), if !pipes.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "pipe ended");
                }
            }
        }
    }
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
    services: Arc<HashMap<String, String>>,
    host_seed: [u8; 32],
) -> eyre::Result<()>
where
    W: io::AsyncWrite + Unpin + Send + 'static,
    R: io::AsyncRead + Unpin + Send + 'static,
{
    let request = Request::read(&mut reader).await?;
    let Ok(service) = request.service.parse::<Service>() else {
        let message = format!("invalid service name {:?}", request.service);
        return Response::Error(message)
            .write(&mut writer)
            .await
            .map_err(Into::into);
    };

    match admit(&gate, peer, request.capability.as_deref(), &service) {
        Ok(()) => {}
        Err(refusal) => {
            tracing::warn!(%peer, service = %service, %refusal, "refused");
            return Response::Error(refusal)
                .write(&mut writer)
                .await
                .map_err(Into::into);
        }
    }

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
                sshh::serve(host_seed, writer, reader).await?;
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
            let message = format!("unknown service {:?}", service.as_str());
            Response::Error(message).write(&mut writer).await?;
        }
    }
    Ok(())
}

/// Apply the gate to a request, mapping a refusal to a peer-facing reason string.
fn admit(
    gate: &Gate,
    peer: NodeId,
    capability: Option<&str>,
    service: &Service,
) -> Result<(), String> {
    // Parse a presented capability at the edge; a malformed token is a refusal, not a hard error, so the
    // connector gets a clean "not permitted" rather than a dropped stream.
    let cap = match capability.map(Cap::parse).transpose() {
        Ok(cap) => cap,
        Err(_) => return Err("malformed capability".to_owned()),
    };
    match gate.admit(peer, cap.as_ref(), service) {
        Decision::Admit => Ok(()),
        Decision::Refuse(Refusal::Missing) => Err("this service requires a capability".to_owned()),
        Decision::Refuse(Refusal::NotGranted) => {
            Err("capability does not grant this service".to_owned())
        }
        Decision::Refuse(Refusal::NotPermitted) => Err("not permitted".to_owned()),
        Decision::Refuse(Refusal::Revoked) => Err("capability has been revoked".to_owned()),
    }
}

/// Parse `name=addr` service entries; a bare `addr` becomes the `default` service.
fn parse_services(entries: &[String]) -> eyre::Result<HashMap<String, String>> {
    let mut services = HashMap::new();
    for entry in entries {
        let (name, addr) = match entry.split_once('=') {
            Some((name, addr)) => (name.to_owned(), addr.to_owned()),
            None => ("default".to_owned(), String::clone(entry)),
        };
        // Validate the name through the same domain type the wire uses, so an exposed name and a
        // requested name are compared as the same kind of thing.
        name.parse::<Service>()?;
        services.insert(name, addr);
    }
    Ok(services)
}

/// Parse node ids into an allowlist set.
fn parse_allowed(ids: &[String]) -> eyre::Result<std::collections::HashSet<NodeId>> {
    ids.iter()
        .map(|id| id.parse::<NodeId>().map_err(Into::into))
        .collect()
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
